# Integration contract: `behavioural_evidence` → threat assessment

**Derived from:**
- `behavioural_evidence/engine.py` (`EvidenceEngine.evaluate`), `catalogue.py` and `__main__.py`, at the hashes in `evidence/hashes_before.txt`;
- every field observed in the 5,704 Task 22 records (`evidence/observed_output_fields.json`).

An example record is in `evidence/example_record_validation.json`. No field is invented. Fields the implementation can emit but that were not observed on V2 are marked *(not observed on V2)*.

## 1. Delivery

- **Python:** `EvidenceEngine(config).evaluate(events, novelty=None)` returns one dict with:
  - `catalogue_version` (str, `"v2-evidence-1.1"`);
  - `telemetry_schema` (str, `"cowrie-json-2.9"`);
  - `config_digest` (16 hex characters);
  - `sessions` (list of session records, §2);
  - `authentication_windows` (dict `"<src_ip>@<iso time>"` → `{src_ip, failures, sessions[]}`);
  - `unknown_event_types` (dict eventid → count).
- **CLI:** `python -m behavioural_evidence` writes one session record per line (JSONL, `sort_keys`) and `<output>.meta.json` containing every top-level field except `sessions`.
- **Errors (raised, never partial output):**
  - `SchemaError`: unsupported telemetry schema, a missing required field, V1 feature fields, or malformed JSONL;
  - `CatalogueError`: incompatible catalogue version, indicator set or kinds, or a bad calibration file;
  - `AttributionError`: login events with no source anywhere in the session.

## 2. Session record

| Field | Type | Values / meaning |
|---|---|---|
| `session_ref` | str | Cowrie session ID (**the session identifier**) |
| `src_ip` | str \| null | First `src_ip` seen in the session. Null only possible for a session with no connect event and no login events |
| `catalogue_version`, `telemetry_schema`, `config_digest` | str | Repeated per record for provenance |
| `calibration` | object \| null | `{sensor, version, digest}` of the `SensorCalibration` used |
| `n_input_lines` | int | Recorded input lines, excluding `exit`/`logout` |
| `authentication_status` | str | `no_authentication_events`, `indeterminate:shared_source`, `below_threshold`, `success_without_repeated_failures`, `repeated_failures`, `repeated_failures+success` |
| `behavioural_status` | str | `interpreted`, `system_discovery_only`, `insufficient_evidence`, `indeterminate` (authentication-only session from a shared source) |
| `abstention_reason` | str \| null | null when interpreted. Observed values: "no command input"; "context indicators only"; "context and/or caveat indicators only"; "authentication-only session; source attribution shared_source"; "action indicator(s) [...] without a satisfied interpretation rule" *(not observed on V2)* |
| `evidence_level` | str | `E0`–`E3`: the session maximum. **E1 can occur with `insufficient_evidence`** (an action indicator without a satisfied rule) |
| `interpretations[]` | list | §3 |
| `indicators[]` | list | §4 |
| `action_indicators[]`, `context_indicators[]`, `caveat_indicators[]` | list[str] | Indicator IDs present, by kind |
| `caveats[]` | list[str] | Parse caveats: `parse_degraded: …`, `command substitution present …` *(not observed on V2)* |
| `timing_context` | object | `session_duration_s` (float \| null), `inter_input_gaps` (int), `inter_input_mean_s`, `inter_input_max_s` (float \| null). **Context only** |
| `statistical_novelty` | object \| null | `{value: <caller-supplied mapping, passed through unchanged>, independent_of_behavioural_evidence: true, explanatory_caveats: [ART-1/EMU-1/TIME-0 present]}`. **The separate novelty field** |

## 3. `interpretations[]`

| Field | Type | Meaning |
|---|---|---|
| `name` | str | One of the 11 rule names (attempt-worded) |
| `scope` | str | `session` or `source_window` (authentication rules) |
| `requires[]`, `requires_one_of[]` | list[str] | The rule's required action IDs, and its at-least-one-of set |
| `supporting_action_indicators[]` | list[str] | Distinct action IDs present that support this interpretation (basis of its level) |
| `evidence_level` | str | `E1` (1 supporting action ID), `E2` (≥ 2), `E3` (E2 plus an observed outcome event) |
| `outcome` | object | Per supporting action ID: `not_observed`, `observed_success`, `observed_failure:emulator_rejected` |
| `files[]` | list[str] | Only for `download-and-execute attempt`: the linked file names |

## 4. `indicators[]`

| Field | Type | Meaning |
|---|---|---|
| `id`, `name`, `category`, `kind`, `evidence_class` | str | From the catalogue. `kind` is action / context / caveat. `evidence_class` is directly_observed / inferred / emulator_dependent / generator_dependent / sensor_calibration |
| `required_telemetry[]`, `limitations` | list[str], str | From the catalogue |
| `outcome` | str | Only on action indicators that carry outcomes (not on AUTH-1, XFER-1-OK, XFER-2-OK) |
| `caveats_on_same_lines[]` | list[str] | EMU-1 / ART-1 on a line this indicator matched |
| `matches[]` | list | `line_index` (int; index into the session's filtered input lines; **-1 for event-based matches**: AUTH-*, XFER-*-OK, TIME-0, and EMU-1 when the failed input cannot be mapped), `line` (source line), `command` (simple command), `token` (matched token; for AUTH-1 the window ID), `detail` (rule detail, e.g. CRED-1 `credential file path` / `path inside .ssh` / `find for credential file name`), `file` (XFER-1/EXEC-1 linked name, optional) |

## 5. Gaps the threat layer must handle (the package is not changed)

| # | Gap | Consumption rule |
|---|---|---|
| G1 | Matches carry no event timestamp or UUID | For audit, resolve evidence by `(session_ref, line_index)` against the raw Cowrie slice and store the event IDs in the assessment record |
| G2 | The relay list, internal networks and authentication parameters are visible only as `config_digest` | The assessment must receive the serialised `EvidenceConfig` and recompute `digest()`; on mismatch, refuse |
| G3 | The package silently falls back to `DEFAULT_INTERNAL_NETWORKS` when no scope is given | NET-1 findings are `network_scope: unconfirmed` unless the supplied config declares an explicit internal CIDR list; such findings are never policy-eligible |
| G4 | Session `evidence_level` can exceed the strongest interpretation (E1 with `insufficient_evidence`) | Assessment uses **per-interpretation** levels only |
| G5 | CRED-1 mixes private keys / `shadow` with `~/.ssh/known_hosts` | Severity uses `matches[].detail` (`severity_model.md`) |
| G6 | `statistical_novelty.value` is opaque caller data | Display only; never an input to severity, evidence or policy |
| G7 | Window membership is at result level (`authentication_windows`), not per record | Join by `src_ip` and AUTH-1 `token` |
| G8 | `behavioural_status` may be `interpreted` while `authentication_status` is `indeterminate:shared_source` (commands typed through a relay) | Attribution is decided by the assessment for **any** action, not only authentication rules |
| G9 | No sensor identifier except `calibration.sensor` | Assessment records the sensor from deployment configuration |
