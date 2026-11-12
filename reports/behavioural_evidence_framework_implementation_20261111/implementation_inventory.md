# Implementation inventory (Task 22)

## New module: `behavioural_evidence/` (repository root, beside `scripts/`)

| File | Responsibility |
|---|---|
| `__init__.py` | Public API: `EvidenceEngine`, `EvidenceConfig`, `CATALOGUE_VERSION`, `INDICATORS`, `INTERPRETATIONS`, error types |
| `catalogue.py` | **Versioned definitions** (`v2-evidence-1.1`): 27 entries (the 25 design indicators, NET-0 from the approved FP-4 amendment, and TIME-0), each with category, kind (action/context/caveat), evidence class, required telemetry and limitations. 11 interpretation rules. `catalogue_document()` is the machine-readable contract and `check_catalogue()` enforces compatibility |
| `commandline.py` | Parsing: split at unquoted `\|`, `;`, `&&`, `\|\|`; POSIX `shlex`; redirections separated; `sudo` recorded as a wrapper; `./x` local execution; `parse_degraded` and command-substitution flags. Nothing is expanded |
| `indicators.py` | Token, flag and path-component matchers. Every `Match` records indicator, line index, source line, simple command, token, detail, linked file and position. `NetScope` holds the qualifying internal targets for NET-1 |
| `engine.py` | Schema-checked event loading; per-session aggregation in (timestamp, log order); source-window authentication (AUTH-1/2); outcomes (`observed_success` only from Cowrie outcome events, `observed_failure:emulator_rejected` from `command.failed`, else `not_observed`); multi-label interpretations; E0–E3; explicit `indeterminate` / `insufficient_evidence` / `system_discovery_only`; caveats; provenance; separate `statistical_novelty` |
| `calibration.py` | `SensorCalibration` (schema `sensor-calibration-1`): slow-command list for ART-1 and an inter-input-gap reference for the TIME-0 caveat. Kept separate from matching |
| `schema.py` | Supported telemetry schema (`cowrie-json-2.9`); required fields per event type; rejects V1 feature fields |
| `errors.py` | `SchemaError`, `CatalogueError`, `AttributionError` |
| `__main__.py` | CLI: `python -m behavioural_evidence --input <cowrie.json> --output <evidence.jsonl> [--calibration] [--relay-source] [--internal-host] [--internal-network]`. No scoring, no actions |

**Tests:** `tests/test_behavioural_evidence.py`, 80 tests on synthetic events only. The full repository suite is 386 passed, previously 306 (`test_results.txt`).

**Dependencies:** standard library only. pandas is used by the validation scripts in this report directory, not by the module.

## Behaviour against the Task 22 requirements

| Requirement | Where | Notes |
|---|---|---|
| Split simple commands; whole tokens, flags, path components; order kept; source line and token recorded | `commandline.py`, `indicators.py` | Validation check V2: 0 tokens that are not parsed tokens of their line |
| All indicators with ID, category, kind, telemetry, result, source, limitations, caveats | `catalogue.py`; per-session `indicators[]` | `caveats_on_same_lines` lists EMU-1/ART-1 on the matched line |
| Context never establishes an interpretation; caveats never become indicators | `INTERPRETATIONS` (`all_of` must be action; enforced by `check_catalogue`) | V6 |
| Authentication: ≥ 3 distinct failures / 300 s / same `src_ip`; relay/NAT → `indeterminate`; no attribution → `AttributionError` | `engine._auth`, `engine._sessions` | Duplicate events are not distinct. A `session.connect` without `src_ip` is a `SchemaError` |
| NET-1 only for scanning tools or qualifying internal/scan targets; `curl -I` → NET-0 (context) | `indicators.network`, `NetScope` | The default internal networks contain no RFC 5737 documentation ranges |
| Caveats: EMU-1, ART-1 (calibrated), SEQ-1 (reference store), TIME-0 (unusual gap) | `engine.evaluate`, `calibration.py` | Calibration is a separate input with its own schema and digest |
| E0–E3; multi-label; attempt wording; no probabilities; no DEC; no Known-like / Ambiguous / Potentially Novel | `engine.evaluate` | E3 requires E2 plus an observed outcome event (`file_download`, `file_upload` or `login.success` via AUTH-2) |
| Schema and catalogue version safety | `schema.py`, `catalogue.check_catalogue`, `calibration.load_calibration` | All three fail loudly |
| Statistical novelty separate | `statistical_novelty` field | V11: behavioural output is byte-identical with and without novelty metadata |

## Legacy implementation (unchanged)

The following were not modified, verified by SHA-256 against the Task 20 recorded hashes (`report.md` §6):
- `scripts/behaviour_pattern_analysis.py`
- `scripts/behaviour_signature_generation.py`
- `scripts/novelty_assessment.py`
- `reports/behaviour_signatures/behaviour_signatures.json`
- `configs/defence_policy.json` (not read by the new module)

## Report-directory scripts

| Script | Purpose |
|---|---|
| `validate_framework.py` | Train/validation validation runs (primary, lab address-plan, no-calibration, oracle-source diagnostic), 25 checks, distributions, false-positive comparison. Writes `config/` (training calibration, configurations, catalogue copy) and `evidence/` |
| `make_status.py` | `indicator_implementation_status.csv` |
