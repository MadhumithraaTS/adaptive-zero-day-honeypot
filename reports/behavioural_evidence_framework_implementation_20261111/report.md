# Behavioural evidence framework: implementation and train/validation testing (Task 22)

**Date:** 2026-11-11.

**What was built:**
- the new module `behavioural_evidence/`;
- the tests `tests/test_behavioural_evidence.py`.

**Not done:**
- no legacy signature, matcher, scoring logic, extractor, frozen configuration or model was changed;
- DEC and the novelty models were not retrained;
- no defence rule was activated, and `configs/defence_policy.json` is not integrated;
- TTY collection was not added;
- the sealed test and exfiltration data were not accessed (an audit hook blocks test, sealed and exfiltration paths);
- nothing was committed.

**No zero-day detection is claimed.**

**Reproduce:**

```
.venv/Scripts/python.exe -m pytest -q tests/test_behavioural_evidence.py
.venv/Scripts/python.exe reports/behavioural_evidence_framework_implementation_20261111/validate_framework.py
.venv/Scripts/python.exe reports/behavioural_evidence_framework_implementation_20261111/make_status.py
```

## 1. Summary

1. **Implemented as designed, with the two approved amendments.** The amendments are now catalogue `v2-evidence-1.1`:
   - **NET-1 restricted:** it needs a scanning tool, or a probe tool aimed at a qualifying internal or scan target. `curl -I` and ordinary reachability checks become **NET-0** (context).
   - **Repeated-failure rule:** ≥ 3 distinct failures within 300 s from the same observed `src_ip`. Relay/NAT sources are `indeterminate`; missing attribution fails loudly.
2. **All 25 validation checks pass on Dataset V2** (`validation_results.csv`). Train and validation are checked separately where applicable.
3. **Every known false positive is removed** (`false_positive_comparison.csv`, validation):

| Measure | Legacy (Task 20) | Design prototype (Task 21) | Implementation |
|---|---:|---:|---:|
| Benign logins with an attack-implying interpretation (of 229) | 79 | 45 | **0** |
| Benign failed guesses labelled credential attack (of 126) | 126 | 0 | **0** |
| Benign "network probing" from `curl -I` | — | 45 | **0** |
| Sessions claiming a successful download | 99 | 0 | **0** |
| Slow-`find` sessions treated as novel or behavioural (of 9) | 9 | 0 | **0** |

4. **Unit tests and the full suite pass:** 80 new tests; the full suite has 386 passed (previously 306).
5. **A second run is byte-identical** for all outputs (§5), and records are identical under shuffled input order (check V9).
6. **Generalisation is not demonstrated** (`limitations.md` §1–2):
   - every action indicator fires in ≤ 2 lab categories;
   - 9 entries never fire on train/validation and are unit-tested only.

## 2. What was implemented (`implementation_inventory.md`)

**Catalogue.** 27 versioned entries:
- 25 design indicators, plus NET-0 (approved amendment) and TIME-0 (timing caveat);
- 13 action, 10 context and 4 caveat entries;
- 11 interpretation rules, each requiring action indicators. The catalogue checker rejects any rule that requires a non-action indicator.

**Per-session record:**
- authentication status;
- behavioural status (`interpreted`, `system_discovery_only`, `insufficient_evidence` or `indeterminate`) and abstention reason;
- evidence level E0–E3;
- interpretations, each with the supporting action indicators and their outcomes;
- every indicator with kind, class, telemetry, limitations, same-line caveats and matches (line, simple command, token);
- caveats and timing context;
- provenance: catalogue version, telemetry schema, configuration digest, calibration digest;
- `statistical_novelty` as an independent field.

There are no DEC clusters, no probabilities and no Known-like / Ambiguous / Potentially Novel outcomes (enforced by a unit test).

**Safety checks:**
- unsupported telemetry schema → `SchemaError`;
- missing required fields, or V1 feature fields → `SchemaError`;
- incompatible catalogue version, indicator set or kinds → `CatalogueError`;
- malformed calibration → `CatalogueError`;
- authentication events with no source anywhere → `AttributionError`.

## 3. Validation on Dataset V2 (primary configuration)

**Configuration:**
- relay 172.22.0.2 (the documented lab relay);
- default internal networks;
- calibration and SEQ-1 references from the training split only (`config/`).

**Interpretations, logged-in validation sessions (one per interaction):**

| Interpretation | Sessions | benign | botnet | brute force | lateral | PE | recon |
|---|---:|---:|---:|---:|---:|---:|---:|
| credential-material access attempt | 124 | 0 | 0 | 0 | 71 | 53 | 0 |
| download attempt | 92 | 0 | 71 | 0 | 0 | 0 | 21 |
| download-and-execute attempt | 71 | 0 | 71 | 0 | 0 | 0 | 0 |
| privilege-context reconnaissance attempt | 69 | 0 | 0 | 0 | 0 | 69 | 0 |
| network probing attempt | 49 | 0 | 0 | 0 | 49 | 0 | 0 |
| history tampering attempt | 21 | 0 | 21 | 0 | 0 | 0 | 0 |

**Statuses, logged-in validation sessions:**

| Status | Count |
|---|---|
| interpreted | 238 |
| system discovery only | 313 (all 229 benign) |
| indeterminate | 41 (brute-force logins with no command; authentication-only, shared source) |
| insufficient evidence | 8 |

**Evidence levels, logged-in validation sessions:** E0 362, E1 114, E2 124, **E3 0**.

**Failed-guess sessions:** all 657 are `indeterminate:shared_source` (E0).

167 validation sessions carry ≥ 2 coexisting interpretations; 437 in train.

**Validation checks** (`validation_results.csv`; train and validation):

| Check | Result (validation; train) |
|---|---|
| V1 no benign single failed login → credential interpretation | 0 / 126; 0 / 302 (primary and oracle) |
| V2 every matched token is a whole parsed token | 0 violations |
| V2b legacy `credential_attack` substring lines not treated as credential/transfer | 240 / 361; 551 / 825 (e.g. `service ssh status`, `cat /etc/passwd \| grep sh`) |
| V3 `curl -I` never establishes probing | 45 sessions with `curl -I` → 0; train 80 → 0 |
| V4 slow `find` caveat-only (identical output without calibration) | 9 / 9; 30 / 30 |
| V5 no download/upload success without an event | 92 attempts, 0 success, 0 events; train 255, 0, 0 |
| V6 context-only → no interpretation; rule integrity | 1,019 / 2,571 context-only sessions, 0 interpretations, 0 violations |
| V7 repeated-failure rules abstain on the shared relay | 1,257 / 1,257 and 3,190 / 3,190 indeterminate |
| V7b oracle-source diagnostic | AUTH-1 fires only on brute force (398; 1,018) |
| V8 coexistence | 167; 437 sessions |
| V9 determinism under input re-ordering | identical |
| V11 novelty metadata does not change behavioural output | identical (600 sessions carry Task 18 scores) |

**Sensitivity runs** (`evidence/interpretation_status_level_distribution.csv`):

| Run | Difference from primary |
|---|---|
| **Lab address plan** (internal hosts = the profile's `lan_ip` pool; generator-derived) | "network probing attempt" 66 instead of 49 (lateral only); everything else identical |
| **Oracle source** (one synthetic source per interaction) | 79 brute-force logins gain "repeated authentication failures" and "credential guessing followed by login" (E3: the login success is an observed event). 319 brute-force failed guesses are interpreted. Benign and other failed guesses stay `insufficient_evidence` |

## 4. Indicator status (`indicator_implementation_status.csv`)

**Fire on V2 (18):**
- AUTH-0, SHELL-1, DISC-1, PRIV-1, CRED-1, FILE-1, FILE-2, XFER-1, EXEC-1, EVADE-1;
- PERS-0, NET-0, NET-1, CHAIN-1;
- EMU-1, ART-1, SEQ-1, TIME-0.

SEQ-1 on train is in-sample by construction.

**Unit-tested only (9; 0 occurrences):** AUTH-1/AUTH-2 (deployable configuration), PRIV-2, XFER-1-OK, XFER-2, XFER-2-OK, STAGE-1, PERS-1, REDIR-1.

## 5. Reproducibility and integrity

- **Second full run:** validation and status scripts re-executed; every output file in `evidence/`, `config/` and the CSV deliverables is byte-identical (`evidence/second_run_check.txt`).
- **Dataset V2:** verified against its `SHA256SUMS` at the start of each run.
- **Legacy files unchanged:** SHA-256 matches the hashes recorded in Task 20 (`evidence/legacy_integrity.txt`).
- **Not accessed:** the test set (no test, sealed or exfiltration paths opened; `evidence/run_summary.json`).
- **Not done:** nothing was committed.

## 6. Awaiting approval

Not connected to threat scoring or automated defence. Open items before any integration:
1. a real-deployment source-key policy for AUTH-1/2 (relay/NAT list);
2. the internal-network configuration for NET-1;
3. a sensor latency benchmark for ART-1;
4. a decision on TTY collection for outcome evidence;
5. how evidence levels, which are not probabilities, may be used by any future policy.
