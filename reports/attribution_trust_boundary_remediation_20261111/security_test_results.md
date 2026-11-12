# Security test results

## Test suites (`test_results_full.txt`, `test_results_verbose.txt`)

| Suite | Result |
|---|---|
| full repository suite (`pytest tests`) | **593 passed** (Task 26A: 499) |
| `tests/test_trust_boundary.py` (new) | 98 passed |
| `tests/test_client_attribution.py` (updated, see below) | 48 passed |
| `tests/test_threat_assessment.py` (unchanged) | 61 passed |
| extractor + labelling suites (unchanged) | 65 passed |

Task 26A tests changed on purpose:
- **Seven tamper cases:** they now expect per-record handling (F-6). The damaged record's session is `log_gap`, and appended garbage or a forged insertion leaves the genuine attribution intact.
- **Integration tests:** the 11 unsigned-v2 assessment tests were replaced by 7 that prove the old unsigned path is **rejected** (F-1). The signed flow is covered in `test_trust_boundary.py`.
- **One key-code test:** extended, so signing is allowed only in `client_attribution/result.py` and `checkpoints.py`, and never in `threat_assessment`.

## Real-data validation in the isolated container (`real_data_results.csv`, `evidence/validation_summary.json`, `evidence/container_runs/`)
- **Data:** the Task 26A captured sessions, with inputs hash-checked against the Task 26A manifest.
- **Signer:** the attribution signer used an ephemeral in-memory key.
- **Verifier:** `threat_assessment.run_signed`, running in the `threat-assessment` container with its isolation check `ok` on every run.

| Case | Verification | S4 (test shell) | S5 (control shell) | Proposals |
|---|---|---|---|---|
| genuine signed result | accepted | **propose**, subject 10.250.25.3, login basis = correlated `login.success` | review (`enforcement_excluded`, gates 5, 6) | **1** (S4, dry-run, approval pending, not executed) |
| **attack A** (26B): unsigned result maps S5 → 10.250.25.3 | rejected: unsigned | review (`result_rejected`) | review (`result_rejected`) | **0** |
| **attack B** (26B): unsigned result maps S4 → 203.0.113.9 | rejected: unsigned | review | review | **0** |
| attack A, signed then altered | rejected: result_hash mismatch | review | review | 0 |
| attack B, signed then altered | rejected: result_hash mismatch | review | review | 0 |
| attack A, re-signed with an attacker key | rejected: key not pinned | review | review | 0 |
| genuine + forged supplied together | forged rejected; gate 7 fails for the batch | review | review | 0 (fails closed) |
| genuine result after `not_after` | rejected: expired | review | review | 0 |
| deployment configs (result key pending) | rejected: no key pinned | review | review | 0 |

Rejected cases fail gates 4 (no verified login evidence), 5 (not attributable) and 7 (unverified input). S1–S3 abstain in every case.

## Requirement → evidence

| Requirement | Evidence |
|---|---|
| Reproduce and block both F-1 attacks | the two attack rows above, plus unit tests `test_attack_A_…` and `test_attack_B_…` |
| Invalid signatures and altered attribution fields | 10 altered entry fields, 4 altered top-level fields, hash recomputed without the key, re-signed with an attacker key, spoofed signer identity |
| Unsigned, expired, duplicated, inconsistent, mismatched results | unsigned; expired / not yet valid / validity too long; duplicated entries; reused `result_id`; conflicting results; 12 correctly-signed-but-inconsistent entries; config digest mismatch; relay tuple ≠ Cowrie source; injected verification object |
| Assessment cannot produce or modify a valid result | no signing, private-key or signer-import code in `threat_assessment` (tests); modification and re-signing rejected |
| Private-key access from the assessment process | container probe: key paths, Docker socket, Cowrie log absent; no network; read-only code; no project private keys; runner self-check refuses non-isolated environments (unit test + real first-run refusal) |
| Login-event correlation | 8 correlation tests; gate 4 with and without the event; forged-result login ignored; direct sources; legacy policy 2.0 |
| Malformed and missing records | mid-log malformed line; mid-log deletion; fork; Task 26A tamper set |
| Incomplete audit tails | tail deletion undetected without a checkpoint and detected with one; divergence; forged checkpoints (5); checkpoint refused on a damaged log |
| All seven session exclusions | 7 parametrised tests plus real demo log (0 of 5 sessions emitted) |
| Configuration drift | address drift, inline lists (5), mismatched pins (gate 7), version pairing (2), unrelaxable condition, allowlist overlap, key/pin mismatch |
| Severity definitions unchanged | `severity.py` matches the Task 24 manifest; S4/S5 findings S2/S3 at E2, as before |
| Behavioural evidence unchanged | 9/9 files match the Task 22 manifest; evidence `authentication_status` passed through untouched |
| Historical V1 reproducible | `regression_v1_results.json`: train 3,190/3,190 and validation 1,257/1,257 identical under 1.2.0 (declared additive fields only) |
| No enforcement | no iptables (filter/nat/mangle/raw) or nft rule mentions 10.250.25.3/.4; all proposals `dry_run`, `manual_approval: pending`, `execution: not_executed`; no enforcement code |
