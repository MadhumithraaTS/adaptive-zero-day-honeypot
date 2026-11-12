# Task 26C — Attribution Trust-Boundary Remediation

Date: 2026-11-11 · Status: **implemented and validated; stopped for review** · No enforcement · No human approval or response engine · No keys generated or rotated · Nothing committed

## Outcome by finding

| Finding (26B) | Status | Summary |
|---|---|---|
| **F-1** unsigned correlation results trusted | **Fixed** | `signed-attribution-result-1`: the attribution component signs the complete result; `threat_assessment` verifies it independently with a pinned public key, enforcing schema, signature, validity window, config digest, uniqueness and internal consistency. Unsigned, altered, re-signed, expired, duplicated, conflicting or inconsistent results are rejected. **Both 26B attacks reproduced and blocked** (unit tests and real data in the isolated container: 0 proposals) |
| **F-3** relay key readable/modifiable by all local users | **Partly fixed** | ACLs restricted to the single operator account (read-only for the key file); relay re-verified. The assessment now runs in an isolated container with no key, socket or network, verified by probe and a runtime self-check. Not achieved: operator-account separation, which Docker Desktop makes root-equivalent. Rotation, revocation, backup and recovery are documented in a **migration plan awaiting approval** |
| **F-2** login inferred from typed commands | **Fixed** (policy 2.1) | Session-level `cowrie.login.success` correlation by session ID, source, sensor and time; carried in the signed result. Gate 4 requires an authentication event; commands alone never count; missing or ambiguous evidence stays indeterminate |
| **F-6** one bad line voids the log | **Fixed** | Per-line verification with a strict chain inside segments; forks and checkpoint divergence untrust the log; gaps are explicit and only overlapping sessions are withheld |
| **F-4** tail deletion undetectable | **Mechanism implemented, not deployed** | Witness-signed checkpoints make incomplete tails and divergence detectable. Without a stored checkpoint, deletion is still undetectable and is reported as `unattested`. Deployment needs the attribution key (pending approval) |
| **F-9** records writable by any user | **Fixed for other users** | Records ACL limited to the operator. The relay is the only container with write access; the assessment has none |
| **F-7** exclusions documentary only | **Fixed** | `configs/session_exclusions_v1.json` + `session_exclusions/`, wired into the dataset builder and V2 feature extractor; separate from scoring; all 7 IDs tested; real demo log yields 0 sessions |
| **F-8** duplicate address lists | **Fixed** | `configs/address_safety_v1.json` is the only list; config v3 and policy 2.1 pin it by digest and reject inline lists; versions and digests are cross-checked |

## Real-data result (Task 26A sessions, isolated container)
- **Genuine signed result:** **S4 → propose** (dry-run, approval pending, not executed). Its subject is 10.250.25.3, and successful login rests on `cowrie.login.success` at 17:19:28.648479Z, correlated by session ID.
- **S5** (control client): review (`enforcement_excluded`). **S1–S3:** abstain.
- **Every attack and failure case:** no proposal.
- **Deployment config:** it rejects all results until the attribution key is provisioned.

## Implementation
- **New:**
  - `client_attribution/authentication.py`, `checkpoints.py`, `result.py` (signer);
  - `threat_assessment/signed_attribution.py` (independent verifier), `run_signed.py` (isolated runner with self-check);
  - `session_exclusions/`;
  - `configs/address_safety_v1.json`, `threat_attribution_v3.json` (`8b79be3c…`, result key pending), `defence_policy_v2_2.json` (schema 2.1), `session_exclusions_v1.json`;
  - `tests/test_trust_boundary.py`, `tests/trust_fixtures.py`;
  - compose service `threat-assessment` (profile `assessment`, purely additive: the rest of the file is byte-identical to Task 26A `83148fab…`).
- **Modified:**
  - `client_attribution/records.py`, `correlate.py`, `__init__.py` (1.1.0);
  - `threat_assessment/config.py`, `attribution.py`, `assessment.py`, `__init__.py` (1.2.0);
  - `tests/test_client_attribution.py`;
  - `scripts/extract_features_v2.py`, `dataset_builder/build_labelled_dataset.py` (exclusions);
  - NTFS ACLs on `secrets/` and `records/` (previous ACLs saved in `cowrie/backups/pre_trust_boundary_20261111/`).
- **Unchanged (verified):**
  - `behavioural_evidence` (9/9);
  - `threat_assessment/severity.py` and `audit.py`;
  - relay code, config, public key and live log (11 records, `496b5a0f…`);
  - Cowrie (`0bec5a78b1cb`, 0 restarts) and the relay container (`a5e156cbca02`, not restarted);
  - every earlier config and policy file;
  - models and Dataset V2; sealed data not accessed.

## Validation
- **Tests:** 593 passed (98 new trust-boundary tests).
- **Historical V1:** 4,447/4,447 sessions reproduce under 1.2.0.
- **No enforcement:** no firewall rules for the demo clients.
- **Details:** `security_test_results.md`.

## Documents
`signed_attribution_design.md`, `key_custody.md` (including the migration plan), `authentication_correlation.md`, `audit_integrity.md`, `exclusion_and_configuration.md`, `security_test_results.md`, `limitations.md`.

## Scripts and data
- **Scripts:** `validate_remediation.py`, `evidence_checks.py`, `regression_v1.py`.
- **Data:** `real_data_results.csv`, `regression_v1_results.json`, `test_results_*.txt`.
- **`evidence/` contains:** the signed result, the checkpoint, container runs, validation fixtures (ephemeral public key only), extractor output and live-state checks.
- **`SHA256SUMS`.**

## Decisions needed before the next task
1. Approve, or amend, the key migration plan (`key_custody.md` A and B). Until then signed attribution cannot run in deployment, and all relay sessions stay unattributed.
2. Delete `cowrie/assessment_work/input` and `output` (validation scratch copies). The automated removal was blocked.

Stopped here. Human approval has not been started.
