# Proposal eligibility

## 1. Policy conditions (`configs/defence_policy_v2_1.json`, policy 2.1.0)

| Policy condition | Gate in `threat_assessment/assessment.py` | Rule as implemented |
|---|---|---|
| `min_finding_severity` S2 | 1 | some finding has severity ≥ S2 |
| `min_interpretation_evidence_level` E2 | 2 | some finding is ≥ S2 **and** its interpretation-specific level is ≥ E2 (qualifying findings) |
| `min_distinct_action_indicators` 2 | 3 | ≥ 2 distinct action-indicator IDs across the qualifying findings |
| `require_successful_login` | 4 | `authentication_status` ∈ {`success_without_repeated_failures`, `repeated_failures+success`} **or** `n_input_lines > 0` |
| `require_attributable_source` | 5 | there are findings, and every qualifying finding (otherwise every finding) has attribution `attributable` or `attributable_via_proxy_mapping` |
| `exclude_protected_and_shared_sources` | 6 | the session attribution is not `protected`, `shared_source` or `enforcement_excluded` |
| `require_verified_configuration_digests` | 7 | all of the following match: the record digest and the evidence config digest; the policy-pinned digest and the attribution digest; evidence relays ⊇ attribution relays; the evidence networks and the attribution internal networks; the AUTH rule (3, 300 s); and, when supplied, the correlation `config_digest` and the attribution digest |
| `require_no_processing_errors` | 8 | the record validates, and a mapping is never supplied with a v1 config |
| (tier rule) | — | `behavioural_status` of `indeterminate` or `insufficient_evidence` → abstain before any gate counts; no S2+ finding → record |

The policy cannot be relaxed: `PolicyConfig` rejects any `require_*` or `exclude_*` set to anything other than true, and any threshold below S2, E2 or 2. The proposal conditions and the proposed action in 2.1.0 are identical to those in 2.0.0.

## 2. S4 reproduction (Cowrie session `3eede5e19e25`)

| Step | Result |
|---|---|
| 26A artefacts hash-checked | 50/50 match the Task 26A SHA256SUMS |
| Relay log re-verified, correlation re-run (same evaluation time) | **byte-identical** to the stored `correlation_result.json` |
| Evidence engine re-run on the captured events (same calibration; no reference sequences, see F-10) | all 5 records **identical except `config_digest`** (`256b03e0…` vs the stored `95183d7f…`) |
| Re-assessment with that self-consistent config | **propose**; 0 failed gates; subject 10.250.25.3; findings identical to the stored ones |
| Stored record (digest `95183d7f…`) against the config without reference sequences | review; **only gate 7 fails**, showing the digest gate is effective |

## 3. Independent evaluation of each condition (written separately from `ThreatAssessor`)

| Condition | Satisfied | Basis |
|---|---|---|
| severity ≥ S2 | yes | download attempt **S2**; download-and-execute attempt **S3** (severity module re-run; matches stored) |
| E2 on an S2+ finding | yes | both findings are **E2** (interpretation-specific) |
| ≥ 2 distinct action indicators | yes | **EXEC-1, XFER-1** |
| successful login (implemented basis) | yes | `n_input_lines = 4`; `authentication_status = indeterminate:shared_source` |
| successful login (Task 23 design wording) | yes | raw telemetry has `cowrie.login.success` for `3eede5e19e25` at 17:19:28.648479Z (user `demo`); this fact is not carried in the evidence record |
| attributable source | yes | `attributable_via_proxy_mapping` → 10.250.25.3 (`test_client`, registered); exactly one verified record; close `consistent` |
| not protected / shared / excluded | yes | 10.250.25.3 is in none of the lists |
| verified digests | yes | evidence digest equals the recorded expected digest; attribution `612d6360…` is pinned by the policy and present in the correlation; all four configuration checks are true |
| no processing errors | yes | none |
| behavioural status | yes | `interpreted` |

## 4. Why S4 qualifies for Propose
1. S4 typed `wget … -O x.sh`, `chmod +x x.sh`, `./x.sh`. These lines produce XFER-1 (retrieval) and EXEC-1 (execution of a retrieved file).
2. Together they satisfy the *download-and-execute* interpretation (S3: an attempt to execute retrieved code) and the *download* interpretation (S2). Both are at E2: multiple corroborating action indicators, with outcome not observed.
3. Severity is attempt-based by the unchanged Task 23/24 definitions. `./x.sh` failed in Cowrie, and no file was downloaded. The severity basis says this explicitly, and the S3 rating does not claim success.
4. Command input proves an authenticated shell, and Cowrie also logged `login.success`.
5. The relay's signed record ties the session to 10.250.25.3. That address is a registered test client and is neither protected, shared nor excluded.
6. All configuration digests verify.
7. The proposal is the policy's fixed action: `block_source_ip` on 10.250.25.3, scope this sensor, TTL 86400 s, inverse `unblock_source_ip`, `mode: dry_run`, `manual_approval: pending`, `execution: not_executed`.

**No eligibility defect.** S4 remains eligible when every condition is evaluated independently. Two caveats do not change this result: the gate 4 basis (F-2) and the trust boundary (F-1). See `authentication_analysis.md` and `report.md`.

## 5. Other demo sessions

| Session | Tier | Why |
|---|---|---|
| S1 published banner | abstain | `insufficient_evidence` (no input); attribution `published_listener` |
| S2 test banner | abstain | `insufficient_evidence` |
| S3 control banner | abstain | `insufficient_evidence`; attribution `enforcement_excluded` |
| S5 control shell | review | same findings as S4; gate 5 (not attributable) and gate 6 (`enforcement_excluded`) fail |
