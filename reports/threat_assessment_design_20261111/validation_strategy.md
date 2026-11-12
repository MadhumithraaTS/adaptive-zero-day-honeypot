# Validation strategy for the threat-assessment layer (to run after implementation is approved)

**Data:**
- synthetic Cowrie-style fixtures for unit tests;
- Dataset V2 **train/validation** evidence records from the unchanged `behavioural_evidence` package for integration tests.

**Never used:** the sealed test or exfiltration data, or synthetic interaction-ID sources as identities.

| # | Scenario | Fixture / data | Expected assessment |
|---|---|---|---|
| T1 | Benign single failed login, then success | Unit fixture; V2 benign failed guesses (126 validation, 302 train) | AUTH-0 context; tier `record` or `abstain`; never a credential finding |
| T2 | Repeated failures from a real, attributable source (≥ 3 in 300 s, 2 sessions, then success) | Unit fixture with a documentation-range IP not in any exclusion list | Findings "repeated authentication failures" (S1) and "credential guessing followed by login" (S2, E3 with the emulator-dependent success caveat); `attributable` |
| T3 | Same failures from a configured shared/NAT address | Unit fixture, address in `shared_sources` (passed as `relay_sources`) | `indeterminate:shared_source`; tier `abstain`; no subject |
| T4 | Relay topology (the lab) | V2 validation records | All `unattributed:trusted_proxy`; 0 proposals (dry-run baseline: abstain 706 / record 313 / review 238) |
| T5 | Legitimate internal activity: `ping` / `curl -I` to internal or external hosts; `service ssh status` | Unit fixtures; V2 benign | NET-0 / PERS-0 context; S0; never a NET-1 finding unless the target is in the explicit allowlist |
| T6 | Network scope not configured | Records produced with package defaults | NET-1 findings marked `network_scope: unconfirmed`; not policy-eligible |
| T7 | Attempted, unsuccessful download (no `file_download` event) | V2 botnet/recon (92 validation attempts) | Finding with `outcome: not_observed`; severity S2/S3 unchanged; text never says "downloaded" |
| T8 | Attempted, unsuccessful upload | Unit fixture (`tar czf …; curl -T …`); no V2 occurrences | "archive-and-upload attempt" S3; outcome `not_observed`; E2 at most |
| T9 | Emulator failure (`./payload` → `command.failed`) | V2 botnet; unit fixture | Outcome `observed_failure:emulator_rejected` reported as an emulator fact; severity unchanged; EMU-1 never a finding |
| T10 | Slow command (ART-1) | V2 PE sessions (9 validation, 30 train) | Tier identical with and without calibration; ART-1 shown as an annotation; novelty on these sessions annotated "explained by emulator latency" |
| T11 | Multiple simultaneous interpretations | V2 (167 validation sessions with ≥ 2) | All findings listed; the highest-severity and evidence attributes shown separately |
| T12 | Insufficient evidence / context only | V2 brute-force logins with 0–1 trivial command; benign | Tier `abstain` / `record`; no severity |
| T13 | Missing source attribution | Unit fixture without a connect event (package raises `AttributionError`) | Assessment `abstain` with reason; no partial record |
| T14 | Unsupported schema / catalogue / config digest mismatch | Unit fixtures (`telemetry_schema="unsw-nb15"`, catalogue v1, altered relay list) | Loud failure, then `abstain`; never a silent default |
| T15 | Novelty cannot trigger | V2 validation with Task 18 scores attached | Tier identical with and without novelty metadata (byte-for-byte on behavioural fields) |
| T16 | Caveat or novelty plus context only | Unit fixture | Never above `record` |
| T17 | Severity/evidence independence | Unit fixtures: S3 at E1 (single CRED-1 on `/etc/shadow`) and S2 at E2 | S3/E1 → `review`, never a proposal; S2/E2 with 2 action IDs and attribution → proposal |
| T18 | Determinism and reproducibility | Repeat runs; shuffled input | Byte-identical assessment records |
| T19 | Audit-log integrity and rollback | Unit fixtures | Hash chain verifies; every proposal has an inverse; expiry logged |

**Acceptance gates:**
- T1–T19 pass;
- 0 benign train/validation sessions above `record`;
- 0 proposals in the lab topology;
- no field in the assessment record lacks a source in the integration contract.
