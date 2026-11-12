# Regression results

| Check | Method | Result |
|---|---|---|
| Behavioural evidence package unchanged | the 9 `behavioural_evidence/*` entries of the Task 22 SHA256SUMS | **9/9 match** |
| Threat severity definitions unchanged | `threat_assessment/severity.py` vs the Task 24 SHA256SUMS; S4 severities recomputed independently | **match**; S2/S3 re-derived identically, with identical basis text |
| Other unchanged threat-assessment modules | `audit.py`, `errors.py` vs Task 24 | match |
| Intended 1.1.0 changes stable since review | `__init__.py`, `assessment.py`, `attribution.py`, `config.py` differ from Task 24 (intended) and match the Task 26A manifest | match (Task 26A manifest 50/50) |
| v1 configs unchanged | SHA-256 of `threat_attribution_v1.json` (`46109a31…`), `defence_policy_v2.json` (`24fd8cf4…`), `defence_policy.json` (`4386464c…`) vs the Task 24/26A manifests | match |
| Historical V1 results reproducible | Not re-executed: re-running needs Dataset V2 (reference sequences) and Task 24 evidence derived from it, which this task prohibits. The Task 26A regression result (train 3,190/3,190, validation 1,257/1,257 identical apart from declared additive fields) still applies, because every input to it is hash-identical now: code, configs, calibration, and the result file itself (Task 26A manifest) | **holds by hash identity** (not re-run) |
| Synthetic test suites | `pytest tests/test_behavioural_evidence.py tests/test_threat_assessment.py tests/test_client_attribution.py` (no dataset access) | **193 passed** |
| Diagnostic sessions `99732d516898`, `b806554e19b9` excluded | `excluded_diagnostic_sessions` in the v2 attribution config; correlation returns `excluded_diagnostic` (unit tests for both IDs); absent from the processed demo input | excluded from attribution and assessment. **F-7:** no code-level exclusion in dataset/ML tooling |
| Five demo sessions excluded from datasets and evaluations | Register `reports/client_attribution_implementation_20261111/demo_session_exclusion.md`. The Dataset V2 manifests were verified unchanged in Task 26A *after* the sessions (17:19Z), so they cannot contain them; this was not re-verified here (Dataset V2 access prohibited). Code search: no filter for these IDs in `dataset_builder/`, `ml_pipeline/*.py`, `scripts/` or `configs/` | not present in frozen data. **F-7:** future builds from the live Cowrie log (which contains them) are protected only by the register |
| Control client cannot become an enforcement target | S3 and S5 → `enforcement_excluded`, tiers abstain / review, no proposal. A forged result naming 10.250.25.4 → `enforcement_excluded`, review. Attribution classifies by the client IP against `enforcement_excluded_sources` (10.250.25.4/32) | **holds**: 10.250.25.4 can never be a subject. **F-1:** a forged unsigned result can re-label the control client's *session* as 10.250.25.3 |
| No enforcement has occurred | No iptables (filter/nat/mangle/raw) or nft rule references 10.250.25.3 or .4 (17:40:11Z). All Task 26A audit entries are `not_executed`. No enforcement code in `threat_assessment`, `client_attribution`, `behavioural_evidence` or the relay | **none** |
| Deployment unchanged since Task 26A | Cowrie `0bec5a78b1cb` (started 2026-11-10T12:30:30Z, 0 restarts); relay `a5e156cbca02` (0 restarts); relay log still 11 records (sha `496b5a0f…`, as in Task 26A) | unchanged; **no new sessions** |
| Task 26A audit chain | `verify_chain` with the checkpoint | intact (5 entries) |

The raw values are in `audit_results.json` (`regression` key), `test_results.txt` and `live_state.txt`.
