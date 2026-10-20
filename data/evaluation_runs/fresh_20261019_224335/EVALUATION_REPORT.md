# Controlled Fresh-Data Evaluation — `fresh_20261019_224335`

**Verdict: COMPLETED**, with one documented verification exception (section 9). Five genuinely new Cowrie sessions were generated, collected, verified as new against every known session set, and evaluated with the unchanged DEC model and reference catalogue. All protected files are unchanged.

Run directory: `data/evaluation_runs/fresh_20261019_224335/`
Run window (UTC): 2026-10-19 17:13:39 → 17:15:45

---

## 1. Environment and prerequisites

| Item | Value | Check |
|---|---|---|
| Honeypot | Docker container `cowrie-project` (`cowrie/cowrie:latest`), host port 2223 → 2222 | `docker ps`: running |
| Target | `127.0.0.1:2223` (local, authorised honeypot only) | port mapping verified |
| Main interpreter | `.venv\Scripts\python.exe` (Python 3.11.4) | generator, collection, parsing, novelty |
| DEC interpreter | `ml\cowrie_dec_integration_skeleton\.venv-dec-smoke\Scripts\python.exe` | loaded saved artifacts before the run: 17 features, 3 clusters, StandardScaler |
| DEC artifacts | `ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/artifacts/` | unchanged (section 8) |
| Reference catalogue | `reports/novelty_assessment/held_out/revised/reference_signatures/behaviour_signatures.json` (3 signatures, 43 source session IDs) | unchanged |
| Thresholds | known 0.70, ambiguous margin 0.05, min compatible features 1, borderline 0.60 (project defaults) | unchanged |

**Controlled profile.** `configs/attack_profiles.json` contains three profiles. `botnet` (`wget http://example.com/...`) and `advanced_persistent_threat` (`curl http://10.0.0.1/...`) cause Cowrie to make real outbound requests from the container, which would contact systems outside the honeypot. To stay within the local environment, the run used a filtered copy containing only `script_kiddie` (`whoami`, `uname -a`, `pwd`, `ls -la`, `cat /etc/passwd`): `inputs/attack_profiles_controlled.json`. The original configuration file is unchanged.

**Credentials.** `root` / `admin`, a pair previously verified to succeed on this container.

---

## 2. Exact commands (from `logs/commands.log`)

All commands were run from the repository root; `$RUN = data\evaluation_runs\fresh_20261019_224335`. Stdout/stderr for each step are in `logs/<step>.stdout.txt` / `.stderr.txt`.

| # | UTC start | Exit | Command |
|---|---|---|---|
| 1 | 17:13:39 | 0 | `.venv\Scripts\python.exe -c "<filter configs/attack_profiles.json to script_kiddie>" $RUN\inputs\attack_profiles_controlled.json` |
| 2 | 17:13:40 | 0 | `.venv\Scripts\python.exe -c "<union of known session-details files>" $RUN\inputs\known_sessions.json <4 known details files>` |
| 3 | 17:13:41 | 0 | `.venv\Scripts\python.exe -u scripts\attack_generator.py --config $RUN\inputs\attack_profiles_controlled.json --host 127.0.0.1 --port 2223 --sessions 5 --username root --password admin` |
| 4 | 17:14:49 | 0 | `.venv\Scripts\python.exe scripts\collect_logs.py --container cowrie-project --dest $RUN\raw\cowrie.json` |
| 5 | 17:14:50 | 0 | `.venv\Scripts\python.exe scripts\pipeline.py --skip-attack --raw-input $RUN\raw\cowrie.json --output-dir $RUN\pipeline --skip-preprocess` |
| 6 | 17:15:14 | 0 | `.venv\Scripts\python.exe scripts\prepare_fresh_evaluation.py --baseline-session-details $RUN\inputs\known_sessions.json --snapshot-session-details $RUN\pipeline\parsed\session_details.json --snapshot-features $RUN\pipeline\parsed\behavior_features.csv --output-session-details $RUN\fresh\fresh_session_details.json --output-features $RUN\fresh\fresh_behavior_features.csv --summary-output $RUN\fresh\preparation_summary.json` |
| 7 | 17:15:17 | 0 | `ml\cowrie_dec_integration_skeleton\.venv-dec-smoke\Scripts\python.exe ml\cowrie_dec_integration_skeleton\scripts\run_dec_evaluation.py $RUN\fresh\fresh_behavior_features.csv --output $RUN\dec\dec_results.csv` |
| 8 | 17:15:40 | 0 | `.venv\Scripts\python.exe scripts\novelty_assessment.py --session-details $RUN\fresh\fresh_session_details.json --signature-file reports\novelty_assessment\held_out\revised\reference_signatures\behaviour_signatures.json --output-dir $RUN\novelty --known-threshold 0.70 --ambiguous-margin 0.05 --min-compatible-features 1 --borderline-score 0.60` |
| 9 | 17:15:43 | **1** | `.venv\Scripts\python.exe $RUN\verification\verify_fresh_run.py <run dir> 2026-10-19T17:13:41.213397Z 5` (see section 9) |
| 10 | after 9 | — | Protected-file hash comparison and git-status check (PowerShell `Get-FileHash`), run manually because step 9 stopped the script |

Step 5 ran parsing, feature extraction and DEC on the full collected snapshot; its log confirms `DEC interpreter: ...\.venv-dec-smoke\Scripts\python.exe`.

---

## 3. Generation and collection

- Generator: 5 sessions started, 0 retries, 0 failures (`logs/attack_generator.stdout.txt`).
- Collection: `docker cp` succeeded; `raw/cowrie.json` is 77,596 bytes.
- The snapshot contains the container's current log: **13 sessions** — the 5 new sessions plus 8 sessions from earlier today (the 5-session pipeline run and the 3-session demo).

---

## 4. New-session identification and overlap checks

A session was treated as new only if its ID (compared as an exact string) is absent from every known set:

| Known set | Sessions | Overlap with new sessions |
|---|---|---|
| Original baseline, `git show HEAD:data/parsed/session_details.json` | 54 | 0 |
| Baseline backup `data/baseline_backup_20261019_213122` | 54 | 0 |
| Current working tree `data/parsed/session_details.json` | 5 | 0 |
| Demo `data/demo_20261019_213439` | 8 | 0 |
| Previous fresh run snapshot `data/fresh_evaluation/fresh_20261019_210649` | 54 | 0 |
| Reference catalogue source IDs | 43 | 0 |
| **Union** | **62** | **0** |

- Snapshot 13 = 8 previously known (excluded) + **5 new**. `prepare_fresh_evaluation.py` selected exactly the same 5 (`baseline_session_count` 62, `excluded_historical_session_count` 8, `new_session_count` 5) and validated the 17-feature DEC order against `config.json`.
- Every new session started after the run's T0 (17:13:41.213 UTC), logged in successfully, ran the 5 profile commands plus `exit` (6 command events) and closed:

| Session ID | Start (UTC) | End (UTC) |
|---|---|---|
| `860e0bc4a018` | 17:13:42.03 | 17:13:55.03 |
| `50ce19c43b81` | 17:13:56.63 | 17:14:07.14 |
| `e22808051703` | 17:14:08.73 | 17:14:21.39 |
| `68c0f1a58402` | 17:14:22.96 | 17:14:34.89 |
| `458003a74c58` | 17:14:35.72 | 17:14:46.61 |

- Session IDs are identical, as exact strings and without duplicates, across `fresh_session_details.json` (keys and nested `features.session_id`), `fresh_behavior_features.csv`, `dec/dec_results.csv` and `novelty/novelty_assessment_results.csv`.

---

## 5. Feature extraction and DEC inference

- Feature extraction: 13 sessions × 24 features (`pipeline/parsed/`); the 5 new rows were carried into `fresh/fresh_behavior_features.csv` unchanged.
- DEC: saved artifacts only (no retraining, no refitting). Output columns: input columns + `dec_cluster`, `dec_confidence`, `cluster_0_prob`..`cluster_2_prob`. All rows: probabilities sum to 1, cluster = argmax, confidence = max probability.

| Session | Cluster | Confidence | p(c0) | p(c1) | p(c2) |
|---|---|---|---|---|---|
| `860e0bc4a018` | 1 | 0.9346 | 0.0411 | 0.9346 | 0.0243 |
| `50ce19c43b81` | 1 | 0.9288 | 0.0449 | 0.9288 | 0.0264 |
| `e22808051703` | 1 | 0.9242 | 0.0476 | 0.9242 | 0.0282 |
| `68c0f1a58402` | 1 | 0.9257 | 0.0468 | 0.9257 | 0.0275 |
| `458003a74c58` | 1 | 0.9261 | 0.0466 | 0.9261 | 0.0274 |

## 6. Cluster and confidence distributions

| Set | Cluster counts | Confidence min / mean / max |
|---|---|---|
| New sessions (5) | cluster 1: 5 | 0.9242 / 0.9278 / 0.9346 |
| Full snapshot (13) | cluster 1: 13 | — |

ARI/NMI were **not computed**: the sessions have no verified ground-truth labels (`extract_features.py` sets `label=0`), and the DEC script omitted them (`ARI/NMI: omitted (labels not verified ...)`).

**Observation vs interpretation.** Observed: all five sessions were assigned to cluster 1 with confidence 0.92–0.93. Interpretation (not verified by labels): in the training data cluster 1 groups longer interactive multi-command sessions, which matches these successful-login, five-command sessions. DEC confidence is relative to the three clusters and is not an out-of-distribution measure.

---

## 7. Novelty results

| Session | Category | Closest signature | Score | Runner-up |
|---|---|---|---|---|
| `860e0bc4a018` | Known-like | `sig-47521826f16efd4b` | 0.728 | 0.150 |
| `50ce19c43b81` | Known-like | `sig-47521826f16efd4b` | 0.784 | 0.226 |
| `e22808051703` | Known-like | `sig-47521826f16efd4b` | 0.836 | 0.177 |
| `68c0f1a58402` | Known-like | `sig-47521826f16efd4b` | 0.820 | 0.171 |
| `458003a74c58` | Known-like | `sig-47521826f16efd4b` | 0.799 | 0.181 |

- Category counts: **Known-like 5**; Potentially Novel 0; Ambiguous 0; Insufficient Evidence 0.
- Reference independence (summary JSON and Markdown report agree): `evaluation_mode = independent`, 43 reference session IDs, **0 overlapping**, no warnings.

**Limitations (heuristic interpretation).**
- The score is a weighted similarity heuristic (70% selected numerical features, 20% command-category overlap, 10% authentication), not a probability. "Known-like" means the session resembles signature `sig-47521826f16efd4b` ("Mixed/Unclassified", 6 reference sessions) above the 0.70 threshold; it does not confirm attack type or intent.
- Only the `script_kiddie` profile was exercised, so this run tests end-to-end operation and consistency on familiar behaviour. It does not test detection of unfamiliar behaviour; no "Potentially Novel" outcome was expected or observed.
- DEC was trained on synthetic sessions; live Cowrie timing features (e.g. `tcprtt`, `synack`) differ from the training data. `ct_srv_src`/`ct_src_ltm` were computed over the 13-session snapshot, so their values depend on snapshot size.
- Known catalogue limitations (audit item D2: a single-session signature with no numerical features) are unchanged and did not affect these results, since no session was closest to that signature.

---

## 8. Protected-file integrity

`verification/hashes_before.txt` and `verification/hashes_after.txt` (SHA-256, 45 files) are **identical**:
DEC weights, scaler, medians and config; the reference catalogue; `configs/attack_profiles.json`; `data/parsed`, `data/processed`, `data/raw`, `models`; the baseline backup; the demo directory; and the previous fresh-evaluation directory. The 44 files shared with the previous task's after-hash list are also identical to it.

Git status is unchanged except for the new untracked directory `data/evaluation_runs/` (40 files at check time, all inside this run, plus this report). No code was changed, no tests were needed, and no destructive Git command was run.

---

## 9. Errors and warnings

**Verification exception (step 9, exit 1).** `verification/verification.json` reports one problem: `fresh DEC row for 458003a74c58 differs from pipeline DEC row`. This check compared, as exact text, the DEC output for the 5 new sessions (step 7, batch of 5) with the rows for the same sessions in the pipeline's full-snapshot DEC run (step 5, batch of 13).

- Input feature values: identical for all five sessions.
- Four sessions: all outputs text-identical.
- `458003a74c58`: cluster and confidence identical; `cluster_0_prob` 0.046560656 vs 0.04656068 (|Δ| = 2.4e-8) and `cluster_2_prob` 0.02738251 vs 0.02738252 (|Δ| = 1.0e-8).

This is last-digit float32 variation consistent with batch-size-dependent numerical computation in TensorFlow/oneDNN, not a data, ID or model error. The strict check is left as recorded rather than relaxed after the fact. All other verification checks passed. Because step 9 stopped the orchestration script, the integrity check (section 8) was run manually with the same hash function.

**Warnings (non-blocking):** paramiko `CryptographyDeprecationWarning` (TripleDES); pandas pyarrow `DeprecationWarning`; TensorFlow `tf.placeholder` deprecation and "GPU support is not available on native Windows"; git "Filename too long" for paths inside the untracked `.venv-dec-smoke` directory.

---

## 10. Output files

| Path (relative to run directory) | Content |
|---|---|
| `inputs/attack_profiles_controlled.json` | script_kiddie-only profile used for generation |
| `inputs/known_sessions.json` | union of 62 known sessions used for exclusion |
| `raw/cowrie.json` | collected Cowrie log snapshot |
| `pipeline/parsed/`, `pipeline/processed/dec_results.csv` | full-snapshot parsing, features and DEC (13 sessions) |
| `fresh/` | 5 new sessions: details, features, preparation summary |
| `dec/dec_results.csv` | DEC results for the 5 new sessions |
| `novelty/` | novelty results CSV/JSON, report, summary |
| `verification/` | verification script and JSON, protected-file hashes (the git-status check was run manually; no delta file was written) |
| `logs/` | per-step stdout/stderr, `commands.log`, `t0_utc.txt` |
