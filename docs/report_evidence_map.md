# Report Evidence Map

This table maps each major claim in [`final_technical_report.md`](final_technical_report.md) to the file or result that supports it. Paths are relative to the repository root.

**Status key:**

- **Verified:** read directly from the file listed.
- **Derived:** computed from the listed file during report preparation; the computation is stated.
- **Gap:** the repository doesn't contain supporting evidence; the report says so.
- **Unsupported:** stated elsewhere in the repository (usually `README.md`), but not supported by any artifact.

Notebook cell numbers refer to the cell index in the `.ipynb` file.

## Chapter 1–2: Scope and architecture

| Claim | Evidence | Status |
|---|---|---|
| Problem statement and objectives | `README.md` (Problem Statement, Project Phases) | Verified |
| Cowrie runs as `cowrie-project`, image `cowrie/cowrie:latest`, ports `2223:2222` | `cowrie/docker-compose.yml` | Verified |
| No Telnet port is exposed | `cowrie/docker-compose.yml` (single port mapping) | Verified |
| Docker network `172.19.0.0/16`, gateway `172.19.0.1` | `docker network inspect cowrie_default`, run during the audit (not stored as a file) | Verified at audit time; needs re-checking if the network is recreated |
| All 75 recorded sessions have source IP `172.19.0.1` | `data/baseline_backup_20261019_213122/data/parsed/session_details.json` (54), `data/demo_20261019_213439/parsed/session_details.json` (8), `data/evaluation_runs/fresh_20261019_224335/pipeline/parsed/session_details.json` (13) | Derived (count of `src_ip`) |
| Only the current `cowrie.json` is collected | `scripts/collect_logs.py` (fixed source path) | Verified |
| Pipeline stages and outputs | `scripts/pipeline.py`, `docs/setup_guide.md` | Verified |
| No MongoDB, REST API or dashboard code | Search of `*.py`, `*.yml`, `*.txt` for mongo/flask/fastapi/dashboard/`/api/ingest` returned no matches | Derived |
| `synack` derived from `tcprtt` (D5); `ct_*` depend on snapshot size (D4) | `scripts/extract_features.py`; audit report in this project's diagnostics (`reports/diagnostics/dec_novelty_audit_20261019_215356/`) | Verified (code); audit findings were reported in-session, and only diagnostics CSV/JSON are stored |
| Novelty score formula and category rules | `scripts/novelty_assessment.py` (`_compare_session_numeric_features`, `compare_session_to_signature`, `assess_session_against_signatures`) | Verified |
| Catalogue: 3 signatures, sizes 1 / 6 / 36, auth rates, feature counts | `reports/novelty_assessment/held_out/revised/reference_signatures/behaviour_signatures.json` | Verified |
| Catalogue built from 43 reference sessions; 11 held out; ratio 0.2; seed 42 | `reports/novelty_assessment/held_out/revised/novelty_assessment_summary.json` | Verified |
| Signatures keep the 8 most variable features (D6) | `scripts/behaviour_signature_generation.py` (`build_feature_profile`) | Verified |
| Several components are uncommitted | `git status` (untracked `scripts/novelty_assessment.py`, `scripts/behaviour_*.py`, `scripts/prepare_fresh_evaluation.py`, `tests/`; modified pipeline scripts) | Verified at report time |

## Chapter 3: Datasets and preprocessing

| Claim | Evidence | Status |
|---|---|---|
| UNSW-NB15 training set 82,332 records; testing set 175,341 | `model_selection/UNSW_NB15_training-set.csv`, `UNSW_NB15_testing-set.csv` (line counts minus header); `dl_tuned.ipynb` cell 4 output "Number of samples: 82332" | Verified |
| 24 selected features; LabelEncoder, inf→NaN, median, StandardScaler | `model_selection/USNW-NB15.ipynb` cells 2–3; `dl_tuned.ipynb` | Verified |
| 20,000-row tuning subset, seed 42 | `model_selection/dl_tuned.ipynb` cell 5 | Verified |
| Rationale for choosing the 24 features | Not documented | **Gap** |
| Deployed DEC trained on 1,800 synthetic sessions | `model_selection/cowrie_tuned.ipynb` (`X_final` shape (1800, 17)); `model_selection/behavior_features.csv` | Verified |
| Synthetic sessions come from `scripts/generate_dataset.py` | `scripts/generate_dataset.py` (eight profiles; `attack_cat`, `label` fields) | Verified (the profiles match the `attack_cat` values in `behavior_features.csv`) |
| Profile counts (264, 234, 229, 228, 222, 217, 213, 193) and labels 264 / 1,536 | `model_selection/behavior_features.csv` | Derived (value counts) |
| 7 dropped features are constant in the synthetic data | `model_selection/behavior_features.csv` (`nunique` = 1 for each) | Derived |
| Stated reason for dropping them | Not documented | **Gap** |
| log1p on 13 features, then StandardScaler | `ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/artifacts/config.json`; `cowrie_tuned.ipynb` cell 0 | Verified |
| Artifacts byte-identical to `model_selection/cowrie_dec_model/` | SHA-256 comparison during the audit | Derived |
| Artifacts need pandas 3.0.5 / scikit-learn 1.9.0; main `.venv` cannot load them | `requirements.txt`; test failures recorded during the remediation task; `docs/setup_guide.md` (DEC Interpreter) | Verified |
| Auxiliary MinMaxScaler not used by DEC | `scripts/preprocess_dataset.py`; `ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/inference.py` loads only `artifacts/` | Verified |
| Live `tcprtt`/`synack` ≈10× smaller; z-values; `ct_*` 8 vs 63–304 | `reports/diagnostics/dec_novelty_audit_20261019_215356/dec_session_diagnostics.csv` and the audit run output | Derived (audit run; the per-feature z table was printed, not saved) |

## Chapter 4: Model comparison

| Claim | Evidence | Status |
|---|---|---|
| Nine models evaluated | `model_selection/USNW-NB15.ipynb` (6 classical); `model_selection/checkpoints/*_best.pkl`; `model_selection/dl_tuned.ipynb` (3 deep) | Verified |
| Why each model was chosen | Not documented | **Gap** (the report's family description is labelled as interpretation) |
| Classical tuning grids and 5,000-row sampling | `USNW-NB15.ipynb` cells 12–18 | Verified |
| Classical best-metric and overall-score table | `USNW-NB15.ipynb` cell 20 output | Verified |
| Deep-model tuning grids; metrics in latent space on a 10,000 sample | `dl_tuned.ipynb` cells 6, 32 and the AE/VAE tuning cells | Verified |
| DEC tuning table | `model_selection/DEC_tuning_results.csv` | Verified |
| Final deep comparison and ranks | `model_selection/DL_Models_Final_Comparison.csv`; `dl_tuned.ipynb` cells 59–60 | Verified |
| Written rationale for choosing DEC beyond the ranks | Not documented | **Gap** |
| No single table comparing all nine models | No such file in `model_selection/` | Derived |
| UNSW held-out DEC: Silhouette 0.2238, DB 1.8441, CH 21,209.36, ARI 0.0923, NMI 0.1245; a 40-record cluster | `model_selection/cowrie_dataset.ipynb` cells 19, 29–30 outputs | Verified |
| Cowrie tuning grid (30 configurations) and ranking method | `model_selection/cowrie_tuned.ipynb` cells 0–1 | Verified |
| Selected configuration: log1p + StandardScaler, latent 4, K 3, Silhouette 0.3537, DB 1.3830, CH 1,090.37, confidence 0.9329, 250 iterations | `cowrie_tuned.ipynb` cell 2 output | Verified |
| Final model clusters 485 / 694 / 621, mean confidence 0.9395 | `cowrie_tuned.ipynb` cell 8 output; reproduced by `tests/test_dec_reproducibility.py` | Verified |
| Cluster meanings (0 short/high-rate, 1 interactive multi-command, 2 no-command) | `cowrie_tuned.ipynb` cell 19 (cluster profile); audit crosstab of `attack_cat` against cluster | Interpretation, based on measured profiles |

## Chapter 5: DEC integration

| Claim | Evidence | Status |
|---|---|---|
| Architecture 17-32-16-4, Student's t layer, α = 1 | `ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/model.py`; `artifacts/config.json` | Verified |
| Inference preprocessing order and error handling | `ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/preprocessing.py`; `tests/test_dec_preprocessing.py` | Verified |
| Output columns; exact-string session IDs; ARI/NMI gating | `ml/cowrie_dec_integration_skeleton/scripts/run_dec_evaluation.py`; `tests/test_dec_runner.py` | Verified |
| Default DEC interpreter; no silent fallback | `scripts/pipeline.py`; `tests/test_pipeline_safety.py` | Verified |
| Baseline DEC distribution 1 / 7 / 46 | `reports/behaviour_analysis/cluster_interpretation_report.md` | Verified |
| Artifact hashes unchanged | `reports/diagnostics/*/hashes_before.txt` and `hashes_after.txt` | Verified |

## Chapter 6: Fresh-data evaluation

All paths are relative to `data/evaluation_runs/fresh_20261019_224335/`.

| Claim | Evidence | Status |
|---|---|---|
| Run window, commands and exit codes | `logs/commands.log`; `EVALUATION_REPORT.md` §2 | Verified |
| Script-kiddie-only profile and the reason for it | `inputs/attack_profiles_controlled.json`; `EVALUATION_REPORT.md` §1 | Verified |
| 5 sessions started, 0 retries, 0 failures | `logs/attack_generator.stdout.txt` | Verified |
| Snapshot 77,596 bytes; 13 sessions; 8 excluded; 5 new | `raw/cowrie.json`; `fresh/preparation_summary.json`; `verification/verification.json` | Verified |
| Known-set sizes (54, 54, 5, 8, 54, 43; union 62) and zero overlap | `verification/verification.json` (`known_set_sizes`, `new_session_overlap_with_known_sets`) | Verified |
| Start, login, command and close checks for each session | `verification/verification.json` (`new_sessions`) | Verified |
| DEC: all cluster 1; confidence 0.924 / 0.928 / 0.935 | `dec/dec_results.csv`; `verification/verification.json` | Verified |
| Full snapshot all cluster 1 | `pipeline/processed/dec_results.csv` | Verified |
| Novelty: 5 Known-like, `sig-47521826f16efd4b`, scores 0.728–0.836 | `novelty/novelty_assessment_results.csv` | Verified |
| `evaluation_mode = independent`; 43 reference IDs; 0 overlap | `novelty/novelty_assessment_summary.json`; `novelty/novelty_assessment_report.md` | Verified |
| ARI/NMI omitted | `logs/dec_inference.stdout.txt` | Verified |
| Strict check failed, exit code 1; differences ≤2.4 × 10⁻⁸ for `458003a74c58` | `logs/commands.log` (exit=1); `verification/verification.json` (`problems`); `EVALUATION_REPORT.md` §9 | Verified |
| Held-out run: 10 Potentially Novel, 1 Known-like; scores mostly 0.60–0.69 | `reports/novelty_assessment/held_out/revised/novelty_assessment_summary.json` and `novelty_assessment_results.csv` | Verified |
| Demo: all cluster 1; 5 Potentially Novel, 3 Known-like; "in-sample" label from the earlier code | `data/demo_20261019_213439/processed/dec_results.csv`, `novelty/novelty_assessment_summary.json` | Verified |
| Demo re-run with corrected code gives `independent` with identical results | `reports/diagnostics/remediation_20261019_220042/demo_novelty_after/` | Verified |

## Chapter 7: Reliability and testing

| Claim | Evidence | Status |
|---|---|---|
| 130 tests pass | Full `pytest tests` run during report validation (see the final validation summary) | Verified at report time |
| Five reproducibility tests and their sub-batch sizes | `tests/test_dec_reproducibility.py`; `tests/dec_batch_probe.py` | Verified |
| Variation values (2.235 × 10⁻⁸, 1.49 × 10⁻⁷, 6.8 × 10⁻⁷, gap 5.94 × 10⁻³) | `reports/diagnostics/reproducibility_20261019_230210/variation_probe.json` | Verified |
| Input-sensitivity values (≈2 × 10⁻⁴ etc.) | Probe run during the reproducibility task (printed, not saved); asserted in part by test 3 | Derived; only the `sbytes` case is stored as a test |
| Tolerance `atol = 1e-6`, `rtol = 0` | `tests/test_dec_reproducibility.py` (module docstring and constants) | Verified |
| Protected-file hashes identical (latest 86 files) | `reports/diagnostics/reproducibility_20261019_230210/hashes_before.txt` and `hashes_after.txt` | Verified |

## Chapter 8: Automated defence

| Claim | Evidence | Status |
|---|---|---|
| Defence engine not implemented | `scripts/defence_engine.py` does not exist; no code reads `configs/defence_policy.json` | Verified |
| `configs/defence_policy.json` is a draft, unused | File contents; search for references | Verified |
| `response_engine.py` is an unused placeholder | `ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/response_engine.py` (docstring); no imports elsewhere | Verified |
| Join on exact `session_id` | Output schemas; `tests/test_dec_runner.py`; `tests/test_novelty_assessment.py` | Verified |
| Keyword classifier is noisy (`whoami` → privilege_escalation) | `scripts/behaviour_pattern_analysis.py` (`classify_command`), checked during the audit | Verified |

## Claims in `README.md` not supported by the repository

| README claim | Finding | Status |
|---|---|---|
| Central storage in MongoDB; `Attack_Session` and other collections | No database code or configuration | **Unsupported** |
| REST APIs `/api/ingest`, `/api/analyze`, `/api/rules` | No web framework or endpoint code | **Unsupported** |
| Analyst dashboard | Not present (listed under Phase 3) | **Unsupported** (planned) |
| SSH/Telnet honeypot | Only SSH is exposed | **Unsupported** for Telnet |
| "Zero-day detection ✅", "Automated rule generation ✅" | Not demonstrated / not implemented (Chapters 6 and 8) | **Unsupported** |
| Phase 1: Nmap scanning, Hydra brute force, IPs `172.20.10.x` | No logs or captures of these activities in the repository (`logs/` is gitignored and empty) | **Gap**; needs human confirmation from Phase 1 records |
