# Cowrie session novelty-scoring baseline (Task 18)

**Date:** 2026-11-11.

## Status (added in Task 19A, 2026-11-11; audit: `reports/cowrie_novelty_freeze_audit_20261111/report.md`)

**Interpretation:**
- **Method C** (input-space kNN distance) is the **primary experimental candidate**.
- **Methods A** (AE reconstruction error) and **B** (latent kNN distance) are **secondary comparisons**.
- **This baseline is not a validated zero-day detector.** Every validation session is from a known category. The only evidence here is that about 1% of known logged-in sessions are flagged (0.50–0.67%).
- **Validation flags are strongly affected by generator pacing.** Flagged sessions over-represent long random think-time draws (sections 6 and 9). They are not unusual behaviour.
- **The `find` experiment shows sensitivity to unfamiliar Cowrie interaction patterns**, an emulated command with an 11.6 s execution delay. It does not necessarily show sensitivity to unseen attack behaviour.
- **The held-out `data_exfiltration` experiment may be confounded by Cowrie command-emulation failures** (`tar` fails, `curl -T` errors). An attribution check is required (section 9).

**Frozen state (verified in Task 19A from the saved artefacts; nothing retrained or changed):**
- Seven inputs, in order.
- Training-only medians and scaling; no missingness indicators; complete imputation records.
- Thresholds (training p99): A 1.171445, B 0.729190, C 1.692104.
- Validation scores and flags reproduce exactly. Five-seed stability results are preserved.
- Sealed test set: never accessed (no Dataset V2 test run exists yet).

**Configuration paths (corrected in Task 19A):**
- Task 18 Phase 1 originally wrote revision **1.1.0** over `configs/model_features_v2_frozen.json`. Task 19A restored the original **1.0.0** there (`8ae17612…`, the configuration of Tasks 16–17) and moved 1.1.0 to `configs/model_features_v2_frozen_v1.1.0.json` (`18a4ab2b…`).
- Section 2 below, and the `relation_to_clustering_config.path` field inside the unchanged `configs/cowrie_novelty_baseline_v1.json`, still name the canonical path. The recorded hash (`18a4ab2b…`) identifies 1.1.0, which is the revision this baseline used.
- `novelty_baseline.py` and `revise_frozen_config.py` now reference the versioned 1.1.0 path, and `revise_frozen_config.py` refuses to write the canonical path. The diff is in the audit's `evidence/script_changes.diff`.
- Scores, thresholds, features and weights are unchanged.

**Scope:** a novelty-scoring baseline for logged-in Cowrie sessions, built and checked on the Dataset V2 train and
validation splits only. Every validation session belongs to a **known** (trained) category. A "flag" here is therefore a
false positive relative to novelty, and **nothing in this report is evidence of detecting an unseen category or a zero-day.**

**Not done:**
- no test-set access (an audit hook found no test paths opened);
- `data_exfiltration` is absent from training and validation;
- no DEC training;
- no cluster labels used;
- Dataset V2, the generator, profiles and extractor are unchanged;
- the frozen clustering configuration was revised only as Phase 1 required, and not replaced;
- no automated defence;
- nothing committed.

**Labels:** **[O]** observed, **[H]** hypothesis, **[L]** limitation.

## 1. Headline

1. **Calibration holds on known sessions [O].**
   - All three methods use a threshold at the 99th percentile of their training scores.
   - On validation they flag **0.50–0.67%** of the 600 sessions (3–4 sessions; bootstrap 95% CI up to 1.3%).
   - That is consistent with the 1% design rate (binomial p 0.30–0.54).
   - Train and validation score distributions match for A and C (KS p 0.43 and 0.72) and shift slightly for B (p 0.03).
2. **The methods disagree on *which* sessions are unusual [O].**
   - No validation session is flagged by all three.
   - Flag-set overlap (Jaccard): A–B 0, A–C 0, B–C 0.17.
   - Score rank correlation: 0.32–0.74.
3. **Repeatability across seeds:**
   - **A (AE reconstruction) is poor [O].** Validation-score Spearman across seeds averages 0.57 (min 0.39). Thresholds range 0.74–1.32. Flag sets barely overlap (mean Jaccard 0.08). 0 sessions are flagged by all 5 seeds; 20 by at least one.
   - **B (latent kNN) is moderate:** Spearman 0.72, Jaccard 0.22.
   - **C (input-space kNN) is deterministic.**
4. **What gets flagged among known sessions is mostly generator noise and session length [O].**
   - **A's flags:**
     - Driven by `time_to_first_input_s` (39% of their reconstruction error).
     - Flagged median 5.65 s vs 1.62 s overall: the tail of the generator's random think-time draw.
   - **C's flags:** all 4 contain a think time above the training p95, and 2 above p99, against 4.8% of all validation sessions.
   - **B's flags:** long sessions (median 23.6 s, 8 lines).
   - **Category of the flags:** benign, lateral movement, reconnaissance and brute force.
   - **[H]** At a 1% operating point, false positives on known traffic are generator pacing outliers rather than unusual behaviour.
5. **The scores react strongly to an unseen Cowrie artefact [O].**
   - With the 30 training sessions containing the slow `find / -name id_rsa` (≈ 11.6 s Cowrie execution) included, 0 of the 9 validation `find` sessions are flagged by any method.
   - Refitted **without** them, B flags **7/9** and C **6/9**; A flags 0/9.
   - So a Cowrie emulation artefact that training has not seen is exactly what these scores flag.
   - **This is the main caveat for the held-out experiment.** Exfiltration uses commands that Cowrie emulates badly (`tar` fails, `curl -T` errors; Task 12/13), and a flag there may reflect emulation, not behaviour [H].
6. **Recommendation for approval:**
   - Freeze **C (input-space kNN)** as the pre-declared **primary** score: it is deterministic, calibrated, train/validation consistent and the simplest.
   - Freeze **A and B (seed 42)** as **secondary** scores.
   - Pre-declare an artefact-attribution check for the held-out evaluation (section 9).
   - Not frozen yet: `configs/cowrie_novelty_baseline_v1.json` is marked provisional.

## 2. Phase 1: configuration consistency

`revise_frozen_config.py`, with checks in `config/frozen_config_revision_checks.json`. All 14 checks pass, and it is idempotent: a second run makes no change.

| Item | Result |
|---|---|
| `configs/model_features_v2_frozen.json` | **1.0.0 → 1.1.0** (`8ae17612…` → `18a4ab2b…`). `input_bytes_total` changed conditional → **inactive**, with `status_history` and a dated reason. `conditional_features` is now empty. The `correlated_pairs` record is resolved. A `revisions` list, an explicit `extracted_features` (13, spec order) block separate from `model_input_features` (8, unchanged), and references to both spec revisions are added |
| 1.0.0 preserved | Byte-identical archive at `reports/dataset_v2_feature_freeze_20261111/model_features_v2_frozen.json` (checked). Copy of 1.1.0 at `config/model_features_v2_frozen_v1.1.0.json` |
| Spec draft.3 (extractor contract) | `configs/feature_spec_v2.json` `9401b355…`, unchanged |
| Spec draft.4 | `configs/feature_spec_v2_draft4.json` `7f444dd1…`, unchanged. It records the 1.0.0 hash of the frozen config; it is a preserved separate revision. Its active list equals 1.1.0's model inputs (checked) |
| Extractor | `c0fdc684…`, unchanged; still writes all 13 features |
| Model-input ordering | Spec order; unchanged from 1.0.0 (checked) |
| Note [L] | Task 16's `build_freeze.py` would rewrite 1.0.0, and Task 17's `revalidate_v2.py` asserts the 1.0.0 hash. Reproducing them needs the archived 1.0.0 copy. Model inputs are identical |

## 3. Population and preprocessing

**Population:**
- Logged-in sessions only: train **1,500**, validation **600**. Each is one per interaction, so rows are independent.
- `login_success` is constant here and is dropped. The 7 inputs are the frozen inputs minus `login_success` (asserted): `session_duration_s`, `input_line_count`, `shell_operator_lines`, `time_to_first_input_s`, `inter_input_mean_s`, `inter_input_std_s`, `tty_output_bytes`.
- This novelty configuration is separate; the 8-feature clustering configuration is unchanged.

**Preprocessing** (`outputs/preprocessing.json`):
1. Medians of non-missing **logged-in training** values. Every feature has valid observations (smallest: `inter_input_std_s`, 1,292), so there was no stop.
2. Impute training and validation with those medians.
3. log1p on the 5 continuous time/byte inputs (the Task 17 rule).
4. StandardScaler fitted on logged-in training data. Validation scaled means are within ±0.07.
5. No missingness indicators.

Training medians: `session_duration_s` 12.2, `input_line_count` 5, `shell_operator_lines` 0, `time_to_first_input_s` 1.663, `inter_input_mean_s` 1.844, `inter_input_std_s` 0.985, `tty_output_bytes` 1,114.

**Imputation** (every value logged per session in `outputs/imputation_log_{train,validation}.csv`):

| Feature | Train | Validation | Cases |
|---|---|---|---|
| `time_to_first_input_s` | 99 | 41 | Brute-force logins with no input line |
| `inter_input_mean_s` | 198 | 79 | All brute force (< 2 lines) |
| `inter_input_std_s` | 208 | 81 | Brute force, plus 10 benign / lateral sessions with exactly 2 lines |

**The failed-login collapse of Task 17 is gone [O].** The largest identical vector group is now 3 rows, with 1,469 distinct vectors among 1,500.

## 4. Methods

Design fixed before running (in the script docstring and `configs/cowrie_novelty_baseline_v1.json`):

| | A: AE reconstruction | B: latent kNN distance | C: input kNN distance |
|---|---|---|---|
| Score | Per-session MSE between scaled input and reconstruction | Mean Euclidean distance to the **5** nearest training points in the 4-d AE latent space | Mean Euclidean distance to the **5** nearest training points in the 7-d scaled input space |
| Model | Existing encoder (`build_encoder`: 7 → 32 → 16 → 4), decoder 4 → 16 → 32 → 7; dec15 pre-training hyperparameters (Adam 1e-3, MSE, 20 epochs, batch 256, `validation_split` 0.1) | Encoder from A | None |
| Training scores | In-sample | Leave-one-out (self excluded) | Leave-one-out |
| Randomness | TF seed, op determinism | Via A | None |
| Seeds | 42 primary; 43–46 for repeatability | Same | — |

- k = 5 is a fixed default; no k was tuned.
- No K-Means or DEC labels are used anywhere.
- **Training (seed 42):** AE MSE 0.298 final (Keras hold-out 0.294).
- **Runtime:** AE 6.1–6.9 s per seed; kNN scoring < 0.05 s; whole script ≈ 65 s.

## 5. Score distributions (seed 42; `outputs/train_scores_seed42.csv`, `outputs/validation_scores.csv`)

| Method | Train median / p95 / p99 / max | Validation median / p95 / p99 / max | Train vs validation KS D (p) | Category ε² (validation, post hoc) |
|---|---|---|---|---|
| A | 0.228 / 0.711 / **1.171** / 1.843 | 0.222 / 0.656 / 0.984 / 1.294 | 0.042 (0.43) | 0.12 |
| B | 0.274 / 0.520 / **0.729** / 1.379 | 0.266 / 0.506 / 0.694 / 1.056 | 0.070 (0.03) | 0.29 |
| C | 0.702 / 1.299 / **1.692** / 2.808 | 0.704 / 1.236 / 1.592 / 1.981 | 0.033 (0.72) | 0.33 |

**Per category, validation medians (post hoc):**

| Method | Brute force | Other categories |
|---|---|---|
| A | 0.109 | 0.17–0.27 |
| B | 0.077 | 0.27–0.30 |
| C | 0.152 | 0.71–0.77 |

- Brute force scores lowest everywhere: near-identical short sessions form a dense region.
- The category ε² for B and C is that brute-force difference.
- Figures: `figures/score_distributions_train_vs_validation.png`, `figures/validation_scores_by_category.png`.

## 6. Threshold and false-positive analysis

**Rule (fixed before running):** threshold = the 99th percentile of the method's training scores, giving a target flag rate of 1% on known traffic.

| Method | Threshold | Validation flagged | Rate [95% CI] | Binomial p vs 1% | Validation p99 (reference only) | At train p95 | At train p99.5 |
|---|---|---|---|---|---|---|---|
| A | 1.1714 | 4 / 600 | 0.67% [0.17, 1.33] | 0.54 | 0.984 | 4.2% | 0.17% |
| B | 0.7292 | 3 / 600 | 0.50% [0.00, 1.17] | 0.30 | 0.694 | 5.0% | 0.17% |
| C | 1.6921 | 4 / 600 | 0.67% [0.17, 1.33] | 0.54 | 1.592 | 4.2% | 0.17% |

The 95th and 99.5th columns are context only; they were not selected. The validation p99 is a reference, not a threshold.

**Per-category false positives (validation, post hoc):**

| Method | Benign (229) | Botnet (71) | Brute force (79) | Lateral (78) | PE (69) | Reconnaissance (74) |
|---|---|---|---|---|---|---|
| A | 1 | 0 | 1 | 2 | 0 | 0 |
| B | 2 | 0 | 0 | 0 | 0 | 1 |
| C | 2 | 0 | 0 | 2 | 0 | 0 |

With 3–4 flags no category rate can be estimated [L]. No category is systematically over-flagged.

**What drives the flags [O]** (`outputs/flag_pacing_attribution.json`):

| Method | Flagged-session profile (median) vs all validation | Think-time attribution |
|---|---|---|
| A | First-input delay **5.65 s** vs 1.62 s; 1.5 operators vs 0; fewer lines. Error share: `time_to_first_input_s` 39%, `shell_operator_lines` 28% | 2 of 4 flags have a think time > train p99. First think of flagged sessions 5.8 s vs 1.5 s |
| B | Long sessions: 23.6 s, 8 lines, 1,754 output bytes | 1 of 3 > p95; 0 > p99 |
| C | Inter-input mean **4.57 s**, std **4.0 s** vs 1.91 / 1.02 | **4 of 4 > p95**, 2 > p99 |

- **Enrichment among the top 5% of scores:** sessions containing a think time > train p99 make up 17% (A), 10% (B) and 23% (C), against 4.8% overall.
- **Cowrie emulation-gap sessions** (≥ 1 `command not found`) are **not** over-flagged: A 0.61% vs 0.69%; B and C 0%.
- **Imputed rows** (brute force) are not over-flagged by B or C (0%). A flags 1 of 81.
- **Spearman of score with session length**, validation (A / B / C):

| Measure | A | B | C |
|---|---|---|---|
| `session_duration_s` | 0.20 | 0.32 | 0.51 |
| Execution sum | 0.17 | 0.31 | 0.32 |
| `tty_output_bytes` | 0.18 | 0.39 | 0.36 |

## 7. Repeatability across seeds (validation)

| Method | Score Spearman across 5 seeds (mean / min) | Thresholds by seed | Flag rate by seed | Flag-set Jaccard (mean / min) | Flagged by all 5 / by any |
|---|---|---|---|---|---|
| A | **0.57 / 0.39** | 1.17, 0.74, 1.32, 0.86, 1.21 | 0.67–1.0% | **0.08 / 0** | 0 / 20 |
| B | 0.72 / 0.65 | 0.73, 1.01, 0.78, 1.23, 1.04 | 0.50–1.17% | 0.22 / 0 | 0 / 13 |
| C | deterministic | 1.692 | 0.67% | — | — |

**Reproducibility [O]:**
- **Same seed:** a same-seed rerun inside the script gives identical A and B scores.
- **Full second run:** gives byte-identical `validation_scores.csv`, an identical novelty configuration, and identical `results.json` excluding runtime.
- **Saved autoencoder:** reloads and reproduces the validation scores.

## 8. Sensitivity to Cowrie artefacts and the slow `find` command

| Method | `find` sessions flagged, full model (validation 9) | Mean percentile of `find` sessions vs non-`find` PE | Refit without 30 training `find` sessions: score Spearman vs full | Flag rate (no-`find` model) | `find` flagged (no-`find` model) |
|---|---|---|---|---|---|
| A | 0 | 58 vs 40 | 0.954 | 0.67% | **0 / 9** |
| B | 0 | 78 vs 48 | 0.946 | 1.83% | **7 / 9** |
| C | 0 | 75 vs 52 | 0.993 | 1.83% | **6 / 9** |

**Interpretation [O / H]:**
- **The distance methods flag artefacts they have not seen.** When the training data contain a Cowrie execution artefact, B and C treat it as normal. When it is absent, they flag it. The slow emulated `find` alone produces a "novel" session.
- **A is insensitive to it here.** Its error is dominated by the first-input delay, not by duration or intervals.
- **[H] Consequence for the held-out experiment.** An unseen category can be flagged because of Cowrie-specific execution, output or failure behaviour of its commands, not because of attacker behaviour.

## 9. Recommendation and the held-out experiment (not run)

**Method comparison:**

| Criterion | A | B | C |
|---|---|---|---|
| Calibration on known validation | ✓ 0.67% | ✓ 0.50% | ✓ 0.67% |
| Train/validation consistency | ✓ (KS p 0.43) | slight shift (p 0.03) | ✓ (p 0.72) |
| Seed repeatability | **poor** | moderate | deterministic |
| What it responds to | First-input delay (pacing noise) | Session length and volume | Session length and pacing tail |
| Sensitivity to an unseen Cowrie artefact (`find`) | low | high | high |
| Complexity | Neural network | Neural network + kNN | kNN only |

**Proposal** (needs approval; nothing frozen yet):
1. **Freeze C** as the pre-declared primary score, with A and B (seed 42) as secondary scores. The preprocessing, reference sets and thresholds are those in `configs/cowrie_novelty_baseline_v1.json` and `models/cowrie_novelty_baseline_20261111/`.
2. **Held-out evaluation, as a separately approved task.** Score the sealed `data_exfiltration` sessions once with the frozen pipeline. Report:
   - the flag rate with CIs against the validation false-positive rate (0.5–0.67%);
   - the score distribution;
   - **an artefact-attribution check:** the share of flagged exfiltration sessions whose distinguishing commands fail or behave abnormally in Cowrie (`tar`, `curl -T`), and per-feature drivers.
3. **No claim beyond that experiment.** These results support only "flags ≈ 1% of known logged-in sessions".

## 10. Limitations

- **[L] Small flag counts.** 600 validation sessions give 3–4 flags. The flag-rate CI is wide (0–1.3%), and per-category false-positive rates cannot be estimated.
- **[L] Known categories only.** Validation contains only trained categories. True-positive behaviour on unseen categories is untested by design.
- **[L] Synthetic pacing.** Lab timing comes from the generator's category-independent lognormal pacing. Its tail produces false positives that real attackers would not reproduce in the same way. Timing features have low deployment compatibility (spec).
- **[L] Unchanged hyperparameters.** AE hyperparameters are unchanged (existing configuration) and k = 5 is a default. Neither was tuned, to avoid validation-driven selection.
- **[L] Single-session scope.** Session-level scores cannot see multi-session behaviour such as brute-force guess sequences. Failed-login sessions are out of scope for this model.
- **[L] Session-length effects.** kNN distances partly measure session length (Spearman 0.3–0.5 with duration).

## 11. Files

| Path | Content |
|---|---|
| `revise_frozen_config.py`, `config/` | Phase 1: revision script, 1.1.0 copy, checks |
| `novelty_baseline.py` | Preprocessing, methods A–C, 5 seeds, thresholds, false-positive and artefact analyses, `find` refit, model saving, figures |
| `config/cowrie_novelty_baseline_v1.json` | Copy of `configs/cowrie_novelty_baseline_v1.json` (provisional novelty configuration: features, medians, scaler, methods, thresholds, artefact hashes) |
| `outputs/preprocessing.json`, `outputs/imputation_log_*.csv` | Preprocessing parameters and per-session imputation record |
| `outputs/results.json` | All metrics: distributions, thresholds, false positives, per category, seeds, method agreement, `find` sensitivity, runtime, environment |
| `outputs/train_scores_seed42.csv`, `outputs/validation_scores.csv` | Per-session scores (validation: all seeds, primary flags; labels and `find` marked post hoc only) |
| `outputs/flag_pacing_attribution.json` | Think-time attribution of flags (section 6) |
| `figures/` | Train vs validation distributions; validation by category with `find` sessions marked |
| `console_run{1,2}.txt` | Console output (run 2 = reproducibility run) |
| `models/cowrie_novelty_baseline_20261111/` | `autoencoder.weights.h5`, `scaler.joblib`, `medians.joblib`, `reference_latent_train.npy`, `reference_scaled_train.npy`, `config.json`, `artifact_sha256.json` |
| `SHA256SUMS` | This directory and the model directory |

**Environment:** Python 3.11.4, TensorFlow 2.21.0, Keras 3.15.1, scikit-learn 1.9.0 (`.venv-dec-smoke`). Nothing was installed.

**First attempt:** it stopped at the script's own safety assertion (`data_exfiltration` absence check) because of an operator-precedence bug. No data was read past that point and no artefact was written. The assertion was fixed (parenthesised) and the script run.
