# Autoencoder + K-Means and DEC revalidation on frozen Dataset V2 features (Task 17)

**Date:** 2026-11-11.

**Scope:** model validation on the Dataset V2 train and validation splits with the frozen 8-feature input set. This is
**not** zero-day detection; no clustering number here is a detection accuracy.

**Not done:**
- no test-set access (an audit hook found no test paths opened);
- Dataset V2, the generator, profiles, extractor and frozen configuration are unchanged (hash-checked);
- no features added;
- no thresholds tuned on labels;
- no novelty detection or defence;
- nothing committed.

**Labels:** **[O]** observed, **[H]** hypothesis, **[L]** limitation.

## 1. Headline

1. **Neither model produces defensible behavioural clusters of attacker activity [O].**
   - Both models find the same structure:
     - **(a)** one cluster that is exactly the failed-login sessions;
     - **(b)** one cluster of brute-force logins that ran at most one command;
     - **(c)** the remaining logged-in sessions split into bands of session length and output volume.
   - **Bands (c) carry no category structure.** Among the five command-running categories, cluster vs category ARI is **0.003–0.011** and NMI **0.01–0.03** on validation.
   - **They are not reproducible.** Mean pairwise ARI across 5 seeds on logged-in validation sessions is **0.27–0.37**.
2. **The good-looking all-row numbers come from the failed-login block [O].**
   - All-row validation silhouette is 0.56–0.58 and all-row seed ARI is 0.81–0.89.
   - 1,227 of 3,190 training rows are one identical vector: failed logins after median imputation.
   - On logged-in sessions only, silhouette is 0.11–0.14. Without brute force it is −0.03 to 0.16.
   - The cluster count rule (training only) selected **K = 7**. It inherits this effect [L].
3. **DEC adds nothing over its own AE + K-Means start [O].**
   - Its assignments are almost the same.
   - It never converged (500/500 iterations in all 10 runs; label change 0.25–1.9% vs 0.1% tolerance).
   - At K = 7 its confidence is low where it matters: logged-in validation mean 0.66, and 51.5% of sessions below 0.7.
   - Plain K-Means on the 8 scaled inputs scores a higher all-row silhouette than both (0.636 at K = 7, 0.620 at K = 3).
4. **The `find` artefact does not shape the clustering, but it is visible [O].**
   - Retraining without the 30 training `find` sessions changes validation assignments less than a seed change does (ARI 0.98 / 0.97, against a seed-to-seed reference of 0.89).
   - All 9 validation `find` sessions land in one "long session" cluster.
5. **Engineering checks pass [O].**
   - **Leakage-safe preprocessing:** fitted on training rows only.
   - **Reproducible:** a full rerun gives identical results.
   - **Reloadable artefacts:** they reproduce the assignments, end to end, through the unchanged inference `preprocess()`.
   - **Consistent splits:** train and validation agree (cluster shares within 1.7 points; silhouette within 0.006).
6. **Implication [H].**
   - With these 8 session-level features, Cowrie V2 sessions separate by *whether there was a login and how much happened*, not by *what kind of activity it was*.
   - The clusters are usable at most as activity-level groupings, not as behaviour classes. The novelty-detection design should take this into account.

## 2. Specification revision 2.0.0-draft.4

| Item | Result |
|---|---|
| File | `configs/feature_spec_v2_draft4.json` (new; SHA-256 `7f444dd1…`), written by `make_spec_draft4.py`, which refuses to overwrite |
| Content | All 13 definitions, formulas, dtypes and columns identical to draft.3 (verified). All revisions kept (draft.4, draft.3, draft.2, draft.1). `active: false` with a dated `inactive_since` reason for `login_failed_count`, `download_command_lines`, `unique_command_names`, `input_line_max_bytes`, `input_bytes_total` |
| Authority | A `model_input_configuration` block names `configs/model_features_v2_frozen.json` (with its SHA-256) as authoritative. The active list equals its 8 inputs (asserted) |
| Why a new file | `scripts/extract_features_v2.py` rejects any `configs/feature_spec_v2.json` whose `spec_version` is not `2.0.0-draft.3`, and the extractor and tests may not change. Editing in place would break extraction. The draft.3 file stays byte-identical (`9401b355…`) as the extractor's formula contract. The formulas are identical, so datasets extracted under draft.3 are valid under draft.4 (versioning policy: deactivation needs no re-extraction) |
| `input_bytes_total` | Inactive in draft.4 (approved 2026-11-11). The frozen configuration was not edited, as instructed, so its per-feature record still says "conditional" (its state at the freeze). Its model-input list (8) is the same either way. Draft.4 documents this |

## 3. Data, population and preprocessing

**Data:**
- Train: 3,190 sessions (1,500 interactions). Validation: 1,257 sessions (600 interactions). All sessions, including failed logins.
- Labels, roles, interaction IDs and manifest `find` flags are post-hoc metadata, never inputs.
- Inputs, in frozen order: `login_success`, `session_duration_s`, `input_line_count`, `shell_operator_lines`, `time_to_first_input_s`, `inter_input_mean_s`, `inter_input_std_s`, `tty_output_bytes`.

**Preprocessing** (`outputs/preprocessing.json`; parameters also saved as `scaler.joblib` and `medians.joblib` with every model):
1. **Median imputation.** Each feature's median over non-missing **training** values. Every feature has valid training observations (smallest: `inter_input_std_s`, 1,292), so there was no stop.
2. **Validation** uses the training medians.
3. **log1p** on the five continuous time and byte features (`session_duration_s`, `time_to_first_input_s`, `inter_input_mean_s`, `inter_input_std_s`, `tty_output_bytes`). This is the existing implementation's rule: the 15-feature model logged continuous duration, byte and time features and not packet counts. Counts and the indicator are not logged. log1p has no fitted parameters.
4. **StandardScaler** fitted on imputed, logged training data only, then applied to validation (validation scaled means within ±0.07, SDs 0.92–1.02).
5. **No missingness indicators.**

Training medians:

| Feature | Median |
|---|---|
| `time_to_first_input_s` | 1.663 s |
| `inter_input_mean_s` | 1.844 s |
| `inter_input_std_s` | 0.985 s |
| `session_duration_s` | 1.1 s |
| `login_success`, `input_line_count`, `shell_operator_lines`, `tty_output_bytes` | 0 |

**Missing timing values [O]:**

| Feature | Train | Validation |
|---|---|---|
| `time_to_first_input_s` | 1,789 | 698 |
| `inter_input_mean_s` | 1,888 | 736 |
| `inter_input_std_s` | 1,898 | 738 |

- **Who has them:** all 1,690 failed-login training rows (100% imputed), the 99 brute-force logins with no command, and sessions with 1–2 lines (for the inter-input features).
- **Effect of imputation:** failed logins get the *typical logged-in* timing values (1.66 s / 1.84 s / 0.98 s). Together with duration 1.1 s, 0 lines and 0 output bytes, they collapse onto one point.
- **Scale of the collapse:** the largest group of identical training vectors has 1,227 rows, and there are 1,476 distinct vectors in 3,190 rows.
- **This is the main mechanism behind the failed-login cluster.** Across validation rows, ARI between "row has an imputed value" and the cluster is 0.59 (K = 7) and 0.78–0.80 (K = 3).

## 4. Models (existing implementation; only the input mapping changed)

Code: `revalidate_v2.py`.
- **Reused unchanged:** `build_dec()` from `ml/cowrie_dec_integration_skeleton`, and the `ml_pipeline/dec15.py` procedure and `HYPERPARAMETERS`.
- **Run with:** single-threaded K-Means and TensorFlow op determinism, as in `models/dec_15_feature_v2_deterministic`.
- **Added:** saving the pre-DEC autoencoder, K-Means centres and per-session outputs. dec15 discarded these, which blocked the Step 13 analysis.

| | Model A: AE + K-Means | Model B: DEC |
|---|---|---|
| Encoder | 8 → 32 → 16 → **4** (ReLU, linear latent) | Same encoder, initialised from Model A's pre-training |
| Decoder (pre-training only) | 4 → 16 → 32 → 8 (linear output) | — |
| Pre-training | MSE, Adam 0.001, 20 epochs, batch 256, Keras `validation_split` 0.1 (last 10% of training rows) | Same |
| Clustering | K-Means on the latent space, `n_init` 20, `random_state` = seed, single-threaded | Student-t layer (α = 1) initialised with Model A's centres. Target distribution p = q²/f, normalised (dec15), updated every 50 iterations. KL loss, Adam 0.001, ≤ 500 iterations, tolerance 0.001 |
| Confidence | **None.** K-Means is not probabilistic. Distance to the assigned centre and the 2nd-minus-1st margin are reported instead, *not* as confidence | max soft assignment q |
| Seeds | 42 (primary, existing), plus 43–46 for stability | Same |
| Artefacts (`models/dataset_v2_revalidation_20261111/`, new) | `ae_kmeans_k{3,7}_seed42/`: `autoencoder_preDEC.weights.h5`, `kmeans.joblib`, `kmeans_centres.json`, `config.json`, scaler, medians, hashes | `dec_k{3,7}_seed42/`: `cowrie_dec.weights.h5` (loads in `CowrieDEC`), `cluster_centroids.json`, `config.json`, scaler, medians, hashes |

**Primary training logs (seed 42):**
- **AE MSE:** 0.945 → 0.045 (Keras hold-out 0.055).
- **DEC at K = 7:** KL 0.120 → 0.104 (minimum 0.086); label change at the 50-iteration checks 1.9% → 0.97%.
- **DEC at K = 3:** KL 0.060 → 0.032; label change 1.0% → 0.75%.
- **Convergence: not converged in any of the 10 runs.**

**Runtime:** about 15 s per full run (AE 6.6–7.3 s, K-Means 0.1–0.2 s, DEC 5.9–6.8 s). The whole script took about 290 s.

## 5. Cluster count (training data only)

**Rule** (fixed before running, recorded in `results.json`):
- **Candidates:** K = 2–8, on AE + K-Means over 5 seeds. K = 3 is the existing configuration; 8 covers the six generator categories plus a failed-login mode without using labels.
- **Eligibility:** keep K whose mean pairwise seed ARI is ≥ 0.8 and whose every cluster has ≥ 1% of rows.
- **Choice:** among those, the highest mean input-space silhouette. If several are within 0.01 of the best, take the smallest. If none qualifies, keep K = 3.

| K | Train silhouette (input) mean ± sd | Latent silhouette | Davies–Bouldin | Calinski–Harabasz | Smallest cluster | Seed ARI |
|---|---|---|---|---|---|---|
| 2 | 0.589 ± 0.011 | 0.716 | 0.870 | 2,745 | 37.8% | 0.896 |
| 3 | 0.590 ± 0.020 | 0.670 | 1.436 | 2,196 | 12.2% | 0.830 |
| 4 | 0.568 ± 0.017 | 0.653 | 1.741 | 1,752 | 4.6% | 0.829 |
| 5 | 0.581 ± 0.023 | 0.664 | 1.554 | 1,638 | 3.4% | 0.785 |
| 6 | 0.588 ± 0.036 | 0.665 | 1.527 | 1,556 | 2.7% | 0.817 |
| **7** | **0.605 ± 0.018** | 0.670 | 1.532 | 1,503 | 2.6% | 0.893 |
| 8 | 0.604 ± 0.017 | 0.669 | 1.592 | 1,443 | 1.9% | 0.907 |

**Selected: K = 7.**
- K = 8 is within 0.01 of K = 7, so the smaller K = 7 is taken.
- The existing K = 3 is 0.015 below the best, so it does not qualify on silhouette. It is still reported as the existing-configuration reference.
- All differences are small (sd 0.02). Every column is driven by the identical failed-login block [L].

## 6. Results (validation unless stated; train in `outputs/results.json`)

### 6.1 All rows (validation n = 1,257)

| Model | K | Silhouette (input) | DB | CH | Latent silhouette | Cluster sizes | ARI / NMI vs category | ARI vs login_success | Seed ARI (all rows) |
|---|---|---|---|---|---|---|---|---|---|
| K-Means on inputs (reference) | 3 | 0.620 | 1.10 | 1,137 | — | 675/409/173 | 0.119 / 0.096 | 0.76 | — |
| AE + K-Means | 3 | 0.567 | 1.70 | 801 | 0.694 | 345/724/188 | 0.183 [0.12, 0.24] / 0.146 | 0.63 | 0.837 (min 0.766) |
| DEC | 3 | 0.564 | 1.72 | 810 | 0.842 | 297/718/242 | 0.178 [0.12, 0.24] / 0.138 | 0.63 | 0.807 (min 0.746) |
| K-Means on inputs (reference) | 7 | 0.636 | 1.16 | 828 | — | 657/123/129/144/86/49/69 | 0.134 / 0.160 | 0.63 | — |
| AE + K-Means | **7** | 0.583 | 1.73 | 544 | 0.661 | 657/106/75/106/36/141/136 | 0.130 [0.08, 0.18] / 0.146 | 0.63 | 0.886 (min 0.867) |
| DEC | **7** | 0.582 | 1.83 | 526 | 0.762 | 657/92/71/123/64/114/136 | 0.130 [0.08, 0.18] / 0.152 | 0.63 | 0.894 (min 0.878) |

**Notes:**
- ARI CIs are 200 interaction-grouped bootstraps.
- **Train vs validation:** cluster shares differ by ≤ 1.7 points; silhouette by ≤ 0.006.
- **Reconstruction MSE:** train 0.0445 / validation 0.0468; medians 0.00017. The large identical block reconstructs almost perfectly.

### 6.2 Without the failed-login block (`posthoc_logged_in.py`; no refitting)

Logged-in sessions only: one per interaction, n = 600. "Without brute force" leaves n = 521.

| Model | K | Logged-in silhouette | Logged-in ARI vs category [95% CI] | Without BF: silhouette | Without BF: ARI / NMI | Seed ARI, logged-in (mean / min) |
|---|---|---|---|---|---|---|
| AE + K-Means | 3 | 0.107 | 0.111 [0.087, 0.145] | 0.001 | 0.011 / 0.020 | **0.371 / 0.152** |
| DEC | 3 | 0.107 | 0.096 [0.075, 0.127] | 0.155 | 0.003 / 0.009 | **0.269 / 0.094** |
| AE + K-Means | 7 | 0.141 | 0.106 [0.078, 0.145] | 0.048 | 0.010 / 0.027 | **0.318 / 0.216** |
| DEC | 7 | 0.137 | 0.106 [0.080, 0.150] | −0.031 | 0.005 / 0.024 | **0.319 / 0.226** |

**Where the logged-in ARI comes from:** the logged-in ARI (about 0.10) is the brute-force-login cluster alone. Without brute force it is essentially 0.

**Category × cluster, logged-in validation, K = 7, AE + K-Means** (`outputs/category_by_cluster_logged_in_validation_k7_*.csv`; figure `cluster_by_category_validation_k7.png`):
- **The brute-force cluster:** 68 brute-force rows, with 2 benign, 3 lateral movement and 2 reconnaissance.
- **The five other clusters:** each is 38–48% benign, against a benign prior of 38%, with every attack category spread across them.
- **Largest lifts:** lateral movement 2.9× and privilege escalation 2.5× in small clusters. Privilege escalation is enriched in the cluster that holds the `find` sessions (12 of 36 rows).

### 6.3 What dominates the clusters (K = 7, validation)

**η² of each scaled input by cluster** (share of the feature's variance explained by the clusters; AE + K-Means / DEC):

| Feature | AE + K-Means | DEC |
|---|---|---|
| `login_success` | 1.00 | 1.00 |
| `tty_output_bytes` | 0.98 | 0.98 |
| `session_duration_s` | 0.96 | 0.95 |
| `input_line_count` | 0.89 | 0.89 |
| `shell_operator_lines` | 0.50 | 0.53 |
| `time_to_first_input_s` | 0.48 | 0.48 |
| `inter_input_std_s` | 0.47 | 0.43 |
| `inter_input_mean_s` | 0.45 | 0.40 |

**Login success and failure [O]:**
- Cramér's V between cluster and `login_success` is **1.0**.
- 100% of failed rows sit in one cluster, and that cluster contains no logged-in row.
- At K = 3, 61–67 brute-force logins with no input also join that cluster.

**Duration, command count and output volume [O]:**
- These are the next dimensions (η² 0.89–0.98).
- Cluster medians step from 2.4–2.6 s, 0 lines and 315 output bytes (brute force) up to 18–22 s and 6–7 lines.

**Imputation [O]:**
- The failed-login cluster is 100% imputed rows.
- The brute-force cluster is 91–97% imputed.
- Other clusters are 0–6% imputed.

**`find` delay [O]:**
- All 9 validation `find` sessions fall into one cluster: AE + K-Means 8 of 9, DEC 9 of 9 (cluster 4: median 21–22 s, 7 lines).
- Removing the find sessions from training changes almost nothing: full-vs-no-find validation ARI is 0.981 for AE + K-Means and 0.969 for DEC, which is above the seed-to-seed reference of 0.89.
- Validation silhouette excluding find rows is 0.591 / 0.590, against 0.583 / 0.582 with them.

**Output volume [O]:** `tty_output_bytes` is the second most cluster-explained input. It reflects Cowrie's emulated output size (Task 15).

**Single-feature reproduction** (depth-3 tree on one input, fitted on training clusters, scored on validation clusters; balanced accuracy, chance 0.14 at K = 7): `session_duration_s` 0.48, `time_to_first_input_s` 0.44–0.46, `tty_output_bytes` 0.42–0.45.

### 6.4 Confidence (DEC) and distances (AE + K-Means)

**DEC confidence:**

| K | Set | Mean | Median | Minimum | Below 0.7 | Below 0.9 | Smallest top-1/top-2 gap |
|---|---|---|---|---|---|---|---|
| 7 | All validation rows | 0.792 | 0.917 | 0.294 | 24.6% | 47.3% | 0.0005 |
| 7 | **Logged-in validation** | **0.656** | 0.689 | 0.294 | **51.5%** | — | — |
| 3 | All validation rows | 0.936 | — | 0.473 | 5.5% | — | — |
| 3 | Logged-in validation | 0.884 | — | — | 11.5% | — | — |

- **Inflated by the failed-login block:** the high all-row confidence comes from it; brute force has the highest category mean (0.90 at K = 7).
- **Not stable across seeds:** validation confidence mean 0.757–0.792 and minimum 0.236–0.315 (K = 7).
- **[O] At K = 7 the confidence is not reliable for logged-in sessions**, with half of them below 0.7.

**AE + K-Means latent distances** (not confidence):

| K | Median distance to assigned centre | 5th percentile of the 2nd-minus-1st margin |
|---|---|---|
| 7 | 0.021 | 0.27 |
| 3 | 0.24 | 0.74 |

The near-zero median distance comes from the identical failed-login block.

## 7. Model comparison

| Criterion | AE + K-Means | DEC | Note |
|---|---|---|---|
| Clustering quality (all rows) | 0.583 / DB 1.73 (K = 7) | 0.582 / DB 1.83 | Both below plain K-Means on inputs (0.636 / 1.16) |
| Quality without the failed-login block | 0.141; without BF 0.048 | 0.137; without BF −0.031 | Weak to none |
| Stability, all rows | 0.886 | 0.894 | Inflated by the failed block |
| Stability, logged-in | 0.318 (min 0.216) | 0.319 (min 0.226) | **Unstable for both** |
| Train vs validation | Shares ≤ 1.7 pts; silhouette +0.004 | ≤ 1.5 pts; +0.004 | Consistent for both |
| Interpretability | Clusters = failed login / brute-force login / activity-volume bands | Same, almost identical assignments | Neither maps to behaviour categories |
| Confidence | None (distances only) | Present, but 51.5% below 0.7 for logged-in at K = 7; not converged | Neither offers reliable confidence |
| Runtime (train) | ~7 s | +~6 s on top of AE + K-Means | Both trivial |
| Cowrie artefacts | `find` sessions co-clustered; output volume η² 0.98 | Same | Same sensitivity |

**Verdict [O]:**
- **No winner.** DEC is not better than its AE + K-Means start on any criterion here, and both are below plain K-Means on internal quality.
- **Neither yields defensible behavioural clusters:** the stable part is login outcome and brute force, and the rest is unstable and category-independent.
- **If one must be carried forward:** AE + K-Means (Gate C option B) is the simpler equivalent. It has no confidence, so a novelty score would have to be defined separately (not done here).

## 8. Reproducibility and integrity

| Check | Result |
|---|---|
| Rerun of the primary configuration inside the run | Identical AE + K-Means labels, DEC q (max diff 0.0) and reconstruction |
| Full second run | `results.json` identical to the first run except timings and saved-model checks (below) |
| Saved models | All four reload identically: AE latent and K-Means labels; DEC through `CowrieDEC`; DEC end to end from raw validation features through the unchanged `preprocess()` (identical assignments, confidence difference 0.0) |
| First run, artefact defect (corrected) | The first run saved DEC weights *after* the pre-DEC autoencoder weights had been restored, which rewrote the encoder layers DEC shares. Its reload check correctly failed. The in-memory results were computed before saving and are unaffected (identical in run 2). That model directory, created by this task, was deleted; the save order was fixed (DEC first) and the script rerun. No pre-existing model was touched |
| Inputs | Frozen configuration `8ae17612…`, dataset `SHA256SUMS` and draft.3 spec `9401b355…` unchanged (section 9) |
| Environment | Python 3.11.4, TensorFlow 2.21.0, Keras 3.15.1, scikit-learn 1.9.0, NumPy 2.4.6, pandas 3.0.5 (`.venv-dec-smoke`, as for the existing DEC). matplotlib was already installed there (2026-11-08); nothing was installed |
| Test set | Not opened (audit hook; `test_like_paths_opened` empty) |
| `ml_pipeline/PIPELINE.md` | A dated Task 17 section was appended (backup `PIPELINE.md.before_task17`). It records no gate approval |

## 9. Files

| Path | Content |
|---|---|
| `make_spec_draft4.py` | Writes `configs/feature_spec_v2_draft4.json` |
| `revalidate_v2.py` | Preprocessing, K-range, 2 K × 5 seeds × 2 models, find sensitivity, evaluation, model saving, figures |
| `posthoc_logged_in.py` | Logged-in / without-brute-force re-scoring and stability (no fitting) |
| `outputs/preprocessing.json` | Medians, scaler parameters, imputation counts |
| `outputs/results.json` | All metrics, stability, confidence, leakage diagnostics, contingency tables, find sensitivity, runtime, training logs, environment |
| `outputs/posthoc_logged_in.json` | Section 6.2 |
| `outputs/k_range_train_{summary,per_seed}.csv` | Section 5 |
| `outputs/assignments_embeddings_k{3,7}_seed42_{train,validation}.csv` | Per session: AE + K-Means cluster, distance and margin, reconstruction MSE, DEC cluster, confidence and q, AE latent (pre-DEC) and DEC latent. Labels and `find` flags are marked post hoc only |
| `outputs/validation_assignments_all_seeds_k{3,7}.csv` | Assignments for 5 seeds × 2 models |
| `outputs/category_by_cluster_logged_in_validation_k*_*.csv` | Post-hoc tables |
| `figures/` | `k_range_train.png`, `cluster_by_category_validation_k{3,7}.png`, `training_and_confidence_k{3,7}.png` |
| `models/dataset_v2_revalidation_20261111/` | Four model directories with `artifact_sha256.json` |
| `SHA256SUMS` | This directory and the model directory |

## 10. Limitations

- **[L] Synthetic lab traffic.** Labels are generation intent; there is no real-attacker data, and these results do not show zero-day detection ability.
- **[L] Unchanged hyperparameters, as instructed.** A different architecture, imputation or population might behave differently. Not tested, to avoid tuning on validation.
- **[L] The K rule is dominated by the failed-login block.** Its silhouette and stability criteria are driven by it, so K = 7 is a defensible application of a pre-stated rule, not evidence of 7 behaviour groups.
- **[L] Grouping.** Session rows from one interaction are not independent. ARI CIs therefore bootstrap interactions, and the logged-in analysis uses one row per interaction. Internal metrics (silhouette and others) are row-level by definition.
- **[L] DEC did not converge** in any run, so its final state depends on the iteration cap.

## 11. Open points for the next decision (not acted on)

1. **Should novelty detection use these clusters?** With these features they encode login outcome and activity volume. Options needing approval:
   - **(a)** Model logged-in sessions separately. This conflicts with keeping `login_success` as an input, since it would be constant.
   - **(b)** Use interaction-level aggregation.
   - **(c)** Treat clusters as activity-level context only, and score novelty by reconstruction error or distance.
2. **The imputation choice.** Training medians make every failed login one identical point. This is inherent to the approved procedure and is the main driver of the all-row metrics.
