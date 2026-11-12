# ML Pipeline: controlled DEC retraining with 15 features

Task: retrain the DEC clustering model without `ct_srv_src` and `ct_src_ltm` (17 -> 15 inputs),
same architecture and hyperparameters, on the original 1,800 synthetic sessions
(`model_selection/behavior_features.csv`, SHA-256 d8d50b6a...df245148, read only).

Design chosen by the user (2026-11-08): follow the full pipeline (no override); train the 15-feature
model only (no fresh 17-feature control). Consequence: any comparison with the existing 17-feature
model mixes the feature change with random-state differences, because the original training ran a
30-configuration grid search after seeding and before the final model, and did not enable
TensorFlow determinism.

## Status

| Step | Status | Result |
|---|---|---|
| 1. Data inspection | done | 1,800 x 29; no missing values; no duplicate rows, session IDs or 15-feature vectors; 7 constant columns; `attack_cat` 8 classes (10.7%-14.7%); `label` flagged by name |
| 2. EDA | done | 7 figures; no missing values; 6 retained-input pairs correlate > 0.95 (synack = 0.45 x tcprtt exactly); ct leakage confirmed visually |
| 3. Problem definition | done | contract below; awaiting Gate A |
| Gate A | approved-gate | approved 2026-11-08 with a stratified 70/15/15 split |
| 4. Data cleaning | done | 6 rules (missing, inf, negatives in log/other inputs, duplicate IDs, duplicate vectors): 0 hits; data unchanged |
| 5. Data engineering | done | one row per session: session_id, 15 inputs, attack_cat (reference) |
| 6. Split | done | guard.split stratified on attack_cat, seed 42: train 1,260 / validation 270 / test 270; shares within 0.2%; test frozen (fingerprint fce7678e...) |
| 7. Feature engineering | done | none by design (controlled experiment) |
| 8. Preprocessing | done | medians + log1p + StandardScaler fitted on train only; saved to ml_pipeline/work/preprocess; applied through the existing inference `preprocess()` (verified identical to the fit-time transform) |
| Gate B | approved-gate | approved 2026-11-08 with the neural-net-small-data override |
| 9. Baseline | done | K-Means K=3 on 15 inputs: validation Silhouette 0.403 (input space), DB 1.178; AE+K-Means (DEC start): 0.415 / 1.133 |
| 10. Training | done | DEC 15-feature trained on 1,260 rows in 15.0 s; AE MSE 1.011 -> 0.238 (held-back 10%: 0.229; corrected 2026-11-08 from a misreported 0.271/0.255, see training_metadata.json); DEC hit the 500-iteration limit without converging (label change 0.16% at 400/450); saved to models/dec_15_feature_v1/. Revisited 2026-11-08: deterministic rerun (single-threaded K-Means), two same-seed runs bit-identical; saved to models/dec_15_feature_v2_deterministic/ |
| 11. Tuning | done | none by design (controlled experiment) |
| 12. Evaluation | done | validation: DEC Silhouette 0.398 input space (does not beat either baseline), 0.880 latent space; DB 1.246; clusters 119/97/54; confidence mean 0.902 (min 0.481); ARI 0.181 vs attack_cat (descriptive). v2 deterministic: identical validation assignments and metrics to v1 (probabilities within 6.1e-4) |
| Gate C | not approved | user chose to stop after step 12 (2026-11-08); deterministic v2 run added at the user's request; test set untouched |
| 13. Error analysis | todo | |
| 14. Final test | todo | |
| 15. Deployment | todo | only if the user asks |
| 16. Monitoring plan | todo | |
| Gate D | todo | |

## Step 1 notes
- Profile: `ml_pipeline/data_profile.json` (target set to `attack_cat` as a reference column only;
  DEC is unsupervised and never reads it).
- Constant columns: proto, service, sttl, dttl, ct_state_ttl, ct_dst_ltm, ct_srv_dst (already
  excluded from the 17-feature model).
- Manual leakage finding (not detected by the guard): `ct_srv_src` = `ct_src_ltm` = number of
  sessions per synthetic `src_ip`; each value maps to one IP and partly to one profile (values 193,
  217, 229 are each a single `zero_day_*` category). This is the reason for removing them.
- `src_ip` is drawn from profile-specific pools (1-4 IPs per category); it is not a model input.
- `label` is derived from `attack_cat` (0 = reconnaissance, 1 = all others); never a model input.

## Environment notes
- matplotlib 3.11.2 installed into `ml/cowrie_dec_integration_skeleton/.venv-dec-smoke` on
  2026-11-08 with user approval (7 packages added, none upgraded). marimo is not installed, so the
  workbenches are cell-based Python scripts (`# %%` cells) rather than marimo notebooks.
- A `pip --dry-run` query to PyPI was made before approval (index read only, nothing installed).

## Step 3: problem contract (proposed, pending Gate A)
- Problem: unsupervised behavioural clustering of SSH sessions. There is no prediction target.
- Prediction unit / population: one session; the 1,800 synthetic sessions from
  `scripts/generate_dataset.py` (`model_selection/behavior_features.csv`).
- Inputs available at inference: the 15 session-level features
  `dur, spkts, dpkts, sbytes, dbytes, rate, sload, dload, sinpkt, dinpkt, sjit, djit, tcprtt,
  synack, ackdat`, in this order, each computed from the session's own events. Excluded:
  `ct_srv_src`, `ct_src_ltm` (cross-session counts; leak profile/IP and collection size) and every
  other column (identifiers, constants, `attack_cat`, `label`).
- Objective: measure the effect of removing the two features under the existing architecture and
  hyperparameters (log1p + StandardScaler; 32-16-4 autoencoder; K = 3; same optimiser, epochs,
  batch size, DEC schedule, seed 42), without tuning.
- Metrics (all computed on sessions the model was not fitted on):
  - internal cluster quality in the 4-d latent space: Silhouette (primary, as in the original
    tuning), Davies-Bouldin, Calinski-Harabasz; occupied clusters; mean confidence;
  - reproducibility (identical inputs) and batch-size stability (assignments exact,
    probabilities within a tolerance justified from measured variation);
  - descriptive only: ARI/NMI and a contingency table against `attack_cat` (the synthetic
    generator's profile, known exactly for this data); never used to choose anything.
- Constraints: K and latent size fixed; no hyperparameter search (step 11 is "none by design");
  `train_v1`/`eval_v1`/`*_v2_corrected` not used; existing 17-feature artifacts untouched; new
  artifacts in `models/dec_15_feature_v1/`.
- Not claimed: real-world attack-detection accuracy or generalisation to live Cowrie traffic.
- Split (decision at Gate A): stratified on `attack_cat`, train / validation / test, via
  `guard.split`. No datetime column; `src_ip` is not used as a group because each `zero_day_*`
  category has a single IP, so a group split would remove whole categories from training.

## Gate B: model rationale (proposed)

Model rationale:
- traits: unsupervised clustering (no target; attack_cat is a reference with 8 classes, minority 10.7%), 1,800 rows (small; train 1,260), no datetime, no groups used, inputs heavily zero-inflated, 6 near-duplicate input pairs
- baseline: K-Means (K=3, n_init=20, seed 42) on the 15 scaled inputs; plus the autoencoder + K-Means initialisation that DEC starts from (no DEC refinement)
- candidates: DEC only, by design: existing architecture with a 15-d input (15-32-16-4 encoder, 4-16-32-15 decoder), K=3, alpha 1, Adam lr 0.001, 20 autoencoder epochs, batch 256, validation_split 0.1, K-Means n_init 20 init, up to 500 DEC iterations, target update every 50, tol 0.001, seed 42 with TensorFlow determinism
- ruled out: hyperparameter search (would confound the feature-removal comparison); other clustering families (already compared in the nine-model study); supervised models (no target); gradient boosting/linear (supervised)
- metric: Silhouette in the 4-d latent space on validation (primary, as in the original tuning); Silhouette in the shared 15-d scaled input space (comparable across baseline and DEC); Davies-Bouldin; Calinski-Harabasz; occupied clusters; confidence; reproducibility and batch-size stability; ARI/NMI vs attack_cat descriptive only

Known risk (playbook red flag `neural-net-small-data`): DEC is a neural network trained on 1,260 rows. It is kept because the experiment's purpose is to change only the input features of the existing model; the baseline will show whether DEC adds anything over K-Means.

## Gate log
- Figure 01_missingness.png: No column has missing values.
- Figure 02_target_balance.png: attack_cat=reconnaissance is 14.7% of 1,800 rows, so a majority-class dummy scores 14.7%; the minority share is 10.7%.
- Figure 02_distributions.png: Histograms of 12 numeric features; 7 are strongly skewed (dur, spkts, dbytes, rate, sload), which matters for scaling and outliers.
- Figure 02_correlations.png: Strongest correlation with attack_cat: dbytes (0.52); anything above 0.95 is a leakage suspect.
- Figure 02_model_space_features.png: The 15 retained inputs after the model's log1p step. Most remaining skewed: sjit (|skew| 2.4), spkts (1.3); several features have spikes at 0 (sessions with no commands), consistent with the existing model placing all no-command sessions in one cluster.
- Figure 02_ct_by_category.png: ct_src_ltm takes 13 values, each from exactly 1 source IP; 9 of the 13 values belong to a single category (e.g. each zero_day_* category has its own value), so the feature partly encodes the generator profile. In the Cowrie deployment it equals the log size instead.
- Figure 02_input_redundancy.png: 6 pairs of retained inputs correlate above 0.95: dur/dinpkt (0.98), dur/djit (0.98), dbytes/dload (0.95), rate/dload (0.99), dinpkt/djit (0.99), tcprtt/synack (1.00). synack/tcprtt ratio is 0.450-0.450 (synack is derived from tcprtt), so these inputs double-count information; kept unchanged in this controlled experiment.
- Gate A: approved 2026-11-08
- Gate A decision: stratified 70/15/15 train/validation/test split on attack_cat (user choice); contract in 'Step 3' approved as written.
- Git checkpoint for Gate A skipped: the task forbids commits (user restriction overrides the skill's commit/tag step).
- Figure 04_cleaning_checks.png: Every cleaning rule found nothing to fix in 1,800 rows, so the data is used unchanged: no rows dropped, no values imputed, and the original training's clip-at-0 before log1p is a no-op.
- Figure 06_split_balance.png: Stratified split: 1260 / 270 / 270 sessions with every category's share within 0.2% across splits, so validation and test represent the same mix as training.
- Figure 08_scaled_inputs_train_vs_val.png: The 15 inputs after log1p and the train-fitted scaler: training has mean 0 / sd 1 per feature and validation, transformed with the same fitted objects, stays close (largest validation mean 0.05 sd), so the scaler did not see validation or test data.
- Gate B: approved 2026-11-08
- Override: red flag neural-net-small-data - user approved training the existing DEC architecture on 1,260 rows 2026-11-08 - reason: controlled experiment that changes only the input features of the existing model; K-Means baselines reported alongside
- Git checkpoint for Gate B skipped: the task forbids commits.
- Figure 10_training_curves.png: Autoencoder MSE fell from 1.011 to 0.238 (held-back 10%: 0.229); DEC ran 500 iterations (stopped at the 500-iteration limit), KL loss 0.0921 -> 0.0622. A second run with the same seed gave different weights.
- Figure 12_validation_metrics.png: On the 270 validation sessions, measured in the same 15-feature space: Silhouette K-Means 0.403, AE+K-Means 0.415, DEC 0.398; Davies-Bouldin 1.178 / 1.133 / 1.246. DEC's latent-space Silhouette is 0.880; latent and input scores are not comparable with each other.
- Figure 12_cluster_composition.png: How the 270 validation sessions' generator categories fall into the 3 DEC clusters (ARI 0.181, NMI 0.322); with 8 categories and 3 clusters some categories must share a cluster. Descriptive only.
- Figure 12_confidence_old_vs_new.png: Confidence on all 1,800 sessions: old mean 0.939 (min 0.446), new mean 0.910 (min 0.473). The new model was fitted on 1,260 of these rows and the old on all 1,800, so this mixes the feature change with training-set and random-seed differences.
- Figure 12_old_vs_new_alignment.png: Cluster IDs are arbitrary, so new clusters were matched to old ones by the best one-to-one pairing {1: 0, 2: 1, 0: 2}; after matching, 72.6% of all sessions (and 71.1% of validation sessions) get the same cluster from both models.

## Steps 9-12 notes
- Baselines are judged in the shared 15-d scaled input space; DEC's latent-space scores are reported separately and are not comparable with input-space scores.
- Result to report plainly: on validation, DEC (Silhouette 0.398, DB 1.246) does not improve on K-Means on the inputs (0.403, 1.178) or on its own autoencoder + K-Means start (0.415, 1.133). Its latent Silhouette (0.880) reflects the space DEC optimises.
- Integrity: weights, scaler and inputs finite; latent dim 4; 3 outputs; probabilities sum to 1 within 1.2e-7; repeated inference bit-identical; batch sizes 1-256 change probabilities by at most 3.6e-7 with identical assignments (smallest top-1/top-2 gap 0.019).
- Reload: the saved folder loads through the unchanged `CowrieDEC(model_dir)`; predictions are bit-identical at the same batch size. The `false` in metrics_validation.json came from comparing batch sizes 32 and 256 (see models/dec_15_feature_v1/verification_addendum.json).
- Training reproducibility: not bit-reproducible with default threading (scikit-learn KMeans centres differ by 2.4e-7 between runs; DEC amplifies to 1e-4-4e-4 in weights) but a repeat pair gave 100% identical assignments. Single-threaded KMeans (threadpoolctl limit 1) makes training bit-identical; not applied to the saved model yet (Gate C decision).
- Old 17-feature vs new 15-feature on all 1,800 sessions (descriptive; the new model was fitted on 1,260 of them, the old on all 1,800 with a different random state): clusters old 485/694/621, new 783/630/387; best one-to-one matching new->old {1:0, 2:1, 0:2}; 72.6% same cluster after matching (71.1% on validation rows); old cluster 2 (621, no-command sessions) maps entirely to new cluster 0; confidence mean 0.939 -> 0.910; ARI vs attack_cat 0.160 -> 0.196.
- Dependence on collection-specific features: setting ct_srv_src = ct_src_ltm = 3125 on the 1,800 sessions changes 73.1% of the old model's assignments and none of the new model's probabilities (the new model does not read them).
- Environment: joblib printed a traceback while counting physical CPU cores (`wmic` unavailable); it fell back to the logical count and K-Means ran normally.
- Gate C: not yet approved - user chose to stop after step 12 on 2026-11-08; steps 13-16 open; test split untouched (test_touches 0).
- Open decision for resuming: score the current model, or retrain once with single-threaded K-Means (bit-reproducible) into a new folder first.
- Figure 10_v2_deterministic_training_curves.png: Deterministic run (single-threaded K-Means): autoencoder MSE 1.011 -> 0.238; DEC ran 500 iterations (stopped at the 500-iteration limit), last check 0.16% of training labels changing vs the 0.1% tolerance. A second same-seed run gave identical weights.
- Figure 12_v2_deterministic_validation_metrics.png: Same 270 validation sessions, same 15-feature input space: Silhouette K-Means 0.403, AE+K-Means 0.415, DEC v1 0.398, DEC v2 0.398; Davies-Bouldin 1.178 / 1.133 / 1.246 / 1.246. Latent-space scores are reported separately and are not comparable with these.
- Figure 12_v2_vs_v1_alignment.png: v2 cluster IDs matched to v1 by the best one-to-one pairing {0: 0, 1: 1, 2: 2}; after matching, 100.0% of validation and 100.0% of training sessions get the same cluster. The two models differ only in K-Means threading.

## Deterministic rerun (2026-11-08, before Gate C, user request)
- Script: ml_pipeline/03b_model_deterministic.py; output models/dec_15_feature_v2_deterministic/ (v1 untouched). Only change: K-Means (DEC initialisation and the K-Means baseline) runs under threadpoolctl.threadpool_limits(limits=1); scikit-learn 1.9 KMeans has no n_jobs parameter. dec15.train_dec gained an opt-in kmeans_single_thread flag (default keeps v1 behaviour).
- Same split IDs (asserted against v1), same stored preprocessing (two train-only refits identical to each other and to the stored scaler/medians), same hyperparameters and seed 42.
- Reproducibility: two same-seed runs bit-identical in every weight layer, K-Means initial centres and labels, final centroids, soft and hard assignments on train + validation, AE and DEC loss curves and label-change checks. Repeated K-Means baseline fits identical.
- Convergence: still not converged; 500/500 iterations, label change 0.16% (2 of 1,260 training sessions) at iterations 400 and 450 vs 0.1% tolerance; KL 0.0921 -> 0.0622.
- Validation (270): clusters 119/97/54; confidence mean 0.902, median 0.914, min 0.481, 3.7% below 0.7; input-space Silhouette 0.398, DB 1.246 (same as v1); latent Silhouette 0.880 (not comparable). Baselines unchanged: K-Means 0.403 / 1.178, AE+K-Means 0.415 / 1.133.
- Validation bootstrap (1,000 resamples, diagnostic, scratchpad only): DEC v2 minus K-Means Silhouette 95% interval -0.023 to +0.012 (no clear difference); Davies-Bouldin -0.019 to +0.157, K-Means better in 93% of resamples. AE+K-Means not bootstrapped (its pre-DEC encoder is not saved).
- Recommendation given to the user: B (AE+K-Means primary, DEC kept as a research comparison), pending their decision. Test split still untouched (test_touches 0).

## Step 13: validation error analysis (2026-11-10, Gate C model choice: option B, AE+K-Means provisional primary)
- Gate C decision recorded as a model choice only; the final test (step 14) is not approved and test_touches stays 0.
- Script ml_pipeline/04_validation_error_analysis.py; output reports/validation_error_analysis_ae_kmeans_20261110/ (report.md, summary.json, 3 figures). Read-only: no fitting, no saved-model changes, test split not loaded.
- Blocked: the 15-feature AE+K-Means model has no saved pre-DEC encoder, K-Means centres, per-session assignments or confidence; only aggregate metrics exist. Per-session AE+K-Means analysis needs an approved deterministic rerun that saves them.
- Model-independent findings: 119/270 validation sessions send no client data (all brute_force_only and zero_day_buffer_overflow plus 19-40% of other categories); zero_day_buffer_overflow payloads are logged as cowrie.command.failed, which the extractor does not count in spkts/sbytes (generator/extractor artefact); synack = 0.45 x tcprtt; exact-value lookup shows no strong residual fingerprint (best 12.6%); 7 sessions beyond 3 SD.

## Dataset V2 (Cowrie telemetry) revalidation - Task 17 (2026-11-11)
- New data, separate from the synthetic 1,800-session experiment above: Dataset V2 train (3,190 sessions / 1,500 interactions) and validation (1,257 / 600) from reports/dataset_v2_training_validation_20261110/ (Task 14B). Steps 1-8 for this data were done as user-approved Tasks 14B (generation, integrity), 15 (L1-L7 leakage audit) and 16 (frozen 8-feature input set, configs/model_features_v2_frozen.json); spec revision 2.0.0-draft.4 written as configs/feature_spec_v2_draft4.json.
- Task 17 (user instruction, 2026-11-11): revalidate AE+K-Means and DEC with the existing architecture/hyperparameters (dec15.HYPERPARAMETERS), all sessions, train-only median imputation + log1p + StandardScaler, no missingness indicators, cluster count from a small training-only range. Labels post hoc only. Sealed test set not accessed. Not a zero-day detection evaluation.
- Script reports/dataset_v2_model_revalidation_20261111/revalidate_v2.py; models in models/dataset_v2_revalidation_20261111/ (new directory; no existing model overwritten). Results and status are recorded in that report; this file records no new gate approval.
