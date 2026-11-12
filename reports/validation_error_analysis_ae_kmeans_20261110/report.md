# Validation error analysis: Autoencoder + K-Means (15 features)

Date: 2026-11-10. Scope: the 270 validation sessions only. The 270 test sessions were not loaded.
No model was trained, refitted or saved. Produced by `ml_pipeline/04_validation_error_analysis.py`;
numbers are in `summary.json` in this folder.

## 1. Is the per-session analysis supported?

No. The 15-feature Autoencoder + K-Means model exists only as the DEC initialisation inside
`ml_pipeline/dec15.py::train_dec`, and these were not saved:

- the pre-DEC encoder weights (DEC refinement overwrites the encoder);
- the K-Means centres fitted on the pre-DEC latent space;
- per-session validation assignments and embeddings;
- any confidence measure (K-Means gives hard assignments, and none was defined).

What was saved is aggregate only, in `models/dec_15_feature_v1/metrics_validation.json` and
`models/dec_15_feature_v2_deterministic/metrics_validation.json` (identical values):

- clusters 119 / 110 / 41;
- input-space Silhouette 0.415, Davies–Bouldin 1.133;
- latent-space Silhouette 0.508 (not comparable with the input-space figures);
- ARI 0.154 and NMI 0.295 against the generator categories.

The older encoders under `model_selection/` don't apply:

- `cowrie_encoder.keras` takes 17 inputs, including `ct_*`, has a 2-d latent space, and was trained on all 1,800 rows;
- `dec_artifacts/*` and `checkpoints/kmeans_best.pkl` take 24 UNSW-NB15 inputs.

These analyses are therefore **unsupported** for Autoencoder + K-Means: per-cluster profiles,
representative sessions, boundary and ambiguous sessions, per-cluster overlap, and session-level
agreement with DEC or with the generator categories. No confidence score was invented and no
assignments were reconstructed.

To support them, the deterministic training could be rerun once, without changing anything, into a
new folder that also saves the pre-DEC encoder, the K-Means model and the validation assignments. Training is now
bit-reproducible, so the rerun can be checked against the recorded aggregates (Silhouette
0.4146488308906555, clusters 119/110/41). That is retraining and needs approval.

## 2. Findings that hold whatever the model (validation data, saved preprocessing)

**No-command group.** 119 of 270 validation sessions send no client data: `spkts`, `sbytes`,
`sload` and `ackdat` are all 0 in exactly the same rows. Autoencoder + K-Means, K-Means and DEC
each have one validation cluster of exactly 119, and for DEC v2 that cluster is exactly this group.
For Autoencoder + K-Means the matching size is consistent with the same group, but this can't be
verified per session. The group contains all of `brute_force_only` (33) and all of
`zero_day_buffer_overflow` (33), plus 19–40% of every other category (53 sessions). Within the
15 features those 53 sessions look like failed logins, so no model using these inputs can separate
them by category.

**Generator / extractor artefact: buffer overflow.** `scripts/generate_dataset.py` gives
`zero_day_buffer_overflow` a `failed_cmd_rate` of 1.0, so its NOP-slide payload is written only as
`cowrie.command.failed`. `scripts/extract_features.py` counts `spkts` and `sbytes` only from
`cowrie.command.input`, so the payload never reaches the 15 features (100% of these sessions have
`spkts` = 0 in both train and validation). The category is distinguishable from failed logins only
through server-side side effects: median `dpkts` 6 vs 4, and `dbytes` 58 vs 0. This "zero-day"
category is therefore not represented by its attack content.

**Redundant inputs.** `synack` / `tcprtt` = 0.45 exactly on every validation row, so one timing
signal is counted twice. This was already noted in EDA.

**Residual fingerprint check.** For each input, I looked up the exact validation value among the
training values and checked whether it belongs to a single generator category. The best single
feature (`dbytes`) names the right category for only 12.6% of validation sessions; `sbytes` gives
11.9% and `dur` 7.8%, and all others are 4% or less. This shows no fingerprint comparable to the
removed `ct_*` features.

**Outliers.** 7 validation sessions have an input more than 3 training SDs from the training mean,
and 3 exceed 4 SDs. All are `privilege_escalation` (4) or `reconnaissance` (3). The largest are:

| Session | Category | Max \|z\| | Input | Value | Training median |
|---|---|---|---|---|---|
| d1326edfd88e | privilege_escalation | 4.71 | `dpkts` | 9 | 5 |
| 336ce1f7947e | privilege_escalation | 4.06 | `sjit` | 2.92 | 0 |
| 14369b7c6cbf | privilege_escalation | 4.06 | `sjit` | 2.92 | 0 |
| 01665a597ddc | reconnaissance | 3.77 | `sjit` | 2.59 | 0 |

These are long multi-command sessions, not data errors. They are the sessions most likely to sit
far from any cluster centre.

## 3. DEC v2 (research comparison only; saved outputs, inference only)

- **Clusters:** 119 / 97 / 54. Cluster 0 is exactly the no-command group.
- **Per-session input-space Silhouette:** 11 sessions are negative and 28 are below 0.1. Cluster means are 0.556 (no-command), 0.304 and 0.217.
- **Ambiguity:** 10 sessions have confidence below 0.7, and 5 have a gap below 0.2 between the top two probabilities.
- **Negative-Silhouette sessions by category:** `privilege_escalation` 4, `zero_day_covert_tunnel` 4, `reconnaissance` 2, `evasion_anti_forensics` 1.
- **Generator categories (generator labels, not independent ground truth):**
  - The command-sending sessions split into one group: botnet, evasion and obfuscated-memory (cluster 1).
  - A second group holds privilege-escalation and reconnaissance (cluster 2).
  - `zero_day_covert_tunnel` is spread over all three clusters (9 / 12 / 8).

None of this describes Autoencoder + K-Means at the session level.

## 4. Limitations

- There are no per-session results for the provisional primary model.
- The generator categories are synthetic profile labels, not ground truth. ARI and NMI are descriptive only.
- The data is fully synthetic (1,800 sessions). Nothing here measures real-world detection.
- The outlier threshold (3 SDs) and the lookup check are heuristics.

## Figures

- `13_no_command_share_by_category.png`: share of each category's validation sessions with `spkts` = 0.
- `13_input_outliers.png`: distribution of the largest |z| per validation session.
- `13_exact_value_lookup.png`: the residual-fingerprint lookup per input.
