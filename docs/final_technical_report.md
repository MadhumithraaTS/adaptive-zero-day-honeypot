# AI-Driven Adaptive Honeypot Platform for Zero-Day Attack Intelligence and Automated Defense

## Final Technical Report

**Repository:** `adaptive-zero-day-honeypot`
**Report basis:** repository state on 2026-10-19 (latest commit `babdd19`, plus the uncommitted work listed in Section 1.6).

### How to read this report

Statements are labelled where the distinction matters:

- **Measured**: a value read from a file in the repository. [`docs/report_evidence_map.md`](report_evidence_map.md) gives the source of each one.
- **Interpretation**: the authors' reading of measured results. It is not separately verified.
- **Planned**: described in the project plan (`README.md`) but not implemented.
- **Limitation**: a known weakness of the current implementation or evaluation.

No result in this report comes from outside the repository. Where the repository doesn't contain the evidence for a claim, the report says so.

---

## Chapter 1: Introduction

### 1.1 Problem statement

Signature-based intrusion detection relies on patterns that are only written after an attack has been analysed. A zero-day exploit has no such pattern at its first occurrence, so it can pass undetected until analysts catch up. The project's problem statement (`README.md`) asks:

> How can we design an adaptive honeypot-driven intelligence platform that captures previously unseen attacker interactions during active exploitation, models behavioral patterns instead of relying on predefined signatures, and automatically generates deployable detection rules in real time?

### 1.2 Honeypot-based monitoring and zero-day intelligence

A honeypot is a decoy service with no legitimate users, so every interaction with it is unsolicited and worth recording. A medium-interaction SSH honeypot such as Cowrie records login attempts, the commands an attacker types, file downloads and session timing. This project uses that behavioural record instead of known exploit signatures. The aim is to group sessions by behaviour, describe each group as a behavioural signature, and check whether a new session resembles any known signature.

"Zero-day intelligence" in this report means evidence that a session's behaviour does not match the stored signatures. It does **not** mean a confirmed zero-day exploit. Section 6.8 and Chapter 9 discuss the gap between the two.

### 1.3 Objectives

From `README.md`, the project set out to:

1. Deploy an SSH honeypot and capture structured attacker interactions.
2. Extract behavioural features from attack sessions.
3. Apply unsupervised clustering to group attack behaviour without labels.
4. Generate behavioural signatures and assess whether new sessions are novel.
5. Generate deployable IDS/firewall rules automatically (automated defence).
6. Share intelligence across nodes and provide an analyst dashboard (Phase 3).

### 1.4 Scope of the delivered system

| Objective | Status |
|---|---|
| 1. Honeypot deployment and capture | Implemented (Cowrie in Docker, SSH on host port 2223) |
| 2. Behavioural feature extraction | Implemented (24 UNSW-NB15-style features per session) |
| 3. Unsupervised clustering | Implemented (nine models compared; DEC integrated) |
| 4. Signatures and novelty assessment | Implemented (3-signature catalogue; heuristic novelty assessment) |
| 5. Automated defence | **Not implemented** (Chapter 8) |
| 6. Intelligence sharing, dashboard, central database, APIs | **Not implemented** (planned in `README.md`) |

### 1.5 Contributions

**Measured / implemented:**

- A reproducible pipeline: Cowrie session generation, log collection, parsing, feature extraction, then DEC inference with saved artifacts (`scripts/pipeline.py`).
- A comparison of nine clustering models on UNSW-NB15, and a tuned DEC model for Cowrie-style behaviour (Chapter 4).
- A behaviour-signature catalogue built only from reference sessions, plus a novelty assessment that reports whether the assessed sessions overlap the catalogue's source sessions (Chapter 2, Chapter 6).
- A controlled fresh-data evaluation on five verified-new sessions (Chapter 6).
- A regression suite of 130 tests, including numerical-reproducibility tests for DEC inference (Chapter 7).

### 1.6 Limitations summary

- The deployed DEC model was trained on **1,800 synthetic sessions**. It was not trained on UNSW-NB15 or on live Cowrie traffic (Chapter 3).
- No ground-truth labels exist for live Cowrie sessions, so no detection accuracy, TPR, FPR, precision or recall is reported.
- The fresh-data evaluation used one attack profile, and all five sessions were Known-like. **Detection of unfamiliar or zero-day attacks has not been demonstrated.**
- Automated defence is not implemented.
- Repository status: several components are **uncommitted**. These are the novelty-assessment, signature-generation and behaviour-analysis scripts, `scripts/prepare_fresh_evaluation.py`, the `tests/` directory, and the reliability changes to the pipeline scripts. They exist only in the working tree. Section 9.4 recommends committing them.

---

## Chapter 2: System Architecture

### 2.1 Planned versus implemented architecture

`README.md` describes a six-layer "Behavior-to-Defense" pipeline:

1. honeypot;
2. central storage in MongoDB;
3. machine-learning analysis;
4. signature and rule generation;
5. security enforcement (IDS/IPS/firewall);
6. an analyst dashboard.

It also lists REST endpoints (`/api/ingest`, `/api/analyze`, `/api/rules`).

The implemented system is a file-based batch pipeline:

```
Cowrie container (SSH, host port 2223 -> container 2222)        [implemented]
        |  docker cp of var/log/cowrie/cowrie.json
        v
scripts/collect_logs.py      -> raw/cowrie.json                   [implemented]
scripts/parse_logs.py        -> parsed/sessions.json              [implemented]
scripts/extract_features.py  -> parsed/behavior_features.csv      [implemented]
                                parsed/session_details.json
        v
run_dec_evaluation.py (saved DEC artifacts, separate interpreter) [implemented]
        -> processed/dec_results.csv
        v
behaviour analysis + signature generation (reference sessions)    [implemented]
        -> behaviour_signatures.json
        v
scripts/novelty_assessment.py -> novelty results and report       [implemented]
        v
automated defence / rule enforcement                              [NOT implemented]
dashboard, MongoDB, REST APIs, Social-IoT sharing                 [NOT implemented]
```

No MongoDB, Flask/FastAPI, REST endpoint or dashboard code exists in the repository. A search for these names in Python, YAML and requirements files finds nothing.

### 2.2 Cowrie honeypot

- **Deployment** (`cowrie/docker-compose.yml`): image `cowrie/cowrie:latest`, container `cowrie-project`, port mapping `2223:2222`. Only the SSH port is exposed. `README.md` mentions SSH/Telnet, but no Telnet port is mapped in this deployment.
- **Docker network:** `cowrie_default`, subnet `172.19.0.0/16`, gateway `172.19.0.1`. On Docker Desktop for Windows, every recorded session appears to come from the gateway address `172.19.0.1` (75 sessions checked across the baseline, demo and fresh-run snapshots).
- **Log storage:** inside the container, on a Docker volume mounted at `/cowrie/cowrie-git/var`. Cowrie rotates its log daily, and `collect_logs.py` copies only the current `cowrie.json`. Rotated files are not collected.

### 2.3 Log collection and session parsing

- **`scripts/collect_logs.py`** copies the log with `docker cp`. It exits 1 if the copy fails or the resulting file is missing or empty. On Windows it reports Docker's own error; the `sudo -n` fallback is used only on POSIX systems.
- **`scripts/parse_logs.py`** groups JSON events by their `session` field. It exits 1 on a missing input, malformed JSON, a non-object line, a non-string session ID or zero sessions. Output is written atomically, so a failed run never replaces a previous output.

### 2.4 Feature extraction

`scripts/extract_features.py` converts each session's events into 24 features named after the UNSW-NB15 flow features. It also writes `session_details.json` (commands, authentication success, endpoints, features). Its outputs are validated (exact 29-column header, matching session IDs) and written atomically.

**Limitation.** The features are derived from Cowrie application events, not packet captures, so several are approximations:

- `synack` is computed as a fixed fraction of `tcprtt` (`extract_features.py`, audit item D5), so the two carry the same information.
- `ct_srv_src` and `ct_src_ltm` count sessions per source IP within the processed log, so their values depend on how many sessions the log contains (audit item D4).

### 2.5 DEC clustering

DEC inference (`ml/cowrie_dec_integration_skeleton/`) loads four saved artifacts and assigns each session to one of three clusters, with a confidence score. Chapter 5 describes it.

### 2.6 Behaviour-signature catalogue and novelty assessment

- **`scripts/behaviour_pattern_analysis.py`** summarises each DEC cluster: feature statistics, command categories and authentication rates.
- **`scripts/behaviour_signature_generation.py`** turns each cluster into a signature. A signature holds the cluster's 8 most variable numerical features (mean/median/std/min/max), its command categories, its authentication success rate and its source session IDs.
- **`scripts/novelty_assessment.py`** compares each session with every signature. The score is:

  0.70 × feature similarity + 0.20 × command-category Jaccard + 0.10 × authentication similarity

  Feature similarity is the mean over the signature's features of `1 − min(|x − mean| / std / 3, 1)`. The best match is labelled:
  - `Known-like`: score ≥ 0.70, a margin ≥ 0.05 over the runner-up, and no contradicting evidence.
  - `Ambiguous`: score ≥ 0.60 with a smaller margin.
  - `Potentially Novel`: comparable evidence but no qualifying match.
  - `Insufficient Evidence`: too few comparable features.

  The summary records an `evaluation_mode`, derived by comparing the assessed session IDs with the catalogue's source session IDs: `independent`, `overlapping` or `reference-provenance-unknown`.

**The reference catalogue** (`reports/novelty_assessment/held_out/revised/reference_signatures/behaviour_signatures.json`, generated 2026-10-15) was built from 43 reference sessions. They are 80% of the 54-session baseline, split with seed 42; the other 11 were held out.

| Signature | DEC cluster | Label | Source sessions | Auth success rate | Selected numerical features |
|---|---|---|---|---|---|
| `sig-fb54a34cea2a64b7` | 0 | Command execution | 1 | 100% | 0 |
| `sig-47521826f16efd4b` | 1 | Mixed/Unclassified | 6 | 100% | 8 |
| `sig-861aae17eb99f9be` | 2 | Credential-attack behaviour | 36 | 0% | 6 |

**Limitations:**

- `sig-fb54a34cea2a64b7` comes from a single session and has no numerical features, so no session can match it as Known-like (audit item D2).
- Signatures keep the *most* variable features, which are arguably the least characteristic of a cluster (audit item D6).

### 2.7 Intended position of automated defence

In the planned architecture, automated defence would read the novelty and behaviour outputs and produce rules for an IDS, IPS or firewall. **This layer is not implemented.** Chapter 8 records its status and the design findings.

---

## Chapter 3: Dataset and Preprocessing

### 3.1 Benchmark dataset for model selection: UNSW-NB15

- **Files:** `model_selection/UNSW_NB15_training-set.csv` (82,332 records) and `UNSW_NB15_testing-set.csv` (175,341 records).
- **Selected features** (24; notebooks `USNW-NB15.ipynb`, `dl_models.ipynb`, `dl_tuned.ipynb`): `dur, proto, service, spkts, dpkts, sbytes, dbytes, rate, sttl, dttl, sload, dload, sinpkt, dinpkt, sjit, djit, tcprtt, synack, ackdat, ct_srv_src, ct_state_ttl, ct_dst_ltm, ct_src_ltm, ct_srv_dst`.
- **Preprocessing:**
  1. `LabelEncoder` on `proto` and `service`.
  2. ±inf replaced with NaN.
  3. Median imputation.
  4. `StandardScaler`.

  For the deep-learning tuning, a 20,000-row tuning subset (seed 42) was drawn from the 82,332 training records.
- **Evidence gap:** the notebooks don't record why these 24 features were chosen.

### 3.2 Synthetic session data used to train the deployed DEC model

The deployed DEC model was **not** trained on UNSW-NB15 or on live Cowrie traffic. It was trained on 1,800 synthetic sessions (`model_selection/behavior_features.csv`) produced by `scripts/generate_dataset.py`, which simulates Cowrie-style sessions from eight behaviour profiles:

| Profile (`attack_cat`) | Sessions |
|---|---|
| reconnaissance | 264 |
| botnet_malware_download | 234 |
| zero_day_obfuscated_memory_attack | 229 |
| evasion_anti_forensics | 228 |
| brute_force_only | 222 |
| zero_day_buffer_overflow | 217 |
| privilege_escalation | 213 |
| zero_day_covert_tunnel | 193 |

The generator assigns `label = 0` to reconnaissance and `label = 1` to every other profile, giving 264 / 1,536. The "zero_day" profiles are synthetic profiles invented for this dataset, not observed zero-day attacks. The source IP addresses in the generator are synthetic values that only populate dataset fields; no traffic is sent to them.

### 3.3 Feature reduction for the Cowrie DEC model

The Cowrie DEC model uses 17 of the 24 features:

`dur, spkts, dpkts, sbytes, dbytes, rate, sload, dload, sinpkt, dinpkt, sjit, djit, tcprtt, synack, ackdat, ct_srv_src, ct_src_ltm`

- **Measured:** the 7 removed features (`proto, service, sttl, dttl, ct_state_ttl, ct_dst_ltm, ct_srv_dst`) each have exactly one distinct value in the 1,800 synthetic sessions, so they carry no information.
- **Evidence gap:** the notebooks don't state this as the reason for removing them.

**Preprocessing chosen by tuning** (`model_selection/cowrie_tuned.ipynb`), applied in this order:

1. Replace ±inf with NaN.
2. Median imputation using the training medians.
3. `log1p` on 13 skewed non-negative features (`dur, sbytes, dbytes, rate, sload, dload, sinpkt, dinpkt, sjit, djit, tcprtt, synack, ackdat`).
4. `StandardScaler`.

### 3.4 Saved preprocessing artifacts and inference compatibility

The artifacts in `ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/artifacts/` are byte-identical to `model_selection/cowrie_dec_model/` (SHA-256 checked):

| File | Content |
|---|---|
| `config.json` | 17 features in order, the 13 log features, `input_dim` 17, `latent_dim` 4, `n_clusters` 3, `alpha` 1.0, architecture 32-16-4 / 16-32-17 |
| `scaler.joblib` | `StandardScaler` fitted on the 1,800 log-transformed sessions; its stored feature names equal the config order |
| `medians.joblib` | training medians for the 17 features |
| `cowrie_dec.weights.h5` | DEC weights |

These artifacts were pickled with pandas 3.0.5 and scikit-learn 1.9.0. The main `.venv` (pandas 2.2, scikit-learn 1.4) can't load them, so DEC runs in `ml/cowrie_dec_integration_skeleton/.venv-dec-smoke/`. The pipeline uses that interpreter by default (Chapter 5).

`scripts/preprocess_dataset.py` fits a separate MinMaxScaler and writes `model_input.csv`. **DEC does not use it.** The pipeline step is labelled "auxiliary" and can be skipped with `--skip-preprocess`.

### 3.5 Differences between benchmark, synthetic training data and live telemetry

| Aspect | UNSW-NB15 | Synthetic training sessions | Live Cowrie sessions |
|---|---|---|---|
| Source | Packet-level network flows | `generate_dataset.py` profiles | Cowrie event log via `extract_features.py` |
| Features | 24 selected | 17 (7 constant columns dropped) | Same 24 computed; 17 used by DEC |
| Labels | Benchmark labels | Profile-derived labels | None (`label = 0` placeholder) |
| Source IPs | Benchmark hosts | Synthetic values | Docker gateway `172.19.0.1` only |

**Measured differences** (audit diagnostics, `reports/diagnostics/dec_novelty_audit_20261019_215356/`):

- Live `tcprtt`/`synack` are about 10× smaller than in the synthetic data, with standardised values down to −4.5.
- `sjit` reaches z = 5.2 and `dpkts` reaches z = 3.5.
- `ct_srv_src`/`ct_src_ltm` were 8 in the 8-session demo, against 63–304 in training.

**Interpretation:** DEC assignments on live traffic should be treated as indicative, because the model is applied outside the distribution it was trained on.

---

## Chapter 4: Nine-Model Comparison and DEC Selection

### 4.1 Models evaluated

The repository holds results for nine unsupervised models, compared in two separate groups on the UNSW-NB15 training set:

| # | Model | Family | Notebook / result file |
|---|---|---|---|
| 1 | K-Means | Classical, centroid | `USNW-NB15.ipynb`; `checkpoints/kmeans_best.pkl` |
| 2 | DBSCAN | Classical, density | `USNW-NB15.ipynb`; `checkpoints/dbscan_best.pkl` |
| 3 | OPTICS | Classical, density | `USNW-NB15.ipynb`; `checkpoints/optics_best.pkl` |
| 4 | Gaussian Mixture | Classical, probabilistic | `USNW-NB15.ipynb`; `checkpoints/gmm_best.pkl` |
| 5 | Agglomerative | Classical, hierarchical | `USNW-NB15.ipynb`; `checkpoints/agglomerative_best.pkl` |
| 6 | Spectral | Classical, graph-based | `USNW-NB15.ipynb`; `checkpoints/spectral_best.pkl` |
| 7 | Autoencoder + K-Means | Deep, two-stage | `dl_tuned.ipynb`; `autoencoder_kmeans_tuning_results.csv` |
| 8 | VAE + GMM | Deep, two-stage probabilistic | `dl_tuned.ipynb`; `VAE_GMM_tuning_results.csv` |
| 9 | DEC (Deep Embedded Clustering) | Deep, joint representation and clustering | `dl_tuned.ipynb`; `DEC_tuning_results.csv` |

**Evidence gap:** the repository doesn't document *why* each model was chosen for evaluation. Read loosely, the set covers the main families of unsupervised clustering: centroid, density, probabilistic, hierarchical, graph-based, and deep representation learning. That reading is the authors' interpretation, not a statement found in the notebooks.

### 4.2 Evaluation metrics

All models were scored with three internal clustering metrics from scikit-learn:

- **Silhouette** (higher is better, range −1 to 1): how much closer points are to their own cluster than to the nearest other cluster.
- **Davies–Bouldin index** (lower is better): the average similarity between each cluster and its most similar cluster.
- **Calinski–Harabasz score** (higher is better): the ratio of between-cluster to within-cluster dispersion.

Training time was also recorded. No external, label-based metric was used for model selection.

### 4.3 Classical models (`USNW-NB15.ipynb`)

**Tuning grids:**

- K-Means, Agglomerative and GMM: k = 2–15.
- DBSCAN: eps ∈ {0.2, 0.4, 0.6, 0.8, 1.0, 1.2} × min_samples ∈ {5, 10, 20}.
- Agglomerative and Spectral used a 5,000-row random sample because of memory limits.

**Measured best configuration per model**, from notebook cell 20:

| Model | Best Silhouette | Best Davies–Bouldin | Best Calinski–Harabasz | Training time (s) | Overall score (lower is better) |
|---|---|---|---|---|---|
| K-Means | 0.4148 | 0.8421 | 15,880.48 | 4.05 | **1.75** |
| Agglomerative | 0.4104 | 0.9030 | 1,089.79 | 1.35 | 2.75 |
| Spectral | 0.5848 | 0.3214 | 284.65 | 1,063.37 | 3.00 |
| Gaussian Mixture | 0.2548 | 2.2788 | 7,494.63 | 23.61 | 3.75 |
| DBSCAN | 0.1139 | 1.6956 | 1,743.85 | 52.87 | 4.25 |
| OPTICS | −0.3361 | 1.3572 | 42.09 | 1,553.39 | 5.50 |

The overall score is the mean of the Silhouette, Davies–Bouldin, Calinski–Harabasz and training-time ranks. Among classical models, K-Means ranks best overall, and Spectral has the best Silhouette and Davies–Bouldin scores but is the second slowest.

### 4.4 Deep models (`dl_tuned.ipynb`)

Procedure:

- The deep models were tuned on the 20,000-row subset.
- Metrics were computed **in each model's latent space**, on a 10,000-point sample.
- Tuning grids:
  - Autoencoder + K-Means: latent ∈ {2, 4, 8} × K = 2–15.
  - VAE + GMM: latent dimension × number of GMM components.
  - DEC: six configurations, latent ∈ {2, 4, 8} × K ∈ {5, 10}, with 20 pre-training epochs and up to 500 DEC iterations.

**Measured DEC tuning results** (`model_selection/DEC_tuning_results.csv`):

| Latent | K | Silhouette | Davies–Bouldin | Calinski–Harabasz | Time (s) | Iterations |
|---|---|---|---|---|---|---|
| 2 | 5 | 0.9162 | 0.3971 | 36,413.12 | 25.05 | 401 |
| 8 | 5 | 0.8249 | 0.4709 | 10,741.95 | 25.91 | 500 |
| 4 | 5 | 0.7851 | 0.4051 | 4,947.87 | 24.84 | 500 |
| 4 | 10 | 0.7770 | 0.5072 | 7,453.31 | 27.38 | 500 |
| 8 | 10 | 0.7387 | 0.4908 | 6,985.92 | 27.14 | 500 |
| 2 | 10 | 0.7083 | 0.5206 | 6,860.60 | 26.34 | 500 |

**Measured final deep-model comparison** (`model_selection/DL_Models_Final_Comparison.csv`):

| Model | Latent | Clusters | Silhouette | Davies–Bouldin | Calinski–Harabasz | Time (s) | Average rank | Final rank |
|---|---|---|---|---|---|---|---|---|
| DEC | 2 | 5 | 0.9162 | 0.3971 | 36,413.12 | 25.05 | 1.00 | 1 |
| Autoencoder + K-Means | 2 | 2 | 0.8695 | 0.7719 | 2,670.65 | 19.96 | 2.33 | 2 |
| VAE + GMM | 4 | 2 | 0.6202 | 0.8788 | 8,032.68 | 20.66 | 2.67 | 3 |

The final rank is the mean of the Silhouette, Davies–Bouldin and Calinski–Harabasz ranks; training time is not included here.

### 4.5 Rationale for selecting DEC

**Documented basis:** DEC ranks first on all three metrics in the deep-model comparison. The repository contains no written rationale beyond these ranking tables.

**Interpretation and limitations:**

- **The two groups were never compared directly.** The deep-model metrics are computed in each model's learned latent space, while the classical metrics are computed in the standardised 24-feature input space. The repository holds no single table ranking all nine models.
- **DEC's high Silhouette (0.916) partly reflects its own objective.** DEC's training sharpens clusters in the latent space where the score is then measured.
- **Only K ∈ {5, 10} was tested** for DEC on UNSW-NB15.

### 4.6 DEC on UNSW-NB15 held-out data

`cowrie_dataset.ipynb` trained DEC (latent 2, K 5) on the full UNSW-NB15 training set and evaluated it on the testing set.

**Measured:**

- Silhouette 0.2238, Davies–Bouldin 1.8441, Calinski–Harabasz 21,209.36.
- Against the benchmark's binary label: ARI 0.0923, NMI 0.1245.
- One training cluster held only 40 of 82,332 records.

**Interpretation:** cluster quality on held-out benchmark data is much lower than the latent-space tuning score, and the clusters align only weakly with the attack/normal label.

### 4.7 Cowrie DEC tuning: latent dimension and cluster count

The deployed model was tuned separately on the 1,800 synthetic sessions (`cowrie_tuned.ipynb`):

- **Grid:** two preprocessing variants (StandardScaler; log1p + StandardScaler) × latent ∈ {2, 4, 8} × K ∈ {3, 4, 5, 6, 8} = 30 configurations, each with 300 tuning iterations.
- **Ranking:** only configurations with at least two occupied clusters were ranked, by the mean of the Silhouette, Davies–Bouldin, Calinski–Harabasz and training-time ranks.

**Measured selected configuration:** log1p + StandardScaler, latent dimension 4, K = 3, 3 occupied clusters:

| Silhouette | Davies–Bouldin | Calinski–Harabasz | Mean confidence | Tuning time (s) | Iterations |
|---|---|---|---|---|---|
| 0.3537 | 1.3830 | 1,090.37 | 0.9329 | 3.81 | 250 |

The selected configuration doesn't have the highest single Silhouette: StandardScaler with latent 2 and K 3 scored 0.3581. It was chosen on the combined rank.

**Final model:** retrained with up to 500 iterations. On the 1,800 sessions it produced clusters of **485 / 694 / 621** sessions with mean confidence **0.9395**. These counts are reproduced exactly by the deployed artifacts (Chapter 7).

**Latent dimension and cluster count:**

- The latent dimension is the size of the encoder's compressed representation. 4 dimensions are enough for 17 inputs while still separating three groups.
- The cluster count K fixes how many behavioural groups DEC forms.

**Interpretation** (measured from the training data, Section 5.5): the three clusters correspond to:

- cluster 0: short, high-rate sessions;
- cluster 1: longer interactive multi-command sessions;
- cluster 2: sessions with no commands (all 222 brute-force-only sessions).

---

## Chapter 5: DEC Integration

### 5.1 Model architecture and latent representation

From `ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/model.py` and `config.json`:

- **Encoder:** 17 → Dense(32, ReLU) → Dense(16, ReLU) → Dense(4, linear) latent.
- **Clustering layer:** Student's t soft assignment (α = 1) to three learned cluster centres in the 4-dimensional latent space:

  q_ij ∝ (1 + ‖z_i − μ_j‖²)^−1, normalised over clusters

- **Decoder:** the 16-32-17 layers were used only for autoencoder pre-training and are not part of inference.

### 5.2 Preprocessing at inference

`preprocessing.py` applies the training pipeline in this order:

1. Select the 17 features in `config.json` order; a missing feature raises an error.
2. Apply saved categorical mappings, if configured; none are used by this model.
3. Treat ±inf as missing.
4. Fill missing values with the saved training medians; an infinity with no saved median raises an error.
5. Coerce to numeric; any remaining non-numeric value raises an error.
6. Apply `log1p` to the 13 log features; a negative value raises an error.
7. Apply the saved `StandardScaler` with `transform` only. Nothing is refitted at inference.

**Limitation:** training clipped negative log-feature values to 0, whereas inference rejects them. Current feature extraction never produces negatives.

### 5.3 Soft assignments and confidence

`run_dec_evaluation.py` outputs, for every input row:

- `dec_cluster`: the argmax of the soft assignment;
- `dec_confidence`: the maximum probability;
- `cluster_0_prob` to `cluster_2_prob`.

`session_id` is read as exact text, so leading zeros and numeric-looking IDs are preserved.

**Interpretation:** confidence is relative to the three clusters. A session far from every cluster can still receive a high value, so confidence is not an out-of-distribution measure.

ARI/NMI are printed only with `--labels-verified` and at least two label classes. Live Cowrie sessions carry a placeholder `label = 0`, so these metrics are omitted for them.

### 5.4 Inference environment

DEC runs in `ml/cowrie_dec_integration_skeleton/.venv-dec-smoke/`, with pandas 3.0.5, scikit-learn 1.9.0 and TensorFlow. `scripts/pipeline.py`:

- uses this interpreter by default and prints it at start-up;
- accepts `--cluster-python` to override it;
- exits with a usage error if the interpreter is missing, rather than falling back to another Python.

### 5.5 Regression evidence and unchanged artifacts

- **Measured:** the deployed artifacts reproduce the training notebook's final cluster counts exactly: 485 / 694 / 621, mean confidence 0.9394905 (Chapter 7).
- **Measured:** on the 54-session live baseline, DEC assigned 1 / 7 / 46 sessions to clusters 0 / 1 / 2. Most baseline sessions were failed logins with no commands.
- The four artifact files kept identical SHA-256 hashes through every remediation, evaluation and test run recorded in `reports/diagnostics/`.

---

## Chapter 6: Fresh-Data Evaluation

Source: `data/evaluation_runs/fresh_20261019_224335/EVALUATION_REPORT.md`, with `verification/verification.json` and `logs/commands.log` in the same folder. The run took place on 2026-10-19 between 17:13:39 and 17:15:45 UTC.

### 6.1 Purpose

The evaluation checked that genuinely new honeypot sessions pass through collection, parsing, feature extraction, DEC inference and novelty assessment. It used the unchanged model and catalogue.

### 6.2 Generation and the profile restriction

- **What ran:** five SSH sessions against the local honeypot (`127.0.0.1:2223`), all as `root`/`admin`, using only the `script_kiddie` profile (`whoami`, `uname -a`, `pwd`, `ls -la`, `cat /etc/passwd`).
- **Why the restriction:** the other two configured profiles, `botnet` and `advanced_persistent_threat`, run `wget`/`curl`. Cowrie performs those downloads for real from inside the container. The restriction kept the evaluation inside the local environment.
- **How:** a filtered copy of the profile file was used. `configs/attack_profiles.json` itself was not changed.
- **Outcome:** the generator started all 5 sessions, with 0 retries and 0 failures.

### 6.3 Collected sessions and new-session checks

- **Snapshot:** the collected log was 77,596 bytes and held **13 sessions**.
- **Excluded:** **8** sessions were already known: the 5-session pipeline run and the 3 demo sessions from earlier that day.
- **Retained:** **5** genuinely new sessions.
- **How "new" was checked:** a session counted as new only if its ID, compared as an exact string, was absent from all of the known sets below. 62 IDs were known in total, and the overlap of the 5 new sessions with each set was 0.

| Known set | Sessions | Overlap |
|---|---|---|
| Original baseline (`git show HEAD:data/parsed/session_details.json`) | 54 | 0 |
| Baseline backup | 54 | 0 |
| Working-tree `data/parsed/session_details.json` | 5 | 0 |
| Demo `data/demo_20261019_213439` | 8 | 0 |
| Previous fresh snapshot `fresh_20261019_210649` | 54 | 0 |
| Reference catalogue source sessions | 43 | 0 |

**Timing and content checks:**

- All five new sessions started after the run's start time (17:13:41.213 UTC).
- Each logged in successfully, ran 6 command events (the 5 profile commands plus `exit`) and closed normally.
- `prepare_fresh_evaluation.py` selected the same 5 sessions and validated the 17-feature DEC order against `config.json`.

### 6.4 DEC results

**Measured:**

| Session | Cluster | Confidence |
|---|---|---|
| `860e0bc4a018` | 1 | 0.9346 |
| `50ce19c43b81` | 1 | 0.9288 |
| `e22808051703` | 1 | 0.9242 |
| `68c0f1a58402` | 1 | 0.9257 |
| `458003a74c58` | 1 | 0.9261 |

- All 5 sessions were assigned to cluster 1, with confidence min / mean / max of 0.924 / 0.928 / 0.935.
- All 13 sessions in the full snapshot were assigned to cluster 1.

**Interpretation:** cluster 1 holds the longer interactive multi-command sessions in the training data, which matches these logged-in, five-command sessions.

### 6.5 Novelty results

**Measured:**

- All 5 sessions were **Known-like**, each closest to `sig-47521826f16efd4b` (Mixed/Unclassified).
- Similarity scores ranged from **0.728 to 0.836**; runner-up scores ranged from 0.150 to 0.226.
- Reference independence: `evaluation_mode = independent`. **0** of the 43 catalogue source session IDs overlap the assessed sessions, and no warnings were raised.

**Interpretation and limits:**

- "Known-like" means the sessions resemble a stored behavioural signature above the heuristic threshold. It is not a confirmed benign or malicious label.
- Session-ID independence shows the assessed sessions weren't used to build the catalogue. It does not establish statistical independence: the sessions came from the same honeypot, generator and profile family as the reference data.

### 6.6 ARI and NMI

ARI and NMI were not computed:

- The sessions have no verified ground-truth labels; `extract_features.py` writes a placeholder `label = 0`.
- The DEC script omits these metrics unless `--labels-verified` is given and the labels contain at least two classes.

### 6.7 The failed exact-output verification check

The run's verification script (`verification/verify_fresh_run.py`) compared, as exact text, two DEC outputs for the same five sessions:

- the separate 5-session inference;
- the same sessions within the 13-session inference over the full log.

**Measured:**

- Input features, assigned clusters and confidence values were identical.
- For session `458003a74c58`, two probability values differed in the last printed digit, by at most 2.4 × 10⁻⁸ in the printed values (the later recomputation measured 2.235 × 10⁻⁸; Section 7.3).
- **The strict check therefore failed with exit code 1.**
- All other verification checks passed, and the protected-file integrity check was then run manually.
- The failure is retained in the evaluation record; the criterion was not weakened after the fact.

**Interpretation:** the difference is consistent with floating-point rounding that depends on batch composition, not with a data, ID or model error. Chapter 7 tests and bounds this behaviour.

### 6.8 What this evaluation does and does not show

- **Shows:** new honeypot sessions can be collected, verified as new and processed end to end with the existing model and catalogue, without modifying any protected file.
- **Does not show:** detection of unfamiliar attacks or zero-day threats. Only one profile was exercised, all results were Known-like, and the model was trained on synthetic data.

### 6.9 Earlier runs, for context

These earlier runs give context only and are not fresh-data results:

- **Held-out catalogue run** (`reports/novelty_assessment/held_out/revised/`): the 11 held-out baseline sessions gave **10 Potentially Novel and 1 Known-like**. Most were failed-login sessions scoring 0.60–0.69 against the credential-attack signature, just below the 0.70 threshold. **Interpretation:** "Potentially Novel" here reflects threshold sensitivity and catalogue sparsity, not unfamiliar behaviour.
- **8-session demo** (`data/demo_20261019_213439/`): all 8 sessions in cluster 1; novelty gave 5 Potentially Novel and 3 Known-like. The Potentially Novel sessions came from profiles (botnet, APT) that also appear in the baseline but have no usable signature in the catalogue.
  - That run's summary records `evaluation_mode: "in-sample"`. This was produced by the earlier code, which labelled every run this way; it was later corrected (audit item D1). Re-running the demo with the corrected code gives `independent` with identical results.

---

## Chapter 7: Reliability and Testing

### 7.1 Test suite

**Measured:** the full suite (`.venv\Scripts\python.exe -m pytest tests`) reports **130 passed**, with 2 pandas `FutureWarning`s. Section 7.6 lists the known warnings.

| Area | Test file(s) |
|---|---|
| Log collection | `test_collect_logs.py` |
| Parsing and feature extraction (missing, malformed, invalid data; failed writes; byte-identical regression) | `test_log_processing.py` |
| DEC preprocessing (infinity, NaN, non-numeric handling) | `test_dec_preprocessing.py` |
| DEC runner (exact session-ID strings, ARI/NMI gating) | `test_dec_runner.py` |
| DEC numerical reproducibility | `test_dec_reproducibility.py` |
| Pipeline safety (output isolation, overwrite refusal, interpreter selection, fail-fast) | `test_pipeline_safety.py` |
| Novelty assessment (categories, thresholds, held-out mode, evaluation mode, report contents) | `test_novelty_assessment.py` |
| Behaviour analysis and signature generation | `test_behaviour_pattern_analysis.py`, `test_behaviour_signature_generation.py` |
| Fresh-evaluation preparation | `test_prepare_fresh_evaluation.py` |

Some tests need local data that is not committed: the demo and fresh-run folders, and the DEC interpreter. They skip when those are missing; none skipped in the recorded run.

### 7.2 DEC reproducibility tests

`tests/test_dec_reproducibility.py` contains five tests. They run inference through `tests/dec_batch_probe.py` in the DEC interpreter.

1. The 1,800 training rows, run as one batch and as seven sub-batches (sizes 1, 2, 3, 5, 13, 31 and 256), give identical inputs, exactly equal clusters, and confidences and probabilities within tolerance.
2. Training cluster counts remain 485 / 694 / 621.
3. Adding one byte to `sbytes` changes every row by more than the tolerance, and `assert_allclose` must fail on it. This proves the tolerance cannot hide a real input change.
4. Fresh-run case: the five sessions keep their order and have bit-identical raw and scaled features. Their 5-batch outputs match their rows in the 13-batch run within tolerance.
5. The recomputed fresh-run outputs equal the recorded CSV values exactly, so the test reproduces the historical case.

### 7.3 Measured batch-dependent variation

Source: `reports/diagnostics/reproducibility_20261019_230210/variation_probe.json`.

| Measurement | Value |
|---|---|
| Fresh case, max \|Δ probability\| | 2.235 × 10⁻⁸ (one session; the other four 0) |
| Same batch run twice | 0.0 |
| 76 random sub-batches of training rows (sizes 1–1,800), max \|Δ\| | 1.49 × 10⁻⁷ (≈ 1.25 float32 ε) |
| Same, maximum relative difference | 6.8 × 10⁻⁷ |
| Cluster changes across all sub-batches | 0 |
| Smallest top-1/top-2 probability gap (training rows) | 5.94 × 10⁻³ |
| float32 machine ε | 1.19 × 10⁻⁷ |

**Interpretation:** the variation depends on batch composition rather than being random, and stays within about one float32 ulp. This is consistent with batch-size-dependent numerical kernels; the exact mechanism was not established independently.

### 7.4 Why `atol = 1e-6`, `rtol = 0`

- **Absolute only:** probabilities lie in [0, 1], so an absolute tolerance is meaningful and a relative term isn't needed.
- **Above the noise:** 1 × 10⁻⁶ is about 8.4 float32 ε, roughly 6.7 × the largest observed variation and 45 × the fresh-run difference.
- **Below real changes:** realistic input changes move probabilities by much more. One extra byte of `sbytes` moves them by about 2 × 10⁻⁴; 1 ms more `tcprtt` by about 7.5 × 10⁻⁵; 10 ms more `dur` by about 7 × 10⁻⁶. Test 3 enforces this.
- **Cannot flip a cluster:** the tolerance is about 5,900 × smaller than the smallest decision gap, and cluster assignments are compared exactly in any case.

### 7.5 Passing suite versus the failed historical check

The two results answer different questions:

- **The 130-test suite** checks behaviour within a justified numerical tolerance.
- **The fresh run's strict check** compared printed values exactly, failed (exit code 1), and is preserved unchanged in `data/evaluation_runs/fresh_20261019_224335/`.

The regression tests were added afterwards to characterise that failure. They don't overturn or rewrite it.

### 7.6 Protected-file integrity

- **Method:** each remediation, evaluation and test task recorded SHA-256 hashes of the protected files before and after (`reports/diagnostics/*/hashes_before.txt` and `hashes_after.txt`).
- **Protected files:** the DEC artifacts, the reference catalogue, the attack-profile configuration, the baseline data, the backup, the demo and the evaluation folders.
- **Measured:** every recorded comparison was identical. The latest covered 86 files, including all 41 files of the fresh-evaluation run.

**Known warnings** (non-blocking):

- pandas `fillna` FutureWarning;
- pandas pyarrow DeprecationWarning;
- paramiko TripleDES CryptographyDeprecationWarning;
- TensorFlow `tf.placeholder` deprecation and the "no GPU on native Windows" notice;
- git "Filename too long" for paths inside the untracked `.venv-dec-smoke`.

### 7.7 Remaining reliability limitations

- The main `.venv` cannot load the DEC artifacts. Two interpreters must be maintained.
- `parse_logs.py` and `extract_features.py` read files with the platform default encoding. Current logs are ASCII.
- `parse_logs.py` rejects a truncated final line, for example from a log copied while Cowrie is still writing it.
- Audit items D2, D4, D5 and D6 (catalogue and feature-definition issues) remain open. They require a catalogue rebuild or retraining, so they were deliberately left unchanged.

---

## Chapter 8: Automated Defence Status and Limitations

### 8.1 Status

**The automated defence engine has not been implemented.**

- No component generates, applies or rolls back IDS, IPS or firewall rules.
- No defensive action has been applied to any system, and the host firewall has not been modified.
- `scripts/defence_engine.py` does not exist.

Two related files exist, and neither performs defence:

- **`configs/defence_policy.json`:** a draft policy file created during an interrupted implementation attempt. It records a requirement that blocking be justified by behavioural evidence, plus a list of protected networks: loopback, link-local and the Docker network `172.19.0.0/16`. **No code reads this file.**
- **`ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/response_engine.py`:** an earlier placeholder that maps a DEC cluster and confidence to a deception-response label. Its own docstring calls it an example; it is not called by the pipeline or any script.

### 8.2 Design findings

These findings come from the repository audit and should inform any future implementation:

1. **Join key:** novelty results, DEC results and session details can be joined on the exact `session_id` string. All three outputs carry it, and the tests verify that it is preserved exactly.
2. **Shared source address:** every recorded session uses the Docker gateway `172.19.0.1` as its source IP, because of how Docker Desktop forwards the published port.
3. **Command classifier too noisy for enforcement:** the keyword classifier in `scripts/behaviour_pattern_analysis.py` matches substrings. It labels `whoami` as privilege escalation and `rm malware.sh` as reconnaissance. That is adequate for similarity scoring but not for justifying an enforcement decision.
4. **Gateway blocking would be disruptive:** blocking the shared gateway address would cut off all access to the honeypot, legitimate test traffic included, rather than one attacker.
5. **Labels alone are not evidence:** the evaluations show that a DEC cluster or a Potentially Novel label can come from catalogue sparsity or threshold effects (Section 6.9), so neither label is sufficient on its own to justify a defensive action.

### 8.3 Consequence for the project objectives

Objective 5 (automated generation of deployable rules) and the "automated defense" in the project title are **not met** by the delivered system. `README.md` marks "Automated rule generation" and "Zero-day detection" as platform features (✅) in its comparison table. The repository doesn't support those marks; Section 9.4 recommends revising them.

---

## Chapter 9: Conclusion and Future Work

### 9.1 Verified achievements

- A containerised Cowrie SSH honeypot, with a fail-fast pipeline for collection, parsing and feature extraction that protects the baseline and existing outputs.
- A comparison of nine unsupervised models on UNSW-NB15, and a DEC model tuned on synthetic Cowrie-style sessions. The model is integrated with its saved preprocessing, and its training distribution is reproduced exactly (485 / 694 / 621).
- A behaviour-signature catalogue built only from reference sessions, plus a novelty assessment that reports its own independence from the catalogue.
- A controlled fresh-data evaluation on five verified-new sessions, with full command, timing and hash records.
- A 130-test regression suite, including tolerance-justified numerical-reproducibility tests.

### 9.2 Novelty assessment versus confirmed zero-day detection

"Potentially Novel" means a session does not fit the current catalogue closely enough under a heuristic score. Confirming a zero-day would require evidence the project does not have:

- ground-truth labels;
- exposure to genuinely unseen attack behaviour;
- analysis of the payload or exploit itself.

The evaluations show that the category is sensitive to the catalogue's coverage and to the 0.70 threshold (Section 6.9). The project therefore provides a mechanism for **flagging behaviour that departs from known patterns**. It does not demonstrate zero-day detection.

### 9.3 Future work

Each item below is supported by the project plan (`README.md` Phases 2 and 3) or by the audit findings:

1. **More diverse behaviour evaluation:** evaluate further profiles and real attacker traffic in an isolated, authorised environment, and use labelled replay to obtain TPR, FPR, precision and recall, as `README.md` Phase 3 plans.
2. **Signature design (audit items D2 and D6):**
   - require a minimum number of sessions per signature;
   - handle signatures with no numerical features;
   - reconsider choosing the most variable features for profiles.
3. **Feature definitions (audit items D4 and D5):** make `ct_*` features independent of snapshot size, and derive `synack` from real timing rather than from `tcprtt`. Both require retraining DEC and rebuilding the catalogue.
4. **Domain alignment:** reduce the gap between synthetic training data and live Cowrie telemetry, for example by including live sessions in training once labels exist.
5. **Automated defence (Phase 2 plan):** implement rule generation from behavioural evidence, with explicit approval, protection of shared and infrastructure addresses, and auditing. The design findings in Section 8.2 apply.
6. **Social IoT threat-intelligence sharing (Phase 3 plan):** share generated signatures or rules across nodes. Nothing for this exists yet.
7. **Dashboard, central storage and APIs (Phase 3 and architecture plan):** not started.

### 9.4 Work required for a complete operational platform

- Implement and evaluate the automated defence layer (Chapter 8).
- **Commit the working-tree components to version control:**
  - `scripts/novelty_assessment.py`, `scripts/behaviour_signature_generation.py`, `scripts/behaviour_pattern_analysis.py` and `scripts/prepare_fresh_evaluation.py`;
  - the `tests/` directory;
  - the modified pipeline scripts and documentation.

  Restore or document the working-tree `data/` files, which currently hold a 5-session dataset from an earlier pipeline run rather than the committed 54-session baseline.
- Align the Python environments so a single interpreter can load the DEC artifacts.
- Collect rotated Cowrie logs, not only the current `cowrie.json`.
- Revise `README.md` claims that the repository does not support: MongoDB storage, REST APIs, a dashboard, Telnet exposure, zero-day detection and automated rule generation.
- Obtain labelled evaluation data so that detection performance can be measured.
