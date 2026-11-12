# Research integrity audit

Date: 2026-11-10. Type: read-only audit. Nothing in the repository was modified apart from creating
this folder. The frozen 270-session test split (`ml_pipeline/work/test.pkl`) was not opened.

## Files in this audit

| File | Content |
|---|---|
| `feature_leakage_audit.csv` | Every feature: source events, generator driver, category association (η²), classification |
| `synthetic_vs_cowrie_comparison.md` | Event and feature differences, plus a common extraction specification |
| `dataset_v2_experimental_protocol.md` | Proposed real-Cowrie Dataset V2 experiment |
| `research_claims_validity_matrix.csv` | 15 claims with evidence, validity and correction |
| `recommended_next_steps.md` | Ordered next steps |

## Evidence used

- **Code:**
  - `scripts/generate_dataset.py` (`generate_synthetic_sessions`);
  - `scripts/extract_features.py` (feature logic identical at c1678cf and HEAD);
  - `dataset_builder/generate_labelled_traffic.py`, `dataset_builder/labelling.py`, `dataset_builder/profiles_v2.json`;
  - `ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/response_engine.py`.
- **Data:**
  - synthetic training and validation rows (`ml_pipeline/work/train.pkl`, `val.pkl`; 1,530 rows);
  - live `dataset_builder/runs/train_v2_corrected/behavior_features.csv` (3,125 rows);
  - live raw logs `dataset_builder/runs/{train_v1,eval_v1}/raw/cowrie_thisrun.json`.
- **Earlier reports:**
  - `docs/final_technical_report.md` (Chapters 3, 4, 6, 8, 9);
  - `reports/buffer_overflow_telemetry_audit_20261110/report.md`;
  - `reports/validation_error_analysis_ae_kmeans_20261110/report.md`;
  - `ml_pipeline/PIPELINE.md`.

Labels used below: **[C]** confirmed finding, **[R]** potential risk, **[U]** unverified assumption, **[Rec]** recommendation.

---

## A. Feature leakage and synthetic artefacts

### Confirmed findings

1. **[C] `dbytes` is an injected category parameter.** `generate_dataset.py` line 241 sets `log.closed.size = random.randint(*tty_size_range)` with a different range per profile. The extractor sets `dbytes` to that size (`extract_features.py` line 315). Every logged-in training and validation row lies inside its category's range.
   - A rule that uses only the training `dbytes` ranges keeps the true category among its candidates for 97.8% of logged-in validation sessions. It narrows to a single, correct category for 24.0% (`feature_leakage_audit.csv`).
2. **[C] `rate` and `dload` inherit the injected value.** `rate` = (`sbytes` + `dbytes`) / `dur` and `dload` = 8 × `dbytes` / `dur` (lines 316 and 320); the identities hold to 1e-5 in the data.
3. **[C] Failed commands are invisible to client features.** The generator emits `command.failed` *instead of* `command.input` (`generate_dataset.py` lines 209–233), and `spkts`/`sbytes`/`sinpkt`/`sjit`/`ackdat` read only `command.input`. As a result:
   - all buffer-overflow payloads, and 316 other failed commands in train + validation, are missing;
   - `dpkts` (5 + number of failures) instead encodes each category's designed `failed_cmd_rate`.
4. **[C] Timing features encode designed per-category parameters.** `dur`, `sinpkt`, `sjit` and `ackdat` come from `cmd_delay_range` (lines 205–207). Among logged-in sessions, category explains most of their variance (η²: `dur` 0.90, `ackdat` 0.88, `sinpkt` 0.73).
   - This is simulated behaviour, not learned attacker behaviour.
   - Profile `duration_range`, `spkts_range` and `dpkts_range` are never read.
5. **[C] `tcprtt` and `synack` carry no behaviour.** They are made of category-independent offsets (η² 0.003), and `synack` = 0.45 × `tcprtt` exactly (line 352).
6. **[C] `ct_srv_src` and `ct_src_ltm` are label leakage in the 17-feature model.** Each category has its own source-IP list and the counts are taken over the whole file (line 360). They were removed in the 15-feature model but remain in the deployed 17-feature DEC, its novelty catalogue and `response_engine.py`.
7. **[C] The "zero_day" categories are not unseen.** They appear in every split of the synthetic data, so they can't test detection of unknown attacks (`generate_dataset.py` lines 65–100).
8. **[C] Failed logins carry almost no category information.** About 25% of each command profile is a failed login (`auth_success = random.choice([1, 1, 1, 0])`, line 166), and all 15 features then have η² ≈ 0 across categories. That holds for every feature, including `dpkts`, which is constant at 4; its η² computation is numerically undefined there.

### Genuine behaviour vs simulation artefact

Full per-feature table: `feature_leakage_audit.csv`.

- **Behavioural content (from fixed strings):** `sbytes`, `sload`.
- **Behavioural count distorted by failure handling:** `spkts`.
- **Designed simulation parameters:** `dur`, `sinpkt`, `sjit`, `ackdat` (and partly `dinpkt`, `djit`).
- **Injected artefacts:** `dbytes`, `dload`, and much of `rate`.
- **Noise or redundant:** `tcprtt`, `synack`.
- **Leakage:** `ct_*` (17-feature model only).

### Potential risks

- **[R]** Because category ranges overlap, the injected `dbytes` signal works together with timing, not alone. A model can reach plausible-looking ARI without learning anything that transfers to live data.
- **[R]** `sbytes` values repeat inside a category, because each category draws from a few fixed strings. The exact-value lookup is correct for 11.9% of validation sessions. This is a content signal, but a brittle one.

---

## B. Dataset and model validity

**Confirmed:** the nine-model comparison (`docs/final_technical_report.md` 4.1–4.5) used **UNSW-NB15**, not the synthetic data. None of the synthetic artefacts affect it. Its existing caveats still apply: latent-space and input-space metrics, and the two groups were never ranked together.

| Result | Status | Basis |
|---|---|---|
| UNSW nine-model rankings | Usable with existing caveats | §4.3–4.5 |
| Choosing DEC for Cowrie | Not supported | Carried over from UNSW; on 15-feature synthetic validation, DEC is not better than K-Means or AE+K-Means (`models/dec_15_feature_v2_deterministic/metrics_validation.json`) |
| Cowrie DEC tuning and 485/694/621 clusters | Needs qualification | `ct_*` leakage, injected `dbytes`, no held-out data (§4.7) |
| 15-feature internal metrics (AE+K-Means 0.415 / 1.133; DEC 0.398 / 1.246) | Usable as synthetic-validation internal metrics | still include `dbytes`, `rate`, `dload` |
| Deterministic training, `ct_*` independence | Usable (engineering) | `reproducibility.json`, tests |
| Category separation (ARI 0.15–0.20) | Needs qualification | generator labels plus designed or injected signals |
| Zero-day or payload detection | Cannot be claimed | A.3, A.7; buffer-overflow audit |
| Novelty assessment | Needs qualification | 17-feature catalogue; threshold sensitivity (§6.9) |

See `research_claims_validity_matrix.csv` for all 15 claims and their required corrections.

---

## C. Synthetic vs real Cowrie

Details are in `synthetic_vs_cowrie_comparison.md`.

- **Confirmed:**
  - Real Cowrie logs `command.input` for every line, with `command.failed` added afterwards.
  - Real Cowrie emits `session.params` and `file_download`, which the generator never produces.
  - Live failed-login attempts are separate Cowrie sessions lasting about 120 s.
  - `dpkts` baselines differ (3 and 6 live, 4 and 5 synthetic).
  - Live `tcprtt` is about 7× smaller.
  - Live `dbytes` is the real tty-log size.
- **Unverified:** the cause of the 120 s failed-login duration [U], and how Cowrie logs raw non-ASCII payload bytes [U].
- **Recommendation:** adopt the common specification in that file, section 4 [Rec].

---

## D. Dataset V2

**Recommendation:** run a separate real-Cowrie experiment. The protocol is in `dataset_v2_experimental_protocol.md`. It specifies:

- generation through the existing `dataset_builder` path;
- a payload-delivery case, explicitly not an exploit;
- input-event and feature-visibility checks;
- manifest-based labels;
- splits grouped by `source_entry`, with a separately seeded and sealed final test run;
- reproducibility records.

Dataset V1 is preserved unchanged.

---

## E. Research claims

Full table: `research_claims_validity_matrix.csv`.

| Validity | Count |
|---|---|
| Valid | 1 |
| Valid with qualification | 4 |
| Partly valid | 1 |
| Requires qualification | 3 |
| Not supported | 2 |
| Cannot be claimed | 4 |

Claims that **cannot be claimed**:

- zero-day attack detection;
- buffer-overflow payload detection;
- adaptive honeypot response (`response_engine.py` is an uncalled placeholder keyed to 17-feature cluster IDs);
- automated defence.

---

## Unverified assumptions (collected)

1. The frozen test split shows the same artefacts as training and validation. This is inferred from the shared generator and extractor; the split was not inspected.
2. The cause of live failed-login durations of about 120 s.
3. How Cowrie logs raw non-ASCII bytes, and whether it truncates long lines.
4. How much of the 17-feature DEC's cluster structure comes from `dbytes` rather than timing or `ct_*`. This wasn't measured; doing so would need ablation experiments, which this audit did not run.
5. Whether `eval_v2_corrected` and other live runs match train_v1/eval_v1 semantics. Only those two raw logs were examined for event pairing.

## Integrity

See `recommended_next_steps.md`, section "Integrity verification for this audit".
