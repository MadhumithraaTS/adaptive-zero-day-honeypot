# Clustering configuration versioning and novelty baseline freeze audit (Task 19A)

**Date:** 2026-11-11.

**Result: all audit checks pass.** The clustering configuration history is restored, and the Task 18 novelty baseline is frozen and reproduces exactly from its saved artefacts.

**Sealed test set: untouched.**
- It was not accessed, scored or inspected.
- No Dataset V2 test run exists; only `train` and `validation` are present.
- An audit hook recorded no test-like or exfiltration file being opened.

**Not done:**
- no model trained or refitted, and no DEC;
- no thresholds tuned;
- no feature-set change;
- no scores, thresholds, features or weights changed;
- extractor and both spec revisions unchanged;
- Task 16 and Task 17 reports unchanged (their `SHA256SUMS` verify);
- no automated defence;
- nothing committed.

## 1. Clustering configuration: versions and what applies where

**Before Task 19A:** Task 18 Phase 1 had written revision 1.1.0 over the canonical `configs/model_features_v2_frozen.json`.

**Task 19A changes** (in this order; `evidence/hashes_before.txt` and `evidence/hashes_after.txt`):
1. Copied the then-canonical 1.1.0 to `configs/model_features_v2_frozen_v1.1.0.json`. It is byte-identical to the Task 18 copy (`cmp`).
2. Restored **1.0.0** at the canonical path from the byte-identical Task 16 archive.

| File | SHA-256 before → after | Version | Applies to |
|---|---|---|---|
| `configs/model_features_v2_frozen.json` | `18a4ab2b…` → **`8ae17612…`** | **1.0.0** (restored) | **Task 16** freeze; **Task 17** AE + K-Means / DEC revalidation (`revalidate_v2.py` asserts this hash; the four saved Task 17 model configs record it); spec draft.4 `authoritative` pointer |
| `configs/model_features_v2_frozen_v1.1.0.json` | (new) → **`18a4ab2b…`** | **1.1.0** | **Task 18** novelty baseline (hash recorded in the novelty configuration). `input_bytes_total` inactive |
| `reports/dataset_v2_feature_freeze_20261111/model_features_v2_frozen.json` | `8ae17612…` (unchanged) | 1.0.0 | Archive / restore source |
| `reports/cowrie_novelty_baseline_20261111/config/model_features_v2_frozen_v1.1.0.json` | `18a4ab2b…` (unchanged) | 1.1.0 | Archive |
| `configs/cowrie_novelty_baseline_v1.json` | `bd3a399e…` (unchanged) | 1.0.0-provisional | Novelty model; separate from both clustering files |
| `configs/feature_spec_v2.json` | `9401b355…` (unchanged) | 2.0.0-draft.3 | Extractor contract |
| `configs/feature_spec_v2_draft4.json` | `7f444dd1…` (unchanged) | 2.0.0-draft.4 | Eligibility revision |
| `scripts/extract_features_v2.py` | `c0fdc684…` (unchanged) | — | Extractor (13 features) |

**1.0.0 vs 1.1.0** (`configuration_hash_comparison.json`):
- **Same 8 model inputs in the same order:** `login_success`, `session_duration_s`, `input_line_count`, `shell_operator_lines`, `time_to_first_input_s`, `inter_input_mean_s`, `inter_input_std_s`, `tty_output_bytes`.
- **Same 13 extracted features.**
- **Only status difference:** `input_bytes_total` is conditional in 1.0.0 and inactive in 1.1.0. 1.1.0 also adds revision, extracted-feature and specification-reference blocks.
- **Novelty model inputs:** the 7 features of 1.1.0 minus `login_success`, in a separate configuration.

**Reproducibility of earlier tasks against 1.0.0** (`evidence/task16_17_reproduction_checks.json`): all pass.

| Task | Check |
|---|---|
| Task 16 | `build_freeze.build()`, run in memory without writing, is byte-identical to the restored canonical file |
| Task 17 | `revalidate_v2.py`'s expected hash equals the canonical hash. All four saved model configs record the canonical path with the matching hash. Draft.4's authoritative hash matches again |
| Both | Their report `SHA256SUMS` verify unchanged |

**Scripts updated** (only where needed; full diff in `evidence/script_changes.diff`):

| Script | Change |
|---|---|
| `reports/cowrie_novelty_baseline_20261111/novelty_baseline.py` | Reads and asserts 1.1.0 from `configs/model_features_v2_frozen_v1.1.0.json`. Writes that versioned path into `relation_to_clustering_config.path` if it is ever rerun |
| `reports/cowrie_novelty_baseline_20261111/revise_frozen_config.py` | Writes 1.1.0 only to the versioned path. Refuses to run unless the canonical file is the original 1.0.0, and never writes it. Rerun after the restore: a no-op, all 14 checks pass (`evidence/revise_frozen_config_rerun.json`) |

**Pre-audit originals:** reconstructed by reversing exactly these edits. Their SHA-256 values equal the pre-audit hashes (`278af62b…`, `29527789…`), so the diff is complete.

**Known stale field [L]:** the frozen novelty configuration `configs/cowrie_novelty_baseline_v1.json` was not modified. Its `relation_to_clustering_config.path` still reads `configs/model_features_v2_frozen.json`. Its recorded `sha256` (`18a4ab2b…`) and `config_version` (1.1.0) identify the versioned 1.1.0 file unambiguously.

## 2. Novelty baseline audit

`audit_novelty_freeze.py`, output `evidence/novelty_audit.json`.
- **No retraining:** autoencoder weights are loaded into the existing architecture (no compile, no fit).
- **Training-only parameters** are checked by arithmetic.
- **kNN scores** are exact queries against the saved reference arrays.

| Requirement | Result |
|---|---|
| Seven inputs, exact order | **Pass.** `session_duration_s`, `input_line_count`, `shell_operator_lines`, `time_to_first_input_s`, `inter_input_mean_s`, `inter_input_std_s`, `tty_output_bytes`. This equals 1.1.0's inputs minus `login_success`. The scaler's `feature_names_in_` and the medians keys are in the same order |
| Training-only medians | **Pass.** All 7 saved medians equal the medians of the 1,500 logged-in **training** sessions. Including validation would have changed 5 of them (e.g. `session_duration_s` 12.2 → 12.3, `tty_output_bytes` 1,114 → 1,134), so validation was not used |
| Training-only scaling | **Pass.** Scaler mean equals the training mean, scale equals the training population SD (rtol 1e-9), and `n_samples_seen_` = 1,500. The saved scaled training reference equals the re-processed training data exactly |
| No missingness indicators | **Pass.** 7 inputs; `missingness_indicators: false`; no indicator-like input |
| Imputed-value records complete | **Pass.** Train: 1,500 rows. Validation: 600 rows. Session order matches. The logged features are exactly those with NaN, and each log column equals the NaN mask. Train counts: `time_to_first_input_s` 99, `inter_input_mean_s` 198, `inter_input_std_s` 208 |
| Method C deterministic, threshold saved | **Pass.** A repeat query is identical. The recomputed training p99 (leave-one-out) of 1.6921045 equals the saved 1.692104 |
| Methods A and B keep their thresholds and outputs | **Pass.** Recomputed training p99: A 1.1714448, B 0.7291904. These equal the configuration and `results.json` values (1.171445 / 0.729190) |
| Validation scores reproduce | **Pass, exactly at stored precision.** Each recomputed train and validation score, formatted with `%.6g` like the saved CSVs, equals the stored value for every session and method. The largest absolute difference before formatting is 5.0e-6, which is CSV rounding |
| Validation flags reproduce | **Pass, exactly.** A 4/600, B 3/600, C 4/600, identical session by session |
| Five-seed stability preserved | **Pass.** Recomputed from the saved per-seed validation scores: A Spearman 0.5727 and Jaccard 0.0808; B 0.7166 and 0.2165. Per-seed flag rates match. Flagged by all 5 seeds / by any: A 0 / 20, B 0 / 13 |
| Artefact hashes | **Pass.** All 7 model files match `artifact_sha256.json` and the novelty configuration's `artefact_sha256`. The configuration copy in the Task 18 report equals `configs/`. The model `config.json` equals the configuration without its hash block |
| No test data, labels, metadata or test-derived information | **Pass.** The audit hook aborts on any path containing `ml_pipeline/work/test`, `sealed`, `/runs/test` or `exfil`. Of 3,539 files opened (mostly TensorFlow libraries), none was test-like. Data categories: the 6 training categories; 0 held-out rows. Dataset V2 run directories: `train` and `validation` only. Thresholds come from training scores only |

**Two findings during the audit (both resolved without changing anything audited):**
1. **Tolerance check.** A first tolerance-based comparison failed by up to 5e-6. That is the `%.6g` rounding in the saved CSVs, as even the deterministic Method C showed. It was replaced by the exact stored-precision check above.
2. **Batch size.** AE predictions must use the configured `predict_batch_size` of 256, as Task 18 did. The Keras default of 32 gives float32 differences below 5e-6. With 256, every score matches at stored precision.

## 3. Interpretation (also added to the Task 18 report as a status section)

- **Method C** (input-space kNN distance, deterministic) is the **primary experimental candidate**. **Methods A and B are secondary comparisons.**
- **The baseline is not a validated zero-day detector.** Validation contains only known categories. It shows only that about 1% of known logged-in sessions are flagged (0.50–0.67%).
- **Validation flags are strongly affected by generator pacing.** Flagged sessions over-represent the generator's long random think-time draws (Task 18 §6).
- **The `find` experiment shows sensitivity to unfamiliar Cowrie interaction patterns**, an emulated command with an 11.6 s execution delay. It does not necessarily show sensitivity to unseen attack behaviour.
- **The held-out `data_exfiltration` experiment may be confounded by Cowrie command-emulation failures** (`tar` fails, `curl -T` errors). Its evaluation must include the artefact-attribution check proposed in Task 18 §9.

## 4. Task 18 report directory changes

- **Changed:** exactly three files (`evidence/task18_SHA256SUMS_changes.diff`).
  - `novelty_baseline.py` and `revise_frozen_config.py` (section 1).
  - `report.md`, which gained the status section.
- **Unchanged:** all outputs, scores, figures, configuration copies and model files are byte-identical.
- **Hash list:** `SHA256SUMS` was regenerated; the pre-audit version is kept as `evidence/task18_SHA256SUMS_before_audit.txt`.

## 5. Files

| Path | Content |
|---|---|
| `report.md` | This report |
| `audit_novelty_freeze.py` | Novelty audit (no training or refitting) |
| `config_hash_comparison.py`, `configuration_hash_comparison.json` | Configuration hashes before and after, versions, and which experiment uses which |
| `evidence/hashes_before.txt`, `evidence/hashes_after.txt` | Raw hash snapshots |
| `evidence/novelty_audit.json` | All audit results: hashes, inputs, parameters, imputation, reproduction, seeds, test-set access |
| `evidence/audit_console.txt` | Console output of the audit run |
| `evidence/task16_17_reproduction_checks.json` | Tasks 16 and 17 against the restored 1.0.0 |
| `evidence/revise_frozen_config_rerun.json` | No-op rerun of the updated revision script |
| `evidence/script_changes.diff` | Exact script changes |
| `evidence/task18_SHA256SUMS_before_audit.txt`, `evidence/task18_SHA256SUMS_changes.diff` | Task 18 directory before and after |
| `SHA256SUMS` | This directory plus both clustering configurations and the novelty configuration |

**Next step (needs explicit approval):** freeze the novelty baseline as audited (Method C primary, A and B secondary). Then generate and score the sealed `data_exfiltration` test run once, with the artefact-attribution check. Nothing has been opened.
