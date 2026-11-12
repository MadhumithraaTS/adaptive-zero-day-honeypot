# Dataset V2 model feature set: final decisions and freeze (Task 16)

**Date:** 2026-11-11.

**Result:** 13 extracted features → **8 model inputs**.
- 4 inactive
- 1 conditional, excluded pending review
- 0 unresolved features silently included

**Frozen configuration:** `configs/model_features_v2_frozen.json`, SHA-256
`8ae17612eabbbc46240aa1011aff8d6e3617df85380b3daa523201675fc3c288`. A byte-identical copy is in this directory.

**Not done in this task:**
- no model trained and no score computed;
- no thresholds tuned;
- no test set accessed;
- Dataset V2, the generator, profiles, extractor and specification are unchanged (hash-checked);
- no matplotlib installed;
- nothing committed.

**Reproduce:**

```
.venv/Scripts/python.exe reports/dataset_v2_feature_freeze_20261111/resolve_correlated_pairs.py
.venv/Scripts/python.exe reports/dataset_v2_feature_freeze_20261111/build_freeze.py
```

| Path | Content |
|---|---|
| `configs/model_features_v2_frozen.json` | The frozen model-input configuration (new file; the specification is untouched) |
| `model_features_v2_frozen.json` | Byte-identical copy |
| `feature_eligibility_final.csv` | One row per feature: status, model input, reason, evidence, risks, deployment limitations |
| `feature_list_before_after.csv` | Extracted vs model-input lists across Task 11 → Task 15 → Task 16 |
| `resolve_correlated_pairs.py`, `evidence/correlated_pairs.json` | Phase 2 pair evidence |
| `build_freeze.py` | Builds and validates the configuration. Decisions are fixed in code, the order comes from the spec, and no timestamps are written |
| `evidence/validation_checks.json` | The 14 validation checks and hashes |
| `SHA256SUMS` | Hashes of this directory |

## 1. Inputs and selection rules

**Inputs:**
- **Task 15:** `reports/dataset_v2_leakage_validation_20261111/report.md`, `feature_eligibility.csv` (`SHA256SUMS` verified) and `tables/leakage_results.json`.
- **Specification:** `configs/feature_spec_v2.json` 2.0.0-draft.3 (`9401b355…`), including its C1–C4 retention criteria.
- **Dataset:** the Task 14B dataset, used only for the pair analysis.

**Rules** (stated before the decisions and recorded in the configuration):
1. **Statuses follow Task 15's evidence and the spec's C1–C4 criteria.** No validation score selects anything: no model or score was computed in this task. Validation is used only to check that a training-split finding has the same direction.
2. **Redundant pair** (Spearman ≥ 0.8 on both splits, the flag used in Tasks 11 and 15):
   - Retain the member with simpler provenance and interpretability and lower training-split category-leakage evidence, provided the partner's extra information is template-specific.
   - If these criteria disagree, the feature is **conditional**.
3. **A conditional feature is never a model input.**
4. **Model-input order is the specification order.**

**Status definitions** (as in Task 15):

| Status | Definition | Model input? |
|---|---|---|
| eligible | No material concern | Yes |
| eligible with limitations | Passes the spec's retention evidence; the remaining category information is behavioural design, with named limitations | Yes |
| conditional | Unresolved | No |
| inactive | Fails a criterion whose spec handling is deactivation, or is the deactivated member of a redundant pair | No |

## 2. Phase 2: correlated pairs (`evidence/correlated_pairs.json`)

The analysis uses logged-in sessions with at least one input line (one per interaction). Task 15's statistics are unchanged: Kruskal ε² with 200 bootstrap CIs, and OLS-residual ε² on log1p.

### Pair 1: `input_line_count` vs `unique_command_names` (ρ 0.911 train, 0.898 validation)

| Criterion | `input_line_count` | `unique_command_names` |
|---|---|---|
| Provenance | Count of recorded `command.input` lines | Count of distinct first tokens of those lines: the same source plus tokenisation |
| Deployment availability | Yes | Yes, but depends on consistent tokenisation of arbitrary attacker input |
| Interpretability | Activity volume | Breadth of tools; ≤ line count by construction (equal in 70% of sessions) |
| Category leakage, train (sessions with input) | ε² **0.404** [0.361, 0.446] | ε² **0.493** [0.458, 0.533] |
| …without brute force | 0.251 [0.215, 0.289] | 0.364 [0.326, 0.404] |
| What it adds beyond the other | Residual ε² 0.382 | Residual ε² **0.467** [0.426, 0.511] |
| Mechanism of that extra information | — | Repeated names per session, set by templates: PE 1.29, reconnaissance 0.80, lateral 0.75, benign 0.11, botnet 0.07 (ε² 0.391) |
| Train / validation consistency | 0.404 / 0.401 | 0.493 / 0.497; residual 0.467 / 0.480 |

**Decision:** all criteria point the same way on both splits.
- **Retain `input_line_count`** (eligible with limitations).
- **Deactivate `unique_command_names`** (inactive).

The two are not perfectly redundant, since each adds residual information. However, what `unique_command_names` adds is template repetition structure. Validation agrees in sign and size.

### Pair 2: `input_bytes_total` vs `input_line_max_bytes` (ρ 0.831 train, 0.828 validation; both conditional in Task 15)

| Criterion | `input_bytes_total` | `input_line_max_bytes` |
|---|---|---|
| Provenance | Σ bytes of recorded lines | Longest line in bytes (NaN when there is no input) |
| Category leakage (T15, logged-in) | ε² 0.588; lookup 0.540; L1 pass | ε² 0.530; BA **0.569** (0.574 without brute force); lookup **0.708**; L1 **fail** (botnet outside every other range in 53% / 58%) |
| Beyond the retained `input_line_count` | Residual ε² **0.419** [0.380, 0.457]; this is command length (mean bytes per line ε² 0.520) | — |
| Beyond each other, without brute force | Adds ε² **0.047** beyond max bytes | Adds ε² 0.107 beyond bytes total |
| Mechanism | Count × template length | Template length (botnet median 39 bytes, PE 37, reconnaissance 20) |
| Train / validation | Consistent (0.497 / 0.454) | Consistent (0.530 / 0.507) |

**Decision:**
- **`input_line_max_bytes` → inactive.**
  - It is the strongest template-length fingerprint and fails both L1 and the L2 lookup proposal.
  - Its signal does not depend on brute force.
  - The exclusion is clear-cut.
- **`input_bytes_total` → conditional, excluded pending review.**
  - Once `input_line_count` is retained, what it adds is command length, the same mechanism as `input_line_max_bytes`.
  - It fails only the L2 lookup proposal, marginally (0.54 > 0.50), not L1.
  - Command length can be genuinely behavioural in deployment (long one-liners, encoded payloads).
  - The evidence does not justify a clear choice either way, so it is **not** silently included. A reviewed decision is requested (section 6).

### Other correlations among the retained features (train, Task 15 matrix)

| Pair | Spearman |
|---|---|
| `inter_input_mean_s`–`inter_input_std_s` | 0.79 |
| `session_duration_s`–`input_line_count` | 0.70 |
| `session_duration_s`–`inter_input_mean_s` | 0.69 |

None reaches the 0.8 flag. Dropping one of them would be a discretionary choice without a stated criterion, so all are kept and the correlation is recorded as a limitation.

## 3. Phase 3: final classification (`feature_eligibility_final.csv`)

| # | Feature | Spec | Task 15 | **Final** | Model input | Reason (short) |
|---|---|---|---|---|---|---|
| 1 | login_success | core | Eligible w/ limitations | **Eligible with limitations** | **1** | Designed failed-guess mix; brute-force rows dominate row-level metrics; constant if training on logins only |
| 2 | login_failed_count | C1 | Inactive | **Inactive** | no | = 1 − login_success in 100% of rows (C1 fail) |
| 3 | session_duration_s | C3 | Eligible w/ limitations | **Eligible with limitations** | **2** | Passes C3. Residual after line count 0.066. Cowrie `find` PE tail; low deployment compatibility |
| 4 | input_line_count | core | Eligible w/ limitations | **Eligible with limitations** | **3** | Retained member of pair 1 |
| 5 | input_bytes_total | core | Conditional | **Conditional** | no | Unresolved command-length signal; review requested |
| 6 | input_line_max_bytes | core | Conditional | **Inactive** | no | Strongest template-length fingerprint (L1 + L2 fail) |
| 7 | unique_command_names | core | Eligible w/ limitations | **Inactive** | no | Deactivated member of pair 1 (template repetition structure) |
| 8 | shell_operator_lines | C4 | Eligible w/ limitations | **Eligible with limitations** | **4** | Passes C4 after the redesign. PE enrichment 87% |
| 9 | download_command_lines | C4 | Inactive | **Inactive** | no | Botnet constant 1 (L1; C4 "still failing → inactive") |
| 10 | time_to_first_input_s | C2 | Eligible w/ limitations | **Eligible with limitations** | **5** | Passes C2; values carry no category information. Structural NaN |
| 11 | inter_input_mean_s | C2 | Eligible w/ limitations | **Eligible with limitations** | **6** | Passes C2 (ε² 0.009). Structural NaN; `find` tail |
| 12 | inter_input_std_s | C2 | Eligible w/ limitations | **Eligible with limitations** | **7** | Passes C2 (ε² 0.016). NaN in 59.5% of rows; ρ 0.79 with the mean |
| 13 | tty_output_bytes | core | Eligible w/ limitations | **Eligible with limitations** | **8** | Residual 0.18. Cowrie-emulation dependent |

**Status changes from Task 15:**
- `input_line_max_bytes`: conditional → inactive.
- `unique_command_names`: eligible with limitations → inactive.

Both are pair resolutions that Task 15 explicitly deferred to this task. No feature was promoted, and **no feature is "eligible" without limitations**.

**Extracted feature set (13, unchanged):** `login_success`, `login_failed_count`, `session_duration_s`, `input_line_count`,
`input_bytes_total`, `input_line_max_bytes`, `unique_command_names`, `shell_operator_lines`, `download_command_lines`,
`time_to_first_input_s`, `inter_input_mean_s`, `inter_input_std_s`, `tty_output_bytes`.

**Model input set (8, frozen order):** `login_success`, `session_duration_s`, `input_line_count`, `shell_operator_lines`,
`time_to_first_input_s`, `inter_input_mean_s`, `inter_input_std_s`, `tty_output_bytes`.

**Excluded:**
- **Inactive:** `login_failed_count`, `input_line_max_bytes`, `unique_command_names`, `download_command_lines`.
- **Conditional:** `input_bytes_total`.

## 4. Phase 4: the frozen configuration

`configs/model_features_v2_frozen.json` (config version 1.0.0, `frozen: true`) contains:
- the specification reference: path, `spec_version` 2.0.0-draft.3, SHA-256, and the 13 extracted features in order;
- the extractor SHA-256;
- the Task 15 and pair evidence, as paths with SHA-256;
- the dataset `SHA256SUMS` hash;
- status definitions and selection rules;
- both pair resolutions;
- `model_input_features` (ordered) and `model_input_count` 8;
- `inactive_features` and `conditional_features`;
- per-feature status, reason, evidence, leakage risks and deployment limitations;
- downstream constraints:
  - missing values are structural and determined by `login_success` and `input_line_count`;
  - no missing-value indicator features;
  - no imputation that re-encodes "no input" without review;
  - imputation is fitted on training data only;
  - interaction-grouped and balanced metrics;
  - a with/without-`find` sensitivity check;
  - the sealed test set stays untouched.

**Specification note [L]:**
- The spec's own `active` flags remain `true` for all 13 features.
- Its versioning policy implements deactivation by setting `active: false` and bumping the patch revision. Task 16 forbids modifying the specification.
- Deactivation is therefore recorded only in the separate frozen configuration, and the configuration says so.
- Downstream code must read the model input list from `model_features_v2_frozen.json`, not from the spec's `active` flags.
- Mirroring the decisions into the spec (as 2.0.0-draft.4) would need separate approval.

## 5. Phase 5: validation (`evidence/validation_checks.json`)

| # | Check | Result |
|---|---|---|
| 1 | All 13 specification features accounted for, each with exactly one valid status | pass |
| 2 | No inactive feature in `model_input_features` | pass |
| 3 | No conditional feature in `model_input_features`; inputs are exactly the eligible / eligible-with-limitations set | pass |
| 4 | Order equals specification order; no duplicates | pass |
| 5 | Valid JSON (parse and round-trip) | pass |
| 6 | Reproducible: an in-process rebuild gives identical bytes, and a second full run gave identical hashes for the configuration and both CSVs | pass |
| 7 | Specification (`9401b355…`) and extractor (`c0fdc684…`) unchanged; the extractor still outputs the 13 columns in spec order | pass |
| 8 | Model inputs ⊂ extracted columns; count matches | pass |

Additional integrity checks:
- **Task 14B dataset:** `SHA256SUMS` re-verified (60 files).
- **Task 15 directory:** `SHA256SUMS` re-verified (20 files).
- **Profiles and generator:** hashes unchanged (`79d47ac4…`, `f8c55f9d…`).
- **Test file:** `ml_pipeline/work/test.pkl` was not read (mtime 2026-11-08).

## 6. Open items for review

1. **`input_bytes_total` (conditional).** Choose one:
   - **(a) Make it inactive.** This treats command length as a lab template artefact. It is consistent with the `input_line_max_bytes` decision.
   - **(b) Make it eligible with limitations.** This accepts command length as behavioural, with a length-fingerprint limitation and a sensitivity check.

   Until a decision is made it stays out of the model inputs. **Recommendation: (a)**, because its information beyond `input_line_count` (residual ε² 0.42) is the same template-length mechanism that made `input_line_max_bytes` inactive.
2. **Mirroring into the spec.** Whether to mirror the deactivations into `feature_spec_v2.json` as a patch revision.
3. **Task 17 handling.** The missing-value policy, and whether models train on all sessions (with `login_success` varying) or on logged-in sessions only (where it is constant).

## 7. Limitations

- **[L] The decisions rest on synthetic lab evidence.** Low deployment compatibility (timing features, duration) is recorded but cannot be tested without real attacker logs.
- **[L] Separability remains high.** Task 15's all-feature diagnostic was 0.88. Removing four features was not done to reduce separability, and no score was computed here. The effect on clustering is for Task 17 to measure, not to decide this set retroactively.
- **[L] The retained features still carry known risks**, listed per feature in the configuration: the brute-force dominance of `login_success`, `input_line_count` and `tty_output_bytes`; the `find` tail in duration and inter-input timing; and structural missingness.
