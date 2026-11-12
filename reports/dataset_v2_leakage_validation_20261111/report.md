# Dataset V2 feature leakage validation (L1–L7) — Task 15

**Date:** 2026-11-11.

**Inputs:** the Task 14B dataset `reports/dataset_v2_training_validation_20261110/`. It was built with generator 2.1 and
`profiles_v2_revised.json`:
- **train:** 1,500 interactions, 3,190 rows;
- **validation:** 600 interactions, 1,257 rows.

**Method:** Task 11 (`reports/v2_feature_leakage_validation/`), unchanged where applicable. Section 3 lists every difference.

**Not done in this task:**
- no traffic was generated;
- no dataset, generator, profile, extractor, specification or historical data was modified;
- no test set was read (an audit hook recorded zero test-set paths opened);
- no clustering or final model was trained (the classifiers below are single-purpose diagnostics, as in Task 11);
- no thresholds were tuned and no features were selected by validation score;
- nothing was committed.

**Labels:** **[O]** observed, **[H]** hypothesis, **[L]** limitation.

**Reproduce:**

```
.venv/Scripts/python.exe reports/dataset_v2_leakage_validation_20261111/analyze_leakage_v2.py
.venv/Scripts/python.exe reports/dataset_v2_leakage_validation_20261111/supplementary_excluding_brute_force.py
```

| Path | Content |
|---|---|
| `analyze_leakage_v2.py` | Phase 1 verification, L1–L7, C1–C4 and investigations A–E. Task 11 functions are copied verbatim |
| `supplementary_excluding_brute_force.py` | Supplementary only (not Task 11 protocol): the same statistics without brute force, and without `find` sessions |
| `feature_eligibility.csv` | Per-feature evidence and recommended status |
| `tables/leakage_results.json` | All results, machine-readable |
| `tables/input_verification.json` | Phase 1 checks |
| `tables/per_feature_statistics.csv` | Per split × set × feature: ε² and 95% CI, single-feature BA, train→validation BA, exact-value lookup, missingness V, L1 |
| `tables/category_distributions.csv` | Per split × set × feature × category: n, missing %, median, IQR, mean, min, max |
| `tables/category_counts.csv` | Interactions, session rows, logged-in and failed rows per category |
| `tables/missingness_by_category_role.csv` | NaN share per feature × category × login role |
| `tables/repeated_sequences_validation_in_train.csv` | Every validation interaction whose command sequence also occurs in train |
| `tables/vocabulary_command_by_category_train.csv` | Observed command-name × category counts |
| `tables/capture_day_ks_logged_in.csv`, `tables/capture_day_per_command.csv` | Train vs validation comparisons |
| `tables/before_after_per_feature.csv` | Task 11 vs V2, per feature |
| `tables/correlation_spearman_logged_in_{train,validation}.csv` | Spearman matrices |
| `tables/supplementary_excluding_brute_force.csv` | Supplementary statistics |
| `tables/console_*.txt` | Console output of the final run |

---

## 1. Headline

1. **Generator-driven leakage is gone [O].** Task 11 found three generator-2.0 mechanisms:
   - per-profile pacing;
   - unclosed 120 s failed logins;
   - category-dependent line loss.

   None of them is present in V2:
   - **Timing values:** `inter_input_mean_s` ε² 0.786 → **0.009**; `inter_input_std_s` 0.405 → **0.016**; `time_to_first_input_s` 0.003 → 0.007.
   - **Failed logins:** median 1.1 s in every category, with 0 sessions near 120 s or 180 s.
   - **L6:** 0 of 10,595 lines lost (Task 11: Cramér's V 0.80).
   - **Duration:** the residual after line count fell from ε² 0.64 to **0.066**.
2. **Profile-template leakage is reduced but not removed [O].**
   - **Vocabulary:** observed mean pairwise Jaccard 0.088 → 0.186. Category pairs sharing no command name: 6 → 0.
   - **Exact-sequence lookup coverage:** 27% → 14%.
   - **Command-name-set coverage:** 61% → 34%.
   - **First command alone:** right 84% → **73%** of the time (74% train→validation). That is still far above the 37% majority rate.
   - **Recurring sequences still identify the category:** a recurring sequence never crosses categories (0.0%), and lookup is 100% precise where it recurs.
   - **Strongest single feature:** `input_line_max_bytes` (BA 0.57, lookup 0.71; botnet outside every other category's range in 53% of sessions).
3. **Most remaining single-feature signal is "brute force runs at most one command" [O].** Without brute force:
   - **Duration:** `session_duration_s` ε² 0.39 → 0.095, BA 0.21 (chance 0.20).
   - **Output volume:** `tty_output_bytes` ε² 0.44 → 0.15.
   - **Missingness:** every C2 timing flag comes from missingness, which is a deterministic function of `input_line_count` and `login_success` (0 unexplained NaN).
4. **Cowrie `find` artefact [O]:**
   - **Where:** an 11.6 s execution pause that occurs only in privilege escalation (30 train / 9 validation sessions).
   - **Category-level effect:** negligible (duration ε² 0.393 → 0.385 with the pause removed).
   - **What it does create:** a PE-only tail. 21 of 30 find sessions exceed the non-PE p95, but 12.8% of botnet sessions also do. It is a partial fingerprint, not a category-wide one.
5. **Train and validation agree [O].**
   - ε² and BA per feature match within their CIs.
   - Train→validation transfer equals within-split cross-validation.
   - No within-category capture-day difference reaches p < 0.01 (59 KS tests).
6. **All 13 features together:**
   - logged-in grouped-CV balanced accuracy **0.88** (Task 11 0.97);
   - train→validation 0.87;
   - chance 0.17.

   The categories remain highly separable, mainly through content features [O].
7. **Recommended statuses** (section 9, `feature_eligibility.csv`):
   - **Inactive:** `login_failed_count` (C1, ρ = −1.0, unchanged) and `download_command_lines` (zero variance in botnet after the redesign).
   - **Conditional:** `input_line_max_bytes` and `input_bytes_total` (template byte lengths).
   - **Eligible with limitations:** the other nine.
   - No feature is unconditionally eligible.

## 2. Phase 1: frozen and verified inputs [O]

| Check | Result |
|---|---|
| Dataset files vs `SHA256SUMS` | 60 files, 0 mismatches. `SHA256SUMS` itself `05e9d838…` |
| Profiles, spec, extractor | `79d47ac4…`, `9401b355…` (spec 2.0.0-draft.3), `c0fdc684…`: identical to Task 14B |
| Train and validation separate | 0 shared interaction IDs, 0 shared session refs. Separate runs, seeds and raw slices |
| Categories | 6 in each split: benign, botnet, brute_force, lateral_movement, privilege_escalation, reconnaissance |
| `data_exfiltration` | 0 rows in either split. 0 rows marked held-out |
| Test set | Not accessed. A Python audit hook aborts on any `ml_pipeline/work/test*`, `sealed` or `runs/test` path. Paths opened: none |
| Features vs metadata | `model_features.csv` columns equal the spec's 13, in order. The 8 descriptive fields and the labels exist only on the metadata side |
| Grouping unit | `interaction_id` (1–6 sessions each). At most one logged-in session per interaction, so the logged-in set (1,500 / 600) has one independent row per interaction. All CV uses GroupKFold(5) by interaction, and all CIs bootstrap interactions |

Task 11's methodology was read from `reports/v2_feature_leakage_validation/report.md` and `analyze_leakage.py`. Its definitions come from `docs/feature_specification_v2.md` (C1–C4) and
`reports/common_feature_specification_v2/report.md` (L1–L7).

## 3. Methodology: unchanged parts and documented differences

**Unchanged** (functions copied verbatim):
- Kruskal–Wallis **ε² = H/(n−1)** with 200-interaction bootstrap 95% CIs.
- Depth-3 single-feature tree on [value, NaN indicator], GroupKFold(5), balanced accuracy.
- Fold-based exact-value lookup.
- L1 modal share (≥ 0.95) and "outside every other category's range".
- χ² / Cramér's V for missingness.
- Spearman correlation.
- OLS residual ε² (duration on line count; log1p tty on log1p input bytes).
- Random-forest context (all 13, core 6, without C2/C3).
- L3 perturbed re-extraction; L4/L5/L6 definitions.
- The 4 × 3 threshold grid (ε² ∈ {0.06, 0.14, 0.26, 0.5} × BA margin ∈ {0.10, 0.20, 0.35}, or missingness V ≥ 0.5).
- **As before, a non-significant p-value is never treated as evidence of safety.**

**Differences** (forced by the data, or additions; no definition or threshold changed):

| # | Difference | Reason |
|---|---|---|
| 1 | Labels from the Task 14B reconciliation (`labels/<split>_session_labels.csv`). Group = `interaction_id`; "logged in" = `role == logged_in` | V2 has no `label_assignments.csv`. Equivalent content (generation intent, one label per session) |
| 2 | Features are the Task 14B extraction outputs (byte-identical across two extractions), not re-extracted | Avoids writing new extraction copies. L3 still re-extracts a perturbed copy (temporary, deleted) |
| 3 | Every statistic is also computed on validation (within-split CV), plus **train→validation transfer** (tree / lookup / RF fit on train, scored on validation) | Task 11 had no eligible validation split. Transfer is an addition; no threshold uses it |
| 4 | C2 "inter-input vs profile `delay_range`" correlation is **not computable**: the revised profiles have no `delay_range` | Replaced by a direct check that manifest think times are category-independent (Kruskal ε² of mean think time per session) |
| 5 | L7: Task 11 compared gen-2.0 training with a 14-session gen-2.1 confirmation. Here V2 train, V2 validation, Task 11 and Task 9 medians are compared, and the common-spec L7 invariants are checked | The gen-2.1 run now exists at scale. Deployment L7 is still untestable |
| 6 | Timestamp anomalies counted on V2 only (eval_v1 not read) | Not needed |
| 7 | L4 adds "Σ per-session events = slice lines" (common-spec L4). L5 lookups are also reported on sessions with ≥ 1 command | Defined in the common spec / separates brute force |
| 8 | Supplementary analysis without brute force (separate script) | Phase 3 investigation; not used for any threshold |
| 9 | **No figures**: matplotlib is not installed in `.venv` and was not installed (environment unchanged). All numbers are in `tables/` | The `plt is None` branch in the script |

## 4. Per-feature results (logged-in sessions; train n = 1,500, validation n = 600; grouped by interaction)

Before/after per feature (`tables/before_after_per_feature.csv`):

| Feature | Group | Missing % (train) | Task 11 ε² | V2 train ε² [95% CI] | V2 val ε² | Task 11 BA | V2 train BA | Train→val BA | Task 11 lookup | V2 lookup | Miss. V (train) | Flags /12 (T11 → V2) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| login_success | core | 0 | const | const | const | 0.167 | 0.167 | 0.167 | 0.36 | 0.37 | 0 | 0 → 0 |
| login_failed_count | C1 | 0 | const | const | const | 0.167 | 0.167 | 0.167 | 0.36 | 0.37 | 0 | 0 → 0 |
| session_duration_s | C3 | 0 | **0.804** | 0.393 [0.354, 0.428] | 0.380 | 0.636 | 0.314 | 0.316 | 0.70 | 0.40 | 0 | 12 → 10 |
| input_line_count | core | 0 | 0.572 | 0.516 [0.478, 0.554] | 0.517 | 0.427 | 0.387 | 0.395 | 0.57 | 0.53 | 0 | 12 → 12 |
| input_bytes_total | core | 0 | 0.483 | **0.588** [0.554, 0.622] | 0.557 | 0.403 | 0.465 | 0.468 | 0.49 | 0.54 | 0 | 11 → 12 |
| input_line_max_bytes | core | 6.6 | 0.669 | 0.530 [0.496, 0.568] | 0.507 | **0.772** | **0.569** | 0.566 | **0.82** | **0.71** | 0.68 | 12 → 12 |
| unique_command_names | core | 0 | 0.571 | 0.587 [0.551, 0.622] | 0.594 | 0.457 | 0.475 | 0.466 | 0.57 | 0.55 | 0 | 12 → 12 |
| shell_operator_lines | C4 | 0 | 0.829 | **0.215** [0.185, 0.247] | 0.202 | 0.308 | 0.167 | 0.167 | 0.47 | 0.37 | 0 | 12 → **6** |
| download_command_lines | C4 | 0 | **1.000** | 0.583 [0.544, 0.627] | 0.516 | 0.333 | 0.310 | 0.301 | 0.48 | 0.45 | 0 | 12 → 12 |
| time_to_first_input_s | C2 | 6.6 | 0.003 | 0.007 [0.002, 0.018] | 0.005 | 0.248 | 0.252 | 0.252 | 0.02 | 0.00 | 0.68 | 12 → 12 |
| inter_input_mean_s | C2 | 13.2 | **0.786** | **0.009** [0.003, 0.026] | 0.016 | 0.659 | 0.345 | 0.342 | 0.00 | 0.00 | **1.00** | 12 → 12 |
| inter_input_std_s | C2 | 13.9 | 0.405 | **0.016** [0.007, 0.035] | 0.011 | 0.519 | 0.353 | 0.354 | 0.00 | 0.00 | 0.97 | 12 → 12 |
| tty_output_bytes | core | 0 | 0.596 | 0.443 [0.403, 0.481] | 0.451 | 0.514 | 0.460 | 0.430 | 0.32 | 0.27 | 0 | 12 → 11 |

How to read the table:
- **Chance BA** is 0.167.
- **Lookup** is "correct share of all rows". It is not chance-corrected; the majority category, benign, is 37.4% of logged-in rows.
- **Flags** count how many of the 12 threshold pairs flag the feature.
- **Missingness flags:** for the three C2 features, all 12 flags come from the missingness rule (V ≥ 0.5), not from their values (ε² < 0.02).

**All sessions (train n = 3,190):**

| Feature | ε² [95% CI] | BA |
|---|---|---|
| `login_success` / `login_failed_count` | 0.159 [0.145, 0.171] | 0.243 |
| `session_duration_s` | 0.208 | 0.273 |
| `tty_output_bytes` | 0.220 | 0.336 |

Task 11: `login_success` ε² 0.18, `session_duration_s` ε² 0.08.

**Correlation [O]** (|ρ| ≥ 0.8, both splits):
- `input_line_count`–`unique_command_names` ρ = **0.91** (0.90 validation). Task 11: 0.96.
- `input_bytes_total`–`input_line_max_bytes` ρ = **0.83** (new).
- The Task 11 pair `session_duration_s`–`inter_input_mean_s` (0.86) is no longer above 0.8.

**Multi-feature context** (random forest; an upper bound on category information, not a model):

| Feature set | Task 11 | V2 train CV | V2 validation CV | Train→validation |
|---|---|---|---|---|
| All 13 | 0.971 | **0.879** | 0.833 | 0.867 |
| Core 6 | 0.965 | 0.878 | 0.813 | 0.879 |
| Without C2/C3 | 0.972 | 0.913 | 0.862 | 0.906 |

**Supplementary, without brute force** (five categories, chance 0.20; `tables/supplementary_excluding_brute_force.csv`):

| Feature | Train ε² [CI] | Val ε² | Train BA | Val BA |
|---|---|---|---|---|
| session_duration_s | 0.095 [0.066, 0.123] | 0.080 | 0.209 | 0.216 |
| input_line_count | 0.251 [0.216, 0.284] | 0.254 | 0.283 | 0.294 |
| input_bytes_total | 0.373 [0.335, 0.414] | 0.326 | 0.352 | 0.349 |
| input_line_max_bytes | 0.424 [0.384, 0.460] | 0.396 | **0.574** | 0.527 |
| unique_command_names | 0.364 [0.328, 0.406] | 0.374 | 0.342 | 0.340 |
| shell_operator_lines | 0.119 [0.093, 0.154] | 0.101 | 0.200 | 0.200 |
| download_command_lines | 0.564 [0.523, 0.609] | 0.493 | 0.372 | 0.361 |
| time_to_first_input_s | 0.007 | 0.005 | 0.202 | 0.199 |
| inter_input_mean_s | 0.009 | 0.016 | 0.203 | 0.206 |
| inter_input_std_s | 0.016 | 0.011 | 0.220 | 0.214 |
| tty_output_bytes | 0.152 [0.120, 0.186] | 0.166 | 0.335 | 0.356 |

## 5. L1–L7

| Check | Question | Train | Validation | vs Task 11 | Verdict |
|---|---|---|---|---|---|
| **L1 Constants** | Does a feature take one value, or a range no other category reaches, within a category? | `download_command_lines` = 1 in **100%** of botnet sessions (zero within-category variance; modal value unique to botnet). Values outside every other category's range: brute force `tty_output_bytes` 100%, `input_line_count` 100%, `input_bytes_total` 81%, `session_duration_s` 53%; botnet `input_line_max_bytes` 53%. `inter_input_mean_s` is NaN for 100% of brute-force logins | Same pattern: botnet download 100%; botnet max bytes 58%; brute force duration 72% | Task 11: botnet download constant; botnet `inter_input_mean_s` 92% outside (now 0%); brute force tty 84%; PE `shell_operator_lines` 85% (now 0%) | **Improved; persistent for `download_command_lines` (botnet) and `input_line_max_bytes` (botnet)**. Brute-force ranges are behavioural (≤ 1 command) |
| **L2 Single-feature prediction** | Can one feature predict the category? | 9 of 13 features above chance + 0.10 BA. Strongest: `input_line_max_bytes` 0.569, `tty_output_bytes` 0.460, `unique_command_names` 0.475, `input_bytes_total` 0.465. Lookup > 50%: `input_line_max_bytes` 0.71, `unique_command_names` 0.55, `input_bytes_total` 0.54, `input_line_count` 0.53 | Transfer BA within ±0.03 of train CV for every feature | Task 11: 11 of 13, strongest 0.77 / 0.66 / 0.64 | **Improved for timing and duration; persistent for content length features** |
| **L3 Label/identifier contamination** | Do identifiers, credentials or labels reach the features? | Perturbed re-extraction (IPs, ports, usernames, passwords, sensor, uuid, hassh, version replaced; `attack_cat`/`label`/`profile` injected) gives **identical** features. 0 reserved-marker sessions | Identical | Same as Task 11. The words `manifest`, `terminal_output` and `profile` appear in the extractor source only in its docstring (lines 6–7: "never a generation manifest, the generator's terminal_output.jsonl, labels, profile names"), exactly as in Task 11 | **Pass** |
| **L4 Duplicates and grouping** | Are records duplicated or groups split? | Session IDs unique; 0 duplicate records; Σ event_count = 29,955 slice lines; 0 unlabelled rows; ≤ 1 logged-in session per interaction. 3.6% of logged-in sessions share a feature vector; 14.8% share their exact sequence, **always within one category** (0.0% across) | 1.5% / 13.8%; 0.0% across | Task 11: 6.5% / 28.8% / 0.0% | **Pass.** Template repetition halved |
| **L5 Profile fingerprints** | Do templates identify the category? | Sequence lookup coverage **14.4%** at 100% precision (8.6% of command-running sessions). Name-set lookup **34.2%** at 100%. First command **73.3%** correct. Failed guesses per interaction: brute force 3–5 (setting [3, 5]), others 0–2 | Transfer: sequence 15.2% at 100%; name set 38.5% at 98.7%; first command **74.3%** | Task 11: 27.1% / 60.8% / 84.2% | **Reduced, still fails.** Recurring sequences and name sets still identify the category almost perfectly; coverage roughly halved |
| **L6 Client/server contamination** | Are client lines lost or added, and does that depend on category? | 0 of 7,516 manifest lines missing; 0 extra; V 0. `tty_output_bytes`–`input_bytes_total` ρ 0.38 | 0 of 3,079; 0 extra | Task 11: botnet 43.8% lost, V 0.80 | **Pass** (generator 2.1 fix confirmed at scale) |
| **L7 Training vs live meaning** | Do the features mean in training what they will mean live? | Invariants: 0 `command.failed` without prior input; 0 logins without `session.params`; 0 sessions with tty < input bytes. Medians V2 train / val / Task 11 / Task 9: duration 12.2 / 12.6 / 1.8 / 16.5 s; time to first input 1.66 / 1.62 / 0.10 / 2.23 s; inter-input mean 1.84 / 1.91 / 0.38 / 2.66 s; failed-login duration 1.1 / 1.1 / 120 s | As train | Generator-2.0 timing semantics replaced | **Generated runs are now consistent with each other. Deployment L7 is untestable [L]** (no real-attacker logs). The lab timing features describe the generator's pacing policy, not attackers |

**Timestamp anomalies:**
- 0 of 1,500 (train) and 0 of 600 (validation) logged-in sessions have their first input before `login.success`. Task 11: 2 sessions.
- 0 `timestamp_order_mismatch` sessions.

## 6. Conditional groups C1–C4 (spec retention evidence)

**C1 `login_failed_count` — fails [O].**
- It equals `1 − login_success` in 3,190/3,190 train and 1,257/1,257 validation rows (Spearman −1.0).
- 0 sessions have more than one failed login, so there are no within-session retries.
- The required evidence, |ρ| < 0.95 plus retries, is absent.
- **Unchanged from Task 11.**

**C2 timing (`time_to_first_input_s`, `inter_input_mean_s`, `inter_input_std_s`) — values pass, missingness needs handling [O].**

| Retention criterion | Evidence |
|---|---|
| (a) One category-independent pacing distribution, a fixed `--speed` and wait-for-prompt | Generator 2.1 PacingPolicy, `--speed 1`, prompt-gated (Task 14B `run_meta.json`). Manifest mean think time per session: ε² 0.006 (p 0.13) in train, 0.014 (p 0.18) in validation |
| (b) L1/L2 pass (proposed η² < 0.8) | ε² 0.007 / 0.009 / 0.016 |
| (c) `time_to_first_input_s` not near-constant | CV 0.81 (Task 11's generator-2.0 values were a fixed 0.0625 s wait plus latency). Medians 1.56–1.80 s in all categories |
| (d) L6 contamination not category-dependent | No lines lost or added in any category |

Missingness:
- Logged-in missingness V is 0.68 / 1.00 / 0.97, and every NaN is structural.
- NaN occurs when there is no login, no input (50% of brute-force logins), fewer than 2 lines or fewer than 3 lines.
- Every brute-force login has at most one line, so `inter_input_mean_s` is NaN for 100% of brute force.
- 0 unexplained NaN and 0 values where the rule expects NaN.

**C3 `session_duration_s` — passes the retention evidence, with a named Cowrie artefact [O].**
- **No pre-fix sessions:** failed-session median 1.1 s in all six categories (max 1.9 s). 0% within 1 s of 120 s or 180 s (Task 11: 25–70% at 120 s).
- **L2 below the spec proposal:** ε² 0.39 (< 0.8); lookup 0.40 (< 50%).
- **Not mostly explained by category after line count:** residual ε² **0.066** (Task 11: 0.64).
- **Artefact:** the Cowrie `find` delay (section 7B).

**C4:**
- **`shell_operator_lines` — passes [O].**
  - Non-zero in 5 of 6 categories (benign 47%, botnet 47%, lateral movement 44%, reconnaissance 25%, privilege escalation 87%).
  - 2–3 distinct values within each category that uses operators (brute force is all 0).
  - BA at chance (0.167); lookup 0.37 (< 50%).
  - ε² 0.215 is flagged only at the two lowest ε² thresholds.
- **`download_command_lines` — fails "values vary within categories" [O].**
  - It is 1 in every botnet session. It is non-zero in benign (14%) and reconnaissance (34%), which is improved from botnet-only.
  - The spec's C4 failure handling is "broaden and overlap vocabularies and regenerate; **if still failing → inactive**". This is the post-redesign run.

**Core `tty_output_bytes` [O]:**
- ε² 0.44, with a residual after input bytes of **0.176** (Task 11: 0.42).
- Brute force is 100% outside other categories' range (median 328 bytes: banner and prompt).
- Without brute force, ε² is 0.15.
- Output volume is Cowrie's emulated output, for example reconnaissance median 2,523 bytes and benign IQR 6,191 bytes.

**Core content features [O]:** discussed in sections 4 and 7A.

## 7. Phase 3 investigations

### A. Repeated command sequences and vocabulary [O]

**Repetition across splits.**
- 50 of 559 validation interactions with commands (8.9%) use an exact sequence also seen in train. They come from 14 distinct sequences.
- By category:

| Category | Repeating / with commands |
|---|---|
| brute_force | 38 / 38 |
| benign | 8 / 229 |
| lateral_movement | 3 / 78 |
| botnet | 1 / 71 |
| privilege_escalation | 0 / 69 |
| reconnaissance | 0 / 74 |

- Excluding brute force, 2.3% repeat.
- **None** of the 14 sequences occurs in train under another category.
- These are different interactions (0 shared interaction IDs or sessions), **not duplicate data**.

**Brute force by design.**
- Its post-login pool is three single commands (`echo ok`, `uname -a`, `whoami`).
- Its train-internal repeat share is therefore 100%, against benign 3.2%, lateral movement 2.1%, privilege escalation 1.1%, botnet 0% and reconnaissance 0%.
- This is legitimately recurring behaviour, but it is also a memorisation path: a model can tie "single `uname -a` after 3–5 failed logins" to brute force.

**Vocabulary overlap.**
Command names were observed in logged-in sessions; Task 11's training run was recomputed read-only with the same definition.

| | Task 11 (gen 2.0, compat-era profiles) | V2 train | Static (Task 12: compat → revised) |
|---|---|---|---|
| Command names | 49 | 50 | — |
| Shared by ≥ 2 categories | 8 | **17** | 12 → 20 |
| Mean pairwise Jaccard | 0.088 | **0.186** | 0.102 → 0.182 |
| Category pairs sharing no name | 6 of 15 | **0 of 15** | 7 of 21 → — |
| Sequences shared across categories | 0.0% | 0.0% | 0.0% → 0.0% |
| First command → category | 84.2% | 73.3% (74.3% transfer) | 80.9% → 70.8% |

The empirical results confirm the static redesign figures closely.

**First command still identifies most categories** (train→validation recall):

| Category | Recall | Typical first commands |
|---|---|---|
| benign | 0.95 | `who`/`w`/`uptime` |
| lateral_movement | 0.90 | `cat` 51%, `ip`, `arp` |
| privilege_escalation | 0.90 | `groups`/`whoami`/`id` |
| botnet | 0.66 | `uname` 53%, `cat` |
| brute_force | 0.62 | — |
| reconnaissance | **0.00** | Its first commands are each owned by another category |

### B. Cowrie `find` execution artefact [O]

**Execution vs think time** (manifest, audit only):
- Execution delay for all other commands: median 0.047 s, p95 0.063 s in both splits.
- Think time: median 1.48 s (train) and 1.51 s (validation), category-independent (section 6).
- `find / -name id_rsa 2>/dev/null` takes 11.4–13.5 s. It is the only command ≥ 5 s and appears only in privilege escalation: 30 of 175 train sessions and 9 of 69 validation sessions.

**Diagnostic copies** (recorded values untouched; train, logged-in):

| Variant | ε² [95% CI] | Single BA | PE median |
|---|---|---|---|
| Recorded `session_duration_s` | 0.393 [0.354, 0.428] | 0.314 | 14.6 |
| Minus slow-command execution | 0.385 [0.353, 0.418] | 0.311 | 13.4 |
| Minus all command execution | 0.382 [0.348, 0.418] | 0.309 | 13.15 |
| Excluding the 30 find sessions | 0.392 [0.354, 0.436] (residual after lines 0.057) | 0.314 | — |
| Manifest think sum (pacing only) | 0.400 | 0.324 | 10.7 |

**What the variants show:**
- Duration's category dependence is the **number of commands × category-independent think time**. The think-only sum carries the same ε² (0.40).
- Execution time is not the source, and the `find` pause hardly moves the category-level statistics.

**Session-level effect:**
- PE duration median is 25.75 s with `find` vs 13.3 s without. Minus the `find` execution, the median is 14.0 s, back to the PE level.
- 21 of 30 PE `find` sessions exceed the non-PE p95 (23.6 s).
- Share of each category above that p95: PE 15.4%, botnet 12.8%, reconnaissance 6.1%, benign 5.0%, lateral movement 1.6%.
- `inter_input_mean_s` median is 3.9 s in `find` sessions vs 1.83 s otherwise. The ranges overlap (find minimum 0.81 s; non-find maximum 8.15 s). L1 shows PE outside other categories' duration range in only 1.7% of sessions.

**Verdict:**
- **Partial, category-exclusive mechanism:** an execution pause ≥ 5 s is 100% PE.
- **No category-wide fingerprint in the features:** the resulting values overlap other categories.
- **What it means for a model:** it can add PE-specific information to a small tail (2% of logged-in sessions).
- Validation reproduces this: 8 of 9 `find` sessions are above the non-PE p95.

### C. Class imbalance [O]

| Category | Train interactions (share) | Train rows (share) | Rows per interaction | Validation interactions / rows |
|---|---|---|---|---|
| benign | 561 (37.4%) | 863 (27.1%) | 1.54 | 229 / 355 |
| brute_force | 198 (13.2%) | **1,018 (31.9%)** | **5.14** | 79 / 398 |
| botnet | 195 (13.0%) | 392 (12.3%) | 2.01 | 71 / 136 |
| lateral_movement | 192 (12.8%) | 294 (9.2%) | 1.53 | 78 / 118 |
| reconnaissance | 179 (11.9%) | 362 (11.3%) | 2.02 | 74 / 151 |
| privilege_escalation | 175 (11.7%) | 261 (8.2%) | 1.49 | 69 / 99 |

- **Imbalance ratio (max/min):** 3.2 for interactions and 3.9 for rows (validation 3.3 / 4.0).
- **Row-level metrics are dominated by brute force.** A diagnostic all-session random forest (13 features, grouped CV) shows this:
  - row accuracy 0.684 vs balanced accuracy 0.597;
  - brute-force recall 0.995 vs 0.35–0.63 for the others;
  - **46% of all correct rows are brute force**;
  - majority-class row accuracy 0.319.
- Therefore every statistic here is reported on the logged-in set (one row per interaction) as primary, with grouped CV and balanced accuracy.
- Nothing was resampled.

### D. Missingness and login behaviour [O]

**All NaN is genuine undefined value, not extraction error:**
- 0 unexplained NaN, 0 values where the rule expects NaN;
- 0 rows with `extraction_status ≠ ok`, 0 warnings.

NaN patterns over (`input_line_max_bytes`, `time_to_first_input_s`, `inter_input_mean_s`, `inter_input_std_s`) in train:

| Pattern | Rows | Meaning |
|---|---|---|
| 1111 | 1,789 | 1,690 failed guesses + 99 brute-force logins with no command |
| 0000 | 1,292 | |
| 0011 | 99 | Brute-force logins with exactly one command |
| 0001 | 10 | Exactly two lines |

- **Every pattern is a deterministic function of `login_success` and `input_line_count`, which are themselves features.** Missingness therefore adds **no information beyond the existing features**, but it repeats the "failed login / brute force" signal.
- **Association:** all-session V is 0.49–0.58; logged-in V is 0.68–1.00, driven entirely by brute force, the only category with logged-in sessions that have fewer than 2 lines.
- **Shortcut strength** (diagnostic depth-3 tree on the four NaN indicators only):
  - all-session BA 0.275, vs 0.243 for `login_success` alone;
  - logged-in BA 0.333, which is exactly "brute force vs the rest".
- **Risk:** the shortcut enters a model only through how NaN is encoded. A constant imputation or a missing-value indicator would carry it. No indicator was introduced and no NaN was replaced.

### E. Capture-day differences (train 2026-11-10, validation 2026-11-11) [O]

KS tests compare train with validation (logged-in sessions):
- **Pooled, 13 features:** all p ≥ 0.09; D ≤ 0.062.
- **Within category (59 tests):** **0** with p < 0.01. Largest D 0.19 (`tty_output_bytes`, reconnaissance, p ≥ 0.01).

| Measure | Train | Validation |
|---|---|---|
| Execution delay median / p95 (excluding `find`) | 0.047 / 0.063 s | 0.047 / 0.063 s |
| Think-time median | 1.482 s | 1.505 s |
| `command.failed` per command sent | 0.0651 | 0.0643 |
| Failed-guess duration median | 1.1 s | 1.1 s (KS D 0.10) |
| Row login-success rate | 0.470 | 0.477 |
| Failed guesses per brute-force interaction | 4.14 | 4.04 |

**Cowrie output** (client terminal capture, diagnostic only):
- 83 of 146 commands have identical median output characters in both splits.
- The rest differ by 0.5–6 characters. The largest are `crontab -l` 53 vs 47 and `ping` 78 vs 83: dates, timestamps and randomised emulator text.

**Conclusion:** no observable capture-day effect on features, timing, Cowrie latency, output or login behaviour. The test has limited power for small per-category shifts [L].

**Excluded banner events:** documented, and confirmed absent from every slice and label file.
- Train baseline lines 968–969 (session `f255752d1854`, 2026-11-10 12:42:51Z).
- Validation baseline lines 1–2 (session `9985cff5a074`, 2026-11-11 05:10:44Z; the log-rotation trigger).

## 8. Before/after summary (Phase 5)

| Question | Static profile design (Task 12, planned sessions) | Empirical telemetry (this task) | Verdict |
|---|---|---|---|
| Command vocabulary overlap improved? | Jaccard 0.10 → 0.18; shared names 12 → 20 | Jaccard 0.088 → 0.186; shared names 8 → 17; disjoint category pairs 6 → 0 | **Yes** |
| First-command prediction decreased? | 80.9% → 70.8% | 84.2% → 73.3% (74.3% transfer); reconnaissance now 0% | **Yes, modestly; still strong for 5 of 6** |
| Exact sequence memorisation remains? | 0% cross-category | Coverage 27% → 14%, still 100% precise; 8.9% of validation repeats train (mostly brute force) | **Remains, at half the coverage** |
| Timing leakage reduced? | `delay_range` removed | C2 ε² 0.79 / 0.41 → 0.009 / 0.016 | **Yes, removed** (values) |
| Session-duration leakage remains? | — | ε² 0.80 → 0.39; residual 0.64 → 0.066; 0 at 120 s; without brute force 0.095 | **Largely removed.** The remainder is command count; `find` tail named |
| Conditional features more reliable? | — | C2 passes on values; C3 passes; C4 operators pass; C4 downloads and C1 fail | **Mostly** |
| Output-volume leakage remains? | — | `tty_output_bytes` ε² 0.60 → 0.44; residual 0.42 → 0.18; mostly brute force | **Reduced; emulation-dependent** |
| Missingness a category shortcut? | — | Yes, as before (V up to 1.0), but fully determined by `login_success` and `input_line_count` | **Persists structurally; must be handled at imputation** |
| Multi-feature separability | — | RF BA 0.97 → 0.88 (0.87 transfer) | **Reduced, still high** |

## 9. Feature eligibility (evidence for the Task 16 decision)

Full evidence is in `feature_eligibility.csv`.

**Statuses:**
- **Eligible:** passes all checks, no material concern.
- **Eligible with limitations:** passes the spec's retention evidence; the remaining category information is behavioural design, with named limitations.
- **Conditional:** fails an L2 proposal (lookup > 50%) through a template mechanism, so it needs an explicit decision or more evidence.
- **Inactive:** fails a criterion whose spec failure handling is deactivation.

The specification is unchanged and every feature stays in the extractor output.

| Feature | Group | Task 11 decision | Key V2 evidence | Recommended |
|---|---|---|---|---|
| login_success | core | Retain | Constant when logged in; all-session ε² 0.16 = designed failed-guess mix | **Eligible with limitations** |
| login_failed_count | C1 | Exclude | = 1 − login_success in 100% of rows; ρ −1.0 | **Inactive** |
| session_duration_s | C3 | Investigate | ε² 0.39 (0.095 without brute force); residual 0.066; no 120/180 s; `find` tail | **Eligible with limitations** |
| input_line_count | core | Investigate | ε² 0.52 (0.25 without brute force); lookup 0.53; ρ 0.91 with unique names | **Eligible with limitations** (keep one of the redundant pair) |
| input_bytes_total | core | Investigate | ε² 0.59 (rose from 0.48); lookup 0.54; ρ 0.83 with max bytes | **Conditional** |
| input_line_max_bytes | core | Investigate | BA 0.57 (strongest, unchanged without brute force); lookup 0.71; botnet 53% outside range | **Conditional** |
| unique_command_names | core | Investigate | ε² 0.59; lookup 0.55; redundant with line count | **Eligible with limitations** (redundancy) |
| shell_operator_lines | C4 | Exclude unless vocabularies change | Non-zero in 5 categories; BA at chance; PE 87% | **Eligible with limitations** |
| download_command_lines | C4 | Exclude unless vocabularies change | Botnet constant 1; ε² 0.58 | **Inactive** |
| time_to_first_input_s | C2 | Investigate | ε² 0.007; CV 0.81; flags only from missingness | **Eligible with limitations** |
| inter_input_mean_s | C2 | Exclude on 2.0 evidence | ε² 0.009 (from 0.79); missingness V 1.0; `find` tail | **Eligible with limitations** |
| inter_input_std_s | C2 | Exclude on 2.0 evidence | ε² 0.016; NaN for 60% of rows | **Eligible with limitations** |
| tty_output_bytes | core | Investigate | ε² 0.44; residual 0.18; Cowrie-emulation dependent | **Eligible with limitations** |

**Notes for the Task 16 decision** (not decided here):
1. Pick one of `input_line_count` / `unique_command_names`.
2. Decide on the two byte-length features (`input_line_max_bytes`, `input_bytes_total`; ρ 0.83).
3. Agree a NaN policy that does not re-encode missingness.
4. Plan a with/without-`find` sensitivity check and per-category (balanced) reporting.
5. Interpret brute force at interaction level, because its failed guesses are separate rows.

## 10. Limitations

- **[L] Labels are generation intent.** The data is synthetic: one client, one relay IP, and a pacing model by design. High separability among lab categories is not evidence of real-world behaviour.
- **[L] Deployment L7 is untestable.** No real-attacker logs exist. The spec rates timing features and `login_failed_count` as low deployment compatibility.
- **[L] Category separation is not in itself leakage** for an unsupervised project. It matters when it comes from generator, template or emulation mechanisms; sections 6–7 attribute it to those.
- **[L] Single diagnostics.** The single-feature classifier is one choice (depth-3 tree), and the lookup metric is not chance-corrected. ε², lookup and L1 agree in direction.
- **[L] Limited capture-day power.** Only two capture days exist, and the per-category KS tests have limited power for small shifts.
- **[L] No figures** (matplotlib absent; environment left unchanged).
- **[L] Exfiltration** is absent from train and validation by design. Its fingerprints (Task 12: `curl -T`, `tar`) are untested until the sealed test.

## 11. Integrity

- **Created:** `reports/dataset_v2_leakage_validation_20261111/` (this report, two scripts, `feature_eligibility.csv`, `tables/`, and `SHA256SUMS` over all of them).
- **Reproducibility:** a second full run of both scripts gave identical results. The only change between runs was a corrected spec-version field in `input_verification`.
- **Modified:** none.
  - Dataset V2 `SHA256SUMS` re-verified after the analysis (section 2).
  - Profiles, generator, extractor and specification hashes are unchanged.
- **Read-only use of historical data:** Task 11's `leakage_results.json`, and the generator-2.0 `train_v1` raw log and labels (vocabulary comparison only).
- **Not accessed:** the test set.
- **Not done:** nothing was committed.
