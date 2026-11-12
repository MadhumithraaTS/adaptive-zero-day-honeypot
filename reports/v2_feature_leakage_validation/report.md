# Dataset V2 feature leakage validation (L1–L7)

**Date:** 2026-11-10. **Task 11.** Analysis only.

**Not done:** no generator, extractor or specification change, no new traffic or dataset, no model fitting (the classifiers below are single-purpose diagnostics, not clustering models), no test-set access, no use of evaluation data for any feature decision, no commits.

**Reproduce:** `.venv/Scripts/python.exe reports/v2_feature_leakage_validation/analyze_leakage.py`. Outputs:

| Path | Content |
|---|---|
| `extraction/train_v1/`, `extraction/confirmation_task9/` | Unmodified V2 extractor output |
| `tables/leakage_results.json` | All per-feature statistics and L1–L7 / C1–C4 results |
| `tables/category_distributions.csv` | Per feature × category: n, missing %, median, IQR, mean, min, max |
| `tables/correlation_spearman_logged_in.csv` | Spearman correlation matrix |
| `tables/data_provenance.json` | Run and label provenance |
| `tables/feature_eligibility.json` | Decision table, machine-readable |

**Labels:** **[O]** observed, **[H]** hypothesis, **[L]** limitation.

---

## 1. Headline

1. **The only eligible labelled training run predates every generator correction [O].** `train_v2_corrected` was produced by generator 2.0:
   - per-profile pacing;
   - timer-based sending;
   - unclosed failed logins;
   - a non-isolated Cowrie;
   - speed 8.

   No training run from the corrected generator 2.1 exists; Dataset V2 has not been generated. **Conclusions about timing, lifecycle and input-loss mechanisms (C2, C3, L6) therefore describe generator 2.0 and cannot validate 2.1 [L].**
2. **Three different categories of mechanism carry category information:**
   - **Content features carry strong category information because the profile vocabularies are disjoint [O].** No recorded command sequence occurs in two categories (0.0%). Command-name sets identify the category with 100% precision whenever they recur (61% of sessions), and the first command name alone is right 84% of the time. This mechanism **persists in generator 2.1**, because the compat profiles keep the same templates apart from three steps.
   - **`download_command_lines` and `shell_operator_lines` are single-category indicators [O].** Download commands appear in botnet only (100%); shell operators in privilege_escalation only (85%, from `2>/dev/null`).
   - **`login_failed_count` is exactly `1 − login_success` in all 3,123 sessions [O].**
3. **The robustness to thresholds is strong [O].** 11 of 13 features are flagged under every one of the 12 tested threshold combinations; `input_bytes_total` drops out only at the strictest pair. All 13 features together give a grouped-CV balanced accuracy of **0.97** (chance 0.17), and the 6 core features alone **0.96**.
4. **Recommendation:** treat all current eligibility as **provisional**. Before generating Dataset V2:
   - (a) redesign the profile vocabularies so commands overlap across categories;
   - (b) generate a generator-2.1 training run;
   - (c) re-run this script on it.

   Section 9 has the per-feature decision table.

## 2. Phase 1: eligible data

| Run | Source log | Sessions | Profiles | Pacing seed | Generator | Extractor | Role |
|---|---|---|---|---|---|---|---|
| **train_v1 / train_v2_corrected** | `dataset_builder/runs/train_v1/raw/cowrie_thisrun.json` | 3,199 extracted; **3,125 labelled** (74 eval_v1 sessions after the baseline excluded); 3,123 analysed (2 `inconsistent` excluded) | 6 (`profiles_v2.json` 2.0.0; held-out excluded) | none (pacing from planning RNG, seed 1) | 2.0 (not recorded) | V2 draft.3 (this task) | **Training: used** |
| eval_v1 / eval_v2_corrected | `dataset_builder/runs/eval_v1/raw/cowrie_thisrun.json` | 1,232 | 7 (includes held-out exfiltration) | none (seed 2) | 2.0 | — | Evaluation: **not used for decisions** (timestamp-anomaly count only) |
| Task 7 smoke test | `reports/generator_cowrie_smoke_test/…` | 21 | 5 (isolated) | 1 (reused) | 2.1 | — | Smoke test: not used |
| Task 9 confirmation | `reports/cowrie_compatibility_confirmation/…` | 28 (14 logged in) | 7 (compat) | 9101–9107 | 2.1 | V2 draft.3 | Smoke test: **L7 description only** |
| Task 10A verification | `reports/diagnostic_redaction_utf8_fix/…` | 2 | 2 | 9201–9202 | 2.1 | — | Smoke test: not used |
| Payload pilot | `reports/cowrie_payload_observability_pilot/…` | 5 | test markers | — | custom | — | Pilot: not used |

**Why train_v2_corrected is used despite its age:** it is the only labelled run of training scale. Using it is preferable to stopping, provided its conclusions are scoped (section 1). No runs were combined.

## 3. Phase 2: label and provenance integrity [O]

- **Labels:** `train_v2_corrected/label_assignments.csv` (labelling v2; `provenance.json` hashes the source run). Category = `source_attack_cat` (generation intent). The manifest is read only as audit evidence (L5, L6) and never by the extractor.
- **One label per session:** all 3,125 labelled sessions map to one extracted Cowrie session; 0 sessions have two labels; 0 interactions have two categories.
- **Grouping:** 1,500 interactions produce 1–6 sessions each (failed guesses are separate connections), with **at most one logged-in session per interaction**. All cross-validation is `GroupKFold(5)` by interaction, and bootstrap CIs resample interactions.
- **Primary analysis set:** the 1,498 logged-in sessions, one per interaction, so independent. The 3,123-session set is secondary.
- **Pacing and termination evidence:** pacing seeds and termination status **were not recorded by generator 2.0** [L]. Input loss is reconstructed from the manifest instead (L6).

## 4. Statistical methods

| Analysis | Method |
|---|---|
| Category dependence (continuous and count features) | Kruskal–Wallis on non-missing values; **ε² = H/(n−1)**, 95% CI from 200 group (interaction) bootstraps |
| Missingness | χ² test of the NaN indicator × category, Cramér's V |
| Single-feature prediction (L2) | Depth-3 decision tree on [value, NaN indicator] with NaN encoded as a sentinel; balanced accuracy, GroupKFold(5) by interaction; chance = 1/6 |
| Exact-value and fingerprint lookup (L2/L5) | Key → majority category learned on training folds, scored on held-out folds |
| Near-constants (L1) | Per-category modal share (≥ 0.95), and the share of a category's values outside every other category's range |
| Correlation | Spearman (logged-in sessions) |
| Residual effects (C3, `tty_output_bytes`) | OLS of log1p(feature) on line count / log1p(input bytes), then Kruskal–Wallis ε² of the residuals |
| Context | Random forest on all, core and non-C2/C3 features (grouped CV); an upper bound on category information, not a model |

**Thresholds:** ε² ∈ {0.06, 0.14, 0.26, 0.5} × BA margin over chance ∈ {0.10, 0.20, 0.35}, plus missingness V ≥ 0.5. These are **proposals**; the results are robust across them (section 1). **A non-significant p-value is never treated as evidence of safety**, and effect sizes are reported for every feature.

## 5. Per-feature results (logged-in sessions, n = 1,498)

| Feature | Group | Missing % | ε² [95% CI] | Single-feature BA | Exact-value lookup correct | Missingness V |
|---|---|---|---|---|---|---|
| login_success | core | 0 | constant (1) | 0.167 | — | 0 |
| login_failed_count | C1 | 0 | constant (0) | 0.167 | — | 0 |
| session_duration_s | C3 | 0 | **0.80** [0.78, 0.83] | 0.64 | 0.70 | 0 |
| input_line_count | core | 0 | 0.57 [0.54, 0.61] | 0.43 | 0.57 | 0 |
| input_bytes_total | core | 0 | 0.48 [0.44, 0.52] | 0.40 | 0.49 | 0 |
| input_line_max_bytes | core | 6.7 | 0.67 [0.63, 0.71] | **0.77** | **0.82** | 0.67 |
| unique_command_names | core | 0 | 0.57 [0.54, 0.61] | 0.46 | 0.57 | 0 |
| shell_operator_lines | C4 | 0 | 0.83 [0.78, 0.88] | 0.31 | 0.47 | 0 |
| download_command_lines | C4 | 0 | **1.00** [1.00, 1.00] | 0.33 | 0.48 | 0 |
| time_to_first_input_s | C2 | 6.7 | 0.003 [0.001, 0.016] | 0.25 | 0.02 | 0.67 |
| inter_input_mean_s | C2 | 14.0 | **0.79** [0.77, 0.81] | 0.66 | 0.00 | **0.99** |
| inter_input_std_s | C2 | 22.0 | 0.41 [0.36, 0.45] | 0.52 | 0.00 | 0.84 |
| tty_output_bytes | core | 0.2 | 0.60 [0.56, 0.63] | 0.51 | 0.32 | 0.12 |

**All sessions (n = 3,123):** `login_success` and `login_failed_count` ε² 0.18 (BA 0.25); `session_duration_s` ε² 0.08.

**Per-category distributions:** `tables/category_distributions.csv`.

**Correlation [O]** (|ρ| ≥ 0.8):

- `input_line_count`–`unique_command_names` ρ = **0.96** (redundant);
- `session_duration_s`–`inter_input_mean_s` ρ = 0.86.

## 6. L1–L7

| Check | Result |
|---|---|
| **L1 Constants** | `download_command_lines` is constant 1 in botnet and 0 elsewhere. Category values outside every other category's range: botnet `inter_input_mean_s` 92%; brute_force `tty_output_bytes` 84% and `session_duration_s` 70%; privilege_escalation `shell_operator_lines` 85% [O] |
| **L2 Single-feature prediction** | 11 of 13 features are above chance by grouped CV. The strongest are `input_line_max_bytes` (0.77), `inter_input_mean_s` (0.66) and `session_duration_s` (0.64) [O] |
| **L3 Label/identifier contamination: pass** | Re-extracting a copy of the training log with every `src_ip`/`src_port`/`dst_*`/`username`/`password`/`sensor`/`uuid`/`hassh`/`version` replaced and `attack_cat`/`label`/`profile` injected gives **identical** model features. The extractor reads only logs and the specification (task 10B tests and audit hook). 0 test-marker sessions. The session id is not a feature [O] |
| **L4 Duplicates and grouping: pass, with a note** | Session ids unique; 0 duplicate records. The 74 eval_v1 sessions in the train slice are excluded. 1 logged-in session per interaction. 6.5% of logged-in sessions share an identical feature vector, and 28.8% share their exact recorded command sequence with another session **of the same category**: template repetition, a profile effect, not duplication [O] |
| **L5 Profile fingerprints: fail** | Exact command sequences are never shared across categories (0.0%). Sequence lookup is 100% precise where it recurs (27% coverage); command-name-set lookup is 100% precise (61% coverage); first command name is right 84% of the time. Failed-guess sessions per interaction: brute_force 3–5 (profile setting `failed_attempts` [3, 5]), others 0–2 [O] |
| **L6 Client/server contamination: category-dependent in generator 2.0** | Manifest lines missing from Cowrie: **botnet 43.8% of lines (82% of sessions)**, lateral_movement 7.7% (26%), all others 0%. χ² p ≈ 0, Cramér's V **0.80**. 0 extra lines among assigned sessions. `tty_output_bytes` vs `input_bytes_total` Spearman 0.50 (echo plus emulation output) [O]. The loss came from timer-based sending, and generator 2.1 showed 0/59 lost lines (task 9) [O, but small] |
| **L7 Training vs live meaning: changed between generators** | No real-attacker deployment logs exist, so deployment L7 is **untestable** [L]. Generator 2.0 training vs generator 2.1 confirmation (descriptive, 14 sessions): failed-login duration median 120 s vs 1.1 s; logged-in duration median 1.8 s vs 16.5 s; `time_to_first_input_s` 0.10 s vs 2.23 s; `inter_input_mean_s` 0.38 s vs 2.66 s; completed downloads 8 vs 0 (isolation). The timing and lifecycle features **mean different things** in the training run and in V2 generation [O] |

## 7. Conditional groups (C1–C4) and core features

**C1 `login_failed_count` [O]:** it equals `1 − login_success` in 3,123/3,123 sessions (Spearman −1.0). It is 0 in every logged-in session and 1 in every failed session. Generator 2.1 still opens one connection per attempt, so the redundancy persists. **Fails C1 retention evidence.**

**C2 timing:**

- **`time_to_first_input_s`:** its values hold no category information (ε² 0.003; median 0.0997 s in all six categories, which is generator 2.0's fixed 0.0625 s wait plus latency). That is **near-constant generator output: fails C2 (c)**. Its category information comes from missingness only (V 0.67: brute force sessions without input).
- **`inter_input_mean_s` and `inter_input_std_s`:** strong category dependence (ε² 0.79 and 0.41). Spearman **0.88** between `inter_input_mean_s` and the profile `delay_range` midpoint, i.e. direct generator-2.0 pacing [O]. **Fails C2 (a) and (b) on this run.**
- **Generator 2.1 removed the mechanism; the features are untested there [L].**

**C3 `session_duration_s`:**

- ε² 0.80; even after accounting for line count, residual ε² **0.64**.
- Every failed-only session lasts 120 s (the pre-fix unclosed connection), and the share of sessions within 1 s of 120 s ranges from 25% (lateral_movement) to 70% (brute_force).
- 0 sessions near 180 s.
- **Fails C3 (a)–(d) on this run [O]; untested on 2.1 [L].**

**C4:**

- **`download_command_lines`:** non-zero in botnet only (100%).
- **`shell_operator_lines`:** non-zero in privilege_escalation only (85%, `2>/dev/null` in `find` templates).
- **Both fail C4 (b)** (non-zero in ≥ 2 categories) [O]. The compat profiles don't change this: they add a download command only to the held-out exfiltration profile.

**Core content features** (`input_line_count`, `input_bytes_total`, `input_line_max_bytes`, `unique_command_names`):

- ε² 0.48–0.67, driven by **disjoint fixed vocabularies** (L5) [O].
- Botnet and lateral counts are additionally biased by generator-2.0 line loss (L6) [O].
- `input_line_max_bytes` is the strongest single fingerprint (BA 0.77; exact-value lookup 82%), because each template has characteristic command lengths.

**Core `tty_output_bytes`:**

- ε² 0.60; residual ε² after input bytes **0.42**.
- The output volume carries category information beyond the input, from **Cowrie's per-command output verbosity** applied to fixed templates (for example `ps aux`, `cat /etc/passwd`) [O].
- Brute force output is outside every other category's range for 84% of its sessions (banner plus prompt only).
- **[H]** In real deployment, verbosity depends on what attackers run, so this is legitimate behaviour there. In lab data it fingerprints the template.

**Core `login_success`:** constant in logged-in sessions. Across all sessions, its category information comes from the number of failed-guess sessions each profile is designed to make; that is behavioural design, not an artefact.

## 8. Timestamp anomalies (Phase 5)

| Run | Logged-in sessions with input | First input before `login.success` | Categories | Lag |
|---|---|---|---|---|
| train_v1 (generator 2.0) | 1,537 | 2 (`05d209c87f5b`, `9f61c9c8a900`) | reconnaissance, benign | −0.017 s, −0.319 s |
| eval_v1 (generator 2.0; data quality only) | 600 | 2 (`42751448ddb0`, `cac085b9da31`) | exfiltration, benign | −0.310 s, −0.015 s |
| Task 9 confirmation (generator 2.1) | 14 | **0** | — | — |

- **[O]** The anomalies are isolated to generator-2.0 runs: 4 of 2,137 sessions (0.19%), in 3 different categories. No category association is detectable with 4 cases.
- **[O]** In 3 sessions the first input also precedes `cowrie.session.params` (1 in train, 2 in eval).
- **[O]** Excluding the two training sessions changes `time_to_first_input_s` ε² from 0.00292 to 0.00290. No conclusion changes.
- **[H]** Cowrie stamps `command.input` when it receives the line, which can be before it emits `login.success`/`session.params` for a client that types before the shell is ready. Generator 2.0's 62.5 ms post-shell wait allowed this; prompt-gating in 2.1 prevents it. The cause is not verified in Cowrie's source.
- **No timestamps or values were altered.** The extractor already flags such sessions (`negative_time_to_first_input`).

## 9. Feature eligibility (evidence for a separate approval decision)

The specification is unchanged; all 13 features stay in the raw extraction.

| Feature | Group | Leakage evidence (generator-2.0 training run) | Decision |
|---|---|---|---|
| login_success | core | Constant in logged-in sessions; across all sessions only the designed failed-guess mix (ε² 0.18) | **Retain** |
| login_failed_count | C1 | = 1 − login_success in 100% of sessions (ρ = −1); persists in 2.1 | **Exclude** (deactivate) |
| session_duration_s | C3 | ε² 0.80, residual 0.64; 120 s failed sessions; pacing-driven | **Investigate:** fails C3 on 2.0; re-test on a 2.1 run |
| input_line_count | core | ε² 0.57; disjoint templates (L5); L6 loss bias | **Investigate** (needs overlapping vocabularies) |
| input_bytes_total | core | ε² 0.48; fixed strings; L6 bias | **Investigate** |
| input_line_max_bytes | core | ε² 0.67; BA 0.77; lookup 82% | **Investigate** (strongest template fingerprint) |
| unique_command_names | core | ε² 0.57; ρ 0.96 with input_line_count | **Investigate** (redundant) |
| shell_operator_lines | C4 | Non-zero in privilege_escalation only | **Exclude unless vocabularies change** |
| download_command_lines | C4 | Botnet-only indicator (ε² 1.0) | **Exclude unless vocabularies change** |
| time_to_first_input_s | C2 | Near-constant generator wait (ε² 0.003); category signal via missingness only | **Investigate:** re-test on 2.1 |
| inter_input_mean_s | C2 | ε² 0.79; ρ 0.88 with profile delay_range; missingness V 0.99 | **Exclude on current evidence;** re-test on 2.1 |
| inter_input_std_s | C2 | ε² 0.41; same mechanism | **Exclude on current evidence;** re-test on 2.1 |
| tty_output_bytes | core | ε² 0.60; residual 0.42 beyond input (Cowrie verbosity × templates) | **Investigate** (emulation fingerprint) |

**Recommended next steps** (each needs approval):

1. Redesign the V2 profiles so command vocabularies, download commands and redirections overlap across categories (including benign).
2. Generate a generator-2.1 *training* run with fresh pacing seeds under the approved protocol.
3. Re-run `analyze_leakage.py` on it unchanged.
4. Decide C1 deactivation now (its redundancy is structural).

**Pipeline note:** missingness patterns themselves carry category information (V up to 0.99). Missing-value indicators added at imputation would carry it into the model.

## 10. Limitations

- **[L] Wrong generator for C2/C3/L6:** the training evidence is generator 2.0, so the 2.1 corrections (timing, lifecycle, line loss) are unvalidated statistically.
- **[L] Labels are generation intent,** not independent ground truth. Behaviour labels (`failed_login`, `login_no_commands`) are partly derived from the same events.
- **[L] Two categories (exfiltration, and the held-out profile generally)** are absent from training.
- **[L] L7 against real attackers is untestable** (no deployment data). The 14-session generator-2.1 comparison is descriptive.
- **[L] The single-feature classifier is one choice** (depth-3 tree). Other classifiers could score differently, but ε², lookups and L1 agree in direction.
- **[L] Category separation is not in itself leakage** for an unsupervised project. It becomes leakage when it comes from generator, template or emulation mechanisms rather than behaviour, which is what the mechanism analysis addresses.

## 11. Integrity

- **Created:** `reports/v2_feature_leakage_validation/` (this report, `analyze_leakage.py`, `extraction/`, `tables/`).
- **Modified:** none. SHA-256 over all repository files confirms no source dataset, model, generator, extractor or specification changed.
- **Not accessed:** the test set (`test_touches` = 0).
- **Not done:** nothing committed.
