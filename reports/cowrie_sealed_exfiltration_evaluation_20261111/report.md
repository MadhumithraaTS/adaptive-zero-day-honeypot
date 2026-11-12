# Sealed `data_exfiltration` test evaluation of the frozen Cowrie novelty baseline (Task 19B)

**Date:** 2026-11-11.

**This was the single approved evaluation of the sealed test category.** The test run was:
- generated once;
- sealed by hash immediately after generation (`evidence/sealed_raw_hashes.txt`, before any extraction);
- extracted once, plus one byte-identical determinism repeat;
- scored once at 15:16:13 UTC (`evidence/SCORING_DONE.lock`; `score_test.py` refuses a second run).

It was not rerun.

**Nothing was modified or added.** The novelty baseline, thresholds, features, preprocessing and model weights are unchanged. No model was trained or refit, no DEC run was made, no automated defence was added, and nothing was committed. Failed Cowrie command sessions are kept in the primary result.

**Headline:** the frozen methods flag the held-out category more often than validation (C: 4.3% vs 0.67%). The evidence shows this increase comes from one **Cowrie execution artefact**, not from exfiltration behaviour:
- the 11–14 s execution of `find / -name '*.sql' 2>/dev/null` inflates the inter-command timing features;
- without that command, the test flag rate equals the validation rate.

**This result is not evidence of zero-day or exfiltration detection.**

## 1. Freeze verification (before any test data existed)

`evidence/freeze_verification.json`: **all 16 checks pass.**

| Check | Result |
|---|---|
| Novelty config `configs/cowrie_novelty_baseline_v1.json` | `bd3a399e…`, equal to the Task 19A audit |
| Model files | Match their recorded hashes (`models/cowrie_novelty_baseline_20261111/`) |
| Clustering configs | 1.0.0 `8ae17612…` and 1.1.0 `18a4ab2b…`, both unchanged |
| Inputs, in order | `session_duration_s`, `input_line_count`, `shell_operator_lines`, `time_to_first_input_s`, `inter_input_mean_s`, `inter_input_std_s`, `tty_output_bytes` |
| Medians and scaler | Equal to the audited training-only values; no missingness indicators |
| Thresholds | A 1.171445, B 0.729190, C 1.692104 |
| Inference | Batch size 256; k = 5 |
| Method roles | C primary; A and B secondary |

**Pipeline self-check.** Immediately before scoring, the exact scoring code reproduced the published Task 18 validation scores and flags for all three methods (`evidence/scoring_record.json`). This step used only already-published validation data.

## 2. Test generation (approved design)

| Item | Value |
|---|---|
| Composition | 600 `data_exfiltration` interactions only. Single-profile config derived from `profiles_v2_revised.json` with the exfiltration profile unchanged (`config/profiles_v2_sealed_exfiltration.json`, `a6522877…`) |
| Placeholders | IPs and domains disjoint from train/validation (0 occurrences in 10,595 train/validation commands; `evidence/test_config_derivation.json`). `{dir}` unchanged |
| Seeds and speed | Planning 14103, pacing 9403 (unused anywhere; reuse check empty); `--speed 1`; generator 2.1 unchanged |
| Preflight | Containers running with 0 restarts and the same hardening. Isolation: VM, gateway, internet and test-placeholder IPs all `OSError`. Test suite 306 passed |
| Run | 09:46:43 to 12:47:19 UTC. **600/600 `clean_exit`**; 0 timeouts; 0 commands not sent |
| Cowrie log | 0 download/upload events. Prefix check passed: the first 11,964 lines of the after-snapshot equal the before-snapshot `9a7e15f7…`. Slice: 9,886 lines (`5235d7c8…`) |
| Reconciliation | 900 Cowrie sessions = 900 manifest attempts (600 logged in, 300 failed guesses); 0 unmatched; every event from 172.22.0.2 |
| Extraction | Two runs byte-identical: `model_features.csv` `8dbfdfa4…`, `session_metadata.csv` `fc461b40…`. Columns are exactly the spec's 13 |

**Scoring population.** The frozen novelty population is logged-in sessions, so **600 were scored**. The 300 failed-guess sessions are counted, not scored, as the frozen design specifies; none was removed for any other reason.

## 3. Results

| Method | Validation flag rate | Test flag rate [95% Wilson] | Flagged sessions | Cowrie-related flags (cat. 2) | Interpretation |
|---|---:|---:|---:|---:|---|
| A — reconstruction error | 0.67% (4/600) | 0.83% [0.36, 1.94] | 5 | 1 | Not different from validation (Fisher p = 1.0) |
| B — latent distance | 0.50% (3/600) | 2.17% [1.27, 3.67] | 13 | 7 (all 13 contain the slow `find`) | Increase (p = 0.020), carried entirely by slow-`find` sessions |
| **C — input distance (primary)** | 0.67% (4/600) | **4.33%** [2.97, 6.28] | **26** | 16 (23 of 26 contain the slow `find`) | Increase (p = 0.00005), carried by slow-`find` sessions |

**Flag rate split by whether the session ran the slow `find`** (`evidence/flag_rate_by_slow_find.json`):

| Method | Sessions with slow `find` (n = 220) | Sessions without (n = 380) | Validation |
|---|---:|---:|---:|
| A | 0.91% (2) | 0.79% (3) | 0.67% |
| B | 5.91% (13) | **0.00%** (0) | 0.50% |
| C | 10.45% (23) | **0.79%** (3) | 0.67% |

Without the slow command, the held-out category is flagged at the validation false-positive rate.

**Flagged session IDs:** listed per method in `method_comparison.csv` (`flagged_session_refs`) and `flagged_session_analysis.csv`.

**Agreement between methods:**
- 2 sessions are flagged by all three (`44ea810639ad`, `de9cd58fae25`); 28 sessions are flagged by any.
- Jaccard: A–B 0.13, A–C 0.15, B–C 0.44.
- Score Spearman: A–B 0.28, A–C 0.37, B–C 0.68.

**Score distributions:** `figures/score_distributions_validation_vs_test.png`.

## 4. Session-level artefact analysis (all 600 scored sessions)

| Evidence | Share of test sessions |
|---|---:|
| `tar` present | 100% |
| `tar` **failed** (`Cannot open: No such file or directory … Error is not recoverable`) | **100%**; no archive was ever created |
| `curl -T` present | 79.2% |
| `curl -T` **rejected** (`curl: option -T not recognized`) | **100% of those present**; no upload was ever attempted on the network |
| `find '*.sql'` / `'*.db'` printed any path | 0%; the expected data files do not exist in Cowrie's filesystem |
| `cowrie.command.failed` events | 0 (tar and curl "run" but fail inside the emulation, so they are not logged as unknown commands) |
| Slow Cowrie execution (a command with ≥ 5 s wait: `find / -name '*.sql'`) | 36.7% |
| Generator pacing anomaly (think time > training p99 of 8.67 s) | 5.5% |
| Command name never seen in training | `tar` (100%); every other name is shared |

**What this means for the features.** No exfiltration step succeeded inside the honeypot. The features record attempts and Cowrie's emulated failures, not data staging or transfer. `tar` is the only command name the baseline has never seen, but no frozen input encodes command identity, so it cannot drive any score.

## 5. Flagged-session classification

Rules were fixed and hashed **before scoring** (`evidence/preregistered_classification_rules.json`, `cb599d21…`, hashed during generation).

| Category | A | B | C |
|---|---:|---:|---:|
| 1. Behavioural novelty (input structure) | 0 | 0 | 0 |
| 2. Cowrie emulation failure/limitation | 1 | 7 | 16 |
| 3. Generator pacing/timing anomaly | 1 | 0 | 1 |
| 4. Ambiguous/insufficient evidence | 3 | 6 | 9 |

What the classification shows:
- **Every flag has timing as its dominant driver** (`inter_input_mean_s`, `inter_input_std_s`, `time_to_first_input_s`). None is driven by command count, operators or output volume.
- **Category 4 cases** mostly contain *both* the slow `find` and a long generator think time. The pre-registered rule therefore cannot separate the two causes, and they stay ambiguous rather than being forced into either category. All 6 category-4 sessions for B and 6 of C's 9 contain the slow `find`.
- **No flag supports behavioural novelty** under the pre-registered criteria.

## 6. Feature distributions, validation vs test (`test_feature_summary.csv`, `figures/feature_distributions_validation_vs_test.png`)

| Feature | Validation median | Test median | KS D | Test share above validation p99 |
|---|---:|---:|---:|---:|
| session_duration_s | 12.6 | 15.25 | 0.22 | 4.5% |
| input_line_count | 6 | 5 | 0.19 | 0% |
| shell_operator_lines | 0 | 1 | 0.25 | 0% |
| time_to_first_input_s | 1.62 | 1.65 | 0.06 (p 0.22) | 0.8% |
| **inter_input_mean_s** | 1.91 | **2.56** | **0.32** | **21.2%** |
| **inter_input_std_s** | 1.02 | **1.55** | **0.35** | **28.9%** |
| tty_output_bytes | 1,168.5 | 942 | 0.34 | 0% |

Exfiltration sessions differ from the known categories mainly in the inter-command timing tail, which is exactly where the slow `find` acts. Content-related inputs (line count, operators, output) shift but stay inside the validation range.

## 7. Interpretation: what was and was not detected

| Possible claim | Evidence | Verdict |
|---|---|---|
| Detecting an unseen dataset category | Higher flag rate on the held-out category (C 4.3% vs 0.67%) | **Only in a weak, aggregate sense**, and entirely through sessions that ran the slow `find` |
| Detecting unfamiliar command sequences | `tar` is unseen but not encoded by any input; 0 flags driven by command structure | **Not demonstrated** |
| Detecting Cowrie emulation failures/artefacts | 23/26 C flags and 13/13 B flags contain the 11–14 s `find /` execution; without it, the rate equals validation | **This is what the scores responded to** |
| Detecting generator timing anomalies | Long think times appear in 31–46% of B/C flags (4–5% of unflagged sessions) | **Contributes** (consistent with Task 18) |
| Detecting genuinely novel malicious (exfiltration) behaviour | No staging or upload succeeded; no flag is explained by input structure; the effect vanishes without the Cowrie delay | **Not supported** |

This mirrors the Task 18 sensitivity test, where `find / -name id_rsa` sessions were flagged once excluded from training. The baseline is sensitive to **unfamiliar Cowrie execution latency**, not to exfiltration as such. No generalisation beyond this single held-out category is claimed.

## 8. Limitations

- **Synthetic data:** generation intent from one client and one relay IP, with a category-independent pacing model.
- **Cowrie emulation:** `tar` and `curl -T` always fail and the target files do not exist, so no realistic exfiltration telemetry existed to detect.
- **Timing features:** these measure Cowrie latency plus generator pacing. The slow-`find` confound affects 37% of test sessions.
- **Scoring population:** only logged-in sessions were scored, per the frozen design; failed-guess sessions are not covered.
- **Lower bound on flags:** the validation reference is 600 known sessions. With 3–4 flags, rates have wide intervals (Wilson intervals in `method_comparison.csv`).
- **Classification rules:** they are heuristic. Category 4 is used whenever causes overlap.

## 9. Files

| Path | Content |
|---|---|
| `run_manifest.json` | Freeze checks, design, preflight, generation, sealing, scoring record, output hashes |
| `test_feature_summary.csv` | Per-feature test vs validation distributions |
| `test_scores.csv` | 600 sessions: scores, flags, imputation, artefact evidence |
| `flagged_session_analysis.csv` | Every flagged (method, session) pair with drivers, evidence and classification |
| `method_comparison.csv` | Per-method rates, intervals, tests, classification counts, flagged IDs |
| `figures/` | Score and feature distributions |
| `evidence/` | Freeze verification, sealed hashes, reconciliation, pre-registered rules, scoring record and internals, slow-`find` split |
| Scripts | `freeze_verify.py`, `make_test_config.py`, `run_test.sh`, `postprocess_test.py`, `score_test.py`, `analyse_test.py`, `make_manifest.py` |
| `SHA256SUMS` | Every file in this directory |

**Sealed test status:** this was the single approved evaluation. The test set must not be re-scored, used for tuning, or used for any model or threshold change. Any further evaluation needs a new, separately approved held-out run.
