# Dataset V2 training/validation — integrity report (Task 14B, Phase 5)

The machine-readable sources are:
- `evidence/integrity_train_validation.json` (from `extract_and_validate.py train validation`);
- `evidence/<split>_reconciliation.json`;
- `evidence/cross_split_sequence_overlap_by_profile.json`.

**Result: all ten checks pass.**

| # | Check | Train | Validation | Pass |
|---|---|---|---|---|
| 1 | **Generation completeness.** Every interaction ended `clean_exit`. No prompt timeouts. No command left unsent. | 1,500/1,500; 0; 0 | 600/600; 0; 0 | ✓ |
| 2 | **Raw-log integrity.** The before-run prefix of the log is unchanged. The slice contains only post-baseline lines. 0 malformed lines. 0 events without a session. | prefix `da2b4593…` ✓ | prefix `7fa4aa91…` ✓ | ✓ |
| 3 | **Reconciliation.** Cowrie sessions pair one-to-one with manifest auth attempts on username, password and outcome. 0 unmatched, 0 interactions not ok. | 3,190 = 3,190 | 1,257 = 1,257 | ✓ |
| 4 | **Command fidelity.** Commands sent equal commands recorded by Cowrie, in the same order. | 7,516 = 7,516 | 3,079 = 3,079 | ✓ |
| 5 | **Isolation during the run.** Every event comes from relay 172.22.0.2. 0 download/upload events. Containers running with 0 restarts. | ✓ | ✓ | ✓ |
| 6 | **Extraction determinism.** Two independent extractor runs give byte-identical `model_features.csv` and `session_metadata.csv`, and identical summaries (time stamps excluded). | ✓ | ✓ | ✓ |
| 7 | **Feature contract.** `model_features.csv` columns are exactly the 13 spec features, in spec order. No label, profile, credential, IP, session ID, manifest or terminal-output column. Labels are joined only to `session_metadata.csv`, by `session_ref`. | ✓ | ✓ | ✓ |
| 8 | **Missing-value rules** (`docs/extractor_v2_output_schema.md`). 0 violations. Every `extraction_status` is `ok`. 0 timestamp-order mismatches. | 0 | 0 | ✓ |
| 9 | **Labels.** Every feature row has exactly one label row and every label row has a feature row. attack_cat and label agree with the profile config. 0 held-out (exfiltration) rows. | 3,190 rows; 0 mismatch; 0 held-out | 1,257 rows; 0 mismatch; 0 held-out | ✓ |
| 10 | **Split independence.** Separate runs and seeds. 0 shared interaction IDs. 0 shared Cowrie session refs. Raw slices are disjoint (consecutive, prefix-checked). | — | — | ✓ |

## Details

**NaN counts** come from the extractor summary. All are structural: they occur exactly when there is no input,
or too few lines to compute the value.

| Feature | Train (3,190) | Validation (1,257) |
|---|---|---|
| `input_line_max_bytes`, `time_to_first_input_s` | 1,789 | 698 |
| `inter_input_mean_s` | 1,888 | 736 |
| `inter_input_std_s` | 1,898 | 738 |
| All other 9 features | 0 | 0 |

- **Train:** 1,789 = 1,690 failed-guess sessions + 99 brute-force logins that sent no command.
- **Validation:** 698 = 657 failed guesses + 41 brute-force logins that sent no command.

**Session roles by `attack_cat`:**

| attack_cat | Train | Validation |
|---|---|---|
| benign | 863 | 355 |
| brute_force | 1,018 | 398 |
| botnet | 392 | 136 |
| reconnaissance | 362 | 151 |
| lateral_movement | 294 | 118 |
| privilege_escalation | 261 | 99 |

**Identical command sequences across splits.** These come from different interactions, so they are *not*
shared data.
- 14 distinct sequences appear in both splits.
- They cover 8.9% of validation interactions that sent commands.

By profile (validation interactions whose exact sequence also occurs in train):

| Profile | Shared / with commands |
|---|---|
| brute_force | 38 / 38 |
| benign_admin | 8 / 229 |
| lateral_movement | 3 / 78 |
| botnet | 1 / 71 |
| privilege_escalation | 0 / 69 |
| reconnaissance | 0 / 74 |

Brute-force post-login sessions are single commands drawn from a very small pool (`whoami`, `uname -a`,
`echo ok`, …), so full overlap is expected. This is passed to Task 15 as an input. It is not treated as a
failure here.

**Descriptive event totals** (from metadata, not features):

| | Unknown-command events | URL download | Download failed | Redirect write | SCP stdin |
|---|---|---|---|---|---|
| Train | 489 | 0 | 0 | 0 | 0 |
| Validation | 198 | 0 | 0 | 0 | 0 |

## What was *not* done

None of the following happened in this task:
- model training or fitting;
- threshold tuning;
- feature selection;
- any change to the spec, generator, profiles, Cowrie or Docker;
- generating the sealed test set;
- accessing any existing test-set file;
- commits.
