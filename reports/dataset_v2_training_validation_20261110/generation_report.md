# Dataset V2 training/validation — generation report (Task 14B)

**Status:** generated and validated. **Training, threshold tuning and the sealed test run have not been
done.** Task 15 (L1–L7 leakage analysis) is waiting for approval.

Related files: [integrity_report.md](integrity_report.md), [timing_analysis.md](timing_analysis.md),
[design_proposal.md](design_proposal.md) (approved design, §4), and `SHA256SUMS` (all files in this
directory).

## 1. Approved design

| Item | Value |
|---|---|
| Train | 1,500 interactions, planning seed 14101, pacing seed 9401 |
| Validation | 600 interactions, planning seed 14102, pacing seed 9402 |
| Speed | `--speed 1` (same value required for the later test run) |
| Held-out `data_exfiltration` | Excluded from both splits (`include_held_out: false`); kept for the sealed test |
| Profiles | `dataset_builder/profiles_v2_revised.json`, config version 2.3.0-revised |
| Generator | `dataset_builder/generate_labelled_traffic.py` 2.1, unmodified |
| Extractor / spec | `scripts/extract_features_v2.py` / `configs/feature_spec_v2.json` (2.0.0-draft.3, 13 model features), unmodified |

## 2. Inputs (SHA-256, checked before train, before validation, and after both runs — unchanged)

| File | SHA-256 |
|---|---|
| `dataset_builder/profiles_v2_revised.json` | `79d47ac48e1f4c242ffcb851c567da884df21d039cc11917dc5bf3dea761fe62` |
| `dataset_builder/generate_labelled_traffic.py` | `f8c55f9d9631913598676e12cd6b24a9fa7f8707229d01fe0c512d6e578e1fa4` |
| `scripts/extract_features_v2.py` | `c0fdc684483e9953db2b6240994daa2b712d9782275eeebff9a38d57344cd5f2` |
| `configs/feature_spec_v2.json` | `9401b355a1bfc48a14da32efba9ad4d5992f55233da3437a0715690d76f8fb1a` |
| `cowrie/docker-compose.yml` | `cd84da489d29840d1f7c81465359b023caa139ad908e37b0c3e622f47f32e9f5` |
| `cowrie/userdb.txt` | `46d68fb536f006093fcc1f3e0b6314fe60bf0826d8113201d13de9f859bd0649` |

Environment:
- Cowrie image `cowrie/cowrie@sha256:bf371c37…cc13a` (2.9.17.dev1).
- Containers `cowrie-project` (`0bec5a78b1cb`) and `cowrie-ssh-relay` (`8d3bafb35f38`): both `running` with 0 restarts throughout. Both are read-only, run with `cap_drop ALL` and `no-new-privileges`.
- Network `cowrie_internal`: `internal: true` with `gateway_mode_ipv4: isolated` (R2, Task 14A/14A.1).
- Published only on `127.0.0.1:2223`.

## 3. Pre-generation audit (`preflight/`)

| Check | Result |
|---|---|
| Full test suite (`preflight/test_suite.txt`) | 306 passed, 5 warnings |
| Isolation (`preflight/isolation_checks.txt`) | From inside Cowrie, these connections failed with `OSError`: VM 192.168.65.3:111, 192.168.65.254:80 and 1.1.1.1:53. There is no gateway route. The relay resolves `cowrie` → 172.22.0.1. |
| Containers (`preflight/containers.txt`) | Running, restarts 0, hardening as above |
| Seed reuse (`find_pacing_seed_reuse`) | 9401 and 9402 unused (`pacing_seed_reuse.reused_by: []` in both `run_meta.json`) |
| Held-out test set | Not accessed. `ml_pipeline/work/test.pkl` was last modified 2026-11-08 21:40, before this task |
| Pre-validation recheck (`preflight/pre_validation_checks.txt`) | Input hashes unchanged; isolation rechecked |

## 4. Exact commands

Both runs went through `run_split.sh` from the repository root. That script:
1. takes a `docker cp` snapshot of `cowrie.json` before the run;
2. runs the generator;
3. takes a second snapshot after the run;
4. checks that the first *N* lines of the after-snapshot hash the same as the before-snapshot (prefix check);
5. writes everything after the baseline to `raw/<split>/cowrie_slice.json`.

```
bash reports/dataset_v2_training_validation_20261110/run_split.sh train 1500 14101 9401
bash reports/dataset_v2_training_validation_20261110/run_split.sh validation 600 14102 9402
```

The generator command each one ran (from `logs/generator_console_<split>.txt`), with `<S>`, `<A>`, `<P>` set
per split:

```
.venv/Scripts/python.exe -W ignore dataset_builder/generate_labelled_traffic.py \
  --config dataset_builder/profiles_v2_revised.json --host 127.0.0.1 --port 2223 \
  --sessions <S> --seed <A> --pacing-seed <P> --speed 1 \
  --output-dir reports/dataset_v2_training_validation_20261110/runs/<split> \
  --runs-root reports/dataset_v2_training_validation_20261110/runs --container cowrie-project
```

Post-processing:

```
.venv/Scripts/python.exe reports/dataset_v2_training_validation_20261110/reconcile_split.py <split>
.venv/Scripts/python.exe reports/dataset_v2_training_validation_20261110/extract_and_validate.py train validation
.venv/Scripts/python.exe reports/dataset_v2_training_validation_20261110/timing_analysis.py train validation
```

No generator parameter was changed between or during runs. No session was regenerated, replaced or discarded.

## 5. Runs

| | Train | Validation |
|---|---|---|
| Start / end (UTC) | 2026-11-10 12:45:44 → 19:06:27 | 2026-11-11 05:10:58 → 07:44:46 |
| Interactions | 1,500 / 1,500 `clean_exit` | 600 / 600 `clean_exit` |
| Cowrie log baseline | 969 lines, `da2b4593…` | 2 lines, `7fa4aa91…` |
| After | 30,924 lines, `d014d445…` | 11,964 lines, `9a7e15f7…` |
| Prefix check | first 969 lines = baseline ✓ | first 2 lines = baseline ✓ |
| Slice | 29,955 lines, `60c38527…` | 11,962 lines, `68879496…` |
| Cowrie sessions = manifest auth attempts | 3,190 = 3,190 | 1,257 = 1,257 |
| Logged in / failed guesses | 1,500 / 1,690 | 600 / 657 |
| Commands planned = sent = recorded in Cowrie | 7,516 | 3,079 |
| Prompt timeouts / not sent / order mismatches | 0 / 0 / 0 | 0 / 0 / 0 |
| Download or upload events | 0 | 0 |
| `cowrie.command.failed` (emulation gaps) | 489 | 198 |
| Source IP of every event | 172.22.0.2 (relay) | 172.22.0.2 (relay) |

### Per-profile (interactions → Cowrie sessions)

Train:

| Profile | Interactions | Sessions | Commands | `command.failed` | Median duration (s) |
|---|---|---|---|---|---|
| benign_admin | 561 | 863 | 3,049 | 204 | 12.3 |
| botnet | 195 | 392 | 1,355 | 179 | 15.2 |
| brute_force | 198 | 1,018 | 99 | 0 | 2.7 |
| lateral_movement | 192 | 294 | 864 | 106 | 10.2 |
| privilege_escalation | 175 | 261 | 1,022 | 0 | 14.6 |
| reconnaissance | 179 | 362 | 1,127 | 0 | 14.3 |

(Source: `evidence/train_profile_table.json`.)

Validation (`evidence/validation_profile_table.json`):

| Profile | Interactions | Sessions | Commands | `command.failed` | Median duration (s) |
|---|---|---|---|---|---|
| benign_admin | 229 | 355 | 1,309 | 84 | 13.0 |
| botnet | 71 | 136 | 506 | 62 | 15.5 |
| brute_force | 79 | 398 | 38 | 0 | 2.6 |
| lateral_movement | 78 | 118 | 353 | 52 | 10.6 |
| privilege_escalation | 69 | 99 | 416 | 0 | 15.7 |
| reconnaissance | 74 | 151 | 457 | 0 | 14.85 |

Category counts are random draws from `weighted_profile_order` (benign weight 3, others 1), as the design
anticipated. They are not balanced.

## 6. Log-rotation event between the runs (documented, not hidden)

Cowrie rotates `cowrie.json` on the first write after the UTC date changes, not exactly at midnight. At
05:10 UTC on 2026-11-11 no write had happened yet, so rotation had not occurred.

To give validation a clean baseline, **one SSH banner read through the relay** was made at 05:10:44 UTC to
trigger the rotation (`preflight/log_rotation_trigger.txt`). Results:
- `cowrie.json.2026-11-10` is byte-identical to the train after-snapshot (30,924 lines, `d014d445…`). The train slice is therefore complete.
- The new `cowrie.json` held only the 2 trigger events (connect + closed, `7fa4aa91…`).

Those 2 events form the validation baseline and are **excluded** from the validation slice. Likewise, the 2
relay preflight events before train (lines 968–969 of the train baseline) are excluded from the train slice.
Neither appears in any labelled dataset.

## 7. Outputs

| Path | Content |
|---|---|
| `runs/<split>/manifest.jsonl`, `run_meta.json`, `terminal_output.jsonl` | Generator output. `terminal_output` is diagnostic only and never a feature source |
| `raw/<split>/cowrie_before.json`, `cowrie_after.json`, `cowrie_slice.json` | Raw Cowrie evidence |
| `extraction/<split>/run1/` | `model_features.csv`, `session_metadata.csv`, `extraction_summary.json`. `run2/` is the byte-identical repeat |
| `labels/<split>_session_labels.csv` | session_ref → split, interaction_id, attempt, profile, attack_cat, label, role. **Metadata only, not features** |
| `evidence/` | Reconciliation, profile tables, command logs, integrity JSON, timing JSON/CSV, cross-split overlap |
| `logs/` | Generator and timing consoles |
| `SHA256SUMS` | Hashes of every file in this directory |

Extraction output hashes:

| | `model_features.csv` | `session_metadata.csv` | `extraction_summary.json` |
|---|---|---|---|
| train | `c0be0ef9e7822ab0…` | `b06bd56a6e4f4c4f…` | `fdb077cc15adf2b9…` |
| validation | `070f5ac16a93681f…` | `19bf5df1b5e60d8d…` | `a2879e8186561c84…` |

## 8. Known limitations

1. **Synthetic traffic.** Labels are generation intent. Every session comes from one client, through one
   relay IP, with one category-independent pacing model. This is not real attacker data.
2. **Cowrie emulation gaps** are part of the data:
   - `ip` and `arp` give `Exec format error`;
   - `/etc/sudoers` is missing;
   - `tar` fails;
   - `curl -T` gives an option error;
   - no downloads succeed (network isolated).

   Together these produce 489 + 198 `command.failed` events, concentrated in benign, botnet and lateral movement.
3. **Timing artefact.** `find / -name id_rsa` executes in about 11.6 s, and only privilege-escalation
   uses it. See [timing_analysis.md](timing_analysis.md). Task 15 must assess this.
4. **Brute-force command sequences repeat across splits.** All 38 validation brute-force sessions that ran
   commands used a single-command sequence also seen in train. These are tiny template pools such as `whoami`
   and `uname -a`, from different interactions, so this is not the same data appearing twice. It still means
   validation scores for brute force mostly measure recall of templates already seen.
5. **Unequal, random category counts.** Benign is about 37–38% of interactions. Session-level rows are
   dominated by brute-force failed guesses: 1,018 of 3,190 train rows.
6. **Different capture days.** The two splits were captured on different UTC days, with a deliberate
   rotation trigger between them. Cowrie latency was constant: median execution delay 0.047 s in both
   splits.
7. **Exfiltration is absent** from train and validation by design. It exists only for the sealed test.
8. **Missing values are structural.** `time_to_first_input_s` and `input_line_max_bytes` are NaN for every
   session with no input. The inter-input timing features are NaN for fewer than 2 or 3 lines. Downstream
   handling must not create a "failed login = NaN" shortcut without Task 15 reviewing it.
