# Buffer-overflow telemetry audit (read-only)

Date: 2026-11-10. Scope: the code path from generator to features for `zero_day_buffer_overflow` in
the 1,800-session synthetic dataset (`model_selection/behavior_features.csv`), plus the live
Cowrie data paths for comparison.

No code, data, model or pipeline file was changed. The 270 test sessions were not loaded. The
evidence comes from source code, git history, real Cowrie logs from the live runs, and the 1,530
training and validation rows (`trace_check.py` → `trace_check_train_val.json`).

## Summary

The premise needs one correction. **Cowrie never saw the buffer-overflow payload.** The 1,800-session
dataset was not collected from Cowrie: `scripts/generate_dataset.py` writes Cowrie-style JSON events
directly, with no SSH connection and no protocol interaction. The generator itself chooses the event
type, and for this profile it always chooses `cowrie.command.failed`. The extractor counts client
packets and bytes only from `cowrie.command.input`, so the payload contributes nothing to `spkts`
or `sbytes`.

Two broader artefacts showed up along the way:

- `dbytes` (and so `rate` and `dload`) is a per-category random draw from the generator's
  `tty_size_range`, not something the session produced.
- Failed commands in every category are counted as server packets (`dpkts`) but never as client
  data.

Real Cowrie behaves differently on both counts, so synthetic and live feature meanings diverge.

## 1. From generator to event to feature

### 1.1 Generator (`scripts/generate_dataset.py`, unchanged since commit 6c8fb32, 2026-09-07)

- **Profile (lines 68–78):** `name: zero_day_buffer_overflow`.
  - `commands: ["\x90" * 256 + "NOP_SLIDE_PAYLOAD_EXPLOIT_EXEC"]`: 286 characters, 542 bytes in UTF-8, because U+0090 encodes as `C2 90`.
  - `failed_cmd_rate: (1.0, 1.0)`, `tty_size_range: (0, 100)`, `cmd_delay_range: (0.0, 0.1)`.
  - `src_ips: ["103.251.167.20"]`.
  - `duration_range`, `spkts_range` and `dpkts_range` are never read by the generator (no reference outside the profile dictionaries).
- **Protocol interaction:** none. `generate_synthetic_sessions` (lines 103–274) appends dictionaries to a list and writes `data/parsed/sessions.json`. No socket or SSH client is used.
- **Event types emitted per session:**
  - always: connect, `client.version`, `client.kex`, `login.success` or `login.failed`, `log.closed`, `session.closed`;
  - when login succeeds and the profile has commands: `client.size` plus one command event per command.
- **Login:** `auth_success = random.choice([1, 1, 1, 0])` for profiles with commands (line 166), so success has probability 0.75.
- **The decision (lines 209–221):** `if random.random() < random.uniform(*failed_cmd_rate)` emits `{"input": cmd, "eventid": "cowrie.command.failed"}`. **No `cowrie.command.input` is emitted for that command.** With a rate of (1.0, 1.0), every buffer-overflow command takes this branch.
- **`log.closed` size (line 241):** `tty_size = random.randint(*tty_size_range) if auth_success else 0`.
- **No random seed is set.** The generated `data/parsed/sessions.json` for the 1,800 sessions is not retained; the current file at that path is a later 46 KB live parse.

### 1.2 Why the event is `command.failed`

The generator hard-codes the failure through `failed_cmd_rate = 1.0`. Nothing models an execution
attempt or a server response. The event says nothing about whether the payload was delivered,
detected or executed; it is a label the generator wrote.

### 1.3 How real Cowrie records the same kind of interaction (for comparison)

From `dataset_builder/runs/{train_v1,eval_v1}/raw/cowrie_thisrun.json`:

- Real Cowrie emits `cowrie.command.input` for every line typed, then a separate `cowrie.command.failed` about 1 ms later (message `Command not found: …`) when the command is unknown.
  - eval_v1: all 169 failed events have a matching input event in the same session.
  - train_v1: 482 of 552 match exactly. The other 70 are fragments of a longer input line that Cowrie split on `;` (an HTML page pasted into the shell) and reported part by part. No failed event appears in a session without input events.
- Real Cowrie also emits `cowrie.session.params` and `cowrie.session.file_download`. It never emits `cowrie.command.success`.
- `log.closed.size` is the byte size of the recorded tty log.

**No live generator has a buffer-overflow profile.** `configs/attack_profiles.json` (used by
`scripts/attack_generator.py`) has script_kiddie, botnet and advanced_persistent_threat.
`dataset_builder/profiles_v2.json` has benign_admin, reconnaissance, brute_force, botnet,
privilege_escalation, lateral_movement and data_exfiltration. So the payload has never been sent to
a real Cowrie in this project, and how Cowrie would log it (for example the non-ASCII `\x90` bytes
through an interactive shell) is untested.

### 1.4 Feature extraction (`scripts/extract_features.py`)

The feature logic is identical at commit c1678cf, when `behavior_features.csv` was added, and at
HEAD. Later commits restructured columns and error handling only.

| Feature | Source events (code) |
|---|---|
| `dur` | `session.closed.duration_ms`, otherwise the first-to-last event span (lines 234–240, 304–311). Synthetic `duration_ms` is the sum of generated delays. |
| `spkts` | count of `command.input` (line 261) |
| `sbytes` | UTF-8 byte length of `command.input` text (line 262) |
| `dpkts` | count of events in `DPKT_EVENT_IDS`: `client.version`, `client.kex`, `login.success`, `login.failed`, `client.size`, `session.params`, `command.success`, **`command.failed`**, `log.closed` (lines 19–29, 291–292) |
| `dbytes` | sum of `log.closed.size` (lines 242–248, 315) |
| `rate` | (`sbytes` + `dbytes`) / `dur` |
| `sload` | `sbytes` × 8 / `dur` |
| `dload` | `dbytes` × 8 / `dur` |
| `sinpkt`, `sjit` | mean and standard deviation of gaps between `command.input` timestamps |
| `dinpkt`, `djit` | mean and standard deviation of gaps between `DPKT_EVENT_IDS` timestamps |
| `tcprtt` | first `client.kex` minus the first event's timestamp |
| `synack` | `tcprtt` × 0.45 (a constant, line 352) |
| `ackdat` | first `command.input` minus the first login event |

`command.failed` adds to `failed_commands` (line 283), which is not among the 15 inputs, and to
`dpkts`. Its `input` text is never read.

## 2. Effect on buffer-overflow features (code prediction, confirmed on the 1,530 train + validation rows)

| Session type | Share | `spkts` | `sbytes` | `sload`, `sinpkt`, `sjit`, `ackdat` | `dpkts` | `dbytes` |
|---|---|---|---|---|---|---|
| Login succeeds (p = 0.75) | 135 / 184 (73%) | 0 | 0 | 0 | 6 (5 baseline + 1 failed) | U[0, 100] from `tty_size_range` |
| Login fails (p = 0.25) | 49 / 184 (27%) | 0 | 0 | 0 | 4 | 0 |

Confirmed facts: `dbytes` ≤ 100 for every buffer-overflow row, and the longest `dur` is 0.564 s.
A failed-login buffer-overflow session is identical in kind to any other failed-login session.

**Affected features:** `spkts`, `sbytes`, `sload`, `sinpkt`, `sjit` and `ackdat` never reflect the
payload. `dpkts` reflects only that one failed-command event exists. `dbytes`, `rate` and `dload`
reflect a generator range, not the payload. If the payload were counted, `sbytes` would be 542 per
session.

## 3. Other categories

Figures below are from training and validation rows only.

| Category | Failed-login rows (`dpkts` = 4, `dbytes` = 0) | Rows with ≥ 1 inferred failed command | Inferred failed commands | Logged in but `spkts` = 0 |
|---|---|---|---|---|
| botnet_malware_download | 44 / 199 | 53 | 64 | 0 |
| privilege_escalation | 50 / 181 | 83 | 121 | 2 |
| evasion_anti_forensics | 40 / 194 | 52 | 63 | 1 |
| reconnaissance | 66 / 224 | 52 | 59 | 0 |
| zero_day_obfuscated_memory_attack | 55 / 195 | 9 | 9 | 0 |
| zero_day_covert_tunnel | 46 / 164 | 0 (rate 0) | 0 | 0 |
| zero_day_buffer_overflow | 49 / 184 | 135 | 135 | 135 |
| brute_force_only | 189 / 189 (no commands, no `client.size`; `tty_size` 0) | 0 | 0 | 0 |

"Inferred failed commands" means `dpkts` − 5 on logged-in rows; this inference holds exactly for
the generator's event set.

- **The same mismatch affects five other categories.** 316 failed commands outside buffer
  overflow are missing from `spkts`/`sbytes` and appear only in `dpkts`. In 3 sessions every command
  failed, so they look command-free. Buffer overflow is the only category where the failure rate is
  100%.
- **`dbytes` fingerprint (all categories).** For every logged-in row, `dbytes` falls inside its
  category's `tty_size_range`:
  - buffer overflow 0–100;
  - covert tunnel 100–500;
  - botnet 200–1500;
  - evasion 300–2000;
  - reconnaissance 500–3000;
  - privilege escalation 800–4000;
  - obfuscated memory 1500–5000.

  This is a designed category parameter, not session content. The ranges overlap, which is
  consistent with the weak exact-value lookup in the validation error analysis; but the range
  bounds, especially 0–100 and 100–500, separate categories for reasons unrelated to behaviour.
- **Uniform failed-login share.** About 25% of every command profile is a failed login with no
  category information except timing.

## 4. Impact on training, validation and test (code and manifest logic only)

- All 1,800 rows come from one generator run and one extraction, so every row of every split is
  produced by the same mechanism. `guard.split` stratified on `attack_cat`, so the frozen test split
  holds about 15% of each category.
- By code, the test buffer-overflow rows must have `spkts` = `sbytes` = 0, and `dpkts` of 6 or 4
  with `dbytes` ≤ 100. The proportions should be about 73/27, like training and validation. **Not
  verified, by design: test rows were not loaded.**
- Consequence: the frozen test set cannot measure whether any model detects a buffer-overflow
  payload. Any result for that category would measure the generator's event pattern and tty range.
- Live datasets (`dataset_builder/runs/*`, `data/evaluation_runs`) contain no buffer-overflow
  profile. Their failed commands are counted in `spkts`/`sbytes` (input event) **and** `dpkts`
  (failed event). They also gain one `dpkts` from `session.params`. Synthetic training data and live
  data therefore use different meanings for `spkts`, `sbytes`, `dpkts` and `dbytes`.

## 5. Can the payload be recovered from existing raw events?

No.

- The synthetic event file for the 1,800 sessions is not on disk.
- `behavior_features.csv` stores no command text and no `failed_commands` count.
- The generator has no seed, so rerunning it would produce different sessions.
- The only "recovery" would be assuming every buffer-overflow session carried the profile string.
  That would be reconstruction, not evidence, so I did not do it.
- Live raw logs contain no such payload.

## 6. Remedies (evaluated, not implemented)

| | A. Correct the event generation | B. Dedicated payload feature | C. Count `command.failed` in `spkts`/`sbytes` | D. Exclude or relabel the category |
|---|---|---|---|---|
| What changes | Emit `command.input` then `command.failed` for failed commands (as real Cowrie does), add `session.params`, derive `dbytes` from content rather than `tty_size_range`. Better still, generate through real Cowrie with `dataset_builder` and add a payload profile. | New input such as length of the longest input line or share of non-printable bytes, read from `command.input`. | Extractor semantics only. | Drop `zero_day_buffer_overflow`, or relabel it (for example "single failed command"), and state that no payload category exists. |
| Works with the current 15-feature model | No: input distributions change; same columns, different meaning | No: input dimension changes | No: meaning changes; old weights invalid | Model unchanged if relabelled for reporting only; dropping rows from training needs a retrain |
| Regenerate data and retrain | Yes, with a new split; the frozen test set is superseded | Yes; raw events must exist, so regeneration is needed for the synthetic data | Needs the raw events, which are gone, so regeneration anyway, plus retraining | Relabel: no. Exclude: retrain on the remaining rows |
| Risk of false signals | Removes the current false signals (failed-only `dpkts`, `dbytes` ranges) | Non-printable or long-line features could fire on pasted text: train_v1 contains an HTML page typed into the shell | **High in live data:** every live failure already has an input event, so it would be counted twice; Cowrie's `;`-split failures inflate counts further | None added; leaves the `dbytes` and failed-command artefacts in other categories |
| Works in live Cowrie | Yes, if it matches Cowrie's real event sequence; verifiable against live logs | Yes if read from `command.input`, which real Cowrie always emits; not if read from `command.failed` | No, it double-counts | Not applicable |

## 7. Recommendation

1. **Now, with no data change:** apply D as documentation only. State in the project report that
   the synthetic `zero_day_buffer_overflow` category carries no payload in its features, and make no
   claim that any model detects buffer-overflow payloads. Do not score the frozen test set as
   evidence for that category.
2. **Real fix, which needs your approval:** A, through the live `dataset_builder` path (real Cowrie
   via paramiko), with a buffer-overflow-style profile added. Then the event types, `spkts`,
   `sbytes` and `dbytes` come from Cowrie itself. Check the resulting event sequence against the live
   logs before any training. This means a new dataset, a new split and retraining from Gate A.
3. B can be added after A, reading `command.input` only.
4. **Do not adopt C.**

## 8. Limitations

- How real Cowrie would log the `\x90` NOP payload through an interactive shell was not tested; Cowrie and Docker were not run.
- The test-split impact is inferred from code, not observed.
- The failed-command inference (`dpkts` − 5) relies on the generator's event set and does not hold for live data.
- The 1,800 synthetic sessions' raw events are unavailable. The trace relies on the generator and extractor code at the relevant commits and on consistency checks against the training and validation features.

## 9. Integrity

- I hashed 348 files with SHA-256 before and after the audit: models, the 17-feature artifacts,
  `model_selection/`, `dataset_builder/`, `reports/`, `configs/`, `ml_pipeline/`, `scripts/` and
  `data/`. All 348 are unchanged; the only new files are the three in this folder.
- Key hashes:

  | File | SHA-256 |
  |---|---|
  | `model_selection/behavior_features.csv` | `d8d50b6a…5148` |
  | `ml_pipeline/work/test.pkl` | `b1bb8867…e189` |
  | `ml_pipeline/.guard_state.json` | `77e8081b…7a14` |
  | `scripts/generate_dataset.py` | `daa74cd2…db68` |
  | `scripts/extract_features.py` | `4d514ff1…d9fc` |

- `ml_pipeline/.guard_state.json` reports `test_touches: 0`. `trace_check.py` reads only
  `work/train.pkl` and `work/val.pkl`.
- Nothing was committed, and Cowrie, Docker and the network were not used.
