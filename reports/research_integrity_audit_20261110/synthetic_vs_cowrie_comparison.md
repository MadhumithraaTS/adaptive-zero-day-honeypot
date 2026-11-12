# Synthetic generator compared with real Cowrie telemetry

## Sources

- **Synthetic:**
  - Generator: `scripts/generate_dataset.py` (`generate_synthetic_sessions`, commit 6c8fb32).
  - Data: the 1,800-row `model_selection/behavior_features.csv`.
  - Distributions below use only the 1,530 training and validation rows (`ml_pipeline/work/train.pkl`, `val.pkl`). The frozen test split was not opened.
- **Live Cowrie:**
  - Raw events: `dataset_builder/runs/train_v1/raw/cowrie_thisrun.json` and `eval_v1/raw/cowrie_thisrun.json`.
  - Features: `dataset_builder/runs/train_v2_corrected/behavior_features.csv` (3,125 Cowrie sessions from the train_v1 run; labelling v2).
  - Generator: `dataset_builder/generate_labelled_traffic.py` with `profiles_v2.json`, seed 1, speed 8.
- **Extractor (both):** `scripts/extract_features.py`. Its feature logic is unchanged between commit c1678cf, which built the CSV, and HEAD.

Labels in each comparison: **[C]** confirmed from code or data, **[U]** unverified.

## 1. Event availability

| Event | Synthetic generator | Real Cowrie (train_v1/eval_v1 logs) | Consequence |
|---|---|---|---|
| `session.connect` | yes | yes | — |
| `client.version`, `client.kex` | yes, at fixed offsets (5–50 ms, 10–80 ms) | yes, real loopback timing | `tcprtt` scale differs [C] |
| `login.success` / `login.failed` | one per session; success p = 0.75 for profiles with commands | **one per session; each failed attempt is a separate Cowrie session** | One generated interaction becomes several sessions in live data [C] |
| `session.params` | **never** | yes, after login | +1 `dpkts` in live data [C] |
| `client.size` | yes, after a successful login with commands | yes | — |
| `command.input` | **only for commands that did not "fail"** | **for every line**, including `exit` and unknown commands | `spkts`/`sbytes` meaning differs [C] |
| `command.failed` | **instead of** `command.input` (`failed_cmd_rate`) | **in addition to** `command.input`, about 1 ms later; one per `;`-separated part | Failed commands are invisible in synthetic client features [C] |
| `command.success` | never | never | Dead entry in `DPKT_EVENT_IDS` [C] |
| `session.file_download` | never | yes (35 in eval_v1) | Download behaviour only exists in live data [C] |
| `log.closed.size` | `randint(tty_size_range)` chosen per category | real tty-log byte size | `dbytes` is injected in synthetic data [C] |
| `session.closed.duration_ms` | sum of generated delays | real session duration | Failed-login sessions last about 120 s in live data [C]; cause unverified (probably an authentication or idle timeout) [U] |

## 2. Feature definitions and resulting differences

Distributions below are for the 1,530 synthetic training and validation rows against the 3,125 live
`train_v2_corrected` rows. Medians are given as synthetic → live.

| Feature | Synthetic median | Live median | Notes |
|---|---|---|---|
| `dur` | 0.60 s | 120.0 s | Live failed logins (1,625 sessions) sit at about 120 s; logged-in live categories have medians of 0.19–3.07 s at speed 8 [C] |
| `spkts` | 1 | 0 | Live counts `exit` (`login_no_commands` has `spkts` = 1) [C] |
| `dpkts` | 5 | 3 | Values: synthetic 4/5/6/7/8/9; live 3/6/7/8/9 plus outliers at 42–43. Baselines are failed login 4 vs 3 and logged in 5 vs 6 [C] |
| `sbytes` | 21 | 0 | Live maximum 5,674: an HTML page pasted into the shell in train_v1 [C] |
| `dbytes` | 326 | 0 | Synthetic values come from category ranges; live values from the real tty log [C] |
| `tcprtt` | 0.073 s | 0.010 s | About 7× smaller live; synthetic values carry no category information (η² 0.003) [C] |
| `synack` | 0.45 × `tcprtt` | 0.45 × `tcprtt` | A formula, not a measurement, in both [C] |
| `ackdat` | 0.20 s | 0 | Synthetic value is the client.size offset plus the first command delay [C] |
| `ct_*` | per-synthetic-IP counts, 63–304 | file size (one source IP, 172.19.0.1) | Constant per live file [C] |

**Missing values:** neither source produces NaN for the 15 features. Absent events give 0, not
missing, so "no event" and "a true zero" can't be told apart (for example `sinpkt` = 0 with fewer
than two inputs) [C].

## 3. Features that can be extracted consistently from both sources

| Status | Features |
|---|---|
| Consistent definition **if** the generator emitted Cowrie's event sequence | `spkts`, `sbytes`, `sload`, `sinpkt`, `sjit`, `ackdat`, `dinpkt`, `djit`, `dur` |
| Inconsistent today | `dpkts` (`session.params`, failure handling); `dbytes`, `rate`, `dload` (injected vs real); `dur` for failed logins |
| Not meaningful in either source | `tcprtt`, `synack` (loopback timing and a derived constant); `ct_*` (collection-size or label leakage); `proto`, `service`, `sttl`, `dttl`, `ct_state_ttl` (constants) |

## 4. Recommended common feature extraction specification (proposal, not implemented)

Compute features **only from events real Cowrie emits, with Cowrie's semantics**. Version the
specification (for example `feature_spec_v2`) and write it into every run's metadata.

1. **Session grouping:** a Cowrie session ID plus a `source_entry` (manifest entry) ID. All sessions from one generated interaction share the entry ID, which is used for grouping in splits and is never a feature.
2. **Authentication:** `login_attempts`, `login_failed`, `login_success` (0/1), and `auth_phase_s` (connect to last login event).
3. **Interactive input:** all from `command.input`, excluding a final `exit`:
   - `input_lines`, `input_bytes`, `max_line_bytes`, `nonprintable_byte_share`;
   - `failed_commands` from `command.failed`, de-duplicated against input lines so nothing is counted twice;
   - `downloads` from `session.file_download`.
4. **Timing:**
   - `interactive_dur_s` (first input to last input or close);
   - mean and standard deviation of inter-input gaps;
   - `first_input_delay_s` (login to first input).
   - Record failed-login duration separately as `auth_timeout_flag`, not as session length.
5. **Server output:** `tty_log_bytes` from `log.closed.size`, but only when the source is real Cowrie. A generator must not invent it.
6. **Excluded:** `tcprtt`, `synack`, `ct_*`, `src_ip`, the constant columns, and anything derived from manifest or profile fields.
7. **Missing-value convention:** features that aren't applicable, such as gaps with fewer than two inputs, are NaN with an explicit indicator, not 0.
8. **Validation hook:** for each run, assert that every `command.failed` has a matching `command.input` in the same session (allowing for `;` splitting), and that `session.params` is present for logged-in sessions.

A synthetic generator, if one is kept, must reproduce this event sequence, or be dropped in favour of real Cowrie runs.
