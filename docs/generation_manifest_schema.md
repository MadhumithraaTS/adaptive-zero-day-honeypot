# Generation manifest schema (generator 2.1)

**Files:** written by `dataset_builder/generate_labelled_traffic.py` into `<output-dir>/`:

- `run_meta.json`: one object per run;
- `manifest.jsonl`: one JSON object per line, one line per planned session.

**What the manifest is for:** it is the **source of generation labels** (via `dataset_builder/labelling.py`) and **audit evidence**. **No manifest field may enter the model feature vector** (`configs/feature_spec_v2.json` → `forbidden_inputs`).

**Compatibility:** every field that generator 2.0 wrote is still written with the same meaning. `labelling.py` reads `index`, `profile`, `attack_cat`, `label`, `username`, `start_utc`, `end_utc`, `auth_attempts`, `auth_success` and `commands_sent`, and ignores the rest. Fields marked **new** are added by 2.1.

## `run_meta.json`

| Field | Type | Meaning |
|---|---|---|
| `generated_at` | ISO UTC | Run start |
| `host`, `port` | str, int | Honeypot endpoint |
| `sessions_requested` | int | `--sessions` |
| `seed` | int or null | Planning seed (profiles, commands, credentials) |
| `config_version`, **`config_path`** | str | Profile file version and absolute path |
| `include_held_out` | bool | Held-out profiles included |
| `container`, `log_baseline_lines` | str, int or null | Cowrie log baseline for run isolation |
| `speed` | float | Global pacing scale |
| **`generator_version`** | str | `"2.1"` |
| **`pacing_seed`** | int | Seed of the per-session pacing streams (required `--pacing-seed`) |
| **`pacing_seed_source`** | str | `"explicit --pacing-seed"` |
| **`pacing_seed_reuse`** | object | `runs_root` scanned, `reused_by` (run directories with the same seed), `allowed` (`--allow-pacing-seed-reuse`) |
| **`terminal_output_file`**, **`output_capture_chars`**, **`output_redact_min_length`** | str, int, int | Diagnostic output file and its bounds |
| **`pacing_policy`** | object | `PacingPolicy` parameters and distribution descriptions |
| **`readiness_policy`** | object | `ReadinessPolicy` parameters, `prompt_regex`, readiness condition |
| **`profile_delay_range`** | str | Always `"ignored: pacing is category-independent (PacingPolicy)"` |
| **`inter_session_delay_s`** | float | Pause between sessions (global) |

## `manifest.jsonl` entry

| Field | Type | Meaning |
|---|---|---|
| `index` | int | 1-based session number in the run |
| `profile`, `attack_cat`, `label`, `held_out` | str, str, int, bool | Generation labels (from the profile file) |
| `username` | str | Username of the final (intended) login |
| `start_utc`, `end_utc` | ISO UTC | Generator-side session bounds |
| **`pacing_stream`** | str | `"pacing:<pacing_seed>:<index>"`, the session's pacing RNG seed |
| `auth_attempts` | [[user, password], …] | Planned attempts; the last is the intended login |
| **`auth_log`** | list | One object per attempt actually made: `attempt`, `username`, `outcome` (`rejected`, `accepted`, `accepted_unexpectedly`, `error`), `utc`, `error` |
| `auth_success` | bool | The final login was accepted |
| `guess_errors` | [str] | Non-authentication errors on wrong guesses (since 2026-11-10) |
| **`commands_planned`** | [str] | All commands planned for the session, in order |
| `commands_sent` | [str] | Commands **actually transmitted**, in order: always a prefix of `commands_planned`. It doesn't imply the command succeeded |
| **`command_log`** | list | One object per planned command (below) |
| **`shell_ready_initial`** | bool or null | First prompt seen after opening the shell (null if no shell was opened) |
| **`shell_initial_wait_s`** | float or null | Time waited for the first prompt |
| **`exit_sent`** | bool | `exit` was transmitted (only after every command returned a prompt) |
| **`exit_confirmed`** | bool or null | The channel closed within `exit_timeout_s` after `exit` |
| **`termination`** | str | `clean_exit`, `exit_unconfirmed`, `readiness_timeout`, `readiness_channel_closed`, `shell_not_ready`, `auth_failed` or `error` |
| `status` | str | `ok` (all commands sent and exit sent), `incomplete` (readiness failure), `error` (exception or rejected login) |
| `error` | str or null | Human-readable cause |

## `command_log` item

| Field | Type | Meaning |
|---|---|---|
| `seq` | int | 1-based position in `commands_planned` |
| `command` | str | The command text |
| `blocking_expected` | bool | First token is in `BLOCKING_COMMANDS` (annotation only) |
| `sent` | bool | Transmitted |
| `think_time_s` | float or null | Generator pacing delay before sending (**not** Cowrie-observed timing) |
| `sent_utc` | ISO UTC or null | Generator clock when sent |
| `ready_before_send` | bool or null | Shell readiness was confirmed before sending (always true when sent) |
| `prompt_returned` | bool or null | The prompt came back after the command |
| `wait_s` | float or null | Time waited for that prompt |
| `readiness_reason` | str or null | `prompt`, `timeout` or `channel_closed` (task 8) |
| `prompt_match` | str or null | The exact text that matched the prompt pattern (task 8) |
| `output_chars`, `output_truncated` | int, bool or null | Size of the terminal output seen during the wait, and whether the diagnostic copy was truncated (task 8). The text itself is in `terminal_output.jsonl` |
| `status` | str | `prompt_returned`, `readiness_timeout`, `readiness_channel_closed`, `not_sent` (no shell, or login failed) or `not_sent_after_termination` |
| `action` | str or null | `continue` or `terminate_session` |

## `terminal_output.jsonl` (diagnostic only; task 8)

One line per readiness wait:

| Field | Meaning |
|---|---|
| `index` | Manifest session |
| `step` | `"initial"` or the command `seq` |
| `readiness_reason`, `prompt_match`, `waited_s` | As in `command_log` |
| `output` | ≤ 2,048 characters plus truncation marker; control sequences stripped; incrementally UTF-8 decoded (invalid bytes as `\xNN`); a session password is redacted only as a whole token typed in that step's command, never in the prompt |
| `output_chars`, `output_bytes`, `output_truncated` | Totals seen during the wait |
| `redaction` | `{applied, reason, occurrences}`; reason is `no_secret_typed`, `typed_secret_echoed_and_redacted`, `typed_secret_not_found_in_output` or `typed_secret_too_short_not_redacted` (task 10A) |
| `invalid_utf8_bytes` | Number of bytes that were not valid UTF-8 (task 10A) |

**Never a model or label input.**

## Invariants (checked in tests)

- `commands_sent == [c.command for c in command_log if c.sent]`, and it is a prefix of `commands_planned`.
- After the first item with `action == "terminate_session"`, no item has `sent == true`, and `exit_sent == false`.
- `exit_sent == true` only if every `command_log` item has `prompt_returned == true`.
- `think_time_s` values equal the draws from `pacing_stream` under `pacing_policy`, independent of `profile` and `attack_cat`.
