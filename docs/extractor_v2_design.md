# Dataset V2 feature extractor: design

**Module:** `scripts/extract_features_v2.py`. **Specification:** `configs/feature_spec_v2.json` `2.0.0-draft.3` (`docs/feature_specification_v2.md`). **Output schema:** `docs/extractor_v2_output_schema.md`.

The extractor turns Cowrie JSON event logs into the 13 model features and 8 descriptive fields of the specification. It is independent of the V1 extractor (`scripts/extract_features.py`), which it neither imports nor modifies, and it makes no feature-selection decisions: conditional features (groups C1–C4) are always computed and left for the leakage-validation task.

## Inputs, and what is never read

- **Read:** the Cowrie JSONL files given with `--input` (in the order given), and the specification file.
- **Never read:** generation manifests, `terminal_output.jsonl`, `run_meta.json`, labels, profile files, or any other file. A test spies on `open()`, and the live validation records every opened file with `sys.addaudithook`.
- **Ignored inside events:** `attack_cat`, `label`, `profile`, `src_ip`/`src_port`/`dst_*`, `username`, `password`, `sensor`, `uuid`, `hassh` and client version (specification `forbidden_inputs`). Changing them does not change any feature (test).
- **The session id** is used only to group events, and appears only in `session_metadata.csv`.

## Pipeline

1. **`read_events`:** reads bytes and decodes each line with strict UTF-8.
   - Invalid UTF-8 always stops the run, reporting the file, line, byte and column.
   - Malformed JSON, or a JSON value that isn't an object, stops the run by default. With `--allow-malformed` it is skipped and reported in `extraction_summary.json` → `file_level_warnings` with `file:line`. It is never silently dropped.
   - Each event gets a global order number and its `file:line`.
2. **`group_sessions`:**
   - Events are grouped by `session`. Events without a session id are reported (`event_without_session_id`, with the line number) and assigned to no session.
   - **Exact duplicate records** (identical JSON content, ignoring internal fields) are removed and reported per session (`duplicate_records_removed=N`). Cowrie's `uuid` is the sensor UUID, the same for every event, so it can't serve as an event key.
   - Events are sorted by **(timestamp, log order)**, as the specification's convention requires. An event with a missing or invalid timestamp is kept and sorted last, with a warning.
3. **`compute_session`:** the features and descriptive fields below, then `validate_session` (the specification's validation rules). Violations become warnings and never change values.
4. **`extract`:**
   - binds to the specification: it refuses to run unless `spec_version` is `2.0.0-draft.3` and the feature and descriptive-field names match exactly, in order;
   - processes sessions in sorted session-id order (deterministic);
   - writes `model_features.csv`, `session_metadata.csv` and `extraction_summary.json`.

## Feature calculations (specification → code)

**Recorded input lines** are `cowrie.command.input` events in (timestamp, log order) order, excluding lines whose stripped text is exactly `exit` or `logout`.

- They are **recorded** lines, not verified client typing: they include lines Cowrie executes itself and can miss client lines.
- Line bytes = `len(input.encode('utf-8'))`.
- Command name = first whitespace token of the stripped line; empty lines have none.

| Feature | Code |
|---|---|
| `login_success` | `1 if cowrie.login.success events else 0` |
| `login_failed_count` | number of `cowrie.login.failed` events |
| `session_duration_s` | `float(duration)` of the first `cowrie.session.closed`; NaN if none or unparsable |
| `input_line_count` | number of recorded input lines (empty lines included; the specification does not exclude them) |
| `input_bytes_total` | sum of line bytes |
| `input_line_max_bytes` | max line bytes; NaN if no lines |
| `unique_command_names` | number of distinct command names |
| `shell_operator_lines` | lines containing any of `\|`, `;`, `&&`, `>`, `<`, `` ` ``, `$(` (substring test, as specified) |
| `download_command_lines` | lines whose command name is in {wget, curl, tftp, ftp, ftpget, scp} (exact first token) |
| `time_to_first_input_s` | first recorded line's timestamp − first `login.success` timestamp; NaN if no login, no line, or a needed timestamp is missing |
| `inter_input_mean_s` | mean of consecutive differences of the recorded lines' timestamps; NaN if < 2 lines or any timestamp missing |
| `inter_input_std_s` | population standard deviation of those differences; NaN if < 3 lines or any timestamp missing |
| `tty_output_bytes` | no login → **0.0** (structural zero); login and ≥ 1 `log.closed` → `float(sum(size))`; login and no `log.closed`, or an unparsable size → NaN |

## Descriptive fields (never in the model matrix)

| Field | Code |
|---|---|
| `unknown_command_events` | number of `cowrie.command.failed` |
| `url_download_events` | `cowrie.session.file_download` events with a `url` field (completed downloads) |
| `download_failed_events` | number of `cowrie.session.file_download.failed` |
| `redirect_write_events` | `cowrie.session.file_download` with `destfile` and no `url` |
| `scp_stdin_events` | `cowrie.session.file_download` with `realm == 'scp'` |
| `event_count` | events of the session after exact-duplicate removal |
| `session_closed_observed` | 1 if a `cowrie.session.closed` is present |
| `timestamp_order_mismatch` | 1 if the `command.input` events' log order differs from their (timestamp, log order) order |

A recorded download *command* is never treated as a download: `download_command_lines` counts commands, and the download fields count only Cowrie's file events. File events are never counted as input.

## Missing values and types

- **Encoding:** NaN is written as the literal `NaN` in the CSVs. Integers are written without decimals; float features always have a decimal point (`0.0`, `654.0`).
- **Never imputed:** NaN only where the specification says a value is undefined. 0 only for true counts and for the structural zero of `tty_output_bytes`.
- **Declared types:** in `extraction_summary.json` → `model_feature_dtypes`.

## Warnings (per session, in `session_metadata.csv`)

| Group | Warnings |
|---|---|
| Data quality | `missing_or_invalid_timestamp@file:line`, `duplicate_records_removed=N`, `missing_eventid@…`, `unknown_event_type:<id>`, `command_input_without_text@…`, `no_session_closed`, `session_closed_duration_unparsable`, `more_than_one_session_closed_first_used`, `log_closed_size_unparsable` |
| Specification flags | `more_than_one_login_success`, `no_authentication_event`, `session_duration_differs_from_event_span` (tolerance 1 s), `negative_session_duration`, `negative_time_to_first_input`, `tty_output_below_recorded_input_bytes`, `logged_in_without_log_closed`, `log_closed_without_login_success`, `recorded_input_without_login_success`, `recorded_input_without_timestamp_timing_undefined` |
| Provenance | `non_ascii_recorded_input`, `reserved_test_marker_present` (lines starting `PILOT_`: flagged, not altered) |
| Rule violations | `*_exceed_*`, `negative_std`, `negative_tty_output`, `empty_session`, `input_lines_without_login` |

`extraction_status` is `ok`, or `ok_with_warnings` when any warning exists.

## Implementation decisions where the specification is silent

These are documented; no definition was changed.

| # | Situation | Decision |
|---|---|---|
| D1 | Exact duplicate records | Removed and counted |
| D2 | More than one `session.closed` | First (in order) used, warned |
| D3 | Empty `command.input` text | Counted as a recorded line, contributes 0 bytes and no command name |
| D4 | A recorded line or login without a valid timestamp | Timing features NaN, warned; counts unaffected |
| D5 | Negative `time_to_first_input_s` | Kept, warned (the specification says "flag") |
| D6 | Event types outside the known set | Kept in `event_count`, warned |
