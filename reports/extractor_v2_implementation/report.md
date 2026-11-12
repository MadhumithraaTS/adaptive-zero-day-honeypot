# Dataset V2 feature extractor: implementation and validation

**Date:** 2026-11-10. **Task 10B.**

**Deliverables:**

- `scripts/extract_features_v2.py` (single module; no supporting modules needed)
- `tests/test_extract_features_v2.py`
- `docs/extractor_v2_design.md`
- `docs/extractor_v2_output_schema.md`
- this folder (`validate_live_logs.py`, `manual_comparisons.py`, `validation/`)

**Not done:** no Dataset V2 or training/validation dataset, no traffic, no model work, no change to V1, the generator, profiles, the specification, Cowrie or Docker. No leakage checks, no commits.

## 1. Specification audit and specification-to-code mapping

**JSON and Markdown agree.** `configs/feature_spec_v2.json` and `docs/feature_specification_v2.md` (both `2.0.0-draft.3`) contain the same 13 features (6 core, 7 conditional in groups C1–C4), the same formulas, conventions, missing-value rules and descriptive fields. No stop condition applied.

**Discrepancy with the task text:** the task brief refers to "seven descriptive fields". **The specification defines eight**: draft.3 (task 8) added `download_failed_events` for `cowrie.session.file_download.failed`, and both the JSON and the Markdown list eight. The extractor implements the eight defined "exactly as in the JSON". Please confirm this is intended.

**Mapping:** the full table is in `docs/extractor_v2_design.md` → "Feature calculations".

| Specification | Code (`scripts/extract_features_v2.py`) |
|---|---|
| `spec_version`, feature and descriptive names and order | `IMPLEMENTED_SPEC_VERSION`, `MODEL_FEATURES`, `DESCRIPTIVE_FIELDS`; `load_spec` refuses any mismatch |
| `conventions.input_lines` (exclude exact `exit`/`logout`, order by timestamp then log order) | `EXCLUDED_INPUT_LINES`; `group_sessions` sort key `(timestamp, _order)` |
| `conventions.line_bytes`, `command_name` | `len(t.encode('utf-8'))`; `command_name()` |
| 13 formulas | `compute_session` → `features` |
| 8 descriptive formulas | `compute_session` → `descriptive` |
| Missing policies (NaN / never / structural zero) | Explicit in `compute_session`; `_cell` writes `NaN` |
| Validation rules | `compute_session` (flags) and `validate_session` (rule checks) → warnings |
| `forbidden_inputs` | Not read: only `--input` files and the specification are opened; prohibited event fields are ignored |
| `shell_operator_lines` and `download_command_lines` constant sets | `SHELL_OPERATORS`, `DOWNLOAD_COMMANDS` (a test checks they match the JSON formulas literally) |

## 2. Architecture

```
read_events(paths)            strict UTF-8 per line; malformed JSON: stop (default) or skip+report with file:line
  -> group_sessions(events)   by session id; exact-duplicate removal (reported); sort by (timestamp, log order)
  -> compute_session(...)     13 model features | 8 descriptive fields | warnings
  -> validate_session(...)    specification rules -> warnings (values never changed)
  -> extract(...)             spec binding; sorted session order; model_features.csv | session_metadata.csv | extraction_summary.json
```

**Independence:** the module imports only the standard library: no V1 extractor, no `dataset_builder`, no `scripts` modules (AST test).

## 3–5. Feature and descriptive-field definitions, missing values

These are in `docs/extractor_v2_design.md` (calculations, descriptive fields, NaN and structural-zero rules) and `docs/extractor_v2_output_schema.md` (types, units, missing encoding).

Key points:

- **Input semantics:** input features count **recorded** `command.input` lines, which may include Cowrie-executed lines (pilot C) and may miss client lines. Nothing is called client typing.
- **Downloads:** `download_command_lines` counts commands. The download fields count only Cowrie file events: completed (`url`), failed (`file_download.failed`), redirect (`destfile`, no `url`), scp stdin (`realm: scp`).
- **No inference:** no success is inferred from prompts (the extractor never sees them) or from commands.
- **NaN only when undefined:** duration without `session.closed`, maximum without lines, timing without login or lines, mean < 2 lines, standard deviation < 3 lines, output when logged in without `log.closed`. `tty_output_bytes` is 0.0 only for no-login sessions (structural zero).

## 6. Data-quality handling

| Case | Behaviour |
|---|---|
| Invalid UTF-8 | Always stops, with file, line, byte and column |
| Malformed JSON / non-object | Stops by default; `--allow-malformed` skips **and reports** each line |
| Event without session id | Reported (file-level warning with line); not assigned |
| Exact duplicate records | Removed and counted (session warning and summary total) |
| Missing or invalid timestamp | Event kept and warned; timing features that need it become NaN |
| Missing `eventid` or `input`; unknown event types | Kept and warned; unknown types count in `event_count` |
| No `session.closed` / `log.closed` | NaN as specified, warned |
| Reserved test markers (`PILOT_…`) | Flagged (`reserved_test_marker_present`), values not altered |
| Specification flags (negative time to first input, duration vs event span, output < input bytes, …) | Warned, values kept |

## 7–8. Tests

**`tests/test_extract_features_v2.py`: 43 tests, all passing.**

- **Specification binding:** names, order, constants equal to the JSON, mismatch refused, and the model matrix has exactly 13 columns with no identifier.
- **Authentication:** success; failed-only; multiple failures; failed-then-successful; no auth event.
- **Session:** duration; missing close; zero duration; span mismatch; out-of-order records; invalid timestamp.
- **Recorded input:** none; one; many with `exit`/`logout` excluded; empty lines; Unicode bytes; shell operators (7 of 9); download commands (first token only; a command is not a download); repeats and arguments.
- **Timing:** one gap; several gaps; missing login timestamp; negative time to first input.
- **Server output:** non-zero, zero, missing `log.closed`.
- **File events:** completed, failed, redirect, scp, and an event without `url`, all separated; `command.failed` descriptive only.
- **Integrity:** duplicates; malformed JSON (stop, and allow-and-report with line numbers); invalid UTF-8; missing fields; unknown event types; escaped and raw Unicode JSON; coverage and determinism; markers.
- **Isolation:** only the log and specification are opened (a manifest and `terminal_output.jsonl` sit next to the input and are not read); labels, profiles, credentials, IPs and the session id don't change features; the V1 extractor is not imported.

**Full suite: 292 passed** (previously 249), 5 warnings, the same as before.

## 9. Live-log validation (existing logs only; no new traffic)

`validate_live_logs.py` → `validation/validation_results.json`. Each log was extracted twice, and every file opened during extraction was recorded with `sys.addaudithook`.

| Log | Events | Sessions in → out | All present once | 13-column matrix | Deterministic | Only log + spec read | Missing-value rule violations | Sessions with warnings |
|---|---|---|---|---|---|---|---|---|
| train_v1 (`dataset_builder/runs/train_v1/raw/cowrie_thisrun.json`) | 28,945 | 3,199 → 3,199 | yes | yes | yes | yes | 0 | 34 |
| eval_v1 | 11,313 | 1,232 → 1,232 | yes | yes | yes | yes | 0 | 3 |
| payload pilot | 46 | 5 → 5 | yes | yes | yes | yes | 0 | 3 (`PILOT_` markers) |
| smoke test (task 7) | 181 | 21 → 21 | yes | yes | yes | yes | 0 | 0 |
| confirmation (task 9) | 261 | 28 → 28 | yes | yes | yes | yes | 0 | 0 |
| verification (task 10A) | 29 | 2 → 2 | yes | yes | yes | yes | 0 | 0 |

**Warnings in the pre-fix live runs:**

- `no_session_closed` (27): train_v1 sessions cut off at the end of its slice.
- `logged_in_without_log_closed` (4 + 1).
- `tty_output_below_recorded_input_bytes` (2): the downloaded-HTML sessions, whose Cowrie-executed lines are not echoed.
- **`negative_time_to_first_input` (2 + 2):** in these four pre-fix sessions, Cowrie timestamped the first `command.input` 15–319 ms **before** its own `login.success`, although it logged it after (for example train_v1 `9f61c9c8a900`: `who` at …51.570, login at …51.889). Generator 2.0 sent commands on a timer, before the shell was ready. The value is kept and flagged as the specification requires. **No prompt-gated session (tasks 7, 9, 10A) shows it.** This is a data-quality fact for the leakage task: Cowrie timestamps are not strictly monotone across event types.

**pandas check:** `pd.read_csv` of `model_features.csv` gives 13 columns, with integer columns as int64 and float columns as float64, and NaN counts equal to `extraction_summary.json` → `nan_counts`.

## 10. Manual source-event comparisons

`manual_comparisons.py` → `validation/manual_comparisons.md` (event listings plus feature tables). An independent recomputation, written directly from the specification text with no shared code, gives **0 differences** for all six sessions:

| Log / session | Case | Spot check against the raw events |
|---|---|---|
| confirmation / `e209f8a07f2f` | `wget` to `.example`, DNS failure | 5 recorded lines: 7 + 5 + 37 + 20 + 12 = **81** bytes; max **37** (the `wget` line); `download_command_lines` **1**; no download event (DNS failure emits none); `exit` excluded; `tty_output_bytes` 853 = `log.closed.size` |
| pilot / `852266ae5622` | Cowrie-executed script line; redirect | 3 recorded lines including Cowrie's own `PILOT_C_…` line: 56 + 18 + 33 = **107** bytes (recorded, not client-verified, as specified); `shell_operator_lines` **1** (`>`); `redirect_write_events` **1**; marker flagged |
| train_v1 / `db3846f69175` | Downloaded HTML executed by Cowrie | 7 recorded lines, max **5,605** bytes (the HTML line); 37 `command.failed`; `url_download_events` **1**; output 2,767 < input 5,670, flagged |
| eval_v1 / `446cba859695` | `scp` stdin | `scp_stdin_events` **1**; `download_command_lines` **1** (`scp`); `shell_operator_lines` **1** |
| smoke test / `fa31b41fec41` | `wget` to an IP, hung (pre-compat) | 3 recorded lines, no `exit`; `download_failed_events` **1**; duration 25.7 s |
| confirmation / `00499366e839` | Failed login only | `login_success` 0, `login_failed_count` 1; `tty_output_bytes` **0.0** (structural zero); timing and max NaN; duration 1.1 s |

## 11. Known limitations

1. **Recorded input mixes provenance** (Cowrie-executed lines in; swallowed or lost client lines out). This is a specification-level limitation; there is no per-line provenance without TTY.
2. **Cowrie timestamps can invert across event types** (four pre-fix sessions). The ordering follows the specification (timestamp, then log order), so such inversions surface as warnings, not corrections.
3. **Exact-duplicate removal compares whole records.** Two genuinely distinct but byte-identical events (same timestamp to the microsecond and the same fields) would be merged. This was not observed.
4. **The known event set is this Cowrie build's.** Other builds may emit other types, which are counted and warned, not interpreted.
5. **`--allow-malformed` changes coverage** (skipped lines are reported). The default is to stop.
6. **The extractor makes no statistical decisions.** All 13 features are always output, and conditional eligibility belongs to the leakage-validation task.
7. **The draft.3 descriptive count (8)** differs from the task text (7); see section 1.

## 12. Repository integrity

- **Created:**
  - `scripts/extract_features_v2.py`
  - `tests/test_extract_features_v2.py`
  - `docs/extractor_v2_design.md`, `docs/extractor_v2_output_schema.md`
  - `reports/extractor_v2_implementation/` (report, two scripts, `validation/`: extraction outputs for six existing logs, `validation_results.json`, `manual_comparisons.{json,md}`)
- **Modified:** none.
- **Verified unchanged (SHA-256 over all repository files):** the V1 extractor and data, models, generator, profiles, specification, builder, labelling.
- **Other:** no test-set access (`test_touches` = 0); nothing committed. Details are in the hand-off message.
