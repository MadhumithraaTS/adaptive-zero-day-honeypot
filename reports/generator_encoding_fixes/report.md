# Generator connection handling and UTF-8 log processing fixes

**Date:** 2026-11-10.
**Scope:** two reliability corrections identified by `reports/cowrie_payload_observability_pilot/report.md` (sections 7 and 8).
**Not done:** no Dataset V1/V2 generation, no model or dataset changes, no Docker/Cowrie use, no traffic, no tty collection, no commits.

## 1. Original defects and root causes

### A. Failed-login connections stayed open for about 120 s

- **Code:** `dataset_builder/generate_labelled_traffic.py`, `run_session`, formerly line 136: `_connect(host, port, username, password).close()` inside `try/except Exception: pass`.
- **Root cause:** `_connect` calls `paramiko.SSHClient.connect`. A rejected password raises `AuthenticationException` inside `_connect`, so it never returns a client and `.close()` is never reached. The SSH transport stays open until Cowrie's `authentication_timeout = 120` drops it.
- **Evidence:** pilot test D1 closed after 120.0 s; D2, with an explicit close, after 1.1 s. In train_v1, the median gap from `login.failed` to `session.closed` was 119.97 s over 1,636 sessions.
- **Second weakness:** `except Exception: pass` also discarded every *non*-authentication error on a wrong guess (refused connection, timeout, protocol error), with no record.

### B. Log reading and writing depended on the platform encoding

| Location | Before | Effect (pilot section 7) |
|---|---|---|
| `scripts/parse_logs.py` read | `open(input_file, 'r')`, platform default (cp1252 here) | Valid UTF-8 non-ASCII → `UnicodeDecodeError` on undefined cp1252 bytes, or silent mis-decoding on others |
| `scripts/parse_logs.py` write / read-back | no encoding | Output ASCII only, because `json.dump` escapes non-ASCII; no visible defect, but implicit |
| `dataset_builder/build_labelled_dataset.py` raw copy (old line 128) | read UTF-8 with `errors='replace'`, write with the platform default | Invalid bytes **silently replaced** with U+FFFD; non-ASCII written with cp1252 → `UnicodeEncodeError`; CRLF translation altered the "raw" copy |
| builder baseline trim (old lines 136–141) | UTF-8 `errors='replace'` text read | Same silent replacement in `cowrie_thisrun.json` |
| builder manifest, run_meta and sessions reads | platform default | Implicit |
| `scripts/extract_features.py` | platform default for the JSON input, CSV and details outputs | Implicit; non-ASCII commands in `session_details.json` relied on `json.dump`'s ASCII escaping |
| `generate_labelled_traffic.py` config read, run_meta and manifest writes | platform default | Implicit |

Already explicit (unchanged): `dataset_builder/labelling.py`, `dataset_builder/relabel_run.py`, `scripts/collect_logs.py` (`docker cp`, binary), and the other analysis scripts.

## 2. Implementation changes

### A. Connection handling (`dataset_builder/generate_labelled_traffic.py`)

1. `_connect` wraps `client.connect(...)` in `try/except BaseException: client.close(); raise`.
   - The half-open client is always closed, and the **original exception object is re-raised unchanged**.
   - The successful path is identical: it returns the connected client, unclosed.
2. Wrong-guess loop in `run_session`:
   - catches only `paramiko.AuthenticationException` as the expected outcome;
   - any other exception is **recorded** in a new manifest field `guess_errors` (`"<user>: <Type>: <message>"`) instead of being silently discarded, and the planned session still continues as before.
3. The final login and interaction path is unchanged (`try/except/finally client.close()`). If the final `_connect` raises, `_connect` has already closed its client, and `record['error']` keeps the original message as before.
4. Config read, `run_meta.json` and `manifest.jsonl` now use explicit UTF-8.

**Manifest compatibility:** `guess_errors` is a new field, always present (empty list) for new runs. `labelling.py` reads only named fields and ignores it. Existing manifests are not changed.

### B. UTF-8 handling

1. **`scripts/parse_logs.py`:**
   - reads the raw log in **binary** and decodes each line with **strict UTF-8**, independent of the OS default;
   - an invalid line raises `LogParseError`, for example: *"Line 3 of … is not valid UTF-8 (byte 0x90 at column N). The raw log was not changed; inspect that line, since Cowrie itself writes UTF-8."*
   - the CLI exits 1 and leaves any existing output untouched (existing behaviour);
   - output writing and read-back use explicit UTF-8;
   - `json.dump` keeps its default ASCII escaping, so outputs stay byte-identical for ASCII input. Newline handling is unchanged.
2. **`dataset_builder/build_labelled_dataset.py`:**
   - `--raw-input` is copied with `shutil.copyfile` (**byte-for-byte**; nothing is decoded, replaced or newline-translated);
   - baseline trimming reads and writes **bytes**, so `cowrie_thisrun.json` is an exact byte slice;
   - invalid UTF-8 now stops the build at the parse step with the line-numbered error above, instead of being replaced;
   - manifest, run_meta and sessions reads use explicit UTF-8.
3. **`scripts/extract_features.py`:** JSON input, CSV output, details output and both read-backs use explicit UTF-8. The CSV keeps `newline=''`, and the details file keeps the existing newline handling.

**Chosen policy for invalid UTF-8:** an explicit error, with no replacement mode. Data loss is therefore never silent. Recovering such a log needs a deliberate, recorded decision.

**What this does not do:** it does not recover bytes Cowrie has already discarded. The pilot showed that this Cowrie build strips every non-ASCII byte from interactive input before writing `cowrie.json` (pilot section 5). The fixes only ensure that whatever Cowrie *does* write is read faithfully, or rejected loudly.

## 3. Regression tests

**`tests/test_generator_connection.py`** (10 tests; no Cowrie, no Docker):

| Test | Checks |
|---|---|
| `test_connect_success_returns_open_client` | success path returns the client, not closed |
| `test_connect_closes_client_and_reraises_original_error` ×4 | `AuthenticationException`, `SSHException`, `socket.timeout`, `ConnectionRefusedError`: client closed once, **same exception object** re-raised |
| `test_run_session_closes_every_failed_guess_and_the_session` | two rejected guesses plus success: all three clients closed exactly once; commands and `exit` sent in order; `guess_errors` empty |
| `test_run_session_records_unexpected_guess_errors_without_aborting` | a refused guess is recorded in `guess_errors`; the session still completes |
| `test_run_session_final_login_failure_is_recorded_and_closed` | the final login is rejected: `status=error`, original message kept, client closed |
| `test_rejected_login_closes_the_connection_promptly` | **real SSH handshake** against a local paramiko server on 127.0.0.1 that rejects every password: the server sees the client disconnect within 5 s of the rejection |
| `test_control_without_cleanup_the_connection_stays_open` | control: the pre-fix pattern (connect raises, no close) leaves the server-side transport **still active** after 3 s, which shows the test can detect the defect |

**`tests/test_log_encoding.py`** (10 tests; temporary files only; CLI runs without `PYTHONUTF8`, so the Windows default cp1252 applies):

| Test | Checks |
|---|---|
| `test_parse_preserves_input_under_the_platform_default_encoding` (ascii / raw-utf8 / json-escapes) | ASCII JSONL, raw UTF-8 (`U+0090`, `é`) and `\u` escapes all parse to the exact original string |
| `test_parse_accepts_crlf_line_endings` | CRLF logs parse |
| `test_parse_output_is_valid_utf8_with_escaped_non_ascii` | output decodes as UTF-8; non-ASCII stored as JSON escapes |
| `test_parse_invalid_utf8_raises_with_line_and_byte_and_writes_nothing` | raw `0x90`: `LogParseError` naming line 3 and byte 0x90; no output; raw file hash unchanged |
| `test_parse_cli_invalid_utf8_exits_1_and_keeps_stale_output` | raw `0xff` via CLI: exit 1, actionable stderr, stale output untouched |
| `test_extract_writes_utf8_outputs_and_keeps_non_ascii_commands` | details and CSV decode as UTF-8; the command is preserved; `sbytes` = UTF-8 bytes of the logged text |
| `test_builder_copies_raw_log_byte_for_byte_and_trims_baseline_in_bytes` | builder raw copy (CRLF, UTF-8) is byte-identical; `cowrie_thisrun.json` is the exact byte slice after the baseline; parsed text preserved |
| `test_builder_stops_on_invalid_utf8_without_replacing_bytes` | builder exits non-zero with the line/byte message; raw copy byte-identical (no `EF BF BD`); no parsed or feature outputs |

**"Before" evidence:** the pilot's `parser_harness.py` against the pre-fix code shows parse failure under cp1252 for raw UTF-8, a builder `UnicodeEncodeError`, and silent U+FFFD replacement (`reports/cowrie_payload_observability_pilot/evidence/parser_harness_results.json`).

## 4. Test results

- `tests/test_generator_connection.py`: **10 passed**.
- `tests/test_log_encoding.py`: **10 passed**.
- **Full suite: 194 passed** (previously 174), 5 warnings.
  - The 3 existing ones: a pyarrow deprecation notice and two pandas `FutureWarning`s.
  - 2 new: paramiko's TripleDES `CryptographyDeprecationWarning`, now imported by the tests.
- The existing `tests/test_log_processing.py` checks that parser and extractor outputs are **byte-identical** to the historical demo outputs. They still pass, so ASCII outputs, including newline style, are unchanged.

## 5. Compatibility

- **Features:** no feature definition changed. `spkts`/`sbytes` still count `command.input`; `dbytes` is still `log.closed.size`, which the pilot established is server terminal **output** bytes, and it is not reinterpreted.
- **Unchanged:** model configurations (15- and 17-feature), Dataset V1, the live run directories, the original and isolated profiles, and all reports.
- **Behaviour change 1:** a raw log containing invalid UTF-8 now fails loudly instead of being parsed with replacement characters (builder) or failing obscurely (parser). Existing raw logs in the repository are pure ASCII (verified in the earlier audit), so they parse as before.
- **Behaviour change 2:** future traffic runs will produce short failed-login sessions instead of about-120 s ones. Their `dur`, `dinpkt` and `djit` for failed logins will therefore differ from `train_v1`/`eval_v1`. Treat data generated before and after this fix as different distributions.

## 6. Remaining limitations

- **Live verification not run:** live verification against Cowrie (a failed login closing in about 1 s) was not repeated here, because the task forbids traffic and Cowrie use. It is covered by the local-server integration test and the pilot's D2 result. Confirm it on the first approved Cowrie run.
- **No recovery mode for invalid UTF-8:** a corrupted log must be investigated, and fixed or excluded, by a deliberate step.
- **Cowrie's own sanitisation is unchanged:** non-ASCII interactive input is still lost before logging, and tty logs are still not collected.
- **Other input channels untested:** `exec` requests, SFTP and credential fields could put non-ASCII into `cowrie.json`. The parser now handles that correctly, but the extractor's counting semantics for such text were not reviewed.
- **Noisy failure output:** `run_script` in the builder raises `CalledProcessError` after `parse_logs.py` prints its message. The actionable message appears first, followed by a traceback; this was left unchanged.

## 7. Files changed

- **Modified:**
  - `dataset_builder/generate_labelled_traffic.py` (`_connect`, `run_session`, three `open` calls)
  - `dataset_builder/build_labelled_dataset.py` (import `shutil`, byte copy, byte trim, three `open` calls)
  - `scripts/parse_logs.py` (strict per-line UTF-8 decode, explicit UTF-8 output and read-back)
  - `scripts/extract_features.py` (five `open` calls)
- **Created:**
  - `tests/test_generator_connection.py`
  - `tests/test_log_encoding.py`
  - this report
- **Unchanged (verified by SHA-256 over all repository files before and after):** every other file, including datasets, models, configurations, profiles and reports. `test_touches` = 0.
