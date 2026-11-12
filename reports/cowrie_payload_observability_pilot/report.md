# Cowrie payload observability pilot

**Date:** 2026-11-10.
**Environment:** the isolated lab from `reports/cowrie_security_isolation_audit/report.md`.
**Scope:** a harmless telemetry experiment. No exploit, no malware, no external download, no outbound access, no Dataset V2, no training, no changes to the extractor, Dataset V1 or the test split.

## Evidence in this folder

| File | Content |
|---|---|
| `pilot_client.py` | The exact client used, with the bytes for each test |
| `evidence/client_record.json` | Hex of every byte sequence sent, with client-side UTC timestamps |
| `evidence/cowrie_pilot_slice.json` | The 46 raw Cowrie events of the pilot: log lines after baseline 12, `evidence_meta/baseline.json` |
| `evidence/cowrie_full_after.json` | The whole current `cowrie.json` after the pilot |
| `evidence/<sha256>` | Cowrie tty logs of sessions A, B and C |
| `evidence/provenance_check.json` | Comparison of each `command.input` event with the tty input stream |
| `parser_harness.py`, `evidence/parser_harness_results.json` | Parser, extractor and builder runs on log variants; work files were in the session scratchpad, not the repository |

**Labels:** **[C]** confirmed by this pilot's evidence, **[S]** from source code, **[U]** unverified.

---

## 1. Environment verification (before sending anything)

| # | Check | Result |
|---|---|---|
| 1 | Pinned digest | Both containers run `cowrie/cowrie@sha256:bf371c37…cc13a`; the image ID matches [C] |
| 2 | Internal network | `cowrie-project` is attached only to `cowrie_cowrie_internal` (`internal=true`) [C] |
| 3 | Outbound blocked | From Cowrie: 1.1.1.1:443, 8.8.8.8:53, 185.220.101.5:80, 192.168.65.254:80 and 172.19.0.1 all give *Network is unreachable*; external DNS fails; only route is 172.22.0.0/16 [C] |
| 4 | Localhost only | `docker port`: `2222/tcp -> 127.0.0.1:2223`; 127.0.0.1:2223 connects; 172.20.10.5, 192.168.56.1 and 172.27.0.1 refuse [C] |
| 5 | Isolated profiles | `dataset_builder/profiles_v2_isolated.json` (`385af936…`) and `configs/attack_profiles_isolated.json` (`cce96008…`) are present and unchanged. **The pilot did not use any profile file.** Its inputs are hard-coded in `pilot_client.py` and contain no network destinations [C] |
| 6 | Relay scope | Relay command: `twistd -n --pidfile= portforward --port=tcp:2222 --host=cowrie --dest_port=2222`; one port binding, 127.0.0.1:2223 [C] |

All checks passed.

## 2. Exact test inputs

Run ID `30457e89`. Each test ran in its own SSH session, with credentials `<user>`/`<user>-pw`. Cowrie's `userdb.txt` accepts these and rejects `scan` with `123456`.

| Test | User / Cowrie session | Bytes sent (excluding the final `\n`) |
|---|---|---|
| A, printable | `pilot_a` / `5f8f7af3f320` | `PILOT_A_30457e89 ` + (`A–Z a–z 0–9 -_.`) × 4 = 277 bytes, all 0x20–0x7E |
| B, high bytes | `pilot_b` / `ac9ae6e306b6` | `PILOT_B_30457e89 ` + `90 90 90 90 90 90 90 90` + ` ` + `c2 90` (UTF-8 U+0090) + ` ` + `c3 a9` (UTF-8 é) + ` ` + `ff` + ` END` = 37 bytes |
| C, provenance | `pilot_c` / `852266ae5622` | `echo PILOT_C_30457e89_line_from_script > /tmp/pilot_c.sh`, then `sh /tmp/pilot_c.sh` (writes and runs a one-line script inside Cowrie's emulated filesystem) |
| D1, timing | `scan` / `c65bb1153ddd` | failed login through `dataset_builder/generate_labelled_traffic.py::_connect` (the generator's own code) |
| D2, timing | `scan` / `3786adc92ee7` | failed login with `paramiko.Transport`, closed explicitly right after the rejection |

Each shell session ended with `exit`. All five tests completed as planned: A–C logged in; D1 and D2 were rejected with `AuthenticationException` [C].

## 3. Raw event evidence

From `evidence/cowrie_pilot_slice.json`:

```
08:34:58.597668 5f8f7af3f320 cowrie.command.input  "PILOT_A_30457e89 ABCDEFGH…-_."            (277 chars)
08:34:58.599325 5f8f7af3f320 cowrie.command.failed "PILOT_A_30457e89 ABCDEFGH…-_."            (+1.7 ms)
08:35:03.242687 ac9ae6e306b6 cowrie.command.input  "PILOT_B_30457e89     END"
08:35:03.243496 ac9ae6e306b6 cowrie.command.failed "PILOT_B_30457e89 END"                     (+0.8 ms)
08:35:09.423836 852266ae5622 cowrie.command.input  "sh /tmp/pilot_c.sh"
08:35:09.426588 852266ae5622 cowrie.command.input  "PILOT_C_30457e89_line_from_script"        (+2.8 ms, Cowrie-executed)
08:35:09.427461 852266ae5622 cowrie.command.failed "PILOT_C_30457e89_line_from_script "
08:35:10.928125 852266ae5622 cowrie.session.file_download  destfile=/tmp/pilot_c.sh, message "Saved redir contents …", no url
08:35:12.997734 c65bb1153ddd cowrie.login.failed  [scan/123456]
08:37:12.950575 c65bb1153ddd cowrie.session.closed "Connection lost after 120.0 seconds"
08:35:19.079805 3786adc92ee7 cowrie.login.failed  [scan/123456]
08:35:20.086993 3786adc92ee7 cowrie.session.closed "Connection lost after 1.1 seconds"
```

Full raw JSON line for B's input event:

```json
{"eventid":"cowrie.command.input","input":"PILOT_B_30457e89     END","message":"CMD: PILOT_B_30457e89     END","sensor":"2a3c9e98967e","uuid":"bafc61de-32ec-11f1-a37e-46de337b5ff9","timestamp":"2026-11-10T08:35:03.242687Z","src_ip":"172.22.0.3","session":"ac9ae6e306b6","protocol":"ssh"}
```

## 4. Byte-preservation analysis

| | Sent (hex) | `cowrie.json` `command.input` | tty log input stream |
|---|---|---|---|
| A | 277 printable bytes | **identical**, 277 bytes [C] | identical (`\n` recorded as `\r`/`\n`) [C] |
| B | `… 20 90 90 90 90 90 90 90 90 20 c2 90 20 c3 a9 20 ff 20 45 4e 44` | `… 20 20 20 20 20 45 4e 44`: **all 13 high bytes removed; nothing escaped or replaced** [C] | **identical to the bytes sent**, all 13 high bytes present [C] |
| C | 81 bytes over 2 lines | both lines identical [C] | identical [C] |

Additional confirmed facts:

- **Whitespace collapses in `command.failed`.** The `command.failed` text for B is `PILOT_B_30457e89 END`, with runs of spaces reduced to one; the event is the parsed command, not the raw line [C].
- **The echo is sanitized too.** Cowrie's echoed terminal output for B also contains only spaces where the high bytes were: the output stream after the marker is `20 20 20 20 20 45 4e 44` [C].
- **Nothing was truncated:** the longest line was 277 bytes. Earlier live logs show lines of 5,605 characters preserved [C]. A limit above that was not tested [U].
- **`log.closed.size` is the tty *output* byte count** [C]: A 654, B 401, C 502, each equal to the output bytes in that session's tty log (inputs 283, 43, 81 bytes). This corrects the statement in `reports/buffer_overflow_telemetry_audit/report.md` sections 5–6 and `reports/research_integrity_audit_20261110/` that it is input plus output.

## 5. Encoding findings

1. **Cowrie (this pinned build) discards non-ASCII bytes from interactive input before logging** [C]:
   - invalid UTF-8 (bare 0x90, 0xFF) and valid multi-byte UTF-8 (U+0090, é) alike;
   - the removal happens in Cowrie's terminal or line-editing layer, before command parsing and before the echo;
   - the exact code path was not traced [U].
2. **`cowrie.json` contains only ASCII** in the pilot slice: 0 bytes above 127 and 0 `\u` escapes [C]. Cowrie's own output therefore never triggers the project's encoding problems for interactive input.
3. **The raw bytes survive only in the tty log** (`var/lib/cowrie/tty/<sha256>`, Cowrie's UML-compatible record format `<iLiiLL`, direction 1 = input) [C][S]. The project's pipeline never reads tty logs: `scripts/collect_logs.py` copies only `cowrie.json` [S].
4. **Not tested:** non-ASCII arriving through other channels, such as an `exec` request (`ssh host 'cmd'`), SFTP/SCP, or usernames and passwords. These may be logged differently [U].

## 6. Event provenance

1. **`command.input` includes lines Cowrie itself executes** [C].
   - In C, `sh /tmp/pilot_c.sh` produced a second `command.input` (`PILOT_C_…_line_from_script`) 2.8 ms later, plus a `command.failed`.
   - The client never typed that line on its own; it appears only inside the `echo` argument.
   - This matches the earlier live evidence of downloaded HTML being "executed" line by line (`reports/buffer_overflow_telemetry_audit/report.md` section 3.7).
2. **`session.file_download` is not necessarily a network download** [C].
   - The shell redirect `> /tmp/pilot_c.sh` produced a `cowrie.session.file_download` with `destfile` and message "Saved redir contents", and **no `url` field**.
   - Earlier live downloads carry `url`. The two can be told apart by the `url` field and the message text [C].
3. **Provenance can be recovered from the tty log** [C] (`evidence/provenance_check.json`). Compare each `command.input` with the session's tty input lines after removing non-printable bytes from those lines:
   - all 7 client-typed lines match, including B's sanitized line, which fails an exact comparison;
   - the Cowrie-executed line does not match.

   Limitations: one example; interactive editing (backspace, arrow keys, tab completion) could make tty lines differ from the logged command; and a client could deliberately type the same text [U]. The timing heuristic (an extra `command.input` within milliseconds of `sh`) is consistent with this but weaker.
4. **The extractor counts Cowrie-executed lines as client input** [C]. Session C has `spkts` = 4 and `sbytes` = 111, which include the 33-byte line Cowrie generated (V0 extraction in the harness).

## 7. Parser compatibility (existing code, unmodified, temporary outputs)

Results are from `parser_harness.py`, which ran `scripts/parse_logs.py`, `scripts/extract_features.py` and `dataset_builder/build_labelled_dataset.py --raw-input`.

- **Variants:** V0 is the real log. V1–V3 are constructed to show what *would* happen if non-ASCII ever reached `cowrie.json`. In V1 and V2 each sent byte is represented as one code point (latin-1 view).
- **Environments:** the Windows default (cp1252 here) and UTF-8 mode (`PYTHONUTF8=1`).

| Variant | Default (cp1252) | UTF-8 mode |
|---|---|---|
| V0, real pilot log (ASCII) | parse ✓, extract ✓, builder ✓ | same |
| V1, `\u0090` JSON escapes | ✓ all; escapes decoded correctly; B `sbytes` = 54 (each code point re-encoded as UTF-8, so not equal to the 37 bytes sent) | same |
| V2, raw UTF-8 | **`parse_logs.py` fails** (`'charmap' codec can't decode byte 0x90`); **builder crashes** with `UnicodeEncodeError` writing its copy (`build_labelled_dataset.py` line 128, `open(raw_path, 'w')` without encoding) | ✓ all |
| V3, invalid raw 0x90 | **parse fails; builder crashes** | **`parse_logs.py` fails** (invalid UTF-8) but **the builder succeeds after silently replacing the byte with U+FFFD** (`errors='replace'`, lines 128 and 136) |

No truncation was observed in any successful path. Because Cowrie strips non-ASCII (section 5), V2 and V3 can't arise from interactive input with this Cowrie build. They remain risks for other input channels and other Cowrie versions [U].

## 8. Timing findings (about 120 s failed-login duration)

| Session | Client behaviour | `login.failed` → `session.closed` | Cowrie message |
|---|---|---|---|
| D1 `c65bb1153ddd` | `generate_labelled_traffic._connect` raises on rejection, so `.close()` (line 136) is never reached | **119.95 s** | "Connection lost after 120.0 seconds" |
| D2 `3786adc92ee7` | transport closed explicitly | **1.0 s** | "Connection lost after 1.1 seconds" |

**Conclusion [C]:** the about-120 s duration is a **client-side artefact of the traffic generator**. In `run_session` (`dataset_builder/generate_labelled_traffic.py` line 136), `_connect(...).close()` raises before `.close()` runs, leaving the SSH transport open. Cowrie then drops the idle, unauthenticated connection at `authentication_timeout = 120` (`cowrie.cfg.dist`) [S][C]. It is not a timestamp-interpretation problem, and not a client retry: each session has exactly one `login.failed`, consistent with train_v1, which shows 1 per failed session and a median gap of 119.97 s over 1,636 closed sessions.

**Consequence:** in the existing live datasets, `dur` (and `dinpkt`/`djit`) of failed-login sessions measure the generator's missing `close()`, not attacker behaviour.

## 9. Limitations

- One run, one sample per test; this pinned development build of Cowrie only (`2.9.17.dev1+gcd0770d3d`).
- Interactive shell input only; exec requests, SFTP/SCP and credential fields weren't tested.
- The exact Cowrie code path that strips non-ASCII wasn't traced.
- The provenance method was demonstrated on one Cowrie-executed line; interactive line editing wasn't tested.
- The relay adds a hop: `src_ip` is 172.22.0.3, and `tcprtt` here (4–14 ms) is not comparable with older runs.
- **The pilot added data to Cowrie's volume:**
  - 46 events in `cowrie.json`;
  - three tty logs;
  - one "redir" file under `var/lib/cowrie/downloads/` (the one-line `/tmp/pilot_c.sh` text, SHA-256 `bb392771…ef4d`).

  Future runs must record a fresh `log_baseline_lines` (the generator already does).

## 10. Recommendation on a payload-related feature

**Not justified from `cowrie.json` for binary-like payloads.** This Cowrie build removes every non-ASCII byte from logged input. A NOP-sled-style payload therefore reaches `cowrie.json` as spaces (or nothing), and no feature computed from `command.input` can represent it.

- **Printable payloads:** fully preserved in `command.input`. A length-type feature (for example maximum input-line length) is technically possible, **but only from client-typed lines**: Cowrie-executed lines are also logged as `command.input`. Provenance would have to come from the tty log comparison (section 6.3) or the generation manifest.
- **Binary payloads:** observable only in tty logs. A tty-based feature would need:
  1. collecting tty logs (currently not collected);
  2. a parser for Cowrie's record format;
  3. a defined handling of terminal control sequences.

  That is a new data source and an extractor change. It needs your decision and is not recommended before the other issues below are addressed.
- **To decide before any Dataset V2 work:**
  - (a) fix the generator's failed-login `close()`, otherwise the 120 s artefact persists;
  - (b) make the parser and builder read and write raw logs as UTF-8 explicitly;
  - (c) decide whether tty logs become part of the collected telemetry.

  None of these was changed here.

## Files

- **Created:** this folder: `report.md`, `pilot_client.py`, `parser_harness.py`, `evidence/`, `evidence_meta/`.
- **Modified in the repository:** none.
- **Changed outside the repository:** Cowrie's data volume (pilot events, tty logs, the redir file above). Harness work files are in the session scratchpad.
