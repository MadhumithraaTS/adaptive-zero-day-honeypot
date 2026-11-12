# Buffer-overflow telemetry and feature-representation audit

**Date:** 2026-11-10.
**Type:** read-only audit. No Docker, no Cowrie, no SSH, no traffic, no training. The held-out test split (`ml_pipeline/work/test.pkl`) was not opened.

This report extends `reports/buffer_overflow_telemetry_audit_20261110/report.md` (written earlier the same day). That report is cited for findings already established, and this one adds:

- the collection and parsing code;
- the Cowrie configuration;
- payload preservation in real logs;
- Cowrie-originated input events;
- an encoding risk;
- an evaluation of each candidate feature.

**Evidence labels:**

- **[C]** confirmed from data or logs;
- **[S]** inferred from source code;
- **[U]** unverified assumption;
- **[Rec]** recommendation.

**Evidence read:**

- `scripts/generate_dataset.py`, `scripts/collect_logs.py`, `scripts/parse_logs.py`, `scripts/extract_features.py`;
- `cowrie/docker-compose.yml`, `cowrie/userdb.txt`;
- `dataset_builder/generate_labelled_traffic.py`, `dataset_builder/profiles_v2.json`, `configs/attack_profiles.json`;
- every raw Cowrie log in the repository:
  - `dataset_builder/runs/{train_v1,eval_v1}/raw/cowrie*.json`;
  - `data/raw/cowrie.json`;
  - `data/{baseline_backup_*,demo_*,evaluation_runs/*,fresh_evaluation/*}/…/cowrie.json`;
- the synthetic training and validation rows (`ml_pipeline/work/train.pkl`, `val.pkl`).

---

## 1. Executive summary

- **The payload was never sent to Cowrie.** The synthetic buffer-overflow "payload" exists only as a text field inside a JSON event that `scripts/generate_dataset.py` wrote itself, labelled `cowrie.command.failed` with no `cowrie.command.input` [S][C]. No network or SSH interaction took place, and the raw synthetic events weren't kept [C].
- **None of the 15 features carries the payload.** The extractor reads command text only from `cowrie.command.input`. For buffer-overflow sessions, the features record only that one failed command existed (`dpkts` = 6), together with a server-byte value (`dbytes`, 0–100) and a duration that the generator chose for that category [C].
- **Real Cowrie records every typed line as `cowrie.command.input`, with full text**, adding `cowrie.command.failed` only for unknown commands [C]. Lines of up to 5,605 characters appear intact in the logs [C].
  - Two complications: `command.input` also contains lines Cowrie generates itself when it runs a downloaded script [C], and no log contains any non-ASCII input [C].
  - **So how Cowrie represents a binary-like (`\x90`) payload is unverified [U].** The project's own parser could fail on such bytes under Windows' default encoding [S].
- **Decision:** the current configuration (synthetic V1 data plus the 15 features) **cannot meaningfully represent buffer-overflow-style behaviour** (section 10).

---

## 2. Synthetic dataset generation

| # | Question | Finding |
|---|---|---|
| 2.1 | How the payload is generated | Profile `zero_day_buffer_overflow` (`scripts/generate_dataset.py` lines 68–78): `commands: ["\x90" * 256 + "NOP_SLIDE_PAYLOAD_EXPLOIT_EXEC"]` — 286 characters, 542 bytes as UTF-8; `failed_cmd_rate: (1.0, 1.0)`; `tty_size_range: (0, 100)`; `cmd_delay_range: (0.0, 0.1)` [S] |
| 2.2 | Sent to Cowrie, or only written as JSON? | **Only written as JSON.** `generate_synthetic_sessions` (lines 103–274) builds Python dicts and `json.dump`s them to `data/parsed/sessions.json`; no socket, paramiko or Cowrie call exists in the file [S]. The 1,800-session events file isn't retained; the current `data/parsed/sessions.json` is a later 46 KB live parse [C] |
| 2.3 | Event types containing the payload | Only `cowrie.command.failed` (field `input`) [S]. When written with `json.dump` defaults, `\x90` becomes the ASCII escape `\u0090` [S] |
| 2.4 | Successful vs failed commands | Lines 209–233: with probability `failed_cmd_rate`, a command is emitted **only** as `command.failed`, otherwise **only** as `command.input`. The two are mutually exclusive in synthetic data [S] |
| 2.5 | Payload retained or lost | **Lost at extraction.** `extract_features.py` reads `input` text only for `command.input` (lines 255–262). A `command.failed` event only increments `failed_commands` (line 283), which is never output, and `dpkts` (lines 291–292) [S]. Confirmed in data: all 184 training and validation buffer-overflow rows have `spkts` = `sbytes` = 0; 135 have `dpkts` = 6 (logged in, one failed command) and 49 have `dpkts` = 4 (failed login) [C] |

An event containing the payload string does not show that Cowrie received or processed it. In V1, it shows only what the generator chose to write [S].

---

## 3. Real Cowrie event representation

| # | Question | Finding |
|---|---|---|
| 3.1 | Typed commands | One `cowrie.command.input` per line, with the full text in `input`. eval_v1 has 3,150 input events [C]. A final `exit` is also recorded [C] |
| 3.2 | Failed commands | `cowrie.command.failed` (message `Command not found: …`) about 1 ms **after** the matching `command.input`. eval_v1: 169/169 have a matching input event. train_v1: 482/552 match exactly and the rest are `;`-separated fragments of a longer input line [C] (earlier audit, section 1.3) |
| 3.3 | Raw input available? | Yes, in `command.input.input` [C]. `scripts/collect_logs.py` copies `cowrie.json` unchanged (`docker cp`, line 30) and `scripts/parse_logs.py` groups events by `session` without dropping fields (lines 50–59) [S] |
| 3.4 | Long or binary payloads | **Long:** preserved. Input lines of 5,605 characters appear in `train_v1`/`eval_v1` raw logs [C]; any Cowrie truncation limit beyond that is unknown [U]. **Binary-like:** no log in the repository contains a single byte above 127 or a `\u` escape [C], so whether Cowrie escapes, replaces, strips or rejects such bytes in an interactive shell is **unverified** [U] |
| 3.5 | Can telemetry tell a payload from an ordinary failed command? | **Raw telemetry: yes, potentially.** The full input text is logged, so length and content are available [C]. **Current features: no** (section 5) |
| 3.6 | Do synthetic events match Cowrie semantics? | **No.** See section 6 [C] |

### 3.7 Additional confirmed observations

1. **Not every `command.input` line comes from the client [C].**
   - What happened: in train_v1, Cowrie's emulated `wget` downloaded `http://185.220.101.5/b.sh` (a `cowrie.session.file_download` event with SHA-256 `33c81a04…`), and the emulated `sh b.sh` then logged each line of that file as `cowrie.command.input`.
   - Evidence: the first such line came 1.4 ms after `sh b.sh`, followed by dozens of `command.failed` events. None of the text appears in `manifest.jsonl` (0 manifest commands contain it).
   - Consequence: input length and content can reflect **server-side** activity, and a "payload" feature could fire on downloaded content.
2. **Cowrie makes real outbound requests [C].**
   - What happened: the downloaded file is the campus gateway's block page ("Gateway GEO-IP Filter Alert", IP 185.220.101.5). Cowrie's `wget` therefore attempted a real HTTP request to an IP listed in `dataset_builder/profiles_v2.json` placeholders (line 6).
   - Download events: 11 in train_v1 and 35 in eval_v1.
   - Why it matters: this is a safety concern for any payload or download experiment.
3. **The Cowrie version and configuration aren't pinned [C].**
   - `cowrie/docker-compose.yml` uses `image: cowrie/cowrie:latest` with no config mount; only `cowrie/userdb.txt` is project-specific.
   - The Cowrie source isn't in the repository. Logging behaviour for unusual input can therefore change between image pulls [U].
4. **Encoding risk in the project's log path [S].**
   - `scripts/parse_logs.py` line 38 opens the raw log with no `encoding=`. On this machine the default is cp1252 (`locale.getpreferredencoding()` gives `cp1252`) [C].
   - `dataset_builder/build_labelled_dataset.py` reads the raw log as UTF-8 with `errors='replace'` (lines 128, 136), writes the run slice as UTF-8 (line 140), and then runs `parse_logs.py` on it (line 148).
   - If Cowrie writes a payload as raw UTF-8, U+0090 becomes bytes `C2 90`. Byte `0x90` is undefined in cp1252, so decoding raises `UnicodeDecodeError` [C, tested on the byte pair alone], and `parse_logs.py` stops with `LogParseError` (lines 60–61).
   - Other non-ASCII bytes would instead be **silently mis-decoded** by cp1252.
   - Invalid UTF-8 in the raw log would be **silently replaced** with U+FFFD by the builder.
   - Whether Cowrie writes raw UTF-8 or `\u` escapes is unknown [U]; with escapes, none of this applies.

---

## 4. Raw payload observability

| Source | Is the payload observable? | Basis |
|---|---|---|
| Synthetic V1 raw events | Only as generator-written text in `command.failed`; the file is gone | [S][C] |
| Synthetic V1 features (`model_selection/behavior_features.csv`) | No | [C] |
| Real Cowrie, printable long payload | Yes in `command.input.input` (≥ 5,605 characters preserved) | [C] |
| Real Cowrie, binary-like (`\x90`) payload | Unknown; never observed | [U] |
| Real Cowrie features (current extractor) | Only indirectly: `sbytes` grows with line length, but nothing marks a payload | [S] |

**Live behaviour for a buffer-overflow-style payload remains unverified.** No log in the repository contains one. No live profile (`configs/attack_profiles.json`, `dataset_builder/profiles_v2.json`) sends one [C].

---

## 5. Suitability of the existing 15 features

The 15 features, in order (`models/dec_15_feature_v2_deterministic/config.json`): `dur, spkts, dpkts, sbytes, dbytes, rate, sload, dload, sinpkt, dinpkt, sjit, djit, tcprtt, synack, ackdat`. No other feature is used.

| Feature | Source (`extract_features.py`) | Synthetic buffer-overflow value | Real Cowrie, if a payload line were typed | Captures the payload? |
|---|---|---|---|---|
| `dur` | `session.closed.duration_ms` (234–240, 304–311) | 0.17–0.56 s, from designed `cmd_delay_range` | real duration | No; timing only |
| `spkts` | count of `command.input` (261) | 0 | +1 per line | Only "a line was typed" |
| `dpkts` | count of `DPKT_EVENT_IDS` incl. `command.failed` (19–29, 291) | 6 (= 5 + 1 failed) | +1 if the line is "not found" | Only "a command failed"; same as any unknown command |
| `sbytes` | UTF-8 length of `command.input` (262) | 0 | + payload length | **Length only, mixed with all other input**; also counts Cowrie-executed script lines (3.7.1) |
| `dbytes` | `log.closed.size` (242–248, 315) | U[0, 100], injected by the generator (`generate_dataset.py` line 241) | tty-log size (input + output) | No; synthetic value is a category parameter |
| `rate` | (`sbytes` + `dbytes`) / `dur` (316) | from injected `dbytes` | derived | No |
| `sload` | 8 × `sbytes` / `dur` (319) | 0 | derived from `sbytes` | Indirect length signal only |
| `dload` | 8 × `dbytes` / `dur` (320) | from injected `dbytes` | derived | No |
| `sinpkt`, `sjit` | gaps between `command.input` (322–343) | 0 | gaps between lines | No |
| `dinpkt`, `djit` | gaps between `DPKT` events (332–344) | generated offsets | real gaps | No |
| `tcprtt` | first `client.kex` minus first event (346–349) | category-independent offsets | loopback handshake | No |
| `synack` | 0.45 × `tcprtt` (352) | constant multiple | constant multiple | No |
| `ackdat` | first `command.input` minus login (354–357) | 0 | time to first line | No |

Answers to the audit questions:

1. **Derived from Cowrie events:** all 15 features are computed from Cowrie-format events. In real data, `synack` is a formula and `tcprtt` measures the lab's loopback handshake [S].
2. **Synthetic or generator-injected (in V1):**
   - `dbytes`, `rate` and `dload` are injected (the `tty_size_range` value);
   - `dur`, `sinpkt`, `sjit` and `ackdat` come from designed per-category delays;
   - `tcprtt` and `synack` are generated noise and a constant.

   See `reports/research_integrity_audit_20261110/feature_leakage_audit.csv`. [C]
3. **Payload length or content:** not represented in V1 [C]. In live data, length enters `sbytes` only as part of a total; content is never represented [S].
4. **Failed commands treated as client input?** No; the reverse problem exists. Failed commands are counted as **server** events (`dpkts`), not client input [S].
   - In synthetic data they are absent from the client features.
   - In live data they appear in both (`command.input` → `spkts`/`sbytes`, `command.failed` → `dpkts`) [C].
   - The concern that failed-command counts are being read as client input does not apply to the current code.
5. **Telling the target behaviour apart from unrelated failed commands:**
   - **Synthetic:** buffer-overflow sessions can be separated from the 3 other train/validation sessions where every command failed (1 evasion, 2 privilege escalation) only by:
     - `dpkts` 6 vs 7 (one command vs two);
     - injected `dbytes` 0–100 vs 1,445–2,626;
     - duration 0.17–0.56 s vs 3.3–9.0 s.

     None of these reflects the payload [C].
   - **Live:** a payload line would look like any long, unknown command [S].
6. **Payload information lost:** yes. Content, encoding, non-printable share, the marker and per-line length are all discarded; `failed_commands` is computed and dropped [S].

---

## 6. Training vs live telemetry

| Aspect | Synthetic training/validation (V1) | Real Cowrie |
|---|---|---|
| Command input events | Only for commands the generator marks as successful [S] | Every line, including `exit`, failed commands, and lines of scripts Cowrie runs itself [C] |
| Failed command events | **Instead of** an input event [S] | **In addition to** the input event, about 1 ms later; one per `;` fragment [C] |
| Raw payload availability | Generator text in `command.failed`; raw file not retained [C] | `command.input.input`, full text; non-ASCII handling unknown [C][U] |
| Payload length | Not in any feature (`sbytes` = 0) [C] | Adds to `sbytes` (≥ 5,605 characters preserved) [C] |
| Packet/byte features | `dpkts` baselines 4 (failed login) and 5 (logged in); `dbytes` = per-category random range [C] | `dpkts` baselines 3 and 6 (`session.params`); `dbytes` = real tty-log size [C] |
| Missing fields | No `session.params`, no `file_download`, no `message`, `sensor`, `uuid`, `shasum` [S] | All present [C] |
| Event semantics | One login event per session; generated timing offsets; `tcprtt` about 0.073 s [C] | Each failed attempt is its own session; failed logins last about 120 s; `tcprtt` about 0.010 s [C] |
| Encoding | `json.dump` ASCII escapes [S] | Unknown for non-ASCII; the project parser assumes the locale encoding [S][U] |
| Version | Generator commit 6c8fb32 | `cowrie/cowrie:latest`, unpinned [C] |

**Every mismatch above affects at least one of the 15 features.** The most important are:

- failed-command handling (`spkts`, `sbytes`, `dpkts`);
- the source of `dbytes`;
- the `dpkts` baselines.

---

## 7. Is a new feature necessary?

A payload-related feature is technically justified **only after** the live payload behaviour is verified, and only from `command.input`.

| Candidate | Source event | Available in synthetic V1? | Available live? | Reproducible? | Risk of matching unrelated failures | Leakage or shortcut risk | Put in the model? |
|---|---|---|---|---|---|---|---|
| Max input-line length (bytes) | `command.input.input` | No (payload not in input; raw file gone) | Yes | Yes, if encoding is fixed | Low for failures; **high for Cowrie-executed script lines** (5,605-character HTML) unless only client lines are counted | Low, if payload lengths vary within the profile | Candidate, after verification |
| Known test marker present | `command.input.input` | No | Yes | Yes | None | **High:** a fixed marker identifies the category exactly, so it's an evaluation check, not a learnable behaviour | **No.** Use only to verify delivery |
| Non-printable / high-byte share | `command.input.input` | No | Unknown (never observed) | Depends on Cowrie and parser encoding | Low | Medium: if only the payload profile has such bytes, the feature is a category flag | Only after the encoding path is verified, with non-printable content also in some benign or other-category sessions |
| Command-input event count | `command.input` | Inconsistent (failed commands missing) | Yes | Yes | Counts failed and successful lines equally | Low | Already approximated by `spkts`; fix the semantics rather than adding a feature |
| Failed-command count | `command.failed` | Yes (`failed_commands`, computed but discarded) | Yes, but one event per `;` fragment | Yes | **Is itself "unrelated failures"** | Medium in V1 (designed `failed_cmd_rate`) | Possibly, de-duplicated per input line; not as a payload indicator |
| Encoding/parse status | parser outcome | No | Unknown | Depends on the parser | — | — | **No.** It's a data-quality flag, not a model input |

Also needed for any content feature: a way to separate client-typed lines from lines Cowrie runs from downloaded scripts. For example, take lines from the client manifest in labelled runs, or exclude `command.input` events that occur within milliseconds after `sh <file>` [Rec, unverified heuristic].

**Without verified live observability, the current honeypot configuration may not support detecting this behaviour with the existing feature set** [S][U].

---

## 8. Limitations and unresolved questions

1. **[U]** How Cowrie (the unpinned `cowrie/cowrie:latest`) logs non-ASCII or control bytes typed into its interactive shell: escaped, replaced, stripped, or a dropped session.
2. **[U]** Whether Cowrie writes `cowrie.json` with ASCII escapes or raw UTF-8. This decides whether the cp1252 parser path would fail (section 3.7.4).
3. **[U]** Any Cowrie input-line length limit above 5,605 characters, and how paramiko `channel.send` chunks long lines.
4. **[U]** Whether a payload line would produce `command.failed` (probably, as an unknown command) and how many fragments.
5. **[S]** The test split is assumed to have the same artefacts, by shared code. It was not inspected.
6. The raw synthetic V1 events are not retained, so V1 statements rely on code plus feature-level confirmation on 1,530 training and validation rows.
7. Only raw logs present in the repository were examined. The Cowrie source and documentation are not in the repository.

---

## 9. Recommendations (for approval; none implemented)

1. **[Rec]** Treat V1 buffer-overflow results as non-evidence for payload detection, and state this in project documentation (see `reports/research_integrity_audit_20261110/research_claims_validity_matrix.csv`).
2. **[Rec] Before any payload experiment:**
   - pin the Cowrie image by digest and record its configuration;
   - block or sinkhole outbound network access from the Cowrie container;
   - replace real placeholder IPs and domains with documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24; `example.invalid`). Cowrie's `wget` really fetches URLs (section 3.7.2).
3. **[Rec]** Run a **small, approved observability pilot** of a few sessions. Send one printable long marker line and one line with raw high bytes, and record:
   - the `command.input` text exactly as logged;
   - any `command.failed` events;
   - the JSON encoding;
   - whether `parse_logs.py` succeeds.

   This settles questions 8.1–8.4. It is traffic generation and needs your approval.
4. **[Rec]** If the pilot confirms observability, specify (don't yet add) a feature computed from **client-typed** `command.input` lines only, such as maximum line length. Exclude the fixed marker from model inputs and use it only to verify delivery.
5. **[Rec]** Address the encoding risk in a future approved code change, for example by reading raw logs with `encoding="utf-8"`. Not done here.
6. **Dataset regeneration:** V1 cannot be repaired (raw events gone; failure semantics wrong), so a payload-aware dataset must be **newly generated through real Cowrie** (Dataset V2; `reports/research_integrity_audit_20261110/dataset_v2_experimental_protocol.md`). Keep V1 unchanged.
7. The approved deterministic Autoencoder + K-Means rerun is independent of this audit. It reproduces V1 results and doesn't address payload observability.

---

## 10. Decision

**The current configuration cannot meaningfully represent buffer-overflow-style behaviour.**

- In the V1 training data, the payload never reaches the features. The buffer-overflow category is distinguishable only by one failed-command count, a generator-injected byte range and designed timing [C].
- In live Cowrie, the payload text would be logged in `command.input`, but the 15 features keep at most its length, merged into `sbytes` [S]. Binary-like payload handling is unverified [U].
- A dedicated, verified feature and a real-Cowrie dataset would both be needed before any claim about this behaviour can be tested.

---

## Integrity

Files hashed with SHA-256 before and after this audit (all repository files except `.git`, `.venv`, `.venv-dec-smoke`, `__pycache__` and `.pytest_cache`); results are in the hand-off message.

- **Test-split access:** none. Analysis read `ml_pipeline/work/train.pkl`, `val.pkl` and raw live logs only. `ml_pipeline/.guard_state.json` reports `test_touches: 0`.
