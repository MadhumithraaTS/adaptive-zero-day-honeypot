# Diagnostic redaction and UTF-8 chunk-decoding fix

**Date:** 2026-11-10. **Task 10A.**

**Scope:** the generator's *diagnostic* terminal-output capture only (`terminal_output.jsonl`).

**Not done:** no dataset, no profile, specification, extractor or model change, no Cowrie or Docker change, no TTY use, no test-set access, no commits.

## 1. Root cause

| Defect | Code before (`dataset_builder/generate_labelled_traffic.py`, task 8 version) | Effect seen in task 9 |
|---|---|---|
| Over-broad redaction | `run_session` passed **every** session password to **every** wait (`redact = tuple(password for _, password in attempts)`). `_OutputCapture.result` replaced the raw substring anywhere in the stored head and tail, including the prompt, without checking whether the client ever typed it | `admin/admin` → every prompt stored as `[REDACTED]@svr04…`. Password `user` → `sudo` help text `-u [REDACTED] name`. 23 false redactions; stored evidence disagreed with the manifest's `prompt_match` |
| Chunk decoding | `data.decode('utf-8', errors='replace')` per received chunk | Multi-byte characters split across chunks became `�`: `wget`'s `‘mirror.example’` stored as `�mirror.example�` |

**Key fact behind the fix:** SSH password authentication never passes through the terminal. A password can therefore appear in terminal output only if the client typed it in a command. Without such a command there is no evidence of an echoed secret, and nothing should be replaced.

## 2. Implementation

| Element | Behaviour |
|---|---|
| `secrets_typed_in(command, secrets)` | Returns only the session passwords that occur **as a whole token** in the command the client sent for that step |
| `wait_for_prompt(..., typed_secrets=())` | The initial wait gets no secrets (nothing has been typed). Each command wait gets `secrets_typed_in(command, session passwords)`. **Prompt detection still runs on the unredacted buffer** |
| `_OutputCapture.result(prompt_match, typed_secrets)` | Redacts only whole-token occurrences (`(?<![A-Za-z0-9_])secret(?![A-Za-z0-9_])`) of typed secrets ≥ 4 characters. **The trailing prompt is never altered.** Records `redaction: {applied, reason, occurrences}` with reason `no_secret_typed` / `typed_secret_echoed_and_redacted` / `typed_secret_not_found_in_output` / `typed_secret_too_short_not_redacted` |
| Bound | Head and tail are kept with a margin equal to the longest typed secret, so a secret straddling a cut is redacted before the final cut. The stored output never exceeds 2,048 characters plus the truncation marker (`TRUNCATION_MARKER`) |
| `_Utf8Stream` | One incremental UTF-8 decoder per wait (`codecs.getincrementaldecoder`, `surrogateescape`). Split characters are reassembled. Invalid bytes are rendered **explicitly** as `\xNN` and counted (`invalid_utf8_bytes`). An incomplete sequence at the end of a wait is flushed explicitly |
| Records | Each `terminal_output.jsonl` record gains `redaction` and `invalid_utf8_bytes`. `run_meta.json` gains `output_redaction_policy` and `output_decoding` |

**The original unredacted text is not stored.** Storing it would keep the very secret being protected. The distinction between original and stored text is preserved by the `redaction` record (`applied`, `reason`, `occurrences`).

**Generator semantics are unchanged** (syntax-tree comparison with the pre-change copy):

- unchanged: `PacingPolicy`, `ReadinessPolicy`, `_connect`, `plan_*`, `weighted_profile_order`, `session_pacing_rng`, `find_pacing_seed_reuse`, `wait_for_close`, `_command_entry`;
- `run_session`: only the secrets passed to each wait changed;
- `main`: only two `run_meta.json` fields added;
- `wait_for_prompt`: only decoding and capture changed; prompt matching uses the same regex on the same unredacted buffer.

The manifest schema is unchanged; a test confirms no redaction or decoding metadata reaches it.

## 3. Unit tests

**New file: `tests/test_diagnostic_redaction_utf8.py` (16 tests):**

- **Overlap and ordinary text:**
  - `admin/admin` overlap: prompts intact, no redaction, evidence equals the manifest's `prompt_match`;
  - `user` in `sudo` help text untouched;
  - a username in the prompt kept.
- **Typed and echoed secrets:**
  - a genuinely typed and echoed password is redacted (2 occurrences) with the prompt intact; the next step is untouched;
  - a typed secret in a command echo is redacted;
  - a typed secret absent from the output is recorded without replacement.
- **Never-echoed and partial matches:**
  - a password never typed but appearing in output is not replaced;
  - substrings inside other words are not redacted;
  - a short typed password is not redacted, with the reason recorded.
- **Truncation:**
  - redaction plus truncation keeps the bound, the prompt and no secret;
  - a secret straddling the cut is not partly leaked.
- **Decoding:**
  - Unicode split across 1-byte chunks (`‘’`, `—`, 😀) is preserved, with no `�` and byte totals exact;
  - invalid UTF-8 is rendered as `\x90\xff\xc3` and counted (3);
  - an incomplete trailing sequence is flushed explicitly;
  - prompt detection works on 2-byte-chunked prompts.
- **Separation:** redaction and decoding metadata never enter the manifest.

**Updated:**

- `tests/test_generator_observability.py`: two capture-class tests moved to the new API with the same intent.
- `tests/generator_fakes.py`: optional `prompt`, `responses` and `chunk_size`; defaults unchanged.

**Full suite: 249 passed** (previously 233), 5 warnings, the same as before.

## 4. Real-Cowrie verification

**Isolation re-checked before connecting:**

- containers up, RestartCount 0;
- Cowrie only on the internal network;
- all external, host and gateway targets *Network is unreachable*;
- external DNS fails;
- 2223 bound to 127.0.0.1 only, LAN addresses refused;
- compat profiles unchanged (`27c4f964…`).

**Baseline:** **506 lines, 244,907 bytes, SHA-256 `020a4463e093ac34daf6c3f48555b9d4a0f1b8a296a2802ede3af77b4bbd9468`**. The test's events are lines 507–535 (29 events): `evidence/cowrie_verification_slice.json`. The first 506 lines of `evidence/cowrie_full_after.json` hash to the baseline.

**Sessions** (`dataset_builder/profiles_v2_compat.json` subsets; chosen offline before connecting: `configs/session_plan.json`):

| | benign_admin | botnet |
|---|---|---|
| Planning / pacing seed | 1 / **9201** (fresh) | 7 / **9202** (fresh; seed 7 = smallest giving `admin/admin` plus `wget` to `.example`) |
| Credentials | `ubuntu` / `Adm1n#2026` | **`admin` / `admin`** (username = password) |
| Cowrie session | a8bece43a6c7 | 8e394a6d867c |
| Commands sent = Cowrie `command.input`, same order, then `exit` | yes (5) | yes (5) |
| Termination / exit confirmed / final event | clean_exit / yes / `session.closed` | clean_exit / yes / `session.closed` |
| Prompts stored | `ubuntu@svr04:~$ ` | `admin@svr04:~$ `, `admin@svr04:/dev/shm$ ` (**intact**) |
| Saved prompt evidence = manifest `prompt_match` | yes (6/6 waits) | yes (6/6 waits) |
| `[REDACTED]` markers / reason | 0 / `no_secret_typed` | 0 / `no_secret_typed` |
| Password text in output | none | only inside prompts, as the username; **0 occurrences elsewhere** |
| Unicode | none produced | `wget: unable to resolve host address ‘mirror.example’` (U+2018/U+2019 preserved); 0 `�`; 0 invalid bytes |
| Duration | 11.9 s | 14.2 s |

## 5. Before and after (botnet `wget` wait)

| | Stored diagnostic output (tail) |
|---|---|
| Task 9 (before), botnet #2, `admin/admin` | `…wget: unable to resolve host address �mirror.example�\n[REDACTED]@svr04:/tmp$ ` (does not end with `prompt_match` `admin@svr04:/tmp$ `) |
| Task 10A (after), `admin/admin` | `…wget: unable to resolve host address ‘mirror.example’\nadmin@svr04:/dev/shm$ ` (ends with `prompt_match`) |

## 6. Remaining limitations

- **Password equal to username:** when the password equals the username (`admin/admin`), the password text necessarily appears in prompts. Removing it would corrupt the evidence the task requires to stay intact, and the username is already in the manifest.
- **Whole-token rule:** a typed secret embedded inside a larger token would not be redacted. Since redaction needs the secret to be a whole token in the typed command, an echo of that command is always a whole token.
- **Short typed secrets:** secrets under 4 characters are not redacted (reason recorded). The command containing them is in the manifest anyway.
- **Split control sequences:** ANSI control sequences split across chunks are not stripped. This is diagnostic text only, and was not observed.

## 7. Integrity

- **Modified:**
  - `dataset_builder/generate_labelled_traffic.py`
  - `tests/test_generator_observability.py`
  - `tests/generator_fakes.py`
  - `docs/generator_pacing_and_sequencing.md`
  - `docs/generation_manifest_schema.md`
- **Created:**
  - `tests/test_diagnostic_redaction_utf8.py`
  - this folder (report, `plan_verification_sessions.py`, `check_verification.py`, `configs/`, `runs/`, `evidence/`)
- **Unchanged (SHA-256 over all repository files):** profiles, `configs/feature_spec_v2.json`, extractors, parser, builder, labelling, datasets, models. `test_touches` = 0.
- **Cowrie:** its volume gained 29 events and 2 TTY recordings. The containers weren't restarted.
