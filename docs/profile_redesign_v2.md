# Dataset V2 profile redesign (profiles_v2_revised.json, 2.3.0-revised)

Status: **proposed, not yet run against Cowrie.** Task 12, 2026-11-10. Evidence and numbers:
`reports/profile_redesign_v2/report.md`.

## Why

The V2 leakage validation (`reports/v2_feature_leakage_validation/report.md`, L5) found the label recoverable from
the command vocabulary alone: no command sequence or command-name set was shared between categories, the first
command named the category 84% of the time, `download_command_lines` was non-zero only in botnet and
`shell_operator_lines` only in privilege escalation. These are properties of the profile templates, not of
attacker behaviour, so a model trained on them would learn the generator.

## Files

| File | Status |
|---|---|
| `dataset_builder/profiles_v2.json` (2.0.0), `profiles_v2_isolated.json`, `profiles_v2_compat.json` (2.2.0-compat) | unchanged |
| `dataset_builder/profiles_v2_revised.json` (2.3.0-revised) | new; built by `reports/profile_redesign_v2/make_revised_profiles.py` from compat |
| `tests/test_profile_revised.py` | new offline validation |

The generator is unchanged and loads the revised file with `--config dataset_builder/profiles_v2_revised.json`.

## What changed globally

- `delay_range` removed from every profile. Generator 2.1 ignores it (one category-independent `PacingPolicy`),
  so keeping per-category delays in the file only invited misuse.
- `compat_notes` replaced by `redesign_notes`. Names, `attack_cat`, `label`, `held_out`, credentials
  (including brute-force `failed_attempts`) and placeholder pools are copied from compat unchanged.
- Steps are rebuilt from **shared command families** that real sessions of several kinds use: identity
  (`whoami`, `id`, `w`, `groups`), system fingerprint (`uname`, `cat /proc/version`, `cat /etc/os-release`),
  resources (`df -h`, `free -m`, `du -sh`), processes (`ps aux`, `ps aux | grep …`), network view (`ip route`,
  `netstat -antp`, `ss`), file listing (`ls -la …`), and pipelines with `grep`/`tail`. Each category draws
  from the families that fit it, plus its own distinctive steps.

## Design principles applied

1. No shared master list: every profile keeps its own step order and distinctive steps.
2. No suspicious commands in benign (enforced by `test_benign_profile_has_no_attack_commands`).
3. Characteristic attack steps are kept: botnet still downloads, marks executable and runs; privilege escalation
   still enumerates sudo, SUID and credential files; exfiltration still stages an archive and attempts an upload.
4. No category-specific timing (no `delay_range`; the generator draws all delays from one policy).
5. No synthetic feature values: profiles only list commands; every feature comes from what Cowrie records.
6. Labels are not used at run time: the generator writes the label from the profile into the manifest only.
7. Cowrie emulation limits are documented below and per command in
   `reports/profile_redesign_v2/evidence/compatibility_revised.csv`.

## Per-profile rationale

**benign_admin** — An administrator checking a host. Adds `ps aux` / `ps aux | grep sshd`, `service ssh status`,
`ls -la /var/log | tail -n 5`, `uname -r`, `hostname`, `cat /etc/apt/sources.list`, and an occasional (p=0.3)
mirror reachability check `curl -I http://{domain}/`. The header check is ordinary admin behaviour and puts a
download-family command name in benign without any file download. Pipelines give benign sessions shell
operators. `cat /proc/meminfo` was dropped (`free -m` covers memory).

**reconnaissance** — Host fingerprinting. Keeps its families and adds `w`/`groups`, `cat /proc/version`,
`cat /etc/passwd | grep sh`, `cat /etc/resolv.conf`, `netstat -antp`, `cat /etc/os-release`, `free -m`, `df -h`,
and an occasional external-address lookup (`curl -s` / `wget -qO-` to a `.example` host), which is a common
real reconnaissance step.

**brute_force** — Unchanged. It stays authentication-oriented: 3–5 rejected guesses, then an accepted one and
an optional short check (p=0.5). Commands are not added just to balance features.

**botnet** — Mirai-style dropper. Adds an architecture check first (`uname -a` / `uname -m` /
`cat /proc/cpuinfo`, which real droppers use to choose a binary), `cd /tmp || cd /var/tmp`, and the
`wget -q … -O {bin}` download form. The download → `chmod` → execute chain is kept. Every command returns the
prompt in the audited model, and `wget` targets only `.example` names (never an IP, which hangs Cowrie).
`id`/`w` were added to noise. The Mirai probes `enable`/`system`/`shell` stay: they are realistic and
specific to this behaviour.

**privilege_escalation** — Adds `groups`, `cat /etc/sudoers`, a pipeline SUID search
(`ls -la /usr/bin | grep rws`), `ls -la /etc/passwd`, `ls -la ~/.ssh`, `ls -la /etc/cron.d` and a kernel check
(`uname -r` / `cat /proc/version`). The `2>/dev/null` redirect stays (it is how these searches are typed) but is
no longer the only operator source in the dataset.

**lateral_movement** — **Reconnaissance for lateral movement only.** The isolated lab cannot represent a
connection to another host (ssh blocks Cowrie, and there is no second host). Adds `cat /etc/hosts | grep -v '^#'`,
`cat ~/.bash_history | grep ssh`, and a connection-table step (`netstat -antp` / `ss -tan` / `w`). `ping -c 2` and
`nc -zv` stay as reachability probes.

**data_exfiltration (held out)** — **An exfiltration attempt, not a success.** Adds `ls -la /home` as an
alternative discovery step, `df -h` to the sizing step, the domain form of the upload, and `whoami` to noise
(noise count 0–2). In this Cowrie build `curl -T` is an option error (curl's option string is `Lsho:IO`), so no
upload is emulated and nothing leaves the lab.

## Cowrie emulation limits (pinned image `bf371c37…`)

| Behaviour | Effect on the revised profiles |
|---|---|
| `ip`, `ss`, `nmap`, `arp`, `systemctl`, `journalctl` are not implemented | "command not found" and the prompt returns; the line is recorded, the output is short. They appear in two or more categories (`ip route`, `ss`) or are kept for realism. |
| `df`, `lscpu`, `nproc`, `enable` are static txtcmds | Fixed output text |
| `&&` and `\|\|` are treated as `;` | `cd /tmp \|\| cd /var/tmp` runs both `cd`s |
| `ping -c N` | Fails immediately ("bad number of packets"); returns. `ping` without `-c` never ends and is excluded |
| `curl -T` | Option error; no upload |
| wget/curl to `.example` | DNS failure; returns, no `file_download.failed` event |
| wget to an IP | Hangs (wget.py `ConnectingDone` bug); excluded, and tested |
| `nc -zv` | Real socket attempt on the internal network; it fails and returns (historical next-line rate 1.0) |
| `sudo -l` | Prints usage text, not a sudoers listing |
| Non-ASCII input | Stripped from `cowrie.json`; the revised commands are ASCII only (tested) |

## Known residual category signals (not removed by design)

- Botnet still downloads in 100% of sessions and is the only training category that runs `chmod` or a
  downloaded file. That is the behaviour, not an artefact. Benign (14%) and reconnaissance (30%) now also contain
  a download-family command name.
- Brute-force sessions keep zero or one command. `login_failed_count` = 1 − `login_success` is a property of
  the generator (one connection per guess), not of the profiles; the redesign does not change it.
- Cowrie output verbosity per command (`tty_output_bytes`) still differs: `ps aux` and `cat /etc/shadow` are
  long, "command not found" is short. Spreading `ps aux`, `df -h` and `cat /etc/passwd` over several
  categories reduces the template link but does not remove it.
- All of this is a static analysis of the *plans*. It is not evidence that model-level leakage is gone; that
  needs a generator-2.1 run and a repeat of `reports/v2_feature_leakage_validation/analyze_leakage.py`.
