# Task 12 — Dataset V2 attack-profile redesign to reduce category leakage

Date: 2026-11-10. Status: **profile redesign complete; not run against Cowrie.** Awaiting approval for a Cowrie
compatibility run of `profiles_v2_revised.json`.

Scope kept: no traffic, no Cowrie run, no dataset generation, no model training or evaluation, no test-set
access. The generator, extractor, feature specification, Docker/Cowrie configuration and all existing profile
files were not modified. Nothing was committed.

## 1. Deliverables

| Path | Content |
|---|---|
| `dataset_builder/profiles_v2_revised.json` | 2.3.0-revised, SHA-256 `79d47ac48e1f4c242ffcb851c567da884df21d039cc11917dc5bf3dea761fe62` |
| `docs/profile_redesign_v2.md` | Design, per-profile rationale, Cowrie limits |
| `reports/profile_redesign_v2/make_revised_profiles.py` | Builds the revised file from compat; refuses to overwrite |
| `reports/profile_redesign_v2/profile_static_analysis.py` | Static before/after analysis and compatibility classification (offline) |
| `reports/profile_redesign_v2/evidence/` | `cowrie_command_registry.json`, `static_analysis.json`, `command_category_matrix_{compat,revised}.csv`, `compatibility_{compat,revised}.csv`, `observed_output_chars_by_command.json` |
| `tests/test_profile_revised.py` | 14 offline validation tests |

## 2. Audit of the existing profiles (compat 2.2.0, unchanged)

| Profile | Steps (mandatory + optional) | Planned lines min/median/max | Operators | Download | Notes |
|---|---|---|---|---|---|
| benign_admin | 2 + 4 | 2 / 5 / 8 | none | none | 11 of 15 names unique to benign (`uptime`, `who`, `service`, `systemctl`, `journalctl`, `tail`, …) |
| reconnaissance | 2 + 5 | 2 / 6 / 9 | none | none | `ifconfig`, `lscpu`, `nproc`, `ps`, `ss` unique |
| brute_force | 0 + 1 (p=0.5) | 0 / 0 / 1 | none | none | 3–5 failed guesses; 53% of interactions have no command |
| botnet | 5 + 2 | 4 / 6 / 8 | none | **100%** | always starts with `cd` (100% of first commands); 13 of 15 names unique |
| privilege_escalation | 2 + 4 | 2 / 6 / 8 | **86%** (`2>/dev/null`) | none | only source of operators among training categories |
| lateral_movement | 1 + 4 | 1 / 4 / 6 | none | none | `arp`, `nc`, `nmap`, `ping` unique |
| data_exfiltration (held out) | 2 + 3 | 2 / 5 / 6 | 100% | 80% (`curl -T`) | always starts with `find`; `tar` unique |

All compat profiles carried per-profile `delay_range` (ignored by generator 2.1). Authentication: every profile
except brute force uses the standard accepted login. Cowrie output patterns are covered in §6.

**Fingerprints found** (static, compat): no planned sequence and no command-name set was shared between any two
categories (2,000 planned sessions per profile); the first command name alone identified the majority category
for 80.9% of planned sessions; 7 of 21 category pairs shared no command name at all (mean Jaccard 0.10). This is
consistent with Task 11's L5 result on real gen-2.0 data (name-set lookup 100% precise, first command 84%).

## 3. Design

The rationale for each profile is in `docs/profile_redesign_v2.md`. In short, steps are rebuilt from shared,
realistic command families: identity, system fingerprint, resources, processes, network view, listings, and
`grep`/`tail` pipelines. Each category keeps its distinctive behaviour. Brute force is unchanged.
`delay_range` is removed. Benign contains no attack commands (tested).

One iteration was made during analysis. `groups`, newly added to privilege escalation, became a first command
seen only in that category (593 of 593 planned sessions). It was added to reconnaissance's identity step, which
is realistic, and the file was regenerated. The SHA above is the final file.

## 4. Command-to-category matrix (command names = first token of each line)

`x` = present before and after, `+` = added, `−` = removed. Ex = held-out exfiltration.

| name | Ben | Rec | BF | Bot | PE | LM | Ex | categories |
|---|---|---|---|---|---|---|---|---|
| `./{bin}` (4 values) |  |  |  | x |  |  |  | 1 → 1 |
| `arp` |  |  |  |  |  | x |  | 1 → 1 |
| `cat` | x | x |  | + | x | x |  | 4 → 5 |
| `cd` |  |  |  | x |  |  |  | 1 → 1 |
| `chmod` |  |  |  | x |  |  |  | 1 → 1 |
| `clear` | x |  |  |  |  |  |  | 1 → 1 |
| `crontab` |  |  |  |  | x |  |  | 1 → 1 |
| `curl` | + | + |  | x |  |  | x | 2 → 4 |
| `date` | x |  |  |  |  |  |  | 1 → 1 |
| `df` | x | + |  |  |  |  | + | 1 → 3 |
| `du` | x |  |  |  |  |  | x | 2 → 2 |
| `echo` |  |  | x |  |  |  |  | 1 → 1 |
| `enable` / `system` / `shell` |  |  |  | x |  |  |  | 1 → 1 |
| `find` |  |  |  |  | x |  | x | 2 → 2 |
| `free` | x | + |  |  |  |  |  | 1 → 2 |
| `groups` |  | + |  |  | + |  |  | 0 → 2 |
| `history` / `unset` |  |  |  | x |  |  |  | 1 → 1 |
| `hostname` | + | x |  |  |  | x |  | 2 → 3 |
| `id` | + | x |  | + | x | + | x | 3 → 6 |
| `ifconfig` |  | x |  |  |  |  |  | 1 → 1 |
| `ip` |  | x |  |  |  | x |  | 2 → 2 |
| `journalctl` / `systemctl` / `service` / `tail` / `uptime` / `who` | x |  |  |  |  |  |  | 1 → 1 |
| `ls` | x | x |  |  | x | x | x | 5 → 5 |
| `lscpu` / `nproc` |  | x |  |  |  |  |  | 1 → 1 |
| `nc` / `nmap` / `ping` |  |  |  |  |  | x |  | 1 → 1 |
| `netstat` |  | + |  |  |  | + |  | 0 → 2 |
| `ps` | + | x |  |  |  |  |  | 1 → 2 |
| `pwd` | x | x |  |  | x |  |  | 3 → 3 |
| `rm` |  |  |  | x |  |  | x | 2 → 2 |
| `sh` |  |  |  | x |  |  |  | 1 → 1 |
| `ss` |  | x |  |  |  | + |  | 1 → 2 |
| `sudo` |  |  |  |  | x |  |  | 1 → 1 |
| `tar` |  |  |  |  |  |  | x | 1 → 1 |
| `uname` | + | x | x | + | + |  |  | 2 → 5 |
| `w` | x | + |  | + | + | + |  | 1 → 5 |
| `wget` |  | + |  | x |  |  |  | 1 → 2 |
| `whoami` |  | x | x |  | x | x | + | 4 → 5 |

The matrix counts only the first token of each line. Pipeline segments add `grep` (benign, reconnaissance,
privilege escalation, lateral movement) and `tail` (benign). The full matrices are in
`evidence/command_category_matrix_*.csv`.

## 5. Static before/after overlap (2,000 planned sessions per profile from the generator's own `plan_commands`)

| Measure | compat | revised |
|---|---|---|
| Distinct command names (first token) | 49 | 51 |
| Names shared by ≥ 2 categories | 12 | 20 |
| Mean pairwise Jaccard of name sets | 0.102 | 0.182 |
| Category pairs sharing no name | 7 / 21 | 0 / 21 |
| Planned sequences shared across categories | 0.0% | 0.0% |
| Planned command-name sets shared across categories | 0.0% | 3.6% |
| First command → majority category (share correct) | 80.9% | 70.8% |
| Share of a category's names unique to it (Ben/Rec/BF/Bot/PE/LM/Ex) | .73/.38/.33/.87/.25/.44/.14 | .40/.15/.33/.63/.18/.31/.11 |

Exact sequences remain unique to their category (as they would in real data, given distinct step structures).
Name-set and first-command overlap improved but did not disappear. The first commands that still name their
category are benign `uptime`/`who`, exfiltration `find`, lateral movement `arp`, and botnet `uname`, which is
shared only with brute force.

**Feature proxies from the plans** (min / median / max; share non-zero for C4). These are proxies: Cowrie may
record additional lines (executed script lines), and planned bytes exclude Cowrie's own output.

| Feature proxy | Ben | Rec | BF | Bot | PE | LM | Ex* |
|---|---|---|---|---|---|---|---|
| `input_line_count` compat | 2/5/8 | 2/6/9 | 0/0/1 | 4/6/8 | 2/6/8 | 1/4/6 | 2/5/6 |
| `input_line_count` revised | 2/5/9 | 2/6/10 | 0/0/1 | 5/7/9 | 2/6/9 | 1/5/7 | 2/5/7 |
| `input_bytes_total` compat | 6/51/107 | 10/45/77 | 0/0/8 | 57/91/127 | 9/81/128 | 6/62/103 | 56/125/168 |
| `input_bytes_total` revised | 6/59/136 | 9/62/137 | 0/0/8 | 67/111/162 | 9/84/149 | 7/72/131 | 36/119/181 |
| `input_line_max_bytes` compat | 5/19/26 | 8/14/15 | 6/7/8 | 30/36/42 | 7/38/38 | 6/21/23 | 32/42/45 |
| `input_line_max_bytes` revised | 5/25/32 | 8/20/36 | 6/7/8 | 30/39/56 | 7/37/38 | 6/23/30 | 24/42/48 |
| `unique_command_names` compat | 2/5/8 | 2/6/9 | 0/0/1 | 4/6/8 | 2/5/7 | 1/3/6 | 2/4/6 |
| `unique_command_names` revised | 2/5/9 | 2/5/10 | 0/0/1 | 5/7/9 | 2/5/8 | 1/4/7 | 2/5/7 |
| `shell_operator_lines` ≠ 0, compat | 0% | 0% | 0% | 0% | 86% | 0% | 100% |
| `shell_operator_lines` ≠ 0, revised | 48% | 26% | 0% | 49% | 84% | 43% | 66% |
| `download_command_lines` ≠ 0, compat | 0% | 0% | 0% | 100% | 0% | 0% | 80% |
| `download_command_lines` ≠ 0, revised | 14% | 30% | 0% | 100% | 0% | 0% | 80% |

Readings:
- `input_line_max_bytes` was the strongest single feature in Task 11 (exact-value lookup 82%). Ranges now
  overlap more: reconnaissance max 15 → 36, benign 26 → 32, lateral movement 23 → 30. Botnet (≥ 30 bytes,
  because of URL lines) and privilege escalation (median 37–38, the `find … 2>/dev/null` line) remain shifted.
- `shell_operator_lines` is now non-zero in five of the six training categories (Task 11 C4 criterion (b) asks
  for ≥ 2). It is a planned property only.
- `download_command_lines` is now non-zero in three training categories. Botnet is still 100%, so the feature
  remains a strong botnet indicator. Whether that is acceptable is a feature-eligibility decision for the
  re-run of Task 11, not something to fix by adding downloads to other categories.
- Brute force is unchanged: zero or one command by design.
- Line and byte counts are similar in scale across the non-brute-force categories, but botnet is
  systematically longer (seven mandatory or near-mandatory steps).

## 6. Cowrie compatibility classification (all 221 concrete revised commands)

Per command: `evidence/compatibility_revised.csv`. Classes are assigned in this precedence order: blocking
rules first, then observed evidence from Tasks 7/9/10A, then the source and registry, then historical rates.

| Class | compat (150) | revised (221) | Revised examples |
|---|---|---|---|
| Confirmed returns (observed prompt return, Tasks 7/9/10A) | 59 | 73 | `uname -a`, `ps aux`, `df -h`, `sudo -l`, `cat /etc/shadow`, `./b.sh`, `ping -c 2 192.0.2.5`, `systemctl status ssh` |
| Expected returns (implemented in Cowrie source; many with historical next-line rate 1.0) | 43 | 69 | `cat /etc/sudoers`, `groups`, `netstat -antp`, `ps aux \| grep sshd`, `ls -la /usr/bin \| grep rws`, `cat /etc/hosts \| grep -v '^#'`, `history -c`, `unset HISTFILE` |
| Network-dependent, fails in isolation and returns | 40 | 70 | wget/curl to `.example` (DNS failure), `nc -zv {lan_ip} 22`, `curl -T` (option error before any network use) |
| Unsupported → "command not found", returns | 6 | 7 | `ip a`, `ip route`, `ss -tulpn`, `ss -tan`, `nmap -sn …`, `journalctl -n 20` |
| Static output (txtcmd) | 2 | 2 | `nproc`, `enable` |
| **Potentially blocking** | **0** | **0** | — |

Unverified in prompt-gated runs, and to be checked in the approved Cowrie run:
- the new pipelines (`ps aux | grep sshd`, `ls -la /var/log | tail -n 5`, `cat /etc/passwd | grep sh`, `ls -la /usr/bin | grep rws`, `cat /etc/hosts | grep -v '^#'`, `cat ~/.bash_history | grep ssh`);
- `wget -qO-` and `wget -q … -O {bin}`;
- `curl -I` and `curl -s`;
- `cd /tmp || cd /var/tmp`;
- `groups`, `netstat -antp`, `cat /etc/apt/sources.list`.

Historical next-line rates below 1.0 for `sh`, `chmod`, `history` and `unset` (0.29–0.42) coincide with
generator 2.0's timer-based line loss (Task 11 L6). They are not evidence of blocking: `sh payload`,
`./b.sh` and `chmod` returned the prompt in the prompt-gated runs.

Cowrie output verbosity (`tty_output_bytes`; median terminal characters observed per command in Tasks 9/10A,
including the echoed command and prompt) ranges from about 6,258 for `ps aux`, 1,204 for `cat /proc/meminfo`,
926 for `ifconfig`, 781 for `cat /etc/shadow` and 682 for `sudo -l`, down to about 30 for `whoami` and 17 for `ls`.
The redesign spreads verbose commands across categories (`ps aux` benign + reconnaissance; `df -h` benign +
reconnaissance + exfiltration; `cat /etc/passwd`/`cat /proc/cpuinfo` in two categories). Privilege escalation's
`cat /etc/shadow` and `sudo -l` remain specific to it. Most new commands have no observed verbosity yet.

## 7. Semantic limitations

1. **Lateral movement is reconnaissance only.** No connection to another host is made or emulated (ssh blocks
   Cowrie; the lab has no second host). The label describes intent inferred from discovery commands.
2. **Exfiltration is an attempt.** `curl -T` is an option error in this Cowrie build; no upload is emulated and
   no data leaves the lab. The profile stays held out.
3. **Botnet downloads never succeed.** `.example` names fail at DNS, so `chmod`/execute act on files that do not
   exist. The command sequence is realistic, but the outcome is not.
4. **Unsupported commands** (`ip`, `ss`, `nmap`, `arp`, `journalctl`, `systemctl`; `systemctl status ssh` is
   listed as confirmed only because the prompt returned)
   produce "command not found". This is a Cowrie fingerprint shared by every category that uses them.
5. **Brute force / `login_failed_count`**: the redundancy found in Task 11 comes from the generator (one
   connection per guess), not from the profiles. It is unchanged here.
6. **Botnet-specific Mirai probes** (`enable`, `system`, `shell`) and the download → `chmod` → execute chain remain
   category-specific because they *are* the behaviour.
7. **Static analysis is not proof.** All numbers here come from planned command lists. The actual extent of
   leakage can only be measured on a generator-2.1 run with these profiles, followed by a repeat of
   `reports/v2_feature_leakage_validation/analyze_leakage.py`. The revised profiles reduce template overlap
   problems; they do not by themselves establish that features are category-independent.

## 8. Validation and tests

`tests/test_profile_revised.py` (14 tests, offline):
- the compat file hash is unchanged;
- version and `derived_from` are correct; names, order, `attack_cat`, label, `held_out`, credentials and
  placeholders are identical to compat; no `delay_range`; brute-force steps are unchanged;
- steps and noise are well formed: non-empty stripped ASCII strings, no duplicates, known placeholders only,
  balanced quotes, `p` in (0, 1], consistent noise bounds;
- no command blocks under the audited Cowrie model (ssh/scp/sftp/telnet, interactive editors, `ping` without
  `-c`, wget to an IP);
- only documentation IP ranges and `.example` hosts;
- benign contains no attack commands;
- each of the 7 profiles × 40 seeds is loaded by the unmodified generator (`load_config`, `plan_commands`) and
  completes a `run_session` with `clean_exit` against the fake Cowrie shell;
- operator and download vocabulary span ≥ 4 and ≥ 2 training categories (a static design property).

Results:
- `tests/test_profile_revised.py` + `tests/test_profile_compatibility.py`: 27 passed.
- Full suite (before the `groups` iteration): **306 passed**, 5 known warnings. That is 292 before this task
  plus 14 new tests.
- `test_profile_revised.py` re-run on the final file: 14 passed. No other test reads the revised file.

Integrity:
- every file in the pre-task SHA-256 snapshot is unchanged (compat, isolated and original profiles; generator;
  extractor; spec; Docker configuration; datasets; models; historical reports);
- the only new git-status entries are `docs/profile_redesign_v2.md`, `reports/profile_redesign_v2/` and
  `tests/test_profile_revised.py`; `dataset_builder/profiles_v2_revised.json` falls inside the already untracked
  `dataset_builder/` directory;
- no network traffic was generated and Cowrie was not contacted.

## 9. Recommended next step (requires approval)

A small Cowrie compatibility run of `profiles_v2_revised.json`, isolated and with a new pacing seed, e.g. 7
profiles × 3 sessions. It would confirm prompt return for the unverified commands in §6 and record their output
verbosity. After that, a generator-2.1 training run and a repeat of the Task 11 leakage analysis.
