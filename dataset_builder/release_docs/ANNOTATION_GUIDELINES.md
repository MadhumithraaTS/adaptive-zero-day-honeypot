# Annotation Guidelines

This document explains how every label in the dataset was assigned, and how much each label can be
trusted.

## 1. Label fields

| Field | Type | Values | Meaning |
|---|---|---|---|
| `attack_cat` | string | `benign`, `reconnaissance`, `brute_force`, `botnet`, `privilege_escalation`, `lateral_movement`, `exfiltration` | Behaviour category of the session. |
| `label` | int | `0` / `1` | Binary label: `0` = benign, `1` = attack. |

`label` is derived from `attack_cat`: it is `0` only for `benign` and `1` for every other category.

## 2. How labels were assigned

Labels are **ground truth by construction**, not human annotation of observed traffic.

1. Every session was produced by a scripted client following one named **generation profile**
   (`metadata/generation_profiles.json`). Each profile is bound to exactly one `attack_cat`.
2. When the client ran a session, it appended a record to `generation_manifest.jsonl` stating the
   profile, category, label, credentials tried, the exact commands sent, and UTC start/end times.
3. After collection, each Cowrie session was matched to a manifest record and given that record's
   label, using the rules below.

### 2.1 Matching rules

| Session type | Matching method | Reliability |
|---|---|---|
| Sessions that executed at least one command (other than `exit`) | **Command fingerprint.** The session is assigned to the manifest record whose sent commands best contain the commands Cowrie logged (containment = shared commands / session commands). | High. The generating record contains every logged command, so the correct record scores ≈1.0. All command-bearing sessions in v1.0.0 scored at or above 0.3; none were flagged low-confidence. |
| Sessions with no commands (failed logins, or a login followed by an immediate disconnect) | **Time.** The session is assigned to the manifest record whose `[start_utc, end_utc]` window contains its connect time, or the nearest record if none does. | Moderate. Category is correct when windows do not overlap; these sessions carry almost no behavioural content, so a boundary error has little effect on features. |

Per-run counts of each method are in `metadata/dataset_stats.json` (`matched_by_command`,
`matched_by_time_no_command`).

## 3. Category definitions

| `attack_cat` | `label` | Behaviour |
|---|---|---|
| `benign` | 0 | Routine administration: uptime, disk and memory checks, service status, reading logs, at human-like pace. |
| `reconnaissance` | 1 | Host fingerprinting after login: identity, kernel, users and groups, network interfaces, processes. |
| `brute_force` | 1 | Credential guessing: several failed logins, then at most one short command or an immediate disconnect. |
| `botnet` | 1 | Dropper pattern: change to a temp directory, download a file, make it executable, run it, clean up. |
| `privilege_escalation` | 1 | Searching for a path to root: `sudo -l`, SUID binaries, shadow file, SSH keys, cron. |
| `lateral_movement` | 1 | Internal discovery and attempts to reach other hosts: routes, ARP, known hosts, ping/nc/ssh to LAN addresses. |
| `exfiltration` | 1 | **Held out (eval split only).** Locating data files, archiving them, and copying them off the host. |

Each profile picks randomly among alternative commands, includes optional steps with fixed
probabilities, and inserts a few filler commands, so sessions within a category vary.

## 4. Failed-login sessions

Every profile may begin with 0–5 deliberately failed login attempts (using the reserved account
`scan`, which the honeypot is configured to reject). Each failed attempt is a separate SSH connection
and therefore a **separate session** in the dataset, labelled with the category of the profile that
made it. Consequences:

- The dataset contains many sessions with zero commands (see `zero_command_sessions` in
  `dataset_stats.json`), most of them in `brute_force`.
- Many of these rows have identical feature values.
- Users who want only behaviour-bearing sessions can filter on the `n_commands` column of
  `sessions.jsonl` (`n_commands > 0`), or on `spkts > 1` in `features.csv` (`spkts` also counts
  the final `exit`).

## 5. Held-out category

`exfiltration` appears **only in the eval split**. It was excluded from the train split so that it
can serve as an unseen ("novel") behaviour when testing novelty or zero-day detection methods.

## 6. What the labels do not mean

- They describe **what the scripted client intended**, which matches what Cowrie logged; they are
  not judgements about real-world attackers.
- Cowrie emulates a shell. Downloads, executions and uploads are **not real**: no payload was
  fetched or run, and no data left the lab.
- Categories are coarse. Real attacks often combine several of them in one session; here each
  session belongs to exactly one.
