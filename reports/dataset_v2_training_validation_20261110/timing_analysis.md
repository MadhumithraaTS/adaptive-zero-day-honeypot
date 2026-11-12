# Dataset V2 — timing and execution analysis (Task 14B, Phase 6)

This analysis is **descriptive only**: no models, no classifiers, no feature decisions.

Sources:
- `evidence/timing_analysis.json`
- `evidence/timing_command_delays_train.csv`
- `evidence/timing_sessions_train.csv`
- `timing_analysis.py`

Category-level statistics use **train only**. Validation is used only to confirm that command execution delay
is a property of Cowrie, not of one split.

Definitions (both come from the manifest's `command_log`, measured by the client):
- **Execution delay** is `wait_s`: the time from sending a command until the shell prompt returns.
- **Think time** is `think_time_s`: drawn from the category-independent pacing policy, lognormal with median 1.5 s and σ 0.75, clipped to [0.2, 15] s.

## 1. Execution delay is near-constant, with one exception

| | Train | Validation |
|---|---|---|
| Commands sent | 7,516 | 3,079 |
| Delay, all commands except the slow one: median / p95 / max | 0.047 / 0.063 / 0.282 s | 0.047 / 0.063 / 0.157 s |
| Commands with delay ≥ 5 s | 30 | 9 |
| …all of them | `find / -name id_rsa 2>/dev/null` | `find / -name id_rsa 2>/dev/null` |
| `find` delay: median (range) | 11.66 s (11.4–13.5) | 11.58 s (11.36–12.11) |

Further observations:
- Cowrie latency did not drift. The median execution delay was 0.047 s in the first, middle and last 300 train interactions, and again in validation on the next day.
- The `find` command walks Cowrie's emulated filesystem. That walk takes about 11.6 s, and **only the privilege-escalation profile uses it**:
  - train: 30 of 175 PE interactions, 17.1%;
  - validation: 9 of 69, 13.0%.

## 2. Think time is category-independent (as designed)

Median think time per profile is 1.45–1.58 s for every category in train. The generator's pacing does not encode the
category.

## 3. Effect on the four timing features (train, logged-in sessions)

| Profile | `session_duration_s` median | `time_to_first_input_s` median | `inter_input_mean_s` median | Share with `find` |
|---|---|---|---|---|
| benign_admin | 12.3 | 1.63 | 1.81 | 0 |
| botnet | 15.2 | 1.56 | 1.90 | 0 |
| brute_force | 2.7 | 1.72 | n/a (≤1 line) | 0 |
| lateral_movement | 10.2 | 1.78 | 1.79 | 0 |
| privilege_escalation | 14.6 | 1.80 | 1.99 | 0.171 |
| reconnaissance | 14.3 | 1.57 | 1.92 | 0 |

**Privilege-escalation `session_duration_s`, with and without `find`:**

| | n | median | p5 | p95 | max |
|---|---|---|---|---|---|
| PE with `find` | 30 | 25.6 | 17.7 | 41.9 | 49.2 |
| PE without `find` | 145 | 13.3 | 7.0 | 23.2 | 31.7 |
| PE with `find`, minus the `find` execution | 30 | 13.8 | — | — | — |

Removing the `find` execution brings the median duration back to that of the other PE sessions. **The
difference is caused by Cowrie's execution time, not by attacker behaviour.**

**`inter_input_mean_s`:**
- Sessions containing `find`: median ≈ 3.9 s.
- All others: ≈ 1.9 s. Non-PE p99 is 4.46 s and the non-PE maximum is 8.15 s.

**`session_duration_s` above the non-PE p95 (23.6 s):**

| benign | botnet | PE | reconnaissance | lateral movement | brute force |
|---|---|---|---|---|---|
| 27 | 25 | 26 | 11 | 3 | 0 |

A long duration alone does not identify PE, because benign and botnet reach the same range.

`session_duration_s` minus (think sum + execution sum) has a median absolute residual of 1.73 s. That residual
is login, initial prompt, exit and connection overhead.

`time_to_first_input_s` is essentially one think-time draw plus the prompt wait. It does not differ meaningfully
by category.

## 4. Conclusion (for Task 15 to test, not decided here)

There is a **partial, category-exclusive timing fingerprint**:
- An execution pause over 5 s occurs only in PE, in about 13–17% of PE sessions.
- It raises `session_duration_s` and `inter_input_mean_s` for those sessions.
- It does not separate whole categories: most PE sessions look like the rest, and long sessions also occur in benign and botnet.

This is a Cowrie emulation artefact tied to one command in one profile. Task 15 should quantify how much of
any PE separability comes from it, for example by ablating or stratifying sessions with `find`. This task
makes no feature, profile or generator change in response.
