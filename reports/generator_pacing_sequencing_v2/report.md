# Generator pacing and command sequencing for Dataset V2

**Date:** 2026-11-10. **Task 6.**

**Result:**

- The Dataset V2 traffic generator now uses one category-independent pacing policy.
- It sends each command only after Cowrie's prompt returns.
- It terminates on readiness failure.
- It records per-command evidence in the manifest.

**Not done:** no Dataset V2 or any dataset was generated. No Cowrie, Docker or network traffic was used; tests use fakes and a loopback paramiko server. No feature extraction, model, profile or specification was changed, and nothing was committed.

**Related documents:**

- `docs/generator_pacing_and_sequencing.md`: policy and behaviour
- `docs/generation_manifest_schema.md`: manifest schema

## 1. Inspection (before changes)

`dataset_builder/generate_labelled_traffic.py` (generator 2.0), with line numbers before the change:

| # | Source | Location | Category-dependent? | Effect on V2 features |
|---|---|---|---|---|
| T1 | Per-command delay `rng.uniform(*profile['delay_range'])` | `run_session` :164; ranges in `profiles_v2*.json`: benign 2–7 s, privilege_escalation 1–5, lateral_movement 1–4, reconnaissance 0.5–3, data_exfiltration 0.5–3, botnet 0.1–1, brute_force 0.1–0.8 | **Yes** | `inter_input_*`, `session_duration_s` encode the category |
| T2 | Fixed post-shell wait `0.5/speed`, no prompt check | :160 | No; a constant | `time_to_first_input_s` reflects only the generator |
| T3 | `--speed` divides every delay | :152, :160, :164, :168, main | Global | Time scale; must be constant across combined runs |
| T4 | Wrong-guess gap `uniform(0.2, 0.8)/speed` | :152 | No | — |
| T5 | Number of wrong guesses `credentials.failed_attempts` | `plan_credentials` | Behaviour, not timing | Kept |
| T6 | Fixed `0.4/speed` after `exit`, no close check | :168 | No | Session end not confirmed |
| T7 | Timer-based sending: output drained only if ready; no readiness check | :161–166 | Interacts with T1 | Lost lines while `curl`/`wget` block; lines after `scp` swallowed (771 lost lines in 262 of 1,498 train_v1 sessions) |
| T8 | Planning and pacing share one RNG | main / `run_session` | Indirect: pacing draws depend on earlier sessions' profiles | Not a distribution leak, but couples pacing to planning |
| T9 | `scripts/attack_generator.py`: per-profile `delay_range`, fixed sleeps | :40–56 | **Yes** | Old demo generator, not the V2 path; documented, not changed |

**Authentication waits and timeouts:** paramiko `timeout=15`, `banner_timeout=20`, `auth_timeout=15` (`_connect`), the same for all profiles. Failed-login cleanup was fixed earlier (`reports/generator_encoding_fixes/report.md`).

## 2. Changes

All in `dataset_builder/generate_labelled_traffic.py`. These functions are unchanged (verified by syntax-tree comparison with the pre-change copy):

- `_connect`
- `capture_log_baseline`
- `fill_placeholders`
- `load_config`
- `plan_commands`
- `plan_credentials`
- `utc_now`
- `weighted_profile_order`

| Change | What |
|---|---|
| `PacingPolicy` (new) | One log-normal think-time distribution (median 1.5 s, σ 0.75, clipped 0.2–15 s) and one uniform auth gap (0.2–0.8 s), both divided by `--speed`. No category, profile or command parameter |
| `session_pacing_rng` (new) | Per-session pacing stream `Random("pacing:<pacing_seed>:<index>")`, independent of the planning RNG (fixes T8) |
| `ReadinessPolicy`, `wait_for_prompt`, `wait_for_close` (new) | Prompt detection on ANSI-stripped output (`user@host:path$/# `); one timeout for all commands (20 s default); `terminate_session` on failure; channel-close confirmation after `exit` |
| `run_session` (rewritten) | Signature `(host, port, attempts, commands, pacing, pacing_rng, readiness)`, so no profile data enters. It waits for the first prompt, then before each command draws a think time, sends, and waits for the prompt. On failure it stops and records the remaining commands as not sent, and doesn't send `exit`. Writes `auth_log`, `command_log`, `commands_planned`, `shell_ready_initial`, `exit_sent`, `exit_confirmed`, `termination` |
| `main` | New flags `--pacing-seed` and `--prompt-timeout`. `run_meta.json` gains `generator_version`, `config_path`, `pacing_seed`, `pacing_policy`, `readiness_policy`, `profile_delay_range: ignored` and `inter_session_delay_s`. Each manifest entry gains `pacing_stream`. `profile['delay_range']` is no longer read (fixes T1). The unused `by_name` was removed |
| T2 | The fixed 0.5 s wait is replaced by "first prompt, then a think time from the shared policy" |
| T6 | The fixed 0.4 s is replaced by "think time, `exit`, wait for close (≤ 5 s)" |
| T7 | Timer-based sending is replaced by prompt-gated sending with explicit termination |

**Manifest compatibility:** `commands_sent` keeps its meaning (commands actually transmitted, now always a prefix of `commands_planned`), and every other 2.0 field is unchanged. `labelling.py` and its tests pass unchanged.

## 3. Tests

| File | Tests | Covers |
|---|---|---|
| `tests/test_generator_pacing.py` (new) | 14 | Policy has no category parameters and `run_session` takes no profile (signature and source check); same seed → identical think times, different seed or session → different; bounds and `--speed` scaling; every command sent only after a prompt (fake shell records readiness at each receive); slow blocking `wget` is waited for; hanging `scp` → `readiness_timeout`, later commands `not_sent_after_termination`, no `exit`, client closed; server closes channel → `readiness_channel_closed`; no initial prompt → nothing sent; exit without close → `exit_unconfirmed`; auth log (rejected, rejected, accepted); final auth failure sends nothing; **end-to-end `main()`** with two profiles whose `delay_range` is 1,000–2,000 s vs 0 s (12 sessions, both categories): every think time equals the session's pacing stream and lies within 0.2–15 s, `commands_sent` = sent `command_log` = commands received by the shell, `run_meta` records the policy and seed, every client closed once; **real paramiko channel** against a loopback shell server (2 cases: clean run; `scp` hang → termination after the second command) |
| `tests/test_generator_connection.py` (updated) | 10 | Unchanged assertions; the three `run_session` tests moved to the new signature and fakes |
| `tests/generator_fakes.py` (new helper) | — | `FakeClient` and a Cowrie-like `FakeShell` (prompt `\x1b[4hroot@svr04:~# `; behaviours normal / slow / hang / close) |

**Results:**

- generator tests: 22 + 2 real-channel = 24 passed;
- **full suite: 208 passed** (previously 194), 5 warnings, the same as before (pyarrow, pandas `FutureWarning` ×2, paramiko TripleDES ×2).

## 4. Validation (Phase 6)

- **Same pacing distribution for every category:** a single `PacingPolicy(speed=args.speed)` is constructed once in `main` and passed to every session. `run_session` has no parameter carrying profile or category data (test), and its source contains no `delay_range`, `attack_cat`, `label` or `profile[` (test).
- **No category label influences pacing:** in the end-to-end test, think times equal `session_pacing_rng(pacing_seed, index)` draws exactly. A profile's 1,000–2,000 s `delay_range` and another's 0 s have no effect.
- **No command after a readiness failure:** the hanging-`scp`, channel-close and no-initial-prompt tests show nothing else sent (not even `exit`), with the remaining commands recorded as `not_sent_after_termination`. The only recovery policy is termination, recorded as `action: terminate_session`.
- **The manifest describes what happened:**
  - `commands_sent` equals the lines the shell received (end-to-end test);
  - `command_log` holds per-command sent / time / readiness / prompt / status;
  - `auth_log` and `termination` are recorded.
- **Unrelated behaviour unchanged:** profile and command planning, credential planning, profile ordering, connection handling and baseline capture are unchanged (syntax-tree comparison); labelling tests pass.

## 5. Limitations

1. **Pacing defaults are not calibrated.** The log-normal parameters are documented choices, not values fitted to real attacker or administrator behaviour. They remove *category dependence*, not *domain mismatch*: deployment-domain compatibility of the timing features stays low (spec C2).
2. **Behavioural pacing differences are gone.** Generator 2.0's assumption that "brute force is fast, admins are slow" no longer exists. If such differences are real, V2 can't show them; this is the intended trade-off against leakage.
3. **`scp` and other stdin-reading emulations end sessions.**
   - Sessions reaching an emulated `scp` (`data_exfiltration`) are terminated at that command, and their later commands are recorded as not sent.
   - `lateral_movement` uses `ssh`, `nc` and `ping`, which may also block; this is unverified against Cowrie.
   - `botnet` uses `wget`/`curl`, expected to fail quickly in the isolated lab.
   - Termination frequency will therefore differ by profile. It is visible in the manifest (`termination`) and must be checked by L6 before training.
4. **Prompt detection is a regular-expression heuristic.** A command whose output ends with text like `x@y:z$ ` would be mistaken for readiness. A different Cowrie hostname or prompt configuration is handled by the generic pattern but wasn't tested against live Cowrie.
5. **No live Cowrie smoke test.** Behaviour was verified with fakes and a loopback paramiko server only. A short controlled run against the isolated Cowrie (a handful of sessions, not a dataset) would confirm prompt detection, blocking-command timing and `exit_confirmed` there; **it needs your approval**.
6. **`--seed` reproduces different plans than generator 2.0,** because pacing no longer consumes planning RNG draws. Earlier runs can't be re-planned with 2.1.
7. **`--speed` still rescales all pacing.** It must stay fixed across runs that are combined.
8. **`scripts/attack_generator.py`** (the demo generator) still has category-dependent timing and is not suitable for V2.
9. **Profile files** still contain `delay_range`, which is now ignored. They were not edited, as required.

## 6. Integrity

- **Modified:**
  - `dataset_builder/generate_labelled_traffic.py`
  - `tests/test_generator_connection.py`
- **Created:**
  - `tests/test_generator_pacing.py`
  - `tests/generator_fakes.py`
  - `docs/generator_pacing_and_sequencing.md`
  - `docs/generation_manifest_schema.md`
  - this report
- **Unchanged (SHA-256 over every repository file before and after; details in the hand-off):** profiles, specification, extractors, parser, builder, labelling, datasets, models and other reports. `test_touches` = 0.
- **Pre-change generator copy:** kept in the session scratchpad (`g6_pre/generate_labelled_traffic.py`).
