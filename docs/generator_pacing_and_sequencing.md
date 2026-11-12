# Traffic generator pacing and command sequencing (generator 2.1)

**Applies to:** `dataset_builder/generate_labelled_traffic.py` (`GENERATOR_VERSION = '2.1'`).
**Not applied to:** `scripts/attack_generator.py`, the older demo generator. It still uses per-profile delays and must not be used for Dataset V2.

## Why

Dataset V2's timing features (`time_to_first_input_s`, `inter_input_mean_s`, `inter_input_std_s`, `session_duration_s`; conditional groups C2/C3 in `configs/feature_spec_v2.json`) are only meaningful if the generator's pacing doesn't depend on the attack category. Generator 2.0 had four problems:

- it slept `uniform(profile.delay_range)` between commands, with ranges from 0.1–0.8 s (brute force) to 2–7 s (benign);
- it waited a fixed `0.5/speed` before the first command;
- it sent commands on a timer, without knowing whether the shell had finished the previous one;
- as a result, lines typed while emulated `curl`/`wget` were blocking were lost, and lines typed after `scp` were swallowed as scp input (`reports/common_feature_specification_v2/report.md` section 2).

## Pacing policy (`PacingPolicy`)

One policy object is created per run and passed unchanged to every session. `run_session` receives no profile, category or label.

| Parameter | Default | Meaning |
|---|---|---|
| `think_median_s` | 1.5 | Median think time before each command, before `exit`, and before the first command after the prompt appears |
| `think_sigma` | 0.75 | Log-normal shape (σ of the underlying normal) |
| `think_min_s`, `think_max_s` | 0.2, 15.0 | Clipping bounds |
| `auth_gap_min_s`, `auth_gap_max_s` | 0.2, 0.8 | Uniform gap after each authentication attempt that precedes the login |
| `speed` | `--speed` (1.0) | Every pacing delay is divided by it. A global time scale, identical for all profiles |

**Think time** = `clip(lognormvariate(ln(median), sigma), min, max) / speed`.

**These defaults are documented choices, not values fitted to real attackers.** They are recorded in `run_meta.json` (`pacing_policy`). Change them only by editing the class defaults, and treat runs with different values or a different `--speed` as different distributions.

**Ignored:** the profile `delay_range` field is not read. `run_meta.json` records `profile_delay_range: ignored`. The profile files are unchanged.

**Kept as behaviour, not timing:**

- the number of wrong guesses before login (`credentials.failed_attempts`, e.g. 3–5 for brute force);
- which commands are sent (`steps`, `noise_pool`).

These define what a profile does, not how fast.

## Reproducibility and the pacing-seed policy (updated 2026-11-10, task 8)

**Two seeds, two jobs:**

| Seed | Flag | Controls | Rule |
|---|---|---|---|
| Planning seed | `--seed` (optional) | Profile order, commands, placeholders, credentials | As before |
| Pacing seed | `--pacing-seed` (**required**) | Every think time and auth gap, through per-session streams | **Must be new for every run.** `main()` scans every `run_meta.json` under `--runs-root` (default: the parent of `--output-dir`) and refuses a seed already used, before any connection or output. `--allow-pacing-seed-reuse` exists only for diagnostics, and its use is recorded in `run_meta.json` (`pacing_seed_reuse`) |

**Why reuse is refused:** the smoke test ran five runs with the same seed, and session 1 of each got identical pacing (time to first input ≈ 7.6 s every time; `reports/generator_cowrie_smoke_test/report.md` section 6).

**Requirement for Dataset V2:** keep all V2 runs under one runs root, so the reuse check sees them all.

- **Pacing seed:** always explicit (`pacing_seed_source: "explicit --pacing-seed"` in `run_meta.json`).
- **Per-session stream:** each session gets its own stream, `random.Random("pacing:<pacing_seed>:<session index>")`, also written to each manifest entry as `pacing_stream`. String seeds are hashed with SHA-512, so streams are identical across processes and platforms.
- **Separate from planning:** the pacing streams are independent of the planning RNG (`--seed`), which chooses profiles, commands and credentials. A session's pacing therefore never depends on its own profile, or on the profiles of earlier sessions.
- **Consequence:** generator 2.1 with a given `--seed` plans different sessions from generator 2.0 with the same seed, because 2.0 drew its delays from the planning RNG. Earlier runs (`train_v1`, `eval_v1`) can't be replayed with 2.1. They couldn't be replayed exactly anyway, because Cowrie timing is not deterministic.

## Generator pacing vs Cowrie-observed timing

`think_time_s` in the manifest is what the **generator** waited before sending. The timestamps in Cowrie's log are what the **honeypot** observed. They differ by:

- network and relay latency;
- the time spent waiting for the prompt;
- Cowrie's own processing.

Features are computed only from Cowrie's timestamps. The manifest values are audit evidence. They must never be used as features or to correct features.

## Shell readiness and sequencing (`ReadinessPolicy`)

| Parameter | Default | Meaning |
|---|---|---|
| `prompt_timeout_s` | 20.0 (`--prompt-timeout`) | Maximum wait for the prompt, after the shell opens and after each command. The same for every command |
| `exit_timeout_s` | 5.0 | Maximum wait for the channel to close after `exit` |
| `poll_interval_s` | 0.05 | Read/poll interval |
| `on_timeout` | `terminate_session` | The only policy (below) |

**Readiness condition:** the shell output, with ANSI control sequences and CR removed, ends with a prompt matching `[^\s@]+@[^\s:]+:[^\r\n]*[#$] $`. Cowrie's prompt is, for example, `\x1b[4hroot@svr04:~# ` (confirmed from the pilot's TTY recordings).

**Sequence per session:**

1. Authentication attempts. Each wrong guess is logged (`auth_log`), and its connection is closed by `_connect` on rejection. An auth gap follows each attempt.
2. Final login. If it is rejected: `termination = auth_failed` and nothing is sent.
3. Open the shell and **wait for the first prompt**. If it doesn't arrive: `termination = shell_not_ready` and nothing is sent.
4. For each planned command:
   1. wait the think time;
   2. send it (`ready_before_send` is always true, because sending only happens after a confirmed prompt);
   3. **wait for the prompt again**;
   4. if it returns: continue;
   5. if it doesn't (`timeout` or `channel_closed`): **terminate the session**. Nothing more is sent, **not even `exit`**, every remaining command is recorded as `not_sent_after_termination`, and the client is closed.
5. After the last command: think time, send `exit`, then wait for the channel to close (`exit_confirmed`). `termination` is `clean_exit` or `exit_unconfirmed`.
6. The client is always closed (`finally`).

**Why terminate rather than recover:**

- Any recovery keystroke (Ctrl-C, extra newline) is itself client input that Cowrie would log, and would change the telemetry the dataset is meant to capture.
- Terminating keeps the session's recorded input equal to the planned prefix that was actually sent.

**Blocking commands:** `BLOCKING_COMMANDS` = wget, curl, scp, sftp, tftp, ftp, ftpget, nc, ncat, ping, ssh, sleep.

- It **only annotates** the manifest (`blocking_expected`); every command gets the same timeout.
- In the isolated lab, emulated downloads fail quickly, so `wget`/`curl` normally return a prompt.
- Emulated `scp` waits for stdin and does not, so a session reaching `scp` is terminated at that command. That is by design: the alternative was the 2.0 behaviour, where the following lines silently became scp input.

**No success is inferred:** `prompt_returned` means only that the shell was ready again. It says nothing about whether the command "worked". Cowrie's log is the authority on what happened.

## Terminal-output capture (diagnostic; added 2026-11-10, task 8)

**What is captured:** every readiness wait (the initial prompt and the wait after each command) records the terminal output it saw:

- control sequences and CR removed;
- **bounded** to `OUTPUT_CAPTURE_CHARS = 2048` characters (the first and last 1,024; a `[...truncated...]` marker in between);
- with the total character and byte counts and an `output_truncated` flag;
- with the reason (`prompt`, `timeout`, `channel_closed`) and the exact `prompt_match`.

This makes every readiness decision traceable to observed output.

**Where it goes:**

- **Full records:** `<output-dir>/terminal_output.jsonl`, one line per wait, keyed by session `index` and `step`.
- **Manifest:** only the non-content summary per command (`readiness_reason`, `prompt_match`, `output_chars`, `output_truncated`).
- **Never a feature or label source:** `configs/feature_spec_v2.json` → `forbidden_inputs`, and the builder, labelling and extractor code never read it (tested).

**Redaction (evidence-based; revised 2026-11-10, task 10A):** SSH authentication never passes through the terminal, so a password can reach the terminal output only if the client typed it in a command. Redaction therefore applies:

- **only** in a step whose **sent command contains the password as a whole token** (`secrets_typed_in`);
- **only** to whole-token occurrences;
- **never** to the trailing prompt;
- **never** in the initial wait;
- **never** for secrets shorter than 4 characters (`REDACT_MIN_LENGTH`).

Every record carries `redaction: {applied, reason, occurrences}`. The reason is one of `no_secret_typed`, `typed_secret_echoed_and_redacted`, `typed_secret_not_found_in_output` or `typed_secret_too_short_not_redacted`.

Prompt detection always runs on the unredacted text. The capture keeps a margin equal to the longest typed secret, so a secret straddling the truncation cut is redacted before the final cut.

The previous rule (replace every occurrence of every password string) corrupted prompts such as `admin@svr04` for `admin/admin` logins (`reports/cowrie_compatibility_confirmation/report.md`). The manifest itself still holds the credentials in `auth_attempts`, as before, because labelling needs them.

**Decoding:** terminal output is decoded with one incremental UTF-8 decoder per wait (`_Utf8Stream`), so characters split across received chunks are reassembled. Invalid bytes are written as explicit `\xNN` escapes and counted in `invalid_utf8_bytes`; they are never silently replaced.

**The prompt heuristic is unchanged.** The audit found no evidence against it: the fast `ping` was a genuine immediate exit (Cowrie's `ping` option parser bug), not a false positive. See `reports/cowrie_profile_compatibility_v2/report.md`.

## Tests

- `tests/test_generator_pacing.py`: 14 tests.
  - The policy has no category parameters, and `run_session` takes no profile.
  - Seeds reproduce pacing; different seeds and sessions differ.
  - Bounds and speed.
  - Prompt gating.
  - Slow blocking commands.
  - Hanging `scp` → termination.
  - The server closing the channel.
  - Initial prompt timeout.
  - Unconfirmed exit.
  - Authentication logging.
  - An end-to-end `main()` run with two profiles whose `delay_range` values differ by 1,000 s: the think times equal the session pacing stream exactly.
  - Two cases against a real paramiko channel on a local loopback server.
- `tests/test_generator_connection.py`: connection cleanup; updated to the new signature.
- `tests/generator_fakes.py`: the fake SSH client and the Cowrie-like shell.
