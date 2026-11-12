# Dataset Builder

Tooling to generate a **larger, properly labelled** honeypot dataset for the public release
(Milestone 3). It is self-contained under `dataset_builder/` and does **not** modify any existing
`scripts/`, `configs/`, or `data/` files — it reuses `scripts/parse_logs.py` and
`scripts/extract_features.py` as-is and writes everything under its own run directory.

## Why this exists

The tracked runs under `data/` are small (≤54 sessions) and every session is labelled
`attack_cat=normal, label=0`, because the original `attack_generator.py` never recorded which
profile produced which session. These tools fix both problems:

- **Labels** — each generated session is written to a ground-truth `manifest.jsonl` the moment it
  runs; the builder matches Cowrie's own session records back to it by time window (+ command
  overlap as a confidence check) and injects the correct `attack_cat`/`label`.
- **Scale & variety** — profiles in `profiles_v2.json` use randomised credentials, optional steps,
  alternative commands and filler, so a 400+ session run is not full of near-duplicates.
- **Novelty** — two profiles are marked `held_out`; skip them when generating DEC training data and
  include them later to test zero-day/novelty detection.

## Files

| File | Purpose |
|------|---------|
| `profiles_v2.json` | Labelled traffic profiles (benign + 6 attack categories, 2 held out). |
| `generate_labelled_traffic.py` | Drives SSH sessions against Cowrie, writes `manifest.jsonl`. |
| `build_labelled_dataset.py` | Collects logs, attaches labels, builds `behavior_features.csv`. |

## Prerequisites

- Cowrie running (your `cowrie/docker-compose.yml`), SSH mapped to `127.0.0.1:2223`.
- The project `.venv` (has `paramiko`). Prefix commands with `.venv/Scripts/python.exe`.

### One-time Cowrie auth setup (required)

Cowrie ships with `auth_class = UserDB` but no `userdb.txt`, so by default it **rejects most
logins** — that is why the earlier baseline had only 8 successful logins out of 54 sessions. Install
the repo's `cowrie/userdb.txt`, which accepts any credentials except the reserved `scan` guesses the
brute-force profile uses (so failed logins still register as failures):

```bash
docker cp cowrie/userdb.txt cowrie-project:/cowrie/cowrie-git/etc/userdb.txt
docker restart cowrie-project
```

This persists across restarts but is lost if the container is **recreated** (`docker compose down`
then `up`). Re-run the two commands after recreating, or add a volume mount to `docker-compose.yml`:

```yaml
    volumes:
      - ./userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro
```

## Usage

```bash
# 1. Start the honeypot
cd cowrie && docker compose up -d && cd ..

# 2. Generate ~800 labelled sessions (held-out categories excluded for training data).
#    The generator records the Cowrie log baseline so this run can be isolated later (see note).
.venv/Scripts/python.exe dataset_builder/generate_labelled_traffic.py \
    --sessions 800 --port 2223 --seed 1 \
    --output-dir dataset_builder/runs/train_v1

# 3. Collect logs + attach labels + extract features
.venv/Scripts/python.exe dataset_builder/build_labelled_dataset.py \
    --output-dir dataset_builder/runs/train_v1
```

Add `--include-held-out` to step 2 for an evaluation run that also contains the novel categories.
If Docker `docker cp` is not available, pass `--raw-input <path/to/cowrie.json>` to step 3.

### Runtime and `--speed`

Each session costs an SSH handshake plus its command delays, so at realistic pacing (`--speed 1`)
a session takes ~20s and 2000 sessions run ~10–12 hours. `--speed N` divides every delay by N while
keeping the relative pacing between profiles, so fast attacks still look faster than slow admin
sessions. The SSH handshake cost per session is fixed (~4s, including failed-login guesses), so that
sets the floor: even at `--speed 8+`, ~2000 sessions take ~2.5 hours. Sessions run sequentially on
purpose — the label matcher relies on non-overlapping time windows, so do not parallelise.

Rough guide: `--speed 8` → ~1000 sessions in ~75 min, ~2000 in ~2.5 h. Record of the chosen speed is
written to `run_meta.json`.

## Outputs (under the run's `--output-dir`)

```
run_meta.json                 run parameters
manifest.jsonl                generation record, one line per generated session
raw/cowrie.json               collected honeypot log
parsed/sessions.json          grouped sessions
labelled/sessions_labelled.json
labelled/behavior_features.csv   <- the labelled dataset (24 UNSW-NB15 features + attack_cat/label)
labelled/session_details.json
labelled/label_assignments.csv   per-session behaviour label, source entry and evidence
labelled/label_report.json       assignment and label-quality counts
```

The builder refuses to overwrite an existing run's `raw/`, `parsed/` or `labelled/` outputs unless
`--allow-overwrite` is given.

## Labelling (version 2)

`labelling.py` labels each session from what Cowrie recorded, and records separately which manifest
entry produced it:

| `attack_cat` | Meaning | `label` |
|---|---|---|
| `failed_login` | Failed authentication only, no successful login | -1 |
| `login_no_commands` | Successful login, no commands other than `exit` | -1 |
| profile category (e.g. `botnet`) | Every command the session ran was sent by its source entry | profile label (0/1) |
| `ambiguous` | Commands fit several candidate entries of different categories | -1 |
| `unassigned` | No reliable source, or commands the source entry never sent | -1 |

Source entries are found by aligning Cowrie's sessions (in connect order) with the manifest's
authentication attempts on outcome, username and password, not by host timestamps, which differ from
Cowrie's clock. Only alignment blocks of at least `--min-block` attempts are trusted. Sessions
outside them fall back to credential and command evidence, then to the entry's time window widened
by `--clock-tolerance`; anything still unresolved stays `ambiguous` or `unassigned`.

These are behaviour labels inferred from Cowrie events and the generation manifest, not
independently verified ground truth. Check `label_report.json` after each run: `source_assignment`
gives confident, ambiguous, unassigned and inconsistent counts; `out_of_window_dropped` should be 0
for an isolated run.

Version 1 (runs labelled before this change, e.g. `runs/train_v1`, `runs/eval_v1`) gave failed-login
sessions their profile's category and resolved command ties to the first matching entry. To correct
such a run without modifying it:

```bash
.venv/Scripts/python.exe dataset_builder/relabel_run.py \
    --source-run dataset_builder/runs/train_v1 --output-dir dataset_builder/runs/train_v2_corrected
```

`relabel_run.py` writes a new directory (it refuses existing ones) with the corrected dataset,
`label_assignments.csv`, `label_report.json`, a version-1 vs version-2 `comparison_report.md`, and
`provenance.json` with SHA-256 hashes of the source files it read.

### How runs are isolated (log baseline)

Cowrie writes every session to one cumulative `cowrie.json` that is never cleared between runs, and
consecutive runs can start less than a second apart, so no time-based filter can reliably separate
them. **Do not try to clear the log by overwriting it** — overwriting the file Cowrie holds open
corrupts its logging and it silently stops writing (recoverable only by recreating the container).

Instead, the generator records `log_baseline_lines` in `run_meta.json`: the number of log lines that
already existed when the run started. The builder collects the full log and parses only the lines
after that baseline, which isolates the run exactly, even from one that started moments earlier. A
small time-window filter runs afterwards as a secondary check. Pass `--no-baseline` only when the
honeypot is not a local docker container; the builder then relies on the time-window filter alone.

## Honesty note for the release

All traffic originates from the local generator against a lab Cowrie instance, so source-IP fields
carry no information and the data is controlled, not wild capture. State this plainly in the dataset
README. The value is in the **labelled, reproducible behavioural sessions**, not in realistic
network origins.

## Scope / safety

For use only against your own honeypot in the project lab. The attack profiles are deliberately
short, well-known command patterns (the same kind already in `configs/attack_profiles.json`) used to
exercise Cowrie's logging — no real payloads are fetched or executed, since Cowrie only emulates a
shell.
