# 🚀 Installation & Setup Guide

> Complete guide to set up, configure, and run the **AI-Driven Adaptive Honeypot Platform** from scratch.

---

## 📋 Table of Contents

- [System Requirements](#-system-requirements)
- [Prerequisites](#-prerequisites)
- [Step 1 — Clone the Repository](#step-1--clone-the-repository)
- [Step 2 — Set Up the Python Environment](#step-2--set-up-the-python-environment)
- [Step 3 — Install Dependencies](#step-3--install-dependencies)
- [Step 4 — Start the Cowrie Honeypot (Docker)](#step-4--start-the-cowrie-honeypot-docker)
- [Step 5 — Run the Pipeline](#step-5--run-the-pipeline)
- [Step 6 — (Optional) Simulate Attacks for Testing](#step-6--optional-simulate-attacks-for-testing)
- [Step 7 — Run Novelty Assessment](#step-7--run-novelty-assessment)
- [Pipeline Options Reference](#-pipeline-options-reference)
- [DEC Interpreter Setup](#-dec-interpreter-setup)
- [Interpreting Results](#-interpreting-results)
- [Connect to the Honeypot Manually](#-connect-to-the-honeypot-manually)
- [Stop the Honeypot](#-stop-the-honeypot)
- [Running Automated Tests](#-running-automated-tests)
- [Troubleshooting](#-troubleshooting)

---

## 💻 System Requirements

| Component | Requirement |
|---|---|
| **OS (Honeypot)** | Linux / WSL2 (Ubuntu 20.04+) or Docker Desktop |
| **OS (Scripts)** | Linux, macOS, or Windows (cross-platform) |
| **RAM** | 2 GB minimum, 4 GB recommended |
| **Disk** | 5 GB free for logs and model artifacts |
| **Python** | 3.10 or higher |
| **Docker** | Required to run Cowrie in a container |

---

## 🧰 Prerequisites

Install the following before proceeding:

| Tool | Purpose | Install |
|---|---|---|
| Python 3.10+ | Core runtime | [python.org](https://python.org) |
| pip | Package manager | Bundled with Python |
| Git | Version control | [git-scm.com](https://git-scm.com) |
| Docker Desktop | Runs the Cowrie honeypot container | [docker.com](https://www.docker.com/products/docker-desktop) |
| WSL2 (Ubuntu) | Required on Windows for Docker/Linux tooling | [WSL docs](https://learn.microsoft.com/en-us/windows/wsl/install) |

**Verify your installations:**

```bash
python3 --version   # Should be 3.10+
git --version
docker --version
```

**Optional tools** (for attack simulation):

| Tool | Purpose | Install |
|---|---|---|
| Hydra | Brute-force attack simulation | `sudo apt install hydra` |
| Nmap | Port scanning and fingerprinting | `sudo apt install nmap` |

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/MadhumithraaTS/adaptive-zero-day-honeypot.git
cd adaptive-zero-day-honeypot
```

---

## Step 2 — Set Up the Python Environment

```bash
# Create a virtual environment
python3 -m venv .venv

# Activate it
source .venv/bin/activate       # Linux / macOS / WSL
.venv\Scripts\activate          # Windows (PowerShell)
```

---

## Step 3 — Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

<details>
<summary>📦 What gets installed?</summary>

| Package | Version | Role |
|---|---|---|
| `paramiko` | 3.4.0 | SSH protocol layer |
| `pandas` | 3.0.5 | Data processing and feature tables |
| `scikit-learn` | 1.9.0 | ML clustering and anomaly detection |
| `joblib` | 1.3.2 | Model serialization and parallel jobs |
| `tensorflow-cpu` | ≥ 2.13.0 | Deep learning (Autoencoder / DEC) |

</details>

---

## Step 4 — Start the Cowrie Honeypot (Docker)

Start the Cowrie container using Docker Compose:

```bash
docker compose -f cowrie/docker-compose.yml up -d
```

Verify it is running:

```bash
docker ps
```

You should see a container named `cowrie-project` in the output.

> ⚠️ **Note:** Docker Desktop must be running before executing the above command.

---

## Step 5 — Run the Pipeline

The main pipeline orchestrates the full flow — attack simulation, log collection, parsing, feature extraction, and DEC clustering.

```bash
# Run with default settings (generates 10 sessions)
python scripts/pipeline.py --attack-username root --attack-password admin
```

**Recommended first run** (writes to a fresh output directory, never touches the baseline):

```powershell
# PowerShell
$Run = "data\demo_" + (Get-Date -Format "yyyyMMdd_HHmmss")
python scripts/pipeline.py --sessions 3 --attack-username root --attack-password admin --output-dir $Run --skip-preprocess
```

```bash
# Bash / WSL
Run="data/demo_$(date +%Y%m%d_%H%M%S)"
python scripts/pipeline.py --sessions 3 --attack-username root --attack-password admin --output-dir "$Run" --skip-preprocess
```

**Reprocess an existing log without generating new sessions:**

```powershell
$Run = "data\demo_" + (Get-Date -Format "yyyyMMdd_HHmmss")
python scripts/pipeline.py --skip-attack --raw-input data\raw\cowrie.json --output-dir $Run --skip-preprocess
```

---

## Step 6 — (Optional) Simulate Attacks for Testing

If you don't have a live honeypot yet, generate a synthetic dataset:

```bash
# Generate a realistic synthetic attack dataset (1800 sessions by default)
python scripts/generate_dataset.py
```

Or manually connect to the honeypot and simulate attacker behavior:

```bash
# Connect to the running Cowrie container
ssh root@localhost -p 2223
# Password: admin
```

Run commands inside to simulate attacker activity:

```bash
whoami
pwd
ls
cat /etc/passwd
wget http://example.com/test.sh
exit
```

---

## Step 7 — Run Novelty Assessment

Compare captured sessions against the stored behavioral signature catalogue:

```powershell
python scripts/novelty_assessment.py `
  --session-details "$Run\parsed\session_details.json" `
  --signature-file reports\novelty_assessment\held_out\revised\reference_signatures\behaviour_signatures.json `
  --output-dir "$Run\novelty"
```

**Output files:**

| File | Description |
|---|---|
| `$Run\processed\dec_results.csv` | DEC cluster assignments and confidence scores |
| `$Run\novelty\novelty_assessment_results.csv` | Per-session novelty scores and labels |
| `$Run\novelty\novelty_assessment_report.md` | Human-readable assessment report |

---

## ⚙️ Pipeline Options Reference

`scripts/pipeline.py` supports the following flags:

| Option | Effect |
|---|---|
| `--output-dir DIR` | Write all outputs under `DIR` instead of the tracked baseline paths |
| `--allow-overwrite` | Allow replacing existing output files (use with caution) |
| `--raw-input FILE` | Parse an existing Cowrie JSON log; skips live log collection |
| `--skip-attack` | Skip session generation (combine with `--raw-input`) |
| `--skip-collect` | Skip copying the log out of the Docker container |
| `--skip-preprocess` | Skip `preprocess_dataset.py` (the auxiliary MinMax step) |
| `--sessions N` | Number of attack sessions to generate (default: 10) |
| `--attack-username U` | SSH username for simulated attacks |
| `--attack-password P` | SSH password for simulated attacks |
| `--cluster-python PATH` | Path to the DEC interpreter (see below) |

> ⚠️ **Safe by default:** Without `--output-dir`, the pipeline checks all output paths first. If any file already exists, it exits with code `2` and lists the conflicts rather than silently overwriting.

---

## 🧠 DEC Interpreter Setup

The DEC (Deep Embedded Clustering) model artifacts were pickled with specific library versions and require a **separate Python interpreter** to avoid version conflicts with the main environment.

**Default DEC interpreter path:**
```
ml\cowrie_dec_integration_skeleton\.venv-dec-smoke\Scripts\python.exe
```

`scripts/pipeline.py` uses this interpreter automatically for the DEC step. To specify a custom path:

```powershell
python scripts/pipeline.py --cluster-python C:\path\to\dec-env\Scripts\python.exe ...
```

To run DEC inference directly:

```powershell
ml\cowrie_dec_integration_skeleton\.venv-dec-smoke\Scripts\python.exe `
  ml\cowrie_dec_integration_skeleton\scripts\run_dec_evaluation.py `
  path\to\behavior_features.csv `
  --output path\to\dec_results.csv
```

> If the default interpreter is missing and `--cluster-python` is not provided, the pipeline exits with a usage error.

---

## 📊 Interpreting Results

### DEC Cluster Assignments (`dec_results.csv`)

| Column | Description |
|---|---|
| `session_id` | Unique session identifier |
| `dec_cluster` | Assigned cluster (0, 1, or 2) |
| `dec_confidence` | Highest soft-assignment probability |
| `cluster_0_prob` to `cluster_2_prob` | Full probability distribution |

**Cluster profiles** (based on 1,800 synthetic training sessions):

| Cluster | Behavioral Profile |
|:---:|---|
| **0** | Short, high-rate sessions (rapid scanning / spray attacks) |
| **1** | Longer interactive sessions with multiple command sequences |
| **2** | No commands — brute-force-only login attempts |

> ⚠️ DEC was trained on synthetic data. Live Cowrie sessions may differ measurably (e.g., lower `tcprtt`/`synack` values). Treat cluster assignments as indicative, not definitive.

### Novelty Assessment Labels

| Label | Meaning |
|---|---|
| `Known-like` | Score ≥ 0.70, clearly matches a signature in the catalogue |
| `Ambiguous` | Two signatures score similarly — no confident decision |
| `Potentially Novel` | No catalogue signature matches closely — warrants investigation |
| `Insufficient Evidence` | Too few comparable features to make a determination |

> The novelty score is a **heuristic similarity score**, not a probability. It weights: numerical feature similarity (70%), command-category overlap (20%), and authentication outcome (10%).

---

## 🔌 Connect to the Honeypot Manually

```bash
ssh root@localhost -p 2223
# Password: admin
```

> **Note:** This Cowrie container rejects logins for usernames `admin`, `user`, and `guest`, and rejects some common passwords (`root`, `123456`).

---

## 🛑 Stop the Honeypot

```bash
docker compose -f cowrie/docker-compose.yml down
```

---

## 🧪 Running Automated Tests

The repository includes a regression and validation test suite of 130 tests covering log ingestion, feature extraction, novelty scoring, clustering, and pipeline safety. All tests run offline without requiring a live honeypot.

```bash
# Install pytest in your virtual environment
pip install pytest

# Run the core offline test suite
pytest tests/test_behaviour_pattern_analysis.py `
       tests/test_behaviour_signature_generation.py `
       tests/test_collect_logs.py `
       tests/test_dec_preprocessing.py `
       tests/test_log_processing.py `
       tests/test_novelty_assessment.py `
       tests/test_prepare_fresh_evaluation.py -v
```

For full details on test coverage, dual-interpreter requirements, and audited results, see [`docs/testing.md`](docs/testing.md).

---

## 🔧 Troubleshooting

| Problem | Solution |
|---|---|
| `docker: command not found` | Install Docker Desktop and ensure it's running |
| `python: command not found` | Use `python3` instead, or check your PATH |
| Pipeline exits with code `2` | Output files already exist — use `--output-dir` for a fresh run |
| DEC interpreter not found | Check path: `ml\cowrie_dec_integration_skeleton\.venv-dec-smoke\Scripts\python.exe` |
| SSH connection refused on port 2223 | Ensure the Cowrie container is running (`docker ps`) |
| `ModuleNotFoundError` after install | Ensure your `.venv` is activated before running `pip install` |

---

*For questions or issues, open a [GitHub Issue](https://github.com/MadhumithraaTS/adaptive-zero-day-honeypot/issues).*
