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
docker compose up -d
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
