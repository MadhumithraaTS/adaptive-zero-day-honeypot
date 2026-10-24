<h1 align="center">🛡️ AI-Driven Adaptive Honeypot Platform</h1>
<h3 align="center">Zero-Day Attack Intelligence & Automated Defense</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Status-Phase%202%20In%20Progress-blue?style=for-the-badge" alt="Status"/>
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/TensorFlow-2.13%2B-FF6F00?style=for-the-badge&logo=tensorflow&logoColor=white" alt="TensorFlow"/>
  <img src="https://img.shields.io/badge/scikit--learn-1.4-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="scikit-learn"/>
  <img src="https://img.shields.io/badge/Cowrie-SSH%20Honeypot-red?style=for-the-badge" alt="Cowrie"/>
  <img src="https://img.shields.io/badge/License-Academic-green?style=for-the-badge" alt="License"/>
</p>

<p align="center">
  <em>A research platform that captures real attacker behavior through honeypots, learns attack patterns using deep unsupervised clustering, and automatically generates deployable IDS/firewall rules — closing the detection gap for zero-day exploits.</em>
</p>

> **23CSE399 – Technical Project | Team 10 | Amrita Vishwa Vidyapeetham**

---

## 📋 Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Pipeline Usage](#pipeline-usage)
- [Implementation Progress](#implementation-progress)
- [Novelty & Differentiation](#novelty--differentiation)
- [Team](#team)
- [References](#references)

---

## Overview


Modern enterprise networks face a critical blind spot: **zero-day attacks** exploit unknown vulnerabilities for which no patch or detection signature exists at the time of exploitation. Traditional signature-based IDS/IPS systems are completely ineffective during this initial exposure window.

This project proposes an **AI-Driven Adaptive Honeypot Platform** that:

- 🎯 Deploys decoy environments (Cowrie SSH/Telnet) to attract and capture real attacker interactions
- 🔍 Extracts rich behavioral intelligence — login attempts, command sequences, session timing, payload data
- 🤖 Applies **Deep Embedded Clustering (DEC)** to identify novel attack patterns without labeled data
- ⚡ **Automatically generates deployable Snort/Suricata-compatible rules** from observed behavior
- 🌐 Shares threat intelligence across nodes using a Social IoT-based collaborative defense model

---

## Problem Statement

> *How can we design an adaptive honeypot-driven intelligence platform that captures previously unseen attacker interactions during active exploitation, models behavioral patterns instead of relying on predefined signatures, and automatically generates deployable detection rules in real time?*

Current enterprise security systems cannot reliably detect zero-day exploits during their initial execution window because they rely primarily on **predefined signatures and static rule sets**. Attackers leverage automation to scan, exploit, and establish persistence within minutes — creating a critical temporal imbalance between compromise and detection.

---

## Key Features

| Feature | Description |
|---|---|
| 🏭 **Honeypot Simulation** | Cowrie SSH/Telnet honeypot with full interaction logging |
| 📊 **Behavioral Feature Extraction** | 17-dimensional feature vectors per session (timing, commands, auth patterns, packet stats) |
| 🧠 **Deep Embedded Clustering** | DEC model with autoencoder pretraining for unsupervised zero-day detection |
| 📁 **Synthetic Data Generation** | Configurable attack profile generator with 8 realistic profiles including zero-day scenarios |
| 🔄 **End-to-End Pipeline** | Single-command pipeline: raw logs → features → ML inference → rule generation |
| 🛡️ **Automated Rule Export** | Converts cluster outputs into Snort/Suricata-compatible IDS rules |
| 🤝 **Collaborative Defense** | Social IoT-based rule sharing for distributed threat intelligence |

---

## System Architecture

The platform follows a closed-loop **Behavior-to-Defense pipeline**:

```
Internet / External Attackers
         │
         ▼
┌─────────────────────────┐
│      Honeypot Layer      │  (Cowrie SSH/Telnet Honeypot)
│  • SSH on port 2222      │
│  • Simulated shell env.  │
│  • Full interaction log  │
└────────────┬────────────┘
             │ JSON event logs
             ▼
┌─────────────────────────┐
│    Log Collection &      │  scripts/collect_logs.py
│    Session Reconstruction│  scripts/parse_logs.py
│  • Parse raw Cowrie logs │
│  • Group by session ID   │
│  • Extract IP, cmd, time │
└────────────┬────────────┘
             │ sessions.json
             ▼
┌─────────────────────────┐
│   Feature Extraction     │  scripts/extract_features.py
│  • 17-dim behavior vec.  │
│  • Timing & freq stats   │
│  • Command sequence enc. │
│  • Auth pattern metrics  │
└────────────┬────────────┘
             │ behavior_features.csv
             ▼
┌─────────────────────────┐
│  Preprocessing &         │  scripts/preprocess_dataset.py
│  Normalization           │
│  • log1p transform       │
│  • StandardScaler (saved)│
│  • Session ID mapping    │
└────────────┬────────────┘
             │ model_input.csv
             ▼
┌─────────────────────────┐
│  Deep Embedded Clustering│  ml/cowrie_dec/
│  (DEC Model)             │
│  • Autoencoder pretrain  │
│  • Cluster assignment    │
│  • Confidence scoring    │
│  • Zero-day flagging     │
└────────────┬────────────┘
             │ dec_results.csv
             ▼
┌─────────────────────────┐      ┌──────────────────────────┐
│  Response Engine &       │      │  Analyst Dashboard / UI   │
│  Rule Generation         │─────▶│  • Live Attack Visual.    │
│  • IDS signature export  │      │  • Threat Intelligence    │
│  • Firewall rule gen.    │      │  • Cluster Monitoring     │
│  • Collaborative sharing │      │  • Alerts & Reports       │
└─────────────────────────┘      └──────────────────────────┘
```

### Attack Profiles Simulated

The synthetic data generator covers **8 realistic attack profiles**:

| Profile | Description |
|---|---|
| `reconnaissance` | System enumeration — `whoami`, `ps aux`, `cat /etc/passwd` |
| `botnet_malware_download` | Download & execute malware via `wget`/`curl` |
| `privilege_escalation` | SUID exploitation, shadow file access, `sudo -l` |
| `evasion_anti_forensics` | Log wiping, `HISTFILE` clearing, `killall rsyslogd` |
| `brute_force_only` | Credential stuffing with no post-auth activity |
| `zero_day_buffer_overflow` | NOP-sled payload injection with anomalous packet ratios |
| `zero_day_covert_tunnel` | Long-duration covert data exfiltration via `netcat` |
| `zero_day_obfuscated_memory_attack` | Base64-encoded in-memory shellcode execution |

### Database Schema

| Collection | Description |
|---|---|
| `Attack_Session` | Per-session attacker activity records |
| `Payload_Data` | Raw and parsed payload captures |
| `Attack_Cluster` | DEC clustering outputs and confidence labels |
| `Generated_Rules` | Synthesized Snort/Suricata-compatible IDS rules |

### REST API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/ingest` | POST | Receive and store honeypot logs |
| `/api/analyze` | POST | Trigger ML analysis pipeline |
| `/api/rules` | GET | Export generated detection rules |

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Honeypot** | [Cowrie](https://github.com/cowrie/cowrie) (SSH/Telnet emulation) |
| **Data Storage** | MongoDB, JSON, CSV |
| **Feature Engineering** | Python, Pandas, NumPy |
| **ML Framework** | TensorFlow ≥ 2.13, scikit-learn 1.4 |
| **Clustering Model** | Deep Embedded Clustering (DEC) with Keras autoencoder |
| **Scaler Persistence** | `joblib` (StandardScaler saved for reproducible inference) |
| **Attack Simulation** | Hydra (brute-force), Paramiko (SSH scripting), Custom generator |
| **Network Scanning** | Nmap |
| **Environment** | Python 3.10+, Docker / VM isolation |

---

## Project Structure

```
adaptive-zero-day-honeypot/
│
├── scripts/                        # Core data pipeline scripts
│   ├── pipeline.py                 # End-to-end orchestration script
│   ├── attack_generator.py         # Automated SSH attack simulation
│   ├── generate_dataset.py         # Synthetic session generator (8 profiles)
│   ├── collect_logs.py             # Docker/Cowrie log collection
│   ├── parse_logs.py               # Raw log parsing → sessions.json
│   ├── extract_features.py         # 17-dim behavioral feature extraction
│   └── preprocess_dataset.py       # Normalization & scaler persistence
│
├── ml/
│   └── cowrie_dec_integration_skeleton/
│       ├── ml/cowrie_dec/
│       │   ├── model.py            # DEC model architecture (Keras)
│       │   ├── preprocessing.py    # Inference preprocessing pipeline
│       │   ├── inference.py        # predict() — returns cluster, confidence, probs
│       │   └── response_engine.py  # Cluster → IDS rule mapping
│       └── scripts/
│           └── run_dec_evaluation.py  # Offline DEC evaluation runner
│
├── data/
│   ├── raw/                        # Raw Cowrie JSON event logs
│   ├── parsed/                     # sessions.json, behavior_features.csv
│   └── processed/                  # model_input.csv, session_mapping.csv
│
├── models/                         # Saved artifacts (scaler.joblib, DEC weights)
├── configs/                        # Honeypot & pipeline configuration files
├── logs/                           # Runtime logs
├── cowrie/                         # Cowrie honeypot installation
├── notebooks/                      # Jupyter notebooks for exploration
├── requirements.txt
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- Docker (optional, for live Cowrie deployment)
- Nmap (optional, for network scanning)

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/adaptive-zero-day-honeypot.git
cd adaptive-zero-day-honeypot
```

### 2. Create a virtual environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## Pipeline Usage

The entire workflow is orchestrated by a single script — `scripts/pipeline.py`.

### Run with synthetic data *(no Docker/live SSH required)*

```bash
python scripts/pipeline.py --synthetic --sessions 200
```

### Run with live Cowrie honeypot data

```bash
# Full pipeline (attack simulation → log collection → ML inference)
python scripts/pipeline.py --sessions 200

# Skip live attack simulation (use existing logs)
python scripts/pipeline.py --skip-attack --skip-collect

# Skip DEC model evaluation
python scripts/pipeline.py --synthetic --skip-dec
```

### Available flags

| Flag | Default | Description |
|---|---|---|
| `--sessions N` | `200` | Number of sessions to generate/simulate |
| `--synthetic` | `False` | Use synthetic data generator (no live SSH) |
| `--skip-attack` | `False` | Skip live attack automation |
| `--skip-collect` | `False` | Skip Docker log collection |
| `--skip-dec` | `False` | Skip DEC model inference step |

### Pipeline outputs

| Artifact | Path | Description |
|---|---|---|
| Parsed Sessions | `data/parsed/sessions.json` | Reconstructed attack sessions |
| Behavioral Features | `data/parsed/behavior_features.csv` | 17-dim feature vectors |
| Session Details | `data/parsed/session_details.json` | Command sequences per session |
| ML Input | `data/processed/model_input.csv` | Normalized model-ready features |
| Session Mapping | `data/processed/session_mapping.csv` | Session ID ↔ feature row mapping |
| Fitted Scaler | `models/scaler.joblib` | Persisted StandardScaler for inference |
| DEC Results | `dec_results.csv` | Cluster assignments + confidence scores |

### Running DEC inference standalone

```python
from ml.cowrie_dec.inference import predict
import pandas as pd

session_df = pd.read_csv("data/parsed/behavior_features.csv").iloc[[0]]
clusters, confidence, probabilities = predict(session_df)
print(f"Cluster: {clusters}, Confidence: {confidence:.2f}")
```

## Implementation Progress

### ✅ Phase 1 — Honeypot Deployment & Structured Data Capture

- [x] Deployed and configured Cowrie SSH/Telnet honeypot (port `2222`)
- [x] Verified service visibility via Nmap port scanning
- [x] Performed manual SSH login attempts to simulate reconnaissance
- [x] Executed automated brute-force attacks using Hydra
- [x] Captured attacker interactions: login attempts, command sequences, IP addresses
- [x] Stored structured logs: login logs, command logs, IP tracking files
- [x] Implemented session reconstruction — raw events grouped by source IP, timestamp, and session ID
- [x] Built synthetic attack data generator with 8 attack profiles (including 3 zero-day scenarios)
- [x] Implemented 17-dimensional behavioral feature extraction pipeline
- [x] Built preprocessing pipeline with persisted StandardScaler for reproducible inference
- [x] Integrated DEC model architecture with autoencoder pretraining

**Sample captured data:**

```json
[
  {
    "ip": "172.20.10.5",
    "failed_attempts": 4,
    "successful_attempts": 4,
    "total_attempts": 8,
    "duration": "few seconds",
    "attack_type": "brute force pattern"
  },
  {
    "ip": "172.20.10.3",
    "failed_attempts": 0,
    "successful_attempts": 1,
    "total_attempts": 1,
    "duration": "instant",
    "attack_type": "single login attempt"
  }
]
```

**Sample login log entry:**
```
2026-02-09T23:28:19Z [HoneyPotSSHTransport,10,172.20.10.4] login attempt [b'root'/b'admin'] succeeded
```

**Sample command log entry:**
```
2026-02-09T23:34:46Z [HoneyPotSSHTransport,13,172.20.10.3] CMD: hydra -l root -P passwords.txt ssh://172.20.10.2:2222 -t 4
```

---

### 🔄 Phase 2 — ML-Based Clustering & Rule Generation *(In Progress)*

- [ ] Train DEC model on behavioral feature dataset
- [ ] Tune cluster count and confidence thresholds for zero-day flagging
- [ ] Implement automated Snort/Suricata rule generation from cluster outputs
- [ ] Validate detection rates against simulated zero-day scenarios

---

### 🔜 Phase 3 — Dashboard & Integration Testing

- [ ] Real-time attack visualization dashboard
- [ ] Social IoT-based rule sharing across distributed honeypot nodes
- [ ] Attack replay and metric evaluation (TPR, FPR, Precision, Recall, F1)
- [ ] Full end-to-end integration test

---

## Novelty & Differentiation

| Feature | This Platform | Traditional IDS (Snort/Suricata) | Commercial SIEM | Traditional Honeypot |
|:---|:---:|:---:|:---:|:---:|
| Zero-day detection | ✅ | ❌ | ❌ | ❌ |
| Live behavioral learning | ✅ | ❌ | ❌ | ❌ |
| Automated rule generation | ✅ | ❌ | ❌ | ❌ |
| Honeypot-integrated intelligence | ✅ | ❌ | ❌ | ✅ |
| Closed-loop defense pipeline | ✅ | ❌ | ❌ | ❌ |
| Collaborative IoT-based sharing | ✅ | ❌ | ❌ | ❌ |
| Deep unsupervised clustering | ✅ | ❌ | ❌ | ❌ |

**Key novel contributions:**

- 🔁 **Behavior-to-Defense Pipeline** — converts live attacker interactions into deployable detection rules without manual intervention
- 🗂️ **Zero-Day Dataset Construction** — automated, continuously evolving behavioral dataset built from real honeypot captures
- 🧠 **Deep Embedded Clustering (DEC)** — unsupervised clustering of multi-stage attack sequences with per-session confidence scoring
- 📝 **Automated Rule Generation Engine** — dynamic export to Snort/Suricata-compatible detection rules with confidence-weighted prioritization
- 🏗️ **Unified Architecture** — honeypot, feature extraction, ML analytics, rule synthesis, and API export in one integrated platform

---

## Team

> **23CSE399 – Technical Project | Team 10 | Amrita Vishwa Vidyapeetham**

| S.No | Register Number | Name |
|:---:|---|---|
| 1 | CB.SC.U4CSE23404 | Amritha S Nidhi |
| 2 | CB.SC.U4CSE23405 | Anaswara K |
| 3 | CB.SC.U4CSE23429 | Madhumithraa T S |
| 4 | CB.SC.U4CSE23435 | Mayuka Sri K |
| 5 | CB.SC.U4CSE23457 | Vrithika K M |

**Faculty Guide:** Dr. Harini N, Associate Professor, Department of Computer Science & Engineering

---

## References

1. Junyuan Xie, Ross Girshick, Ali Farhadi — *"Unsupervised Deep Embedding for Clustering Analysis"* — ICML 2016
2. Kipf, T. & Welling, M. — *"Variational Graph Auto-Encoders"* — NeurIPS 2016
3. Cowrie Project — [github.com/cowrie/cowrie](https://github.com/cowrie/cowrie)
4. Snort IDS — [snort.org](https://www.snort.org/)
5. Suricata IDS — [suricata.io](https://suricata.io/)
6. MITRE ATT&CK Framework — [attack.mitre.org](https://attack.mitre.org/)
7. Pedregosa et al. — *"Scikit-learn: Machine Learning in Python"* — JMLR 2011

---

<p align="center">
  <em>Built with 🔒 for advancing autonomous cyber defense research</em><br/>
  <em>Amrita Vishwa Vidyapeetham · Department of CSE · 2023–2027</em>
</p>
