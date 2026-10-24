<div align="center">

# 🛡️ AI-Driven Adaptive Honeypot Platform
### Zero-Day Attack Intelligence & Automated Defense

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.13%2B-FF6F00?style=for-the-badge&logo=tensorflow&logoColor=white)](https://tensorflow.org)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.9-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Cowrie](https://img.shields.io/badge/Honeypot-Cowrie-red?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/cowrie/cowrie)
[![License](https://img.shields.io/badge/License-Academic-blue?style=for-the-badge)](LICENSE)
[![Phase](https://img.shields.io/badge/Phase-1%20Complete-brightgreen?style=for-the-badge)]()

<br/>

> **23CSE399 – Project Phase 1 &nbsp;|&nbsp; Team 10 &nbsp;|&nbsp; Amrita Vishwa Vidyapeetham, Coimbatore**

<br/>

*A research-grade cybersecurity platform that captures real attacker behavior through honeypots, applies unsupervised machine learning to model zero-day attack patterns, and automatically generates deployable IDS/firewall rules — closing the detection gap before any signature exists.*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Problem Statement](#-problem-statement)
- [Motivation](#-motivation)
- [System Architecture](#-system-architecture)
- [Tech Stack](#-tech-stack)
- [Repository Structure](#-repository-structure)
- [Implementation — Phase 1](#-implementation--phase-1)
- [Key Scripts](#-key-scripts)
- [Project Roadmap](#-project-roadmap)
- [Novelty & Differentiation](#-novelty--differentiation)
- [Advantages & Limitations](#-advantages--limitations)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](INSTALLATION.md)
- [Contributing](#-contributing)
- [References](#-references)

---

## 🔍 Overview

Modern enterprise networks face a critical blind spot: **zero-day attacks** exploit unknown vulnerabilities for which no patch or detection signature exists at the time of exploitation. Traditional signature-based IDS/IPS systems are completely ineffective during this initial exposure window — often measured in hours to days.

This project proposes an **AI-Driven Adaptive Honeypot Platform** that fundamentally shifts the detection paradigm from *signature-matching* to *behavioral intelligence*:

| Capability | Description |
|---|---|
| 🪤 **Deception Layer** | Deploys realistic decoy environments (SSH/Telnet) to attract and capture real attacker sessions |
| 🧠 **Behavioral Intelligence** | Extracts and models login patterns, command sequences, timing, and session metadata |
| 🤖 **ML-Driven Analysis** | Applies unsupervised clustering and anomaly detection to identify novel attack patterns |
| 📜 **Automated Rule Generation** | Synthesizes deployable Snort/Suricata-compatible IDS and firewall rules from observed behavior |
| 🌐 **Collaborative Defense** | Shares threat intelligence across nodes using a Social IoT-based federated model |

---

## ❗ Problem Statement

> *How can we design an adaptive honeypot-driven intelligence platform that captures previously unseen attacker interactions during active exploitation, models behavioral patterns instead of relying on predefined signatures, and automatically generates deployable detection rules in real time?*

Current enterprise security systems **cannot reliably detect zero-day exploits** during their initial execution window because they rely primarily on predefined signatures and static rule sets. Meanwhile, attackers leverage automation to scan, exploit, and establish persistence within minutes — creating a critical temporal imbalance between compromise and detection.

**The core challenge:** Detection systems need to *know what to look for* before they can detect it. Zero-day attacks, by definition, have no prior fingerprint.

---

## 💡 Motivation

- **Signature Blindness:** IDS/IPS systems have zero knowledge of a zero-day exploit at the time of first occurrence — resulting in delayed or missed detection entirely.
- **Manual Latency:** Human-driven signature creation and rule deployment introduce significant response latency, giving attackers a wide operational window before containment.
- **Untapped Intelligence:** Honeypots generate rich, real-world behavioral data — login patterns, command sequences, attacker tooling — that currently goes largely unprocessed.
- **The Goal:** Minimize the time gap between attack discovery, behavioral analysis, and defensive mitigation through adaptive, closed-loop automation.

---

## 🏗️ System Architecture

The platform follows a **Behavior-to-Defense pipeline** — every attacker interaction flows from capture to automated defensive action:

```
Internet / External Attackers
         │
         ▼
┌─────────────────────────────┐
│       Honeypot Layer         │  (Cowrie — VM/Container)
│  • SSH / Telnet Simulation   │  Port 2222
│  • Full Interaction Logging  │
│  • Payload Capture           │
└─────────────┬───────────────┘
              │  Structured JSON Logs
              ▼
┌─────────────────────────────┐
│   Data Collection & Storage  │
│   (MongoDB / JSON)           │
│  • Attack Sessions           │
│  • Payload Data              │
│  • Command Sequences         │
│  • Session Metadata          │
└─────────────┬───────────────┘
              │  Parsed Feature Vectors
              ▼
┌─────────────────────────────┐
│   ML-Based Attack Analysis   │
│  • Feature Extraction        │
│  • Unsupervised Clustering   │  (DBSCAN, K-Means)
│  • Anomaly Detection         │  (Isolation Forest, Autoencoder)
│  • Behavior Modeling         │
│  • Novelty Assessment        │
└─────────────┬───────────────┘
              │  Behavioral Signatures
              ▼
┌─────────────────────────────┐
│   Signature & Rule Engine    │
│  • Content-Based Signatures  │
│  • Behavior-Based Rules      │
│  • Confidence Scoring        │
│  • Snort/Suricata Export     │
└─────────────┬───────────────┘
              │
    ┌─────────┴──────────┐
    ▼                    ▼
┌──────────────┐  ┌──────────────────────────┐
│  Enforcement  │  │   Analyst Dashboard / UI  │
│  • IDS Rules  │  │  • Live Attack Visuals    │
│  • IPS Block  │  │  • Threat Intelligence    │
│  • Firewall   │  │  • Rule Monitoring        │
└──────────────┘  │  • Alerts & Reports       │
                  └──────────────────────────┘
```

### Database Schema

| Collection | Description |
|---|---|
| `Attack_Session` | Per-session attacker activity records (IP, duration, commands) |
| `Payload_Data` | Raw and parsed payload captures with encoding analysis |
| `Attack_Cluster` | ML clustering outputs, labels, and confidence scores |
| `Generated_Rules` | Synthesized, deployment-ready IDS/firewall rules |

### REST API Endpoints

| Endpoint | Method | Description |
|---|:---:|---|
| `/api/ingest` | `POST` | Receive and store structured honeypot logs |
| `/api/analyze` | `POST` | Trigger the ML analysis pipeline on new data |
| `/api/rules` | `GET` | Export generated detection rules (Snort/Suricata format) |
| `/api/sessions` | `GET` | Retrieve reconstructed attack session summaries |

---

## 🛠️ Tech Stack

| Category | Technology |
|---|---|
| **Honeypot** | [Cowrie](https://github.com/cowrie/cowrie) (SSH/Telnet medium-interaction honeypot) |
| **Language** | Python 3.10+ |
| **ML / DL** | scikit-learn 1.9, TensorFlow-CPU 2.13+, joblib |
| **Data** | pandas 3.0, JSON, CSV |
| **Networking** | paramiko 3.4 (SSH protocol layer) |
| **Attack Simulation** | Hydra (brute-force), Nmap (port scanning) |
| **Storage** | MongoDB (production), JSON flat-file (development) |
| **Environment** | Python venv, Linux VM / Docker container |

---

## 📁 Repository Structure

```
adaptive-zero-day-honeypot/
│
├── configs/                                    # Runtime configuration files
│   ├── attack_profiles.json                    # Attack scenario profiles used by the generator
│   └── defence_policy.json                     # Defence response policy definitions
│
├── cowrie/                                     # Cowrie honeypot container setup
│   └── docker-compose.yml                      # Docker Compose file to launch the Cowrie container
│
├── data/                                       # All data produced and consumed by the pipeline
│   ├── raw/                                    # Raw Cowrie JSON event logs (cowrie.json)
│   ├── parsed/                                 # Structured session and feature data
│   ├── processed/                              # Preprocessed ML-ready input files
│   ├── evaluation_runs/                        # Archived outputs from evaluation experiments
│   └── fresh_evaluation/                       # Outputs from fresh (non-baseline) pipeline runs
│
├── ml/                                         # Machine learning integration modules
│   └── cowrie_dec_integration_skeleton/        # DEC (Deep Embedded Clustering) integration package
│       ├── ml/cowrie_dec/                      # DEC model, autoencoder, and scaler logic
│       └── scripts/
│           └── run_dec_evaluation.py           # Entry point: runs DEC inference on a feature CSV
│
├── model_selection/                            # Model comparison and hyperparameter tuning experiments
│   ├── USNW-NB15.ipynb                         # Baseline experiments on the UNSW-NB15 benchmark dataset
│   ├── cowrie_dataset.ipynb                    # Dataset exploration and modelling on Cowrie telemetry
│   ├── cowrie_tuned.ipynb                      # Tuned DEC / Autoencoder experiments on Cowrie data
│   ├── dl_models.ipynb                         # Comparison of deep learning model architectures
│   ├── dl_tuned.ipynb                          # Hyperparameter-tuned deep learning experiments
│   ├── DEC_tuning_results.csv                  # DEC hyperparameter search results
│   ├── VAE_GMM_tuning_results.csv              # VAE + GMM tuning results
│   ├── autoencoder_kmeans_tuning_results.csv   # Autoencoder + K-Means tuning results
│   ├── DL_Models_Final_Comparison.csv          # Final cross-model performance comparison
│   ├── cowrie_autoencoder.keras                # Trained autoencoder model (Cowrie data)
│   ├── cowrie_dec_model.keras                  # Trained DEC model (Cowrie data)
│   └── cowrie_encoder.keras                    # Trained encoder for latent space extraction
│
├── models/                                     # Production model artifacts used by the live pipeline
│   └── scaler.joblib                           # Fitted MinMaxScaler for feature normalisation
│
├── reports/                                    # Auto-generated analysis output reports
│   ├── behaviour_analysis/                     # Clustering and behavioural pattern reports
│   ├── behaviour_signatures/                   # Generated behavioural signature files
│   ├── diagnostics/                            # Pipeline diagnostic and sanity-check reports
│   └── novelty_assessment/                     # Per-session novelty scoring reports
│
├── scripts/                                    # Core pipeline scripts
│   ├── pipeline.py                             # End-to-end orchestrator: attack → collect → parse → cluster
│   ├── attack_generator.py                     # Generates structured SSH attack sessions against Cowrie
│   ├── collect_logs.py                         # Copies Cowrie JSON logs out of the Docker container
│   ├── parse_logs.py                           # Parses raw Cowrie JSON into structured session records
│   ├── extract_features.py                     # Derives numerical behavioural features from sessions
│   ├── preprocess_dataset.py                   # Builds auxiliary MinMax-scaled model_input.csv
│   ├── generate_dataset.py                     # Generates synthetic labelled attack datasets for training
│   ├── behaviour_pattern_analysis.py           # Unsupervised clustering and pattern detection
│   ├── behaviour_signature_generation.py       # Converts clusters into behavioural signature files
│   ├── novelty_assessment.py                   # Scores sessions for novelty against the signature catalogue
│   └── prepare_fresh_evaluation.py             # Isolates new sessions from baseline for clean evaluation
│
├── tests/                                      # Automated test suite (11 test files)
│   ├── test_pipeline_safety.py                 # Pipeline overwrite-protection and flag safety tests
│   ├── test_log_processing.py                  # Log collection and parsing unit tests
│   ├── test_behaviour_pattern_analysis.py      # Clustering logic unit tests
│   ├── test_behaviour_signature_generation.py  # Signature generation unit tests
│   ├── test_novelty_assessment.py              # Novelty scoring unit and integration tests
│   ├── test_collect_logs.py                    # Log collection tests
│   ├── test_dec_preprocessing.py               # DEC input preprocessing tests
│   ├── test_dec_reproducibility.py             # DEC determinism and reproducibility tests
│   ├── test_dec_runner.py                      # DEC inference runner tests
│   ├── test_prepare_fresh_evaluation.py        # Fresh evaluation isolation tests
│   └── dec_batch_probe.py                      # Batch probe utility for DEC cluster sanity checks
│
├── docs/                                       # Project documentation and research artefacts
│   ├── final_technical_report.md               # Full technical report covering all project phases
│   ├── report_evidence_map.md                  # Maps report claims to output files and evidence
│   ├── final_demo_checklist.md                 # End-to-end demo verification checklist
│   ├── setup_guide.md                          # Legacy setup guide (superseded by INSTALLATION.md)
│   ├── report.pdf                              # Project report (PDF)
│   └── presentation.pdf                        # Project presentation slides (PDF)
│
├── logs/                                       # Pipeline execution logs
│
├── INSTALLATION.md                             # Step-by-step installation and setup guide
├── README.md                                   # Project overview and documentation
├── requirements.txt                            # Python package dependencies
└── .gitignore                                  # Git ignore rules
```

---

## ⚙️ Implementation — Phase 1

Phase 1 establishes the **foundational data collection infrastructure** — honeypot deployment, attack simulation, structured logging, and session reconstruction.

### Completed Steps

| # | Step | Status |
|:---:|---|:---:|
| 1 | Deploy Cowrie SSH/Telnet honeypot in isolated environment | ✅ |
| 2 | Configure honeypot to simulate SSH service on port `2222` | ✅ |
| 3 | Verify service visibility via Nmap port scan and fingerprinting | ✅ |
| 4 | Execute manual SSH login attempts (reconnaissance simulation) | ✅ |
| 5 | Run automated brute-force attacks using Hydra | ✅ |
| 6 | Capture attacker interactions: IPs, credentials, commands | ✅ |
| 7 | Store logs in structured JSON format for downstream processing | ✅ |
| 8 | Implement session reconstruction from raw event logs | ✅ |

### Sample Captured Data

**Reconstructed Attack Session (JSON):**
```json
[
  {
    "ip": "172.20.10.5",
    "failed_attempts": 4,
    "successful_attempts": 4,
    "total_attempts": 8,
    "duration": "few seconds",
    "attack_type": "brute_force"
  },
  {
    "ip": "172.20.10.3",
    "failed_attempts": 0,
    "successful_attempts": 1,
    "total_attempts": 1,
    "duration": "instant",
    "attack_type": "credential_reuse"
  }
]
```

**Live Login Attempt Log:**
```
2026-02-09T23:28:19Z [HoneyPotSSHTransport,10,172.20.10.4]
    login attempt [b'root'/b'admin'] succeeded
```

**Command Sequence Log (attacker pivoting):**
```
2026-02-09T23:34:46Z [HoneyPotSSHTransport,13,172.20.10.3]
    CMD: hydra -l root -P passwords.txt ssh://172.20.10.2:2222 -t 4
```

> **Observed Attacker IPs:** `172.20.10.3`, `172.20.10.4`, `172.20.10.5`

### Installation & Setup

> 📄 See the full **[INSTALLATION.md](INSTALLATION.md)** for a complete step-by-step setup guide — including Docker/Cowrie configuration, pipeline options, DEC interpreter setup, and result interpretation.

---

## 🔑 Key Scripts

| Script | Purpose |
|---|---|
| [`pipeline.py`](scripts/pipeline.py) | Orchestrates the full data flow from log ingestion to feature extraction |
| [`generate_dataset.py`](scripts/generate_dataset.py) | Generates realistic synthetic attack datasets for model training |
| [`extract_features.py`](scripts/extract_features.py) | Derives behavioral features: timing, frequency, command entropy, session depth |
| [`behaviour_pattern_analysis.py`](scripts/behaviour_pattern_analysis.py) | Applies DBSCAN/K-Means clustering to group attack sessions by pattern |
| [`behaviour_signature_generation.py`](scripts/behaviour_signature_generation.py) | Converts behavioral clusters into Snort/Suricata-compatible detection rules |
| [`novelty_assessment.py`](scripts/novelty_assessment.py) | Scores each session for behavioral novelty — flags potential zero-day activity |
| [`attack_generator.py`](scripts/attack_generator.py) | Simulates structured attack scenarios for controlled testing and evaluation |

---

## 🗺️ Project Roadmap

### ✅ Phase 1 — Honeypot Deployment & Structured Data Capture
- [x] Deploy and configure Cowrie honeypot (SSH/Telnet simulation)
- [x] Enable structured logging of attack sessions, commands, and payloads
- [x] Validate collection via controlled brute-force and reconnaissance simulations
- [x] Implement session reconstruction from raw event logs

### 🔜 Phase 2 — ML-Based Clustering & Rule Generation
- [ ] Extract behavioral feature vectors (timing, frequency, command entropy)
- [ ] Apply unsupervised clustering (DBSCAN, K-Means) to identify attack families
- [ ] Train anomaly detection models (Isolation Forest, Autoencoder) for zero-day flagging
- [ ] Generate behavioral signatures and Snort/Suricata-compatible IDS rules with confidence scores

### 🔜 Phase 3 — Dashboard Development & Integration Testing
- [ ] Build real-time web dashboard for attack visualization and threat intelligence
- [ ] Implement Social IoT-based rule sharing across collaborative defense nodes
- [ ] Perform attack replay experiments and evaluate with TPR, FPR, precision, recall
- [ ] Integration and stress testing across the full pipeline

---

## 🌟 Novelty & Differentiation

| Feature | **This Platform** | Traditional IDS (Snort/Suricata) | Commercial SIEM | Traditional Honeypot |
|---|:---:|:---:|:---:|:---:|
| Zero-day detection (no prior signature) | ✅ | ❌ | ❌ | ❌ |
| Live behavioral learning | ✅ | ❌ | ❌ | ❌ |
| Automated rule generation | ✅ | ❌ | ❌ | ❌ |
| Honeypot-integrated intelligence | ✅ | ❌ | ❌ | ✅ |
| Closed-loop defense pipeline | ✅ | ❌ | ❌ | ❌ |
| Collaborative IoT-based sharing | ✅ | ❌ | ❌ | ❌ |
| No manual analyst intervention required | ✅ | ❌ | ❌ | ❌ |

### Key Novel Contributions

- 🔄 **Behavior-to-Defense Pipeline** — converts live attacker interactions into deployable rules with zero manual intervention
- 📊 **Zero-Day Dataset Construction** — continuously evolving behavioral dataset built from real honeypot captures, not synthetic benchmarks
- 🧩 **Integrated ML Framework** — multi-stage attack sequence modeling: reconnaissance → exploitation → lateral movement → persistence
- ⚙️ **Automated Rule Generation Engine** — dynamic export to Snort/Suricata-compatible rules with confidence thresholding
- 🏛️ **Unified Platform** — honeypot capture, ML analytics, rule synthesis, dashboard, and API export in a single cohesive system

---

## ⚖️ Advantages & Limitations

### Advantages

| | |
|---|---|
| 🎯 | Detects novel attacks with **no prior signature requirement** |
| ⚡ | Dramatically reduces time-to-detection for zero-day exploits |
| 🤖 | Fully automated analysis-to-rule pipeline with no human bottleneck |
| 🌐 | Collaborative defense model scales across distributed networks |
| 📈 | Continuously improves as more real-world attack data is captured |

### Current Limitations

| | |
|---|---|
| ⚠️ | High-interaction attacker behavior may reveal the honeypot nature to sophisticated actors |
| ⚠️ | ML model accuracy depends on volume and diversity of training data |
| ⚠️ | Generated rules require validation before deployment in production IDS |
| ⚠️ | Social IoT sharing module requires trust establishment between participating nodes |

---

## 🧰 Prerequisites

### System Requirements

| Component | Requirement |
|---|---|
| **OS (Honeypot)** | Linux (Ubuntu 20.04+ recommended) — VM or Docker container |
| **OS (Scripts)** | Linux, macOS, or Windows (cross-platform) |
| **RAM** | 2 GB minimum, 4 GB recommended |
| **Disk** | 5 GB free for logs and model artifacts |
| **Python** | 3.10 or higher |

### Required Software

| Tool | Version | Purpose | Install |
|---|---|---|---|
| Python | 3.10+ | Core runtime | [python.org](https://python.org) |
| pip | Latest | Package manager | Bundled with Python |
| Git | Any | Version control | [git-scm.com](https://git-scm.com) |
| Cowrie | Latest | SSH/Telnet honeypot | [cowrie.readthedocs.io](https://cowrie.readthedocs.io) |

### Optional Tools (Attack Simulation & Storage)

| Tool | Version | Purpose | Install |
|---|---|---|---|
| Hydra | Any | Brute-force attack simulation | `sudo apt install hydra` |
| Nmap | 7.0+ | Port scanning and fingerprinting | `sudo apt install nmap` |
| MongoDB | 6.0+ | Production log storage | [mongodb.com](https://www.mongodb.com/try/download/community) |

> ⚠️ **Important:** Cowrie **must** run on a Linux host. All Python analysis scripts are cross-platform and can be run on any OS.

---

## 🚀 Installation & Setup

### Step 1 — Clone the Repository

```bash
git clone https://github.com/MadhumithraaTS/adaptive-zero-day-honeypot.git
cd adaptive-zero-day-honeypot
```

### Step 2 — Set Up the Python Environment

```bash
# Create a virtual environment
python -m venv .venv

# Activate it
source .venv/bin/activate       # Linux / macOS
.venv\Scripts\activate          # Windows (PowerShell)
```

### Step 3 — Install Dependencies

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
| `tensorflow-cpu` | ≥ 2.13.0 | Deep learning (Autoencoder) |

</details>

### Step 4 — Configure Cowrie Honeypot

Cowrie must be set up separately on a Linux machine. Follow the [official Cowrie documentation](https://cowrie.readthedocs.io/en/latest/INSTALL.html) to:

1. Install Cowrie and its dependencies
2. Configure it to listen on port `2222` (or redirect port `22` via `iptables`)
3. Point its log output to `data/raw/cowrie.json` in this repository

```bash
# Example: symlink Cowrie's JSON log into this repo
ln -s /home/cowrie/cowrie/var/log/cowrie/cowrie.json \
      /path/to/adaptive-zero-day-honeypot/data/raw/cowrie.json
```

### Step 5 — Run the Pipeline

```bash
# Parse raw honeypot logs into structured format
python scripts/parse_logs.py

# Extract behavioral features from parsed sessions
python scripts/extract_features.py

# Run the full end-to-end pipeline
python scripts/pipeline.py
```

### Step 6 — (Optional) Simulate Attacks for Testing

If you don't have live honeypot data yet, generate a synthetic dataset:

```bash
# Generate a realistic synthetic attack dataset
python scripts/generate_dataset.py

# Or run a controlled brute-force simulation (requires Hydra)
bash -c "hydra -l root -P /usr/share/wordlists/rockyou.txt \
         ssh://127.0.0.1:2222 -t 4"
```

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. **Fork** this repository
2. **Create** a feature branch
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Commit** your changes with a descriptive message
   ```bash
   git commit -m "feat: add your feature description"
   ```
4. **Push** to your fork and open a **Pull Request**

Please ensure your code:
- Follows the existing script structure and naming conventions
- Includes comments for non-obvious logic
- Does not commit raw log files or credentials

---

## 📚 References

1. Spitzner, L. (2003). *Honeypots: Tracking Hackers*. Addison-Wesley.
2. Provos, N. (2004). *A Virtual Honeypot Framework*. USENIX Security Symposium.
3. Cowrie Project — Medium-interaction SSH/Telnet honeypot. https://github.com/cowrie/cowrie
4. Liao, H. J., et al. (2013). *Intrusion Detection System: A Comprehensive Review*. Journal of Network and Computer Applications.
5. Ahmed, M., et al. (2016). *A Survey of Anomaly Detection Techniques in Financial Domain*. Future Generation Computer Systems.
6. Roesch, M. (1999). *Snort — Lightweight Intrusion Detection for Networks*. USENIX LISA.
7. Sicari, S., et al. (2015). *Security, Privacy and Trust in Internet of Things: The Road Ahead*. Computer Networks.
