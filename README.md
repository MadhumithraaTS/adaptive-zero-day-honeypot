# AI-Driven Adaptive Honeypot Platform for Zero-Day Attack Intelligence and Automated Defense

> **23CSE399 – Project Phase 1 | Team 10 | Amrita Vishwa Vidyapeetham**

---

## Team

| S.No | Register Number   | Name              |
|------|-------------------|-------------------|
| 1    | CB.SC.U4CSE23404  | Amritha S Nidhi   |
| 2    | CB.SC.U4CSE23405  | Anaswara K        |
| 3    | CB.SC.U4CSE23429  | Madhumithraa T S  |
| 4    | CB.SC.U4CSE23435  | Mayuka Sri K      |
| 5    | CB.SC.U4CSE23457  | Vrithika K M      |

**Guide:** Dr. Harini N, Associate Professor, Department of CSE

---

## Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Motivation](#motivation)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Implementation – Phase 1](#implementation--phase-1)
- [Project Phases](#project-phases)
- [Novelty and Differentiation](#novelty-and-differentiation)
- [Advantages and Limitations](#advantages-and-limitations)
- [References](#references)

---

## Overview

Modern enterprise networks face a critical blind spot: **zero-day attacks** exploit unknown vulnerabilities for which no patch or detection signature exists at the time of exploitation. Traditional signature-based IDS/IPS systems are completely ineffective during this initial exposure window.

This project proposes an **AI-Driven Adaptive Honeypot Platform** that:

- Deploys decoy environments to attract and capture real attacker interactions
- Extracts behavioral intelligence (login attempts, command sequences, session metadata)
- Applies unsupervised machine learning to cluster attack patterns
- **Automatically generates deployable IDS/firewall rules** from observed behavior
- Shares intelligence across nodes using a Social IoT-based collaborative defense model

---

## Problem Statement

> *How can we design an adaptive honeypot-driven intelligence platform that captures previously unseen attacker interactions during active exploitation, models behavioral patterns instead of relying on predefined signatures, and automatically generates deployable detection rules in real time?*

Current enterprise security systems cannot reliably detect zero-day exploits during their initial execution window because they rely primarily on **predefined signatures and static rule sets**. Meanwhile, attackers leverage automation to scan, exploit, and establish persistence within minutes — creating a critical temporal imbalance between compromise and detection.

---

## Motivation

- Signature-based IDS/IPS systems have no knowledge of a zero-day exploit at the time of first occurrence, resulting in delayed or missed detection.
- Manual signature creation and rule deployment introduce significant response latency, giving attackers a wide operational window before containment.
- Honeypots provide rich, real-world behavioral data including login attempts, command sequences, and attacker patterns — intelligence that can be converted into automated defenses.
- The objective is to **minimize the time gap** between attack discovery, analysis, and defensive mitigation through adaptive automation.

---

## Architecture

The platform follows a **Behavior-to-Defense pipeline**:

```
Internet/External Attackers
         │
         ▼
┌─────────────────────────┐
│     Honeypot Layer       │  (VM / Container — Cowrie SSH/Telnet)
│  • Simulated Services    │  SSH, FTP, HTTP
│  • Full Interaction Log  │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Central Data Collection │
│  & Storage (MongoDB)     │
│  • Attack Logs           │
│  • Payload Data          │
│  • Command Sequences     │
│  • Session Metadata      │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  ML-Based Attack Analysis│
│  • Feature Extraction    │
│  • Unsupervised Cluster. │
│  • Anomaly Detection     │
│  • Behavior Modeling     │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Signature & Rule Gen.   │
│  • Content-Based Sigs    │
│  • Behavior-Based Rules  │
│  • Confidence Scoring    │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐      ┌──────────────────────────┐
│  Security Enforcement    │      │   Analyst Dashboard / UI  │
│  • IDS (Detection)       │◄─────│  • Live Attack Visual.    │
│  • IPS (Blocking)        │      │  • Threat Intelligence    │
│  • Firewall Rules        │      │  • Rule Monitoring        │
└─────────────────────────┘      │  • Alerts & Reports       │
                                  └──────────────────────────┘
```

### Database Schema

| Collection        | Description                            |
|-------------------|----------------------------------------|
| `Attack_Session`  | Per-session attacker activity records  |
| `Payload_Data`    | Raw and parsed payload captures        |
| `Attack_Cluster`  | ML clustering outputs and labels       |
| `Generated_Rules` | Synthesized IDS/firewall rules         |

### Key APIs

| Endpoint         | Method | Purpose                          |
|------------------|--------|----------------------------------|
| `/api/ingest`    | POST   | Receive honeypot logs            |
| `/api/analyze`   | POST   | Trigger ML analysis pipeline     |
| `/api/rules`     | POST   | Export generated detection rules |

## Implementation – Phase 1

Phase 1 focuses on **honeypot deployment, attack simulation, data collection, and session reconstruction**.

### Steps Completed

1. **Deployed Cowrie SSH/Telnet honeypot** in a controlled, isolated environment
2. **Configured** honeypot to simulate a real SSH service on port `2222`
3. **Verified visibility** using Nmap port scanning — confirmed open port and service fingerprint
4. **Manual SSH login attempts** performed to simulate attacker reconnaissance behavior
5. **Automated brute-force attacks** executed using Hydra against the honeypot
6. **Captured attacker interactions** including login attempts, command sequences, and IP addresses
7. **Stored logs** in structured formats: login logs, command logs, IP tracking files
8. **Session reconstruction** implemented — raw events grouped by source IP, timestamps, and session ID into structured attack sessions

### Sample Captured Data

**Attack Session (JSON)**
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

**Captured Attacker IPs:** `172.20.10.3`, `172.20.10.4`, `172.20.10.5`

**Sample Login Log Entry:**
```
2026-02-09T23:28:19Z [HoneyPotSSHTransport,10,172.20.10.4] login attempt [b'root'/b'admin'] succeeded
```

**Sample Command Log Entry:**
```
2026-02-09T23:34:46Z [HoneyPotSSHTransport,13,172.20.10.3] CMD: hydra -l root -P passwords.txt ssh://172.20.10.2:2222 -t 4
```

---

## Project Phases

### Phase 1 — Honeypot Deployment and Structured Data Capture ✅
- Deploy and configure honeypot environment (SSH/Telnet simulation)
- Enable structured logging of attack sessions, commands, and payload data
- Validate data collection through controlled attack simulations
- Session reconstruction from raw logs

### Phase 2 — ML-Based Clustering and Rule Generation 🔜
- Extract behavioral features from attack sessions (timing, frequency, command patterns)
- Apply unsupervised clustering and anomaly detection to identify zero-day patterns
- Generate behavioral signatures and IDS rules with confidence scoring

### Phase 3 — Dashboard Development and Integration Testing 🔜
- Develop real-time dashboard for attack visualization and threat intelligence
- Implement Social IoT-based rule sharing across nodes for collaborative defense
- Perform attack replay and evaluate system using detection and performance metrics (TPR, FPR, precision, recall)

---

## Novelty and Differentiation

| Feature | This Platform | Traditional IDS (Snort/Suricata) | Commercial SIEM | Traditional Honeypots |
|---|:---:|:---:|:---:|:---:|
| Zero-day detection | ✅ | ❌ | ❌ | ❌ |
| Live behavioral learning | ✅ | ❌ | ❌ | ❌ |
| Automated rule generation | ✅ | ❌ | ❌ | ❌ |
| Honeypot-integrated intelligence | ✅ | ❌ | ❌ | ✅ |
| Closed-loop defense pipeline | ✅ | ❌ | ❌ | ❌ |
| Collaborative IoT-based sharing | ✅ | ❌ | ❌ | ❌ |

**Key novel contributions:**

- **Behavior-to-Defense Pipeline** — converts live attacker interactions into deployable rules without manual intervention
- **Zero-Day Dataset Construction** — automated, continuously evolving behavioral dataset built from real honeypot captures
- **Integrated ML Framework** — unsupervised clustering of multi-stage attack sequences (reconnaissance → exploitation → persistence)
- **Automated Rule Generation Engine** — dynamic export to Snort/Suricata-compatible detection rules
- **Unified Architecture** — honeypot, ML analytics, rule synthesis, dashboard, and API export in one platform

---

## Advantages and Limitations

### Advantages
- Real-time capture of live attacker interactions during zero-day exposure windows
- Behavioral modeling instead of static signature dependency
- Automated rule generation reduces manual intervention and response latency
- Modular and scalable — deployable in academic, research, or enterprise environments
- Observable and traceable via real-time dashboard

### Limitations
- Detection quality depends on the richness and diversity of attacker interactions captured
- Sophisticated attackers who detect the honeypot environment may alter their behavior
- ML clustering requires careful parameter tuning to avoid false positives or under-clustering
- Automated rules need validation before production deployment to avoid disrupting legitimate traffic
- Real-time processing may require scalable infrastructure in high-traffic environments

---

## References

1. R. R. Patel and C. S. Thaker, "Zero-day attack signatures detection using honeypot," *IJCSIS*, Sept. 2017.
2. H. Hindy et al., "Utilising deep learning techniques for effective zero-day attack detection," *Electronics*, vol. 9, no. 10, 2020. https://doi.org/10.3390/electronics9101684
3. Y. Guo, "A review of machine learning-based zero-day attack detection," *Computer Communications*, vol. 198, 2023. https://doi.org/10.1016/j.comcom.2022.11.001
4. M. Balamurugan, "AI-enhanced honeypots for zero-day exploit detection and mitigation," *IJFMR*, vol. 6, no. 6, 2024. https://doi.org/10.36948/ijfmr.2024.v06i06.32866
5. A. Blaise, M. Bouet, and V. Conan, "Detection of zero-day attacks: An unsupervised port-based approach," *Computer Networks*, vol. 180, 2020. https://doi.org/10.1016/j.comnet.2020.107391
6. Y. Yu, J. Li, and J. Li, "An adaptable deep learning-based intrusion detection system to zero-day attacks," *Computer Networks*, vol. 196, 2021. https://doi.org/10.1016/j.neucom.2024.128073
7. R. Sommer and V. Paxson, "Outside the closed world: On using machine learning for network intrusion detection," *IEEE S&P*, 2010.
8. L. Bilge and T. Dumitras, "Before we knew it: an empirical study of zero-day attacks in the real world," *ACM CCS*, 2012.
9. Cowrie Project, "Cowrie honeypot documentation," https://cowrie.readthedocs.io
10. L. Spitzner, *Honeypots: Tracking Hackers*. Addison-Wesley, 2002.

---

*Department of Computer Science and Engineering — Amrita Vishwa Vidyapeetham | March 2026*
