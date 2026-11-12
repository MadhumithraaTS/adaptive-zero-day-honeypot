# Threat assessment and policy-eligibility engine: implementation and validation (Task 24)

**Date:** 2026-11-11.

**What was built:**
- the new module `threat_assessment/`;
- the tests `tests/test_threat_assessment.py`;
- new configurations `configs/threat_attribution_v1.json` and `configs/defence_policy_v2.json`.

**Unchanged:**
- `behavioural_evidence/` and its catalogue;
- the extractor, models and novelty thresholds;
- Cowrie networking (inspected read-only);
- policy v1 (SHA-256 before and after: `evidence/hashes_*.txt`).

**Not done:**
- no defensive action executed and no enforcement activated;
- nothing connected to a firewall or host;
- the sealed test and exfiltration data were not accessed;
- nothing was committed.

**Reproduce:**

```
.venv/Scripts/python.exe -m pytest -q tests/test_threat_assessment.py
.venv/Scripts/python.exe reports/threat_assessment_implementation_20261111/validate_assessment.py
```

## 1. Summary

1. **Implemented as approved.** The module provides:
   - S0–S3 severity independent of evidence, with the credential refinement;
   - interpretation-specific evidence levels;
   - per-finding attribution from the Cowrie-observed `src_ip` only;
   - four tiers with the 8 proposal conditions applied conjunctively;
   - mandatory manual approval;
   - a hash-chained audit log with inverse operations.

   Nothing is executed.
2. **Deployment network confirmed before setting CIDRs** (read-only `docker network inspect`):

| Network | Subnet | Members |
|---|---|---|
| `cowrie_cowrie_internal` | 172.22.0.0/16 | Cowrie 172.22.0.1, relay 172.22.0.2 |
| `cowrie_relay_frontend` | 172.21.0.0/16 | relay 172.21.0.2 |
| `cowrie_default` | 172.19.0.0/16 | legacy, still present |

Policy v1's protected list contained only 172.19.0.0/16. Policy v2 protects all three networks, and the internal CIDRs are set explicitly to 172.21/16 and 172.22/16.

3. **Dataset V2 result: 0 proposals in both splits.** Every session is `unattributed:trusted_proxy`; the requirements were not relaxed.

| Split | abstain | record | review | propose |
|---|---:|---:|---:|---:|
| Train | 1,817 | 754 | 619 | 0 |
| Validation | 706 | 313 | 238 | 0 |

- **Benign:** 0 benign sessions are above `record`.
- **Why review sessions fail:** all 238 validation review sessions fail gate 5 (attribution); 114 also fail gates 2–3 (E2 and indicator diversity). **124 sessions meet every condition except attribution.** That is exactly what the relay topology is meant to block.
4. **All checks pass:**
   - 61 new unit tests; full suite 447 passed (previously 386);
   - 13/13 attribution scenarios;
   - 22/22 audit checks, including 16 tamper simulations on the real V2 logs;
   - deterministic second assessment pass;
   - second full run byte-identical (16 files; `evidence/second_run_check.txt`).

## 2. Severity (`severity_validation.csv`; validation findings)

| Interpretation | Severity / evidence level (findings) |
|---|---|
| credential-material access | S2/E1 29 (lateral: `cat ~/.ssh/known_hosts`, `cat ~/.ssh/config`, `ls -la ~/.ssh`); S2/E2 27 (PE: `ls -la` listings of `/etc/shadow`, `~/.ssh`, `/root/.ssh`; a listing is not a content operation); **S3/E1 42** (lateral `cat ~/.bash_history`); **S3/E2 26** (PE: `cat /etc/shadow` 20, `find -name id_rsa` 6) |
| download attempt | S2/E1 21 (recon IP-echo fetches); S2/E2 71 (botnet) |
| download-and-execute attempt | S3/E2 71 (botnet) |
| privilege-context reconnaissance | S2/E1 16; S2/E2 53 |
| network probing | S2/E1 49 |
| history tampering | S2/E1 21 |

- **`success_observed` is false for every V2 finding.** There are no download or upload events.
- **Unit tests confirm the refinement:**
  - `known_hosts`, `config`, `.pub` and `ls /etc/shadow` → S2;
  - `cat /etc/shadow`, `cat id_rsa`, `find -name id_rsa`, `sudo cat /etc/shadow`, `cp authorized_keys` → S3;
  - an attempted upload is S3 with outcome `not_observed`; the same upload with a `file_upload` event is S3 with `observed_success`, so severity is unchanged.
- **For your confirmation:** treating `.bash_history` as a secret, which follows the approved list, makes 42 lateral findings S3.

## 3. Attribution and configuration (`source_attribution_tests.csv`)

| Scenario | State | Tier |
|---|---|---|
| External client (documentation address, synthetic) | attributable | **propose** (dry-run, inverse recorded, approval pending) |
| Lab relay 172.22.0.2 | unattributed:trusted_proxy | review |
| 172.22.0.1, 172.21.0.2, 172.19.0.1, 127.0.0.1 | protected | review |
| NAT/shared (config variant) | shared_source | review |
| `x_forwarded_for` on a relay session | trusted_proxy; header listed as ignored | review |
| Missing source | unattributed:no_source | review |
| Incorrect evidence config digest | gate 7 fails | review |
| Missing evidence config digest | processing error | abstain |
| All V2 train/validation sessions and findings | unattributed:trusted_proxy | 0 proposals |

**Configuration safety (unit tests).** The following are rejected:
- empty or implicit internal CIDRs;
- non-null proxy mappings;
- non-`src_ip` source fields;
- policy v1;
- an unpinned or mismatched attribution digest;
- relaxed conditions or thresholds;
- enabled enforcement, or disabled manual approval;
- an action without an inverse.

Using the package's default internal networks fails gate 7.

## 4. Independence and integrity

- **Novelty:** adding the Task 18 scores (flag true or false) changes nothing but the annotation. On validation, the 4 novelty-flagged sessions are placed in record (2) and review (2) by behaviour alone.
- **Caveats:** ART-1, TIME-0, EMU-1 and SEQ-1 never change severity or tier. The 9 ART-1 sessions are in review through their PRIV-1/CRED-1 findings.
- **Evidence records:** never modified (deep-copied; tested).
- **Audit:** each entry has:
  - record ID, sequence, previous and current hash, timestamp;
  - session and finding references, attribution, evidence and severity;
  - versions and digests, tier and gates, proposed action;
  - manual-approval, inverse-operation, execution, verification and rollback status.

  The V2 logs verify against their checkpoints (train 3,190 entries, last hash `c7f61ac1…`; validation 1,257, last hash `41f82c42…`).
- **Tamper detection:** modification, source edits, deletion, reordering, insertion, truncation, hash recomputation after an edit, and a forged "executed" status are all detected (`audit_integrity_results.csv`).
- **Checkpoint and log preservation:** requirements are in `limitations.md`.

## 5. Files

| File | Content |
|---|---|
| `implementation_inventory.md` | Module, configs, gates |
| `severity_validation.csv` | Findings by interpretation × severity × level × success × category, plus credential bases |
| `policy_tier_results.csv` | Tiers by split, unit and category |
| `source_attribution_tests.csv` | Scenarios and the V2 lab result |
| `audit_integrity_results.csv` | Chain verification and tamper tests |
| `limitations.md` | Limitations, checkpoint and log-preservation requirements |
| `test_results.txt` | Verbose unit-test run and full-suite result |
| `evidence/` | Network inspection; protected-file hashes; evidence, assessments and audit logs per split; checkpoints; gate summary; validation summary; second-run check |

## 6. Awaiting explicit approval

**No enforcement work has been started.** Before any:
1. confirm the severity table, especially `.bash_history` as S3;
2. decide whether and how a relay→client mapping could ever make lab sessions attributable;
3. specify the approval workflow and the external checkpoint/signing arrangement;
4. specify the enforcement target, which must stay outside the scope of this module.
