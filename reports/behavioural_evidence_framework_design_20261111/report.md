# Dataset V2-compatible behavioural evidence framework: design and evidence review (Task 21)

**Date:** 2026-11-11.

**Design and evidence analysis only.**
- No existing signature, matcher, threat-scoring logic, extractor or model was changed.
- No defence rule was deployed.
- The sealed test and exfiltration data were not accessed (an audit hook blocks those paths; the only "test"-named file opened was the dataset's preflight pytest log during hash verification).
- Nothing was committed.
- No zero-day detection is claimed.

| File | Content |
|---|---|
| `existing_architecture_inventory.md` | Current components and the reuse / redesign / retire decision for each |
| `indicator_catalogue.csv` | 25 proposed indicators plus timing as context: telemetry, exact semantics, what each establishes and cannot establish, false-positive conditions, evidence class, measured V2 rates |
| `evidence_semantics.md` | Evidence classes, attempt vs outcome, evidence levels instead of probabilities, abstention, separation from novelty |
| `matching_design.md` | Token parsing, indicator groups, multi-label interpretation rules, identity/versioning, output record |
| `false_positive_requirements.md` | 10 requirements checked against V2 evidence |
| `limitations.md` | Limitations |
| `evaluate_indicator_design.py`, `make_indicator_catalogue.py`, `evidence/` | Read-only prototype evaluation on train/validation and its outputs |

## 1. Existing architecture (summary)

- **Retire:** the stored V1 catalogue. Its features don't exist in V2.
- **Redesign:**
  - substring keyword categories;
  - the first-match interpretation ladder;
  - per-DEC-cluster signatures;
  - the 0.70/0.20/0.10 weighted similarity and its Known-like / Ambiguous / Potentially Novel outcome classes.
- **Reuse:**
  - Cowrie JSON telemetry and the V2 session reconstruction;
  - the explicit "Insufficient Evidence" outcome;
  - reference/evaluation separation;
  - the draft policy principle "≥ 2 distinct behavioural indicators, never a cluster" (`configs/defence_policy.json`, read by no code).
- **No threat-scoring dependency** and no response action exist.

## 2. Key telemetry fact

Cowrie's JSON log records what the client **typed** (`command.input`) and a few **outcome events**:
- `login.success` / `login.failed`;
- `command.failed` (unknown to the emulator);
- `session.file_download` / `file_upload`.

It records **no command output**, and TTY content is not collected. The design therefore separates *attempts* (directly observed) from *outcomes*, which default to `not_observed` unless an outcome event exists. On V2:
- 347 download attempts with 0 download events;
- 0 upload attempts.

## 3. Proposed framework (see `matching_design.md`)

1. **Token matching.** Lines are split into simple commands at shell operators and tokenised with `shlex`. Indicators match command names, flags and path components, never substrings.
2. **25 indicators in three groups:**
   - action indicators (authentication bursts, privilege probes, credential-material access, download/upload, download-then-execute, archive, history tampering, persistence modification, network probing);
   - context indicators (discovery, depth, chaining, read-only service/cron inspection);
   - caveat flags (EMU-1 emulator-unknown command, ART-1 calibrated emulator latency, SEQ-1 sequence repetition, TIME-0 timing).
3. **Multi-label interpretations.**
   - Each interpretation requires an action indicator.
   - Several interpretations may coexist in one session.
   - Wording is fixed to *attempt*.
   - Context-only sessions are "system discovery only" or "insufficient evidence".
4. **No single failed login is an interpretation.** Repeated failures need ≥ 3 from one source within 300 s. Shared source keys abstain ("indeterminate").
5. **No probabilities.** Records list indicators, evidence lines and evidence class. An ordinal evidence level is defined by counts: E0–E3, where E3 needs an observed outcome event; no V2 session reaches E3.
6. **Statistical novelty is a separate, independent field.** ART-1 and EMU-1 caveats are displayed beside any novelty flag, and neither channel alters the other.
7. **Stable, versioned identities.** Indicator and rule names are stable and versioned; there are no DEC cluster IDs. A schema check fails loudly instead of returning silent "Insufficient Evidence".

## 4. Evidence review on Dataset V2 (validation; train in `evidence/`)

**Interpretations under the proposed rules** (logged-in sessions; authentication rows count all sessions):

| Interpretation | Sessions | benign | botnet | brute force | lateral | PE | recon |
|---|---:|---:|---:|---:|---:|---:|---:|
| repeated authentication failures* | 398 (79 interactions) | 0 | 0 | 398 | 0 | 0 | 0 |
| credential guessing followed by login* | 79 | 0 | 0 | 79 | 0 | 0 | 0 |
| privilege-context reconnaissance | 69 | 0 | 0 | 0 | 0 | 69 | 0 |
| credential-material access attempt | 124 | 0 | 0 | 0 | 71 | 53 | 0 |
| download attempt (outcome not observed) | 92 | 0 | 71 | 0 | 0 | 0 | 21 |
| download-and-execute attempt | 71 | 0 | 71 | 0 | 0 | 0 | 0 |
| upload / archive-and-upload / persistence modification | 0 | — | — | — | — | — | — |
| history tampering | 21 | 0 | 21 | 0 | 0 | 0 | 0 |
| network probing attempt | 111 | **45** | 0 | 0 | 66 | 0 | 0 |
| system discovery only (context) | 268 | 184 | 0 | 30 | 1 | 0 | 53 |
| insufficient evidence | 49 | 0 | 0 | 49 | 0 | 0 | 0 |

\* With an oracle source key (interaction ID). In the lab topology all sessions share one source IP, so the deployable rule would return "indeterminate".

**Against the known problems** (`false_positive_requirements.md`):

| Known problem | Result |
|---|---|
| Benign failed-login false positives | 126 → **0** |
| Substring false matches | Removed by construction; 240 validation lines previously "credential_attack" no longer match |
| Benign attack-implying labels | 34.5% → **19.7%**, all from `curl -I` reachability checks (open item FP-4) |
| Cowrie `find` latency | Never used as evidence; the 9 sessions are flagged by the ART-1 caveat |
| Download/upload success claims | None possible; all 347 attempts are outcome `not_observed` |
| Generator-template dependence | Rules are generic, but V2 cannot demonstrate generalisation. Every action indicator fires in ≤ 2 categories because the lab profiles are disjoint by design |

## 5. Open decisions (need approval before implementation)

1. **NET-1 scope (FP-4):** restrict NET-1 to internal or scan targets and scanning tools, and treat `curl -I` as context. Recommended, as a semantic correction rather than a label-fitted one.
2. **AUTH-1 parameters and source key:** 3 failures / 300 s on `src_ip` are proposed, with abstention for known relay/NAT addresses.
3. **Sensor latency calibration for ART-1:** benchmark emulated commands on the sensor rather than relying on the single training-derived command.
4. **TTY collection:** whether to collect TTY content, which would make more outcomes observable but remains emulator output.
5. **Implementation location:** a new module beside, not replacing, the existing scripts, with unit tests built from the catalogue's semantics.

## 6. Integrity

- **Created:** this directory only.
- **Unchanged:** existing signatures, `behaviour_pattern_analysis.py` (imported read-only for the substring comparison), `behaviour_signature_generation.py`, `novelty_assessment.py`, the configs, the extractor, Dataset V2 (verified against its `SHA256SUMS`) and all models.
- **Not accessed:** the sealed test and exfiltration data.
- **Not done:** nothing was committed.
