# Behavioural signature revalidation on Cowrie Dataset V2 (Task 20)

**Date:** 2026-11-11. **Read-only audit.**

**Not done:**
- no signature definition, threat-scoring logic, feature extraction, model or defence rule was changed, deployed or activated;
- no model was retrained (E3 uses saved Task 17 assignments);
- the sealed test set and the exfiltration category were not accessed (an audit hook blocked test, sealed and exfiltration paths; none was opened);
- nothing was committed.

**No zero-day detection is claimed.** Category labels are generation intent and are used for post-hoc description only.

**Reproduce:**

```
.venv/Scripts/python.exe reports/behavioural_signature_revalidation_v2_20261111/revalidate_signatures.py
.venv/Scripts/python.exe reports/behavioural_signature_revalidation_v2_20261111/make_tables.py
```

## 1. Headline

1. **The stored signature catalogue cannot be used on Dataset V2 (classification 6).**
   - The 3 signatures in `reports/behaviour_signatures/behaviour_signatures.json` (2026-10-15) were built from V1 DEC clusters of the synthetic UNSW-style data.
   - Their numeric profiles use only V1 features (`ackdat`, `ct_dst_ltm`, `ct_src_ltm`, `ct_srv_dst`, `ct_srv_src`, `ct_state_ttl`, `dbytes`, `dinpkt`), and none of these exists in V2.
   - The unchanged matcher therefore finds **0 comparable features** and returns "Insufficient Evidence" for all 3,190 train and 1,257 validation sessions.
2. **The rule layer that does run on V2 telemetry is weak.** These are the keyword categories and session interpretations in `behaviour_pattern_analysis.py`.
   - **Generic keywords:** the substring keywords are non-specific. `w`, `ls`, `ps`, `su`, `ssh` and `rm ` fire inside unrelated words and paths: up to 71% of a category's hits, and 29–39% for reconnaissance, privilege escalation, networking and evasion.
   - **Benign mislabelled:** 34.5% of benign logged-in validation sessions get an attack-implying interpretation (Reconnaissance, Persistence or Download), and every benign failed login is labelled "Credential-attack behaviour".
   - **What survives:** only "Download or payload retrieval", the privilege-escalation keyword category and the "Insufficient Evidence" abstention are partially supported, with qualifications.
3. **Re-instantiating signatures from V2 data adds nothing defensible.** This used the existing reference-only builder with the saved Task 17 DEC K = 3 assignments.
   - **The signatures follow the clusters:** "Credential-attack behaviour" is the failed-login cluster, and the other two are "Mixed/Unclassified" with a category mix close to the population's.
   - **No behavioural distinction in matching:** the matcher labels 27% of known-category validation logins "Potentially Novel", including all 79 brute-force logins.
   - **The slow-`find` artefact again:** all 9 privilege-escalation sessions with the 11–12 s Cowrie execution are novel, against 0 of the other 60 privilege-escalation logins.
4. **No response actions exist.** `configs/defence_policy.json` is read by no code, and the final technical report records automated defence as not implemented.

## 2. Implementation actually present

| Component | File | What it does |
|---|---|---|
| Keyword categories | `scripts/behaviour_pattern_analysis.py` `CATEGORY_KEYWORDS`, `classify_command` | 8 categories; a command matches a category if any keyword is a **substring** of the lower-cased line |
| Session interpretation | same, `infer_session_interpretation` | Ordered rules: failed login or `credential_attack` → Credential-attack (unless recon/transfer/persistence → Mixed); then persistence → file_transfer → privilege_escalation → reconnaissance; several categories → Mixed; one category → Command execution; none → Insufficient Evidence |
| Signature definition | `scripts/behaviour_signature_generation.py` `build_signatures` | One signature **per DEC cluster**. Label = majority session interpretation; feature profile = up to 8 numeric features ranked by within-cluster relative variability (mean/std/min/max); command categories; authentication success rate; heuristic evidence-strength "confidence" (0.25 + support + consistency + command + auth terms) |
| Matching | `scripts/novelty_assessment.py` `compare_session_to_signature`, `assess_session_against_signatures` | Similarity = 0.70 × numeric z-distance similarity (raw values against cluster mean/std, clipped at 3 SD) + 0.20 × command-category Jaccard + 0.10 × auth agreement. Known-like ≥ 0.70 with margin ≥ 0.05; Ambiguous if top two within 0.05 and ≥ 0.60; otherwise Potentially Novel; Insufficient Evidence when no numeric feature is comparable |
| Reference-only builder | same, `_reference_only_signatures` | Builds signatures from reference sessions only (used by the held-out evaluation path) |
| Stored catalogue | `reports/behaviour_signatures/behaviour_signatures.json` | 3 signatures: cluster 0 "Command execution" (1 session), 1 "Mixed/Unclassified" (7), 2 "Credential-attack behaviour" (46); built from `data/processed/dec_results.csv` (V1 pipeline) |
| Response actions | — | **None implemented** |

**Dependencies** (`feature_dependency_matrix.csv`):
- signatures depend on **DEC cluster assignments** by construction;
- the matcher does **not** use DEC confidence or the Task 18 novelty scores;
- the stored catalogue depends on **V1 features**;
- the rule layer depends only on **recorded command text and login outcome**, so it doesn't depend on Cowrie output, though it does reflect the generator's fixed command strings.

## 3. Data and method

- **Data:** Dataset V2 train (3,190 sessions / 1,500 interactions) and validation (1,257 / 600). All 60 files were verified against `SHA256SUMS` before use.
- **Commands:** recorded `cowrie.command.input` lines in time order, with `exit`/`logout` excluded.
- **Login outcome:** `login_success`.
- **Grouping:**
  - logged-in sessions (one per interaction, so independent) are the primary unit;
  - failed-guess sessions are reported separately;
  - interaction IDs are disjoint across splits.

| Evaluation | What it runs |
|---|---|
| **E1** | The stored catalogue against every V2 session, with all 13 extracted V2 features offered as numeric evidence |
| **E2** | The keyword and interpretation rules on V2 commands; per-category firing rates; substring hits found with a diagnostic whole-word test |
| **E3** | The existing reference-only builder on the **train** split, using the saved Task 17 DEC K = 3, seed-42 train assignments (the existing project K). Numeric inputs are the frozen 8 V2 features. Matching on **validation** with the default thresholds. No fitting beyond what the existing builder computes (cluster means and standard deviations from train) |

## 4. Results

### 4.1 Stored catalogue (E1)

| Signature | Label | V1 support | V2 features comparable | Train Known-like | Validation Known-like |
|---|---|---|---|---|---|
| `sig-b1feaa1697ecd1bb` | Command execution | 1 | 0 / 8 | 0 | 0 |
| `sig-7a800a68707bfcfd` | Mixed/Unclassified | 7 | 0 / 8 | 0 | 0 |
| `sig-47188a96dccd0950` | Credential-attack behaviour | 46 | 0 / 8 | 0 | 0 |

The code runs without error, but every session is "Insufficient Evidence"; the maximum score was 0.30, from the command and auth terms only. This is a schema mismatch, not a property of the attacks.

### 4.2 Keyword categories (E2, logged-in validation sessions; share of each category's sessions)

| Category | Matched | benign | botnet | brute force | lateral | PE | recon | Substring (not whole-word) hits | Class |
|---|---|---|---|---|---|---|---|---|---|
| reconnaissance | 534 | 0.96 | 0.97 | 0.38 | 0.92 | 1.00 | 1.00 | 29% (`w` in `/etc/passwd`, `ps` in `groups`) | 5 |
| credential_attack | 297 | 0.65 | 0.00 | 0.00 | 0.82 | 0.65 | 0.53 | 71% (`ssh` in `~/.ssh`, `passwd` in `/etc/passwd`) | 5 |
| file_transfer | 170 | 0.20 | 1.00 | 0.00 | 0.37 | 0.00 | 0.34 | 2% | 3 |
| file_system | 421 | 0.55 | 1.00 | 0.10 | 0.97 | 1.00 | 0.97 | 4% | 5 |
| persistence | 168 | 0.63 | 0.00 | 0.00 | 0.00 | 0.33 | 0.00 | 9% | 5 |
| privilege_escalation | 171 | 0.00 | 0.51 | 0.20 | 0.21 | 1.00 | 0.46 | 37% (`su` in `/etc/issue`) | 2 |
| networking | 379 | 0.73 | 1.00 | 0.00 | 0.97 | 0.45 | 0.47 | 39% | 5 |
| evasion | 94 | 0.00 | 0.82 | 0.00 | 0.00 | 0.52 | 0.00 | 32% (`rm ` in `-perm`) | 3 |

Train shares agree within a few points (`evidence/keyword_category_by_attack_cat.csv`), so the rules behave consistently across splits, including their errors.

### 4.3 Session interpretations (E2)

Logged-in validation sessions, one per interaction (train in brackets):

| Interpretation | Validation (train) | Category composition, validation | Class |
|---|---|---|---|
| Mixed/Unclassified | 296 (662) | benign 50%, lateral 21%, PE 15%, recon 13% | 5 |
| Download or payload retrieval | 99 (270) | botnet 72%, recon 14%, benign 10% | 2 |
| Reconnaissance | 72 (186) | benign 53%, brute force 19%, recon 18% | 5 |
| Command execution / privilege escalation | 46 (120) | PE 43%, brute force 35%, recon 17% | 3 |
| Insufficient Evidence | 42 (104) | brute force 98% (logins with no command) | 2 |
| Persistence-related activity | 35 (113) | benign 89%, PE 11% | 5 |
| Command execution | 8 (31) | brute force 100% (`echo ok`) | 3 |
| Credential-attack behaviour | 2 (14) logged in; **657 (1,690) failed guesses** | logged-in: lateral 100%; failed: every category, including 126 benign | 3 |

### 4.4 Re-instantiated V2 signatures and matching (E3)

| Signature (train DEC cluster) | Label | Train support | Train composition | Validation Known-like (all sessions) |
|---|---|---|---|---|
| `sig-9bdd6f77af7fb40f` (1) | Credential-attack behaviour | 1,838 (8% logged in) | brute force 53%, benign 16% | 656 (all failed guesses: benign 126, brute force 318, …) |
| `sig-ceb071c58646821e` (0) | Mixed/Unclassified | 730 | benign 43%, lateral 16% | 55 |
| `sig-5bf9142552bb3532` (2) | Mixed/Unclassified | 622 | benign 40%, PE 19% | 138 |

Assessment of logged-in validation sessions:

| Category | Known-like | Ambiguous | Potentially Novel |
|---|---:|---:|---:|
| benign | 75 | 107 | 47 |
| botnet | 27 | 38 | 6 |
| brute force | 0 | 0 | **79 (100%)** |
| lateral movement | 32 | 36 | 10 |
| privilege escalation | 35 | 25 | **9 = exactly the 9 slow-`find` sessions** |
| reconnaissance | 24 | 37 | 13 |

How to read this:
- The closest-signature *label* is "Mixed/Unclassified" for every logged-in session, so the label carries no behavioural information.
- "Potentially Novel" marks sessions far from the cluster means. That covers:
  - brute-force logins with 0–1 command, which the logged-in clusters don't cover;
  - sessions inflated by Cowrie `find` latency;
  - generator pacing tails.

  This repeats the Task 17–19B findings.

## 5. Classification summary

Codes: 1 supported; 2 partially supported (qualified); 3 generator/template-dependent; 4 Cowrie-emulation/timing-dependent; 5 unsupported or non-functional; 6 cannot be evaluated with available telemetry.

| Item | Class | Main evidence |
|---|---|---|
| Stored catalogue signatures (3) | **6** | 0 of 8 V1 features exist in V2; all sessions "Insufficient Evidence". Built from 54 V1 sessions; DEC on features later removed for leakage (`ct_src_ltm`, `ct_srv_src`) |
| Keyword: privilege_escalation | **2** | 100% PE, 0% benign; but fires in 51% botnet and 46% recon; 37% substring hits |
| Keyword: file_transfer, evasion | **3** | Reflect profile template lines (download, cleanup) rather than general behaviour |
| Keyword: reconnaissance, credential_attack, file_system, persistence, networking | **5** | Non-discriminative or benign-dominated; heavy substring false hits |
| Interpretation: Download or payload retrieval | **2** | Consistent botnet association (72%); means a download *command*, since no download succeeded (0 events) |
| Interpretation: Insufficient Evidence | **2** | Correct abstention for no-command logins |
| Interpretation: Credential-attack, Command execution / PE, Command execution | **3** | Driven by the generator's per-connection failed guesses and brute force's 3-command post-login pool |
| Interpretation: Reconnaissance, Persistence, Mixed/Unclassified | **5** | Benign-dominated or catch-all |
| Matching on V2 signatures (E3) | **4** | Novelty decisions track Cowrie `find` latency (9/9) and duration/timing; 27% of known logins flagged |
| E3 signature, failed-login cluster | **3** | Matches failed guesses of every category |
| E3 signatures, two Mixed clusters | **5** | Labels and composition uninformative |

**No item reaches classification 1.** Full per-item evidence is in `signature_validation_results.csv`.

## 6. False-positive evidence (validation; `false_positive_analysis.csv`)

Benign sessions are used here as the known non-attack reference, not as ground truth for novelty.

| Evidence | Count |
|---|---|
| Benign logins with an attack-implying interpretation | 79 / 229 (34.5%): Reconnaissance 38, Persistence 31, Download 10 |
| Benign failed guesses labelled "Credential-attack behaviour" | 126 / 126 (100%). A single mistyped password produces this label |
| E3 "Potentially Novel" on known-category logins | 164 / 600 (27.3%); benign 20.5%; brute force 100% |

## 7. Answers to the task questions, per evaluated item

- **Executes successfully?** Yes for every component. The stored catalogue executes but cannot match anything (schema mismatch).
- **Telemetry available?** Commands and login outcome: yes. V1 numeric features: no. V2 numeric features: yes, used only through E3.
- **Depends on generator command sequences?** Yes for the rule layer, whose keyword hits follow fixed profile strings: `.ssh` paths, `service`/`systemctl` in benign admin, `echo ok`/`whoami` in brute force.
- **Depends on Cowrie failures or timing?** The rule layer, no: it reads client input only. The E3 matching, yes: duration, inter-input timing and `tty_output_bytes` carry Cowrie latency and output. The "Download" label overstates what Cowrie recorded, because every download failed.
- **Sufficiently general to be useful?** Not in the current form. See `limitations.md`. Possible changes are listed there for approval; none was made.

## 8. Integrity

- **Created:** this directory only:
  - scripts: `revalidate_signatures.py`, `make_tables.py`;
  - deliverables: `signature_inventory.csv`, `signature_validation_results.csv`, `feature_dependency_matrix.csv`, `false_positive_analysis.csv`, `limitations.md`;
  - evidence: `evidence/`;
  - `SHA256SUMS`.
- **Unchanged:** the signature, analysis and novelty scripts, the stored catalogue, the frozen configs, Dataset V2 and the Task 17 outputs. Source hashes are recorded in `evidence/results.json` and were re-checked after the run.
- **Not accessed:** the sealed test or exfiltration data.
- **Not done:** nothing was committed.
