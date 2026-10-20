# Final Demonstration Checklist

A repeatable demonstration of the implemented pipeline, using only existing scripts and recorded outputs.

**Ground rules:**

- **Parts A–D generate no network traffic and change no protected file.** Every new output goes into a fresh, timestamped folder.
- **Part E is optional.** It creates new sessions on the local honeypot, so run it only with approval.
- **Automated defence is not part of this demonstration**, because it is not implemented (report Chapter 8).

Run everything from the repository root in one Windows PowerShell window.

---

## Part A: Setup and prerequisites

- [ ] Set the paths:

  ```powershell
  cd C:\AMRITA\Final_Year_Project_zero_day_27\adaptive-zero-day-honeypot
  $Py    = ".\.venv\Scripts\python.exe"
  $DecPy = ".\ml\cowrie_dec_integration_skeleton\.venv-dec-smoke\Scripts\python.exe"
  $Run   = "data\demo_" + (Get-Date -Format "yyyyMMdd_HHmmss")
  $Run
  ```

  `$Run` must be a folder that doesn't exist yet. The pipeline refuses to overwrite existing outputs and exits with code 2.

- [ ] Confirm the honeypot container is running. It's only needed for Part E, but it's useful to show:

  ```powershell
  docker ps --filter "name=cowrie-project"
  ```

  Expected: `cowrie-project`, port `0.0.0.0:2223->2222/tcp`.

- [ ] Confirm the DEC interpreter exists:

  ```powershell
  Test-Path $DecPy
  ```

  Expected: `True`.

- [ ] Optionally, record protected-file hashes for the integrity check in Part D:

  ```powershell
  $Protected = @(Get-ChildItem -File ml\cowrie_dec_integration_skeleton\ml\cowrie_dec\artifacts) + @(Get-Item reports\novelty_assessment\held_out\revised\reference_signatures\behaviour_signatures.json)
  $Before = $Protected | Get-FileHash -Algorithm SHA256
  ```

---

## Part B: Tests and model reproducibility

- [ ] Run the full regression suite. It takes about 2–3 minutes.

  ```powershell
  & $Py -m pytest -q tests
  ```

  Expected: `130 passed` (warnings are expected; see report §7.6).

- [ ] Show the DEC reproducibility tests on their own:

  ```powershell
  & $Py -m pytest -v tests\test_dec_reproducibility.py
  ```

  Expected: 5 passed.

  Talking points:
  - The saved model reproduces the training clusters 485 / 694 / 621.
  - Batch-dependent probability differences stay within `atol=1e-6`.
  - A one-byte input change is detected.

---

## Part C: End-to-end processing without new traffic

This reprocesses the recorded demo log (`data\demo_20261019_213439\raw\cowrie.json`, 8 sessions) into the new `$Run` folder.

- [ ] Run parsing, feature extraction and DEC:

  ```powershell
  & $Py scripts\pipeline.py --skip-attack --raw-input data\demo_20261019_213439\raw\cowrie.json --output-dir $Run --skip-preprocess
  ```

  Expected output:
  - `DEC interpreter: ...\.venv-dec-smoke\Scripts\python.exe`
  - `Parsed 8 unique sessions.`
  - `Cluster 1: 8 (100.00%)`
  - `ARI/NMI: omitted (labels not verified ...)`
  - exit code 0

- [ ] Show the DEC results:

  ```powershell
  Import-Csv "$Run\processed\dec_results.csv" | Select-Object session_id, dec_cluster, dec_confidence | Format-Table
  ```

  Expected: 8 rows, all cluster 1, confidence about 0.81–0.95. They should be identical to `data\demo_20261019_213439\processed\dec_results.csv`.

- [ ] Run the novelty assessment against the reference catalogue:

  ```powershell
  & $Py scripts\novelty_assessment.py --session-details "$Run\parsed\session_details.json" --signature-file reports\novelty_assessment\held_out\revised\reference_signatures\behaviour_signatures.json --output-dir "$Run\novelty"
  Import-Csv "$Run\novelty\novelty_assessment_results.csv" | Select-Object session_id, assessment_category, closest_signature_id, score | Format-Table
  Get-Content "$Run\novelty\novelty_assessment_report.md" | Select-String -Context 0,3 "Reference independence"
  ```

  Expected:
  - 3 Known-like and 5 Potentially Novel;
  - `Evaluation mode: independent`, 43 reference IDs, 0 overlapping.

  Talking point: "Potentially Novel" means "doesn't fit the current catalogue". These sessions come from profiles that have no usable signature; it is not a zero-day finding (report §6.9).

- [ ] Show that the pipeline refuses to overwrite:

  ```powershell
  & $Py scripts\pipeline.py --skip-attack --raw-input data\demo_20261019_213439\raw\cowrie.json --output-dir $Run --skip-preprocess
  $LASTEXITCODE
  ```

  Expected: `Error: refusing to overwrite existing pipeline outputs:` and exit code `2`.

---

## Part D: Recorded fresh-data evaluation and integrity

- [ ] Open the recorded evaluation report, which is read-only evidence:

  ```powershell
  notepad data\evaluation_runs\fresh_20261019_224335\EVALUATION_REPORT.md
  Get-Content data\evaluation_runs\fresh_20261019_224335\logs\commands.log
  ```

  Talking points:
  - 13 sessions were collected, 8 known sessions excluded and 5 new ones retained.
  - All 5 were in cluster 1 (confidence 0.924–0.935) and Known-like (scores 0.728–0.836).
  - The mode was `independent`.
  - The strict verification check failed with exit code 1 because of a difference of at most 2.4 × 10⁻⁸; that failure is kept on record.

- [ ] If `$Before` was recorded in Part A, confirm the protected files are unchanged:

  ```powershell
  $After = $Protected | Get-FileHash -Algorithm SHA256
  Compare-Object $Before $After -Property Path, Hash
  ```

  Expected: no output, meaning nothing changed.

---

## Part E (optional, needs approval): Live controlled sessions

This adds new sessions to the honeypot's log. It uses only the local honeypot and the `script_kiddie` profile. The other profiles make real outbound downloads from the container, so they are excluded. The commands follow `data\evaluation_runs\fresh_20261019_224335\logs\commands.log`.

- [ ] Create a filtered profile file (`configs\attack_profiles.json` is only read):

  ```powershell
  New-Item -ItemType Directory "$Run\live" | Out-Null
  & $Py -c "import json,sys; d=json.load(open('configs/attack_profiles.json',encoding='utf-8')); d['profiles']=[p for p in d['profiles'] if p['name']=='script_kiddie']; json.dump(d, open(sys.argv[1],'x',encoding='utf-8'), indent=2)" "$Run\live\profiles.json"
  ```

- [ ] Generate 3 sessions and collect the log:

  ```powershell
  & $Py scripts\attack_generator.py --config "$Run\live\profiles.json" --host 127.0.0.1 --port 2223 --sessions 3 --username root --password admin
  & $Py scripts\collect_logs.py --container cowrie-project --dest "$Run\live\raw\cowrie.json"
  ```

  Stop if the generator prints `Failed to connect`, or if `collect_logs.py` exits non-zero.

- [ ] Process the collected log and keep only sessions that aren't already in the recorded fresh-run snapshot:

  ```powershell
  & $Py scripts\pipeline.py --skip-attack --raw-input "$Run\live\raw\cowrie.json" --output-dir "$Run\live\pipeline" --skip-preprocess
  & $Py scripts\prepare_fresh_evaluation.py --baseline-session-details data\evaluation_runs\fresh_20261019_224335\pipeline\parsed\session_details.json --snapshot-session-details "$Run\live\pipeline\parsed\session_details.json" --snapshot-features "$Run\live\pipeline\parsed\behavior_features.csv" --output-session-details "$Run\live\fresh_session_details.json" --output-features "$Run\live\fresh_behavior_features.csv" --summary-output "$Run\live\preparation_summary.json"
  ```

  Expected: `new_session_count` of 3 in `preparation_summary.json`. That baseline file holds the 13 sessions known at the time of the recorded run. For a full check against every earlier set, use the procedure in the recorded evaluation report.

- [ ] Run DEC and the novelty assessment on the new sessions:

  ```powershell
  & $DecPy ml\cowrie_dec_integration_skeleton\scripts\run_dec_evaluation.py "$Run\live\fresh_behavior_features.csv" --output "$Run\live\dec_results.csv"
  & $Py scripts\novelty_assessment.py --session-details "$Run\live\fresh_session_details.json" --signature-file reports\novelty_assessment\held_out\revised\reference_signatures\behaviour_signatures.json --output-dir "$Run\live\novelty"
  ```

---

## What not to claim during the demonstration

- Zero-day detection: not demonstrated (report §6.8, §9.2).
- Automated defence or firewall rules: not implemented; no rule has been applied (report Chapter 8).
- ARI/NMI or accuracy on live sessions: no verified labels exist.
- MongoDB storage, REST APIs or a dashboard: not implemented.
