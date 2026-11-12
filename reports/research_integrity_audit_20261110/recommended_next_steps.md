# Recommended next steps

Each step needs your explicit approval. Steps 1–2 change no data or models. Dataset V1 and every
existing model, report and the frozen test split are kept as they are.

## 1. Correct the written claims (documentation only; safest first step)

- **Where:**
  - `docs/final_technical_report.md`, as a new revision or addendum, not overwriting the historical text;
  - the `README.md` feature table.
- **What:** apply the "required_correction" column of `research_claims_validity_matrix.csv`. In particular:
  - no zero-day or buffer-overflow payload detection;
  - the "zero_day" categories are invented synthetic profiles that were present in training;
  - DEC is a research comparison, not shown to be best for Cowrie;
  - `dbytes`, `rate` and `dload` carry an injected category parameter;
  - adaptive response and automated defence are not implemented.
- **Why first:** it removes the overclaims without touching any experiment.

## 2. Freeze the V1 record

Write a short V1 provenance note: the dataset hash, split fingerprint, model folders and the three
audit reports from 2026-11-10. Leave the V1 test split unscored, because its labels and features
can't support the claims it would be used for. Any later decision to score it once should be
recorded as an explicit decision.

## 3. Write the common feature specification as a separate, versioned extractor (code; approval needed)

- Implement `synthetic_vs_cowrie_comparison.md` section 4 as a **new** module, for example `scripts/extract_features_v2.py`. Leave `scripts/extract_features.py` unchanged, since the live pipeline and V1 depend on it.
- Add unit tests built from the existing live raw logs:
  - failed commands are counted once;
  - `session.params` is handled;
  - `exit` is excluded;
  - payload bytes are visible.

## 4. Payload-delivery pilot on real Cowrie (approval needed; uses Docker and generates traffic)

- **Scale:** a handful of Level 1 sessions only (`dataset_v2_experimental_protocol.md` section 3).
- **Purpose:** confirm that the payload line appears in `cowrie.command.input`, find out how Cowrie normalises non-ASCII bytes and whether it truncates, and settle the unverified assumptions 2–3 in `research_integrity_report.md`.
- **Not a model step:** no model training happens in this step.

## 5. Generate Dataset V2 (approval needed)

Follow `dataset_v2_experimental_protocol.md`:

1. Generate the train and validation runs (seeds A and B).
2. Pass the acceptance checks.
3. Run the leakage checks on training data only.
4. Run the ML pipeline from Gate A in a new folder, for example `ml_pipeline_v2/`.
5. Generate the test run (seed C, disjoint placeholders, held-out profiles) last, seal it, and score it once.

## 6. Optional analysis on V1 (approval needed; would retrain)

Run ablations of `dbytes`/`rate`/`dload` and `tcprtt`/`synack` on V1 train and validation only, to measure how much of the current cluster structure the artefacts explain (unverified assumption 4). It is useful for the report's discussion, but it isn't required if V2 goes ahead.

## Not recommended

- Patching `scripts/generate_dataset.py` and regenerating V1. A synthetic generator would still have to imitate Cowrie's event semantics, and real Cowrie runs already exist.
- Counting `command.failed` toward client packets or bytes. It would double-count in live data (see the buffer-overflow audit, section 6, option C).
- Describing Level 1 payload sessions as exploits.

---

## Integrity verification for this audit

Recorded with SHA-256 over every repository file outside `.git`, `.venv`, `.venv-dec-smoke`,
`__pycache__` and `.pytest_cache`, before and after the audit, together with `git status`. The
results are in the final message to the user and in
`<scratchpad>/ria_hashes_{before,after}.txt` and `ria_gitstatus_{before,after}.txt`.

- **Before:** 1,155 files hashed; 0 modified tracked files.
- **Untracked before:**
  - `cowrie/userdb.txt`, `dataset_builder/`, `docs/dataset_and_evaluation_methodology.md`, `ml_pipeline/`;
  - `reports/buffer_overflow_telemetry_audit_20261110/`, `reports/diagnostics/relabel_20261108_211249/`, `reports/validation_error_analysis_ae_kmeans_20261110/`;
  - `tests/dec15_probe.py`, `tests/test_dataset_labelling.py`, `tests/test_dec_15_feature_model.py`.
- **Test-set access:** none. The evidence scripts read only `ml_pipeline/work/train.pkl`, `ml_pipeline/work/val.pkl`, live `train_v2_corrected` features and live raw logs. `ml_pipeline/.guard_state.json` reports `test_touches: 0`.
