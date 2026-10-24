# 🧪 Testing and Verification Guide

This document details the automated test suite of the **Adaptive Zero-Day Honeypot** repository, covering test architecture, component coverage, execution instructions, prerequisites, verified audit results, and known limitations.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Test Framework & Dependencies](#test-framework--dependencies)
- [Component Coverage Matrix](#component-coverage-matrix)
- [Prerequisites & Isolation](#prerequisites--isolation)
- [How to Run the Tests](#how-to-run-the-tests)
  - [1. Running the Full Test Suite](#1-running-the-full-test-suite)
  - [2. Running the Pure Offline Core Suite](#2-running-the-pure-offline-core-suite)
  - [3. Running Individual Test Modules](#3-running-individual-test-modules)
- [Test Files & Detailed Responsibilities](#test-files--detailed-responsibilities)
- [Audited Execution Results](#audited-execution-results)
  - [Summary](#summary)
  - [Passed Tests Analysis](#passed-tests-analysis)
  - [Skipped Tests Analysis](#skipped-tests-analysis)
  - [Failed Tests Analysis & Root Causes](#failed-tests-analysis--root-causes)
  - [Observed Warnings](#observed-warnings)
- [Untested Components & Academic Limitations](#untested-components--academic-limitations)
- [Recommendations for Future Work](#recommendations-for-future-work)

---

## 🔍 Overview

The repository contains an automated regression and safety test suite located in [`tests/`](../tests/). It comprises **130 distinct test items** collected across **10 test modules** and **1 subprocess helper script**:

- **Safety & Overwrite Protection:** Ensures the pipeline refuses to clobber baseline datasets or production models.
- **Data Validation & Parsing:** Tests ingestion of raw Cowrie honeypot events, edge-case JSON strings, malformed records, and atomic file-writing.
- **Statistical & Novelty Assessment:** Tests multi-cluster distance metrics, behavioral signature matching, held-out evaluation isolation, and data-leakage safeguards.
- **Numerical Reproducibility:** Tests DEC (Deep Embedded Clustering) inference across varying batch sizes against defined floating-point tolerances.

---

## ⚙️ Test Framework & Dependencies

| Component | Specification / Tool | Purpose |
|---|---|---|
| **Test Framework** | [`pytest`](https://docs.pytest.org/) (tested with pytest 9.1.1) | Discovery, parameterization, fixture management, and test execution |
| **Data Processing** | `pandas`, `numpy` | DataFrame manipulation, array assertions, tolerance checking |
| **Machine Learning** | `scikit-learn`, `joblib` | Scaling transforms, cluster evaluation metrics (ARI, NMI) |
| **Deep Learning** | `tensorflow` / `keras` | DEC neural network model inference (used by DEC tests) |
| **System Mocking** | `monkeypatch`, `tmp_path`, `tmp_path_factory` | Subprocess interception, file-system isolation |

> [!IMPORTANT]
> **Dual-Interpreter Architecture:**
> The project distinguishes between two Python environments:
> 1. **Primary Environment (`.venv`):** Python 3.11 with `pandas`, `scikit-learn`, `joblib`, and `pytest`. Runs pipeline logic, data parsing, feature extraction, behavioural analysis, and novelty assessment.
> 2. **DEC Interpreter (`.venv-dec-smoke`):** A dedicated environment required for TensorFlow-based DEC inference and batch reproducibility tests due to specific package and serialization requirements.

---

## 📊 Component Coverage Matrix

The following table honestly audits the project components against actual test coverage:

| Component | Tested? | Relevant Test File(s) | Description of Coverage |
|---|:---:|---|---|
| **Data Loading & Preprocessing** | ✅ Yes | [`test_log_processing.py`](../tests/test_log_processing.py), [`test_dec_preprocessing.py`](../tests/test_dec_preprocessing.py), [`test_prepare_fresh_evaluation.py`](../tests/test_prepare_fresh_evaluation.py) | Ingestion of raw Cowrie JSON logs, imputation of NaN/inf values, non-numeric validation, session schema parsing. |
| **Feature Extraction** | ✅ Yes | [`test_log_processing.py`](../tests/test_log_processing.py) | Extraction of duration, packet counts, byte counts, TCP flags, regression check against reference outputs. |
| **ML Model Input & Output** | ✅ Yes | [`test_dec_runner.py`](../tests/test_dec_runner.py), [`test_dec_reproducibility.py`](../tests/test_dec_reproducibility.py) | Exact session-ID string preservation, batch inference consistency, numerical output bounds, sensitivity tests. |
| **Clustering & Model Evaluation** | ✅ Yes | [`test_behaviour_pattern_analysis.py`](../tests/test_behaviour_pattern_analysis.py), [`test_dec_runner.py`](../tests/test_dec_runner.py), [`test_dec_reproducibility.py`](../tests/test_dec_reproducibility.py) | Cluster distribution calculations, feature statistic derivations, ARI/NMI metric gating, cluster stability. |
| **Cowrie Log Processing** | ✅ Yes | [`test_collect_logs.py`](../tests/test_collect_logs.py), [`test_log_processing.py`](../tests/test_log_processing.py) | Mocked Docker container extraction, empty snapshot detection, stale file guards, malformed JSON handling. |
| **Novelty Assessment / Anomaly Scoring** | ✅ Yes | [`test_novelty_assessment.py`](../tests/test_novelty_assessment.py) | Distance threshold matching, signature catalogue lookup, held-out evaluation partitioning, session leakage prevention. |
| **Threat Scoring** | ⚠️ Partial | [`test_novelty_assessment.py`](../tests/test_novelty_assessment.py), [`test_behaviour_pattern_analysis.py`](../tests/test_behaviour_pattern_analysis.py) | Tested as **novelty/anomaly scoring** and behavioral categorization against signatures. No standalone CVSS or vulnerability threat-scoring engine exists. |
| **Defensive Rule Generation & Validation** | ❌ No | *None* | **Not implemented.** The repository does not currently contain an automated firewall, iptables, or Snort rule generation engine. |
| **Configuration & Error Handling** | ✅ Yes | [`test_pipeline_safety.py`](../tests/test_pipeline_safety.py), [`test_prepare_fresh_evaluation.py`](../tests/test_prepare_fresh_evaluation.py), [`test_novelty_assessment.py`](../tests/test_novelty_assessment.py) | Command-line flag parsing, default path resolution, fail-fast mechanics, atomic write verification, collision prevention. |

---

## 🛡️ Prerequisites & Isolation

- **Live Honeypot NOT Required:** All unit and regression tests run completely **offline**. Tests that simulate Cowrie collection (`test_collect_logs.py`) mock `subprocess.run` calls, meaning Docker Desktop does not need to be running.
- **No External Network Access:** The test suite does not require internet connectivity, cloud APIs, or active network ports.
- **Filesystem Isolation:** Tests that produce file outputs write strictly to temporary directories using pytest's `tmp_path` fixture, leaving repo files untouched.
- **Tracked Reference Assets:** A small number of integration tests verify byte-identical outputs against tracked baseline assets:
  - `model_selection/behavior_features.csv`
  - `data/demo_20261019_213439/`
  - `models/scaler.joblib`

---

## 🚀 How to Run the Tests

Ensure your virtual environment is active and dependencies (including `pytest`) are installed:

```bash
# Activate virtual environment (Windows PowerShell)
.\.venv\Scripts\Activate.ps1

# Or activate virtual environment (Linux / macOS / WSL)
source .venv/bin/activate

# Install pytest if not already present
pip install pytest
```

### 1. Running the Full Test Suite

To run all discovery tests in the repository:

```bash
pytest tests/ -v
```

*(Or via Python executable directly)*:
```bash
python -m pytest tests/ -v
```

### 2. Running the Pure Offline Core Suite

To run the self-contained core suite (which does not require the secondary DEC virtual environment):

```bash
pytest tests/test_behaviour_pattern_analysis.py \
       tests/test_behaviour_signature_generation.py \
       tests/test_collect_logs.py \
       tests/test_dec_preprocessing.py \
       tests/test_log_processing.py \
       tests/test_novelty_assessment.py \
       tests/test_prepare_fresh_evaluation.py -v
```

### 3. Running Individual Test Modules

Run individual components depending on the area under investigation:

```bash
# Novelty assessment & signature matching (41 tests)
pytest tests/test_novelty_assessment.py -v

# Cowrie log parsing & feature extraction (13 tests)
pytest tests/test_log_processing.py -v

# Fresh evaluation preparation & session splitting (10 tests)
pytest tests/test_prepare_fresh_evaluation.py -v

# Behavioral pattern analysis (7 tests)
pytest tests/test_behaviour_pattern_analysis.py -v

# Behavioral signature generation (17 tests)
pytest tests/test_behaviour_signature_generation.py -v

# Log collection & Docker error paths (11 tests)
pytest tests/test_collect_logs.py -v

# DEC preprocessing logic (8 tests)
pytest tests/test_dec_preprocessing.py -v
```

---

## 📂 Test Files & Detailed Responsibilities

The [`tests/`](../tests/) directory contains 11 files:

| File | Type | Target Module | Purpose & Tested Scenarios |
|---|:---:|---|---|
| [`test_behaviour_pattern_analysis.py`](../tests/test_behaviour_pattern_analysis.py) | Unit | `scripts/behaviour_pattern_analysis.py` | Validates cluster distributions, statistical aggregations (mean, std, median), command intent categorization (reconnaissance, file transfer, persistence), and schema validation. |
| [`test_behaviour_signature_generation.py`](../tests/test_behaviour_signature_generation.py) | Unit | `scripts/behaviour_signature_generation.py` | Tests signature compilation from cluster summaries, handling of missing auth/command evidence, deterministic signature ID hashing, and consistency between JSON and CSV outputs. |
| [`test_collect_logs.py`](../tests/test_collect_logs.py) | Unit | `scripts/collect_logs.py` | Tests log extraction from Docker containers, detection of stale or empty snapshots, and OS-specific fallback mechanisms (Windows vs POSIX sudo). |
| [`test_dec_preprocessing.py`](../tests/test_dec_preprocessing.py) | Unit | `ml/cowrie_dec/preprocessing.py` | Tests numerical cleanup for DEC clustering: median imputation for `NaN` and `±inf`, rejection of non-numeric text, and log1p feature transformation. |
| [`test_dec_reproducibility.py`](../tests/test_dec_reproducibility.py) | Regression | `tests/dec_batch_probe.py` | Validates that DEC model predictions remain within a strict numerical tolerance (`1e-6` absolute) across different batch compositions and sizes (1 to 256). |
| [`dec_batch_probe.py`](../tests/dec_batch_probe.py) | Helper | `ml/cowrie_dec/inference.py` | Subprocess probe invoked by `test_dec_reproducibility.py` to run multi-batch inference using saved model artifacts without altering disk state. |
| [`test_dec_runner.py`](../tests/test_dec_runner.py) | Integration | `ml/cowrie_dec/scripts/run_dec_evaluation.py` | Tests the DEC evaluation CLI, verifying that session IDs are preserved as exact strings without scientific notation distortion and checking ARI/NMI gating. |
| [`test_log_processing.py`](../tests/test_log_processing.py) | Unit & Regr. | `scripts/parse_logs.py`, `scripts/extract_features.py` | Validates Cowrie JSON event parsing, schema enforcement, feature column formatting, handling of corrupt lines, and exact byte-identical output matching. |
| [`test_novelty_assessment.py`](../tests/test_novelty_assessment.py) | Unit & Integ. | `scripts/novelty_assessment.py` | Extensive tests for novelty classification (Known vs Novel vs Ambiguous), distance scoring, contradiction gating, evaluation mode reporting, and held-out partition isolation. |
| [`test_pipeline_safety.py`](../tests/test_pipeline_safety.py) | Safety & CLI | `scripts/pipeline.py` | Ensures the orchestrator refuses to overwrite existing files without `--allow-overwrite`, validates CLI flags, enforces correct interpreter selection, and verifies fail-fast exits. |
| [`test_prepare_fresh_evaluation.py`](../tests/test_prepare_fresh_evaluation.py) | Unit & Safety | `scripts/prepare_fresh_evaluation.py` | Tests isolation of unseen honeypot sessions from historical training data, rejecting duplicate session IDs, non-finite values, and schema mismatches. |

---

## 🔬 Audited Execution Results

### Summary

Direct execution of the test suite in the project environment (`Python 3.11.9`, `pytest 9.1.1` on Windows) yielded:

```text
=================== 3 failed, 117 passed, 10 skipped, 3 warnings in 6.02s ===================
```

### Passed Tests Analysis (117 Passed)

- **107 Core Unit Tests:** All tests across `test_behaviour_pattern_analysis.py`, `test_behaviour_signature_generation.py`, `test_collect_logs.py`, `test_dec_preprocessing.py`, `test_log_processing.py`, `test_novelty_assessment.py`, and `test_prepare_fresh_evaluation.py` passed with **zero errors**.
- **10 Pipeline Safety Tests:** Path resolution, planned output detection, flag routing, interpreter validation, and mock execution isolation in `test_pipeline_safety.py` passed successfully.

### Skipped Tests Analysis (10 Skipped)

Ten tests were skipped due to explicit `@pytest.mark.skipif` decorators:
- **4 tests in `test_dec_runner.py`:** Skipped with reason `"DEC interpreter not present"`. These tests require `.venv-dec-smoke/Scripts/python.exe` to execute inference with the saved model artifacts.
- **5 tests in `test_dec_reproducibility.py`:** Skipped with reason `"DEC interpreter not present"`. Reproducibility probe requires `.venv-dec-smoke`.
- **1 test in `test_pipeline_safety.py` (`test_pipeline_with_output_dir_leaves_baseline_models_and_artifacts_untouched`):** Skipped with reason `"DEC interpreter or demo log not present"`.

### Failed Tests Analysis & Root Causes (3 Failed)

To ensure scientific honesty and complete audit clarity, the 3 failures are documented below with their precise technical causes:

1. **`test_dec_runner.py::test_dec_runner_help_loads_with_tensorflow_before_sklearn`**
   - **Error:** `ModuleNotFoundError: No module named 'tensorflow.keras'`
   - **Root Cause:** The test executes `run_dec_evaluation.py --help` using `sys.executable` (the active `.venv`). In TensorFlow 2.12 / newer Keras configurations under Python 3.11, `tensorflow.keras` is decoupled from standalone `keras`. The script is intended to execute under the dedicated DEC interpreter.
2. **`test_pipeline_safety.py::test_pipeline_refuses_to_overwrite_existing_outputs`**
   - **Error:** `AssertionError: assert 'refusing to overwrite' in ... pipeline.py: error: DEC interpreter not found at ...\.venv-dec-smoke\Scripts\python.exe; pass --cluster-python`
   - **Root Cause:** When `pipeline.py` starts, its argument parser validates the presence of the default DEC interpreter path (`DEFAULT_DEC_PYTHON`). Because `.venv-dec-smoke` is absent in the test environment, the CLI parser aborts with exit code 2 *before* checking whether the output directory already contains files.
3. **`test_pipeline_safety.py::test_parse_failure_stops_pipeline_before_later_steps`**
   - **Error:** `AssertionError: assert 2 == 1`
   - **Root Cause:** Same underlying cause as failure #2: the missing default DEC interpreter triggers an argument parsing exit (code 2) before the pipeline reaches the log parsing stage (which would have returned exit code 1).

### Observed Warnings

Three non-blocking warnings were logged during execution:
- **Pandas Pyarrow Deprecation:** `DeprecationWarning: Pyarrow will become a required dependency of pandas in the next major release of pandas (pandas 3.0)`
- **Pandas Downcasting FutureWarning:** 2 warnings in `ml/cowrie_dec/preprocessing.py:96` regarding downcasting object dtype arrays on `.fillna`.

---

## ⚠️ Untested Components & Academic Limitations

For accurate evaluation in academic settings, the following limitations should be noted:

1. **Automated Defense Engine is Unimplemented:**
   - Although the research project investigates adaptive response, **no automated defensive rule generation (e.g. iptables, Snort, Suricata, nftables) is currently implemented in code**.
   - No tests exist for automated defense rule synthesis or firewall modifications.
2. **Dual-Interpreter Requirement:**
   - The deep learning clustering components (DEC) require a separate virtual environment (`.venv-dec-smoke`) due to specific package version alignments with the trained model artifacts.
3. **Live Cowrie Telemetry:**
   - There are no automated integration tests that boot an active Docker daemon, launch Cowrie, simulate live SSH sessions over network sockets, and verify end-to-end log streaming in real time. All log collection tests use mocked filesystem operations.

---

## 💡 Recommendations for Future Work

1. **Add `pytest` to `requirements.txt` or a `requirements-dev.txt`:** Formally declare testing dependencies so contributors can run the suite immediately after cloning.
2. **Pipeline CLI Validation Refactoring:** In `scripts/pipeline.py`, decouple the check for `--cluster-python` from non-DEC stages (or allow dummy fallbacks during dry-run / safety checks) so that safety flag tests pass even when the secondary DEC environment is unconfigured.
3. **Automate DEC Environment Bootstrap:** Provide a script or documentation for provisioning `.venv-dec-smoke` on new systems to enable the 10 skipped reproducibility tests.
