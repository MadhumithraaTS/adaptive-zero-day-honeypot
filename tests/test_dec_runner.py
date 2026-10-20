import csv
import subprocess
import sys
from pathlib import Path

import pandas as pd
import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
TRAINING_ROWS = REPO_ROOT / "model_selection" / "behavior_features.csv"
# The saved DEC artifacts need the dedicated DEC interpreter (newer pandas/scikit-learn).
DEC_PYTHON = REPO_ROOT / "ml" / "cowrie_dec_integration_skeleton" / ".venv-dec-smoke" / "Scripts" / "python.exe"
needs_dec_python = pytest.mark.skipif(not DEC_PYTHON.is_file(), reason="DEC interpreter not present")
# IDs that pandas would otherwise coerce: leading zeros, scientific notation, NA tokens.
TRICKY_IDS = ["012345678901", "123e45678901", "NA", "0000000000aa", "1e5", "nan"]
DEC_RUNNER = (
    REPO_ROOT
    / "ml"
    / "cowrie_dec_integration_skeleton"
    / "scripts"
    / "run_dec_evaluation.py"
)


def test_dec_runner_help_loads_with_tensorflow_before_sklearn():
    result = subprocess.run(
        [sys.executable, str(DEC_RUNNER), "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Run offline Cowrie DEC clustering" in result.stdout
    assert "--output" in result.stdout


def _write_input(path, labels):
    frame = pd.read_csv(TRAINING_ROWS, nrows=len(TRICKY_IDS))
    frame["session_id"] = TRICKY_IDS
    frame["label"] = labels
    frame.to_csv(path, index=False)


def _run(input_csv, output_csv, *extra):
    return subprocess.run(
        [str(DEC_PYTHON), str(DEC_RUNNER), str(input_csv), "--output", str(output_csv), *extra],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def _metric_lines(stdout):
    return [line for line in stdout.splitlines() if line.startswith(("ARI:", "NMI:"))]


@pytest.fixture(scope="module")
def default_run(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("dec_default")
    _write_input(tmp / "in.csv", [0, 1, 0, 1, 0, 1])
    result = _run(tmp / "in.csv", tmp / "out.csv")
    return tmp, result


@needs_dec_python
def test_session_ids_are_preserved_as_exact_strings(default_run):
    tmp, result = default_run
    assert result.returncode == 0, result.stderr
    with open(tmp / "out.csv", encoding="utf-8", newline="") as handle:
        ids = [row["session_id"] for row in csv.DictReader(handle)]
    assert ids == TRICKY_IDS


@needs_dec_python
def test_ari_nmi_omitted_without_verified_labels_even_if_non_constant(default_run):
    _, result = default_run
    assert result.returncode == 0, result.stderr
    assert _metric_lines(result.stdout) == []
    assert "labels not verified" in result.stdout


@needs_dec_python
def test_ari_nmi_reported_only_with_verified_multi_class_labels(tmp_path):
    _write_input(tmp_path / "in.csv", [0, 1, 0, 1, 0, 1])
    result = _run(tmp_path / "in.csv", tmp_path / "out.csv", "--labels-verified")
    assert result.returncode == 0, result.stderr
    assert [line.split(":")[0] for line in _metric_lines(result.stdout)] == ["ARI", "NMI"]


@needs_dec_python
def test_ari_nmi_omitted_for_verified_but_constant_labels(tmp_path):
    _write_input(tmp_path / "in.csv", [0] * len(TRICKY_IDS))
    result = _run(tmp_path / "in.csv", tmp_path / "out.csv", "--labels-verified")
    assert result.returncode == 0, result.stderr
    assert _metric_lines(result.stdout) == []
    assert "fewer than two classes" in result.stdout
