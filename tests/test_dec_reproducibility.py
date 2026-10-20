"""Numerical reproducibility of DEC inference across batch compositions.

The fresh evaluation fresh_20261019_224335 found DEC probabilities for the same session differing by
2.2e-8 (float32) between a 5-row batch and a 13-row batch with identical inputs. Repeating the same
batch is bit-identical; the variation comes from batch-dependent float32 accumulation order.

Tolerance: DEC_PROB_ATOL = 1e-6 absolute, rtol = 0 (probabilities are bounded in [0, 1]).
- Measured variation: at most 1.49e-7 over 76 random sub-batches (sizes 1..1800) of the 1,800 training
  rows, i.e. about 1.25 float32 machine epsilon (1.19e-7); 2.2e-8 in the fresh-run case.
- 1e-6 (~8.4 epsilon) leaves ~6.7x headroom over the worst observed variation.
- Meaningful changes are far larger: +1 byte in sbytes moves probabilities by ~2e-4 (median row),
  +1 ms tcprtt by ~7.5e-5. test_tolerance_detects_a_one_byte_input_change keeps this guarantee.
- The smallest top-1/top-2 probability margin among the training rows is 5.9e-3, so variation within
  the tolerance cannot change a cluster assignment; assignments are also compared exactly.
"""
import csv
import json
import subprocess
from pathlib import Path

import numpy as np
import pytest
from numpy.testing import assert_allclose


REPO_ROOT = Path(__file__).resolve().parents[1]
DEC_PYTHON = REPO_ROOT / "ml" / "cowrie_dec_integration_skeleton" / ".venv-dec-smoke" / "Scripts" / "python.exe"
PROBE = Path(__file__).resolve().parent / "dec_batch_probe.py"
FRESH_RUN = REPO_ROOT / "data" / "evaluation_runs" / "fresh_20261019_224335"
DEC_PROB_ATOL = 1e-6

pytestmark = pytest.mark.skipif(not DEC_PYTHON.is_file(), reason="DEC interpreter not present")


@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    output = tmp_path_factory.mktemp("dec_probe") / "probe.json"
    result = subprocess.run([str(DEC_PYTHON), str(PROBE), str(output)], cwd=REPO_ROOT,
                            capture_output=True, text=True, timeout=600, check=False)
    assert result.returncode == 0, result.stderr[-3000:]
    return json.loads(output.read_text(encoding="utf-8"))


def _assert_same_predictions(probs, reference):
    probs = np.asarray(probs, dtype=np.float32)
    reference = np.asarray(reference, dtype=np.float32)
    assert probs.shape == reference.shape
    np.testing.assert_array_equal(probs.argmax(axis=1), reference.argmax(axis=1))
    assert_allclose(probs.max(axis=1), reference.max(axis=1), rtol=0, atol=DEC_PROB_ATOL)
    assert_allclose(probs, reference, rtol=0, atol=DEC_PROB_ATOL)


def test_training_rows_are_reproducible_across_batch_compositions(probe):
    full = np.asarray(probe["training"]["probs_full"])
    assert len(full) == 1800
    for batch in probe["training"]["sub_batches"]:
        assert batch["inputs_equal"], batch["size"]
        _assert_same_predictions(batch["probs"], full[batch["rows"]])


def test_training_cluster_counts_unchanged(probe):
    counts = np.bincount(np.asarray(probe["training"]["probs_full"]).argmax(axis=1), minlength=3)
    assert counts.tolist() == [485, 694, 621]


def test_tolerance_detects_a_one_byte_input_change(probe):
    base = np.asarray(probe["sensitivity"]["probs_base"])
    perturbed = np.asarray(probe["sensitivity"]["probs_sbytes_plus_1"])
    row_change = np.abs(perturbed - base).max(axis=1)
    assert (row_change > DEC_PROB_ATOL).all()
    with pytest.raises(AssertionError):
        assert_allclose(perturbed, base, rtol=0, atol=DEC_PROB_ATOL)


@pytest.mark.skipif(not FRESH_RUN.is_dir(), reason="fresh evaluation run not present")
def test_fresh_run_five_sessions_match_their_rows_in_the_thirteen_session_batch(probe):
    run = probe["fresh_run"]
    fresh_ids, snapshot_ids = run["fresh_ids"], run["snapshot_ids"]
    assert len(fresh_ids) == 5 and len(snapshot_ids) == 13
    positions = [snapshot_ids.index(session_id) for session_id in fresh_ids]
    assert positions == sorted(positions), "session order differs between the two batches"

    np.testing.assert_array_equal(np.asarray(run["fresh_raw"]), np.asarray(run["snapshot_raw"])[positions])
    np.testing.assert_array_equal(np.asarray(run["fresh_scaled"]), np.asarray(run["snapshot_scaled"])[positions])
    _assert_same_predictions(run["probs_fresh"], np.asarray(run["probs_snapshot"])[positions])


@pytest.mark.skipif(not FRESH_RUN.is_dir(), reason="fresh evaluation run not present")
def test_recomputed_fresh_run_outputs_match_the_recorded_csvs(probe):
    # The recorded outputs are read only; this confirms the historical observation is reproduced exactly.
    run = probe["fresh_run"]

    def recorded(path, ids):
        with open(path, encoding="utf-8", newline="") as handle:
            rows = {row["session_id"]: row for row in csv.DictReader(handle)}
        return np.array([[float(rows[i][f"cluster_{k}_prob"]) for k in range(3)] for i in ids], dtype=np.float32)

    np.testing.assert_array_equal(
        np.asarray(run["probs_fresh"], dtype=np.float32),
        recorded(FRESH_RUN / "dec" / "dec_results.csv", run["fresh_ids"]),
    )
    np.testing.assert_array_equal(
        np.asarray(run["probs_snapshot"], dtype=np.float32),
        recorded(FRESH_RUN / "pipeline" / "processed" / "dec_results.csv", run["snapshot_ids"]),
    )
