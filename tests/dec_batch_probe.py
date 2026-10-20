"""Helper run with the DEC interpreter by test_dec_reproducibility.py (not collected by pytest).

Runs inference with the saved artifacts on identical inputs in different batch compositions
and writes the raw float32 outputs to a JSON file. It never fits, saves or modifies anything
except the JSON output path given on the command line.
"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.inference import get_model  # noqa: E402
from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.preprocessing import preprocess  # noqa: E402

TRAINING_ROWS = REPO_ROOT / "model_selection" / "behavior_features.csv"
FRESH_RUN = REPO_ROOT / "data" / "evaluation_runs" / "fresh_20261019_224335"
SUB_BATCH_SIZES = [1, 2, 3, 5, 13, 31, 256]
SEED = 0


def _infer(model, frame, batch_size):
    X = preprocess(frame, model.config, model.scaler, model.medians)
    return X, model.model.predict(X, verbose=0, batch_size=batch_size)


def _as_lists(array):
    return np.asarray(array, dtype=np.float64).tolist()


def main(output_path):
    model = get_model()
    features = model.config["features"]
    result = {"features": features}

    # Training rows: one full batch vs random sub-batches of the same rows.
    train = pd.read_csv(TRAINING_ROWS)
    X_full, p_full = _infer(model, train, batch_size=len(train))
    rng = np.random.default_rng(SEED)
    sub_batches = []
    for size in SUB_BATCH_SIZES:
        idx = np.sort(rng.choice(len(train), size=size, replace=False))
        X_sub, p_sub = _infer(model, train.iloc[idx].reset_index(drop=True), batch_size=size)
        sub_batches.append({
            "size": size,
            "rows": idx.tolist(),
            "inputs_equal": bool(np.array_equal(X_sub, X_full[idx])),
            "probs": _as_lists(p_sub),
        })
    result["training"] = {"probs_full": _as_lists(p_full), "sub_batches": sub_batches}

    # Sensitivity: a one-byte change in sbytes must move outputs by more than the tolerance.
    sample = train.iloc[:64].reset_index(drop=True)
    _, p_base = _infer(model, sample, batch_size=len(sample))
    perturbed = sample.copy()
    perturbed["sbytes"] = perturbed["sbytes"] + 1
    _, p_pert = _infer(model, perturbed, batch_size=len(sample))
    result["sensitivity"] = {"probs_base": _as_lists(p_base), "probs_sbytes_plus_1": _as_lists(p_pert)}

    # The fresh evaluation case: five sessions alone vs the same sessions inside the 13-session snapshot.
    fresh_csv = FRESH_RUN / "fresh" / "fresh_behavior_features.csv"
    snapshot_csv = FRESH_RUN / "pipeline" / "parsed" / "behavior_features.csv"
    if fresh_csv.is_file() and snapshot_csv.is_file():
        fresh = pd.read_csv(fresh_csv, converters={"session_id": str})
        snapshot = pd.read_csv(snapshot_csv, converters={"session_id": str})
        X_fresh, p_fresh = _infer(model, fresh, batch_size=32)
        X_snap, p_snap = _infer(model, snapshot, batch_size=32)
        result["fresh_run"] = {
            "fresh_ids": fresh["session_id"].tolist(),
            "snapshot_ids": snapshot["session_id"].tolist(),
            "fresh_raw": _as_lists(fresh[features].to_numpy(dtype=float)),
            "snapshot_raw": _as_lists(snapshot[features].to_numpy(dtype=float)),
            "fresh_scaled": _as_lists(X_fresh),
            "snapshot_scaled": _as_lists(X_snap),
            "probs_fresh": _as_lists(p_fresh),
            "probs_snapshot": _as_lists(p_snap),
        }

    Path(output_path).write_text(json.dumps(result), encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1])
