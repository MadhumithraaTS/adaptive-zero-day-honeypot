"""Run in the DEC interpreter: load a 15-feature DEC folder and report inference facts as JSON.

Usage: python tests/dec15_probe.py <model_dir> <output_json>
Uses the validation sessions listed in <model_dir>/split_session_ids.json.
"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.inference import CowrieDEC  # noqa: E402
from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.preprocessing import preprocess  # noqa: E402

model_dir, out_path = Path(sys.argv[1]), Path(sys.argv[2])
model = CowrieDEC(str(model_dir))
ids = set(json.loads((model_dir / "split_session_ids.json").read_text())["val"])
data = pd.read_csv(REPO / "model_selection" / "behavior_features.csv", dtype={"session_id": str})
val = data[data["session_id"].isin(ids)].reset_index(drop=True)

X = preprocess(val, model.config, model.scaler, model.medians)
reference = model.model.predict(X, batch_size=len(X), verbose=0)
repeat = model.model.predict(X, batch_size=len(X), verbose=0)
latent = model.encoder.predict(X, verbose=0)
by_batch = {str(bs): model.model.predict(X, batch_size=bs, verbose=0) for bs in (1, 3, 13, 32, 256)}
shifted = val.copy()
shifted[["ct_srv_src", "ct_src_ltm"]] = 3125
without_ct = val.drop(columns=["ct_srv_src", "ct_src_ltm", "ct_dst_ltm", "ct_srv_dst"])

result = {
    "n_rows": int(len(val)),
    "input_shape": list(X.shape),
    "model_input_dim": int(model.model.input_shape[-1]),
    "latent_dim": int(latent.shape[1]),
    "n_outputs": int(reference.shape[1]),
    "max_abs_prob_sum_error": float(np.abs(reference.sum(axis=1) - 1).max()),
    "probabilities_in_unit_interval": bool(((reference >= 0) & (reference <= 1)).all()),
    "repeat_identical": bool(np.array_equal(reference, repeat)),
    "batch_max_abs_diff": {bs: float(np.abs(q - reference).max()) for bs, q in by_batch.items()},
    "batch_assignments_equal": {bs: bool(np.array_equal(q.argmax(1), reference.argmax(1))) for bs, q in by_batch.items()},
    "ct_shift_unchanged": bool(np.array_equal(model.predict(shifted)[2], model.predict(val)[2])),
    "ct_columns_not_required": bool(np.array_equal(model.predict(without_ct)[2], model.predict(val)[2])),
    "weights_finite": bool(all(np.isfinite(w).all() for w in model.model.get_weights())),
    "occupied_clusters": int(len(np.unique(reference.argmax(1)))),
    "config_features": model.config["features"],
    "scaler_n_features_in": int(model.scaler.n_features_in_),
    "scaler_feature_names": [str(f) for f in model.scaler.feature_names_in_],
    "scaler_finite_positive": bool(np.isfinite(model.scaler.mean_).all() and np.isfinite(model.scaler.scale_).all()
                                   and (model.scaler.scale_ > 0).all()),
    "median_features": [str(f) for f in model.medians.index],
    "medians_finite": bool(np.isfinite(model.medians.to_numpy(dtype=float)).all()),
}
out_path.write_text(json.dumps(result))
