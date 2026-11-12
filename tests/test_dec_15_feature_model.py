import hashlib
import json
import subprocess
from pathlib import Path

import numpy as np
import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
V1_DIR = REPO_ROOT / "models" / "dec_15_feature_v1"
V2_DIR = REPO_ROOT / "models" / "dec_15_feature_v2_deterministic"
MODEL_DIRS = [V1_DIR, V2_DIR]
OLD_DIR = REPO_ROOT / "ml" / "cowrie_dec_integration_skeleton" / "ml" / "cowrie_dec" / "artifacts"
DEC_PYTHON = REPO_ROOT / "ml" / "cowrie_dec_integration_skeleton" / ".venv-dec-smoke" / "Scripts" / "python.exe"
PROBE = REPO_ROOT / "tests" / "dec15_probe.py"
REMOVED = ["ct_srv_src", "ct_src_ltm"]
# Probability tolerance for batch-size differences, as justified in test_dec_reproducibility.py.
ATOL = 1e-6

# The 17-feature model and its training data are historical evidence and must never change.
OLD_SHA256 = {
    "config.json": "ac1acab422f6050a97faee2fcdbf8ba6b698a59bfd254769739c9ece2517e8c1",
    "cowrie_dec.weights.h5": "4efd1e976cad37f62ad163dce1170612872bfbba99219d6bf583c227bc8bd0c9",
    "medians.joblib": "e498a3c90d6e3201f433629c216e6c79eea8dcdc227947a9bfa075db182c7e83",
    "scaler.joblib": "d38bb3da7cfd87ec3b67a869aca847d43656890ba386376a6bd3d855db9c8ae5",
}
TRAINING_DATA_SHA256 = "d8d50b6a1461d4d931abc3be0d98903564269e84ce653aad7ee93c53df245148"
# The first 15-feature model (multithreaded K-Means) is kept as evidence alongside the deterministic v2.
V1_SHA256 = {
    "config.json": "1e5ec9fbfc3cecae5fc313f64e0aa43f4e73aeb565ad6ce5c09461c5da069512",
    "cowrie_dec.weights.h5": "0d4d1cf54c6fa75777d207fb2bb4507f3f73ca0128ea2bddf7cc59b767f6ecca",
    "medians.joblib": "136d4e5ddc6b84ec6dee3b45d73a2f5b39747411134095e7efd98b0895888687",
    "scaler.joblib": "819339820391b68b232e65d025480cd94476a08f8a21fa2b00199e81ecae1151",
    "metrics_validation.json": "61a8f402bc650151053ec1d23d2e78e1a3272846c7592a5a81a4924af144c5ef",
    "split_session_ids.json": "67dbdf8d3ef48e5a9022407accce76a7e8a11a14cfc96886e528b52358c3ed30",
}

needs_v1 = pytest.mark.skipif(not (V1_DIR / "config.json").is_file(), reason="models/dec_15_feature_v1 not present")
needs_v2 = pytest.mark.skipif(not (V2_DIR / "config.json").is_file(), reason="models/dec_15_feature_v2_deterministic not present")
model_dirs = pytest.mark.parametrize("model_dir", [pytest.param(d, id=d.name, marks=pytest.mark.skipif(
    not (d / "config.json").is_file(), reason=f"{d.name} not present")) for d in MODEL_DIRS])
needs_dec_python = pytest.mark.skipif(not DEC_PYTHON.is_file(), reason="DEC interpreter not present")


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _configs(model_dir):
    return (json.loads((OLD_DIR / "config.json").read_text(encoding="utf-8")),
            json.loads((model_dir / "config.json").read_text(encoding="utf-8")))


def test_17_feature_artifacts_and_training_data_unchanged():
    for name, digest in OLD_SHA256.items():
        assert _sha256(OLD_DIR / name) == digest, name
    assert _sha256(REPO_ROOT / "model_selection" / "behavior_features.csv") == TRAINING_DATA_SHA256


@model_dirs
def test_exactly_15_features_in_original_order_without_removed_features(model_dir):
    old, new = _configs(model_dir)
    assert len(new["features"]) == 15
    assert new["features"] == [f for f in old["features"] if f not in REMOVED]
    assert not set(REMOVED) & set(new["features"])
    assert new["removed_features"] == REMOVED
    assert new["log_features"] == [f for f in old["log_features"] if f in new["features"]]


@model_dirs
def test_model_dimensions_match_the_feature_list(model_dir):
    old, new = _configs(model_dir)
    assert new["input_dim"] == 15
    assert new["architecture"]["decoder"][-1] == 15
    for key in ("latent_dim", "n_clusters", "alpha"):
        assert new[key] == old[key], key
    centroids = json.loads((model_dir / "cluster_centroids.json").read_text(encoding="utf-8"))
    assert np.asarray(centroids["centroids"]).shape == (new["n_clusters"], new["latent_dim"])


@model_dirs
def test_split_ids_are_disjoint_and_cover_the_training_data(model_dir):
    ids = json.loads((model_dir / "split_session_ids.json").read_text(encoding="utf-8"))
    sets = {name: set(values) for name, values in ids.items()}
    assert sum(len(v) for v in sets.values()) == 1800
    assert not (sets["train"] & sets["val"]) and not (sets["train"] & sets["test"]) and not (sets["val"] & sets["test"])
    meta = json.loads((model_dir / "training_metadata.json").read_text(encoding="utf-8"))
    assert meta["training_rows"] == len(sets["train"])
    assert meta["training_data"]["sha256"] == TRAINING_DATA_SHA256


_probe_cache = {}


@pytest.fixture
def probe(model_dir, tmp_path_factory):
    if model_dir not in _probe_cache:
        out = tmp_path_factory.mktemp("dec15") / "probe.json"
        result = subprocess.run([str(DEC_PYTHON), str(PROBE), str(model_dir), str(out)], cwd=REPO_ROOT,
                                capture_output=True, text=True, timeout=600, check=False)
        assert result.returncode == 0, result.stderr[-3000:]
        _probe_cache[model_dir] = json.loads(out.read_text(encoding="utf-8"))
    return _probe_cache[model_dir]


@model_dirs
@needs_dec_python
def test_new_model_loads_in_dec_environment_with_correct_dimensions(model_dir, probe):
    assert probe["n_rows"] == 270
    assert probe["input_shape"] == [270, 15]
    assert probe["model_input_dim"] == 15
    assert probe["latent_dim"] == 4
    assert probe["n_outputs"] == 3
    assert probe["weights_finite"]


@model_dirs
@needs_dec_python
def test_scaler_and_medians_match_the_15_features(model_dir, probe):
    # Loaded in the DEC environment: the artifacts were pickled with pandas 3 / scikit-learn 1.9.
    _, new = _configs(model_dir)
    assert probe["config_features"] == new["features"]
    assert probe["scaler_n_features_in"] == 15
    assert probe["scaler_feature_names"] == new["features"]
    assert probe["scaler_finite_positive"]
    assert probe["median_features"] == new["features"]
    assert probe["medians_finite"]


@model_dirs
@needs_dec_python
def test_probabilities_are_normalised(model_dir, probe):
    assert probe["probabilities_in_unit_interval"]
    assert probe["max_abs_prob_sum_error"] <= ATOL


@model_dirs
@needs_dec_python
def test_repeated_inference_is_identical(model_dir, probe):
    assert probe["repeat_identical"]


@model_dirs
@needs_dec_python
def test_batch_size_stability(model_dir, probe):
    assert all(probe["batch_assignments_equal"].values()), probe["batch_assignments_equal"]
    assert max(probe["batch_max_abs_diff"].values()) <= ATOL, probe["batch_max_abs_diff"]


@model_dirs
@needs_dec_python
def test_removed_features_have_no_influence(model_dir, probe):
    assert probe["ct_shift_unchanged"]
    assert probe["ct_columns_not_required"]


@needs_v1
def test_v1_model_unchanged():
    for name, digest in V1_SHA256.items():
        assert _sha256(V1_DIR / name) == digest, name


@needs_v1
@needs_v2
def test_v2_differs_from_v1_only_in_trained_weights():
    for name in ("config.json", "scaler.joblib", "medians.joblib", "split_session_ids.json"):
        assert _sha256(V2_DIR / name) == _sha256(V1_DIR / name), name
    v1 = json.loads((V1_DIR / "training_metadata.json").read_text(encoding="utf-8"))
    v2 = json.loads((V2_DIR / "training_metadata.json").read_text(encoding="utf-8"))
    assert v2["hyperparameters"] == v1["hyperparameters"]
    assert v2["features"] == v1["features"]
    assert v2["training_data"]["test_fingerprint"] == v1["training_data"]["test_fingerprint"]


@needs_v2
def test_v2_two_same_seed_runs_were_bit_identical():
    record = json.loads((V2_DIR / "reproducibility.json").read_text(encoding="utf-8"))
    assert record["runs"] == 2
    assert record["weights_identical"] and record["max_weight_diff"] == 0.0
    assert record["kmeans_init_centres_identical"] and record["final_centroids_identical"]
    assert record["soft_assignments_train_plus_val_identical"]
    assert all(record["training_log_identical"].values())
    assert all(record["preprocessing"].values())
