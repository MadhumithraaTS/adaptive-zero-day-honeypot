# Steps 10-12 (revisited before Gate C): one controlled deterministic DEC run.
# Cell-based script ("# %%" cells). Run from the repository root with the DEC interpreter:
#   ml\cowrie_dec_integration_skeleton\.venv-dec-smoke\Scripts\python.exe ml_pipeline\03b_model_deterministic.py
# Identical to 03_model.py's training except that K-Means runs single-threaded. Trains twice with the
# same seed to check reproducibility. Uses train and validation only; the test split is not loaded.
# Writes models/dec_15_feature_v2_deterministic/, ml_pipeline/work/step12_v2_results.json and figures.

# %% Setup
import hashlib
import json
import platform
import shutil
import sys
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO))
import dec15  # noqa: E402
import guard  # noqa: E402

plt = guard._plt()
OUT = REPO / "models" / "dec_15_feature_v2_deterministic"
V1 = REPO / "models" / "dec_15_feature_v1"
if OUT.exists():
    raise SystemExit(f"{OUT} already exists; refusing to overwrite a saved model.")

config, scaler, medians = dec15.load_preprocessing()
FEATURES = config["features"]
train, val = dec15.load_split("train"), dec15.load_split("val")
v1_ids = json.loads((V1 / "split_session_ids.json").read_text())
assert train["session_id"].tolist() == v1_ids["train"], "training IDs differ from dec_15_feature_v1"
assert val["session_id"].tolist() == v1_ids["val"], "validation IDs differ from dec_15_feature_v1"
X_train = dec15.transform(train, config, scaler, medians)
X_val = dec15.transform(val, config, scaler, medians)
ref_val = val["attack_cat"].to_numpy()
v1_metrics = json.loads((V1 / "metrics_validation.json").read_text())
results = {"split_sizes": {"train": len(train), "validation": len(val)}, "split_ids_match_v1": True}


# %% Preprocessing: refit on train twice with the 02_prep.py rules and compare with the stored artifacts
def refit_preprocessing(frame):
    from sklearn.preprocessing import StandardScaler
    inputs = frame[FEATURES].replace([np.inf, -np.inf], np.nan)
    fitted_medians = inputs.median()
    logged = inputs.fillna(fitted_medians).copy()
    for f in config["log_features"]:
        logged[f] = np.log1p(logged[f].clip(lower=0))
    return StandardScaler().fit(logged[FEATURES]), fitted_medians


refits = [refit_preprocessing(train) for _ in range(2)]
results["preprocessing"] = {
    "refits_identical_to_each_other": bool(all(np.array_equal(getattr(refits[0][0], a), getattr(refits[1][0], a))
                                               for a in ("mean_", "scale_", "var_"))
                                           and refits[0][1].equals(refits[1][1])),
    "refit_identical_to_stored": bool(all(np.array_equal(getattr(refits[0][0], a), getattr(scaler, a))
                                          for a in ("mean_", "scale_", "var_")) and refits[0][1].equals(medians)),
}
print("preprocessing:", results["preprocessing"])

# %% Step 9: K-Means baseline on the 15 scaled inputs, single-threaded, fitted twice
from sklearn.cluster import KMeans  # noqa: E402

baseline_runs = []
for _ in range(2):
    with dec15.kmeans_threads(True):
        km = KMeans(n_clusters=3, random_state=dec15.SEED, n_init=20).fit(X_train)
        baseline_runs.append((km.cluster_centers_.copy(), km.predict(X_val)))
km_val = baseline_runs[0][1]
results["baseline_kmeans_inputs"] = {
    "validation_input_space": dec15.cluster_metrics(X_val, km_val),
    "validation_clusters": {str(k): int(v) for k, v in zip(*np.unique(km_val, return_counts=True))},
    **dec15.reference_agreement(km_val, ref_val),
    "two_runs_identical_centres": bool(np.array_equal(baseline_runs[0][0], baseline_runs[1][0])),
    "v1_recorded_validation_input_space": v1_metrics["baseline_kmeans_inputs"]["validation_input_space"],
}
print("baseline K-Means:", results["baseline_kmeans_inputs"])

# %% Step 10: two DEC runs, same seed, single-threaded K-Means (run A is kept)
dec, encoder, log = dec15.train_dec(X_train, X_eval=X_val, kmeans_single_thread=True)
dec_b, encoder_b, log_b = dec15.train_dec(X_train, X_eval=X_val, kmeans_single_thread=True)
X_both = np.vstack([X_train, X_val])
q_a, q_b = dec15.soft_assign(dec, X_both), dec15.soft_assign(dec_b, X_both)
weights_a, weights_b = dec.get_weights(), dec_b.get_weights()


def max_diff(a, b):
    return float(np.max(np.abs(np.asarray(a, dtype=float) - np.asarray(b, dtype=float))))


log_keys = ("ae_loss_per_epoch", "ae_val_loss_per_epoch", "kmeans_init_inertia", "dec_iterations", "dec_converged",
            "dec_label_change_checks", "dec_loss_per_iteration")
reproducibility = {
    "runs": 2,
    "seed": dec15.SEED,
    "weights_identical": bool(len(weights_a) == len(weights_b)
                              and all(np.array_equal(a, b) for a, b in zip(weights_a, weights_b))),
    "max_weight_diff": max(max_diff(a, b) for a, b in zip(weights_a, weights_b)),
    "per_layer_max_weight_diff": [max_diff(a, b) for a, b in zip(weights_a, weights_b)],
    "kmeans_init_centres_identical": bool(np.array_equal(log["kmeans_init_centers"], log_b["kmeans_init_centers"])),
    "kmeans_init_labels_identical": bool(np.array_equal(log["kmeans_init_labels"], log_b["kmeans_init_labels"])),
    "final_centroids_identical": bool(np.array_equal(dec.get_layer("clustering").get_weights()[0],
                                                     dec_b.get_layer("clustering").get_weights()[0])),
    "soft_assignments_train_plus_val_identical": bool(np.array_equal(q_a, q_b)),
    "max_soft_assignment_diff": max_diff(q_a, q_b),
    "hard_assignments_train_plus_val_identical": bool(np.array_equal(q_a.argmax(1), q_b.argmax(1))),
    "ae_kmeans_validation_labels_identical": bool(np.array_equal(log["eval_init_labels"], log_b["eval_init_labels"])),
    "training_log_identical": {k: log[k] == log_b[k] if not isinstance(log[k], np.ndarray) else
                               bool(np.array_equal(log[k], log_b[k])) for k in log_keys},
    "preprocessing": results["preprocessing"],
    "baseline_kmeans_two_runs_identical": results["baseline_kmeans_inputs"]["two_runs_identical_centres"],
}
results["reproducibility"] = reproducibility
print("reproducibility:", json.dumps(reproducibility, indent=1))
print("DEC iterations:", log["dec_iterations"], "converged:", log["dec_converged"], "seconds:", log["total_seconds"])

ae_val = log["eval_init_labels"]
results["baseline_autoencoder_kmeans"] = {
    "validation_input_space": dec15.cluster_metrics(X_val, ae_val),
    "validation_latent_space": dec15.cluster_metrics(log["eval_latent_init"], ae_val),
    "validation_clusters": {str(k): int(v) for k, v in zip(*np.unique(ae_val, return_counts=True))},
    **dec15.reference_agreement(ae_val, ref_val),
    "v1_recorded_validation_input_space": v1_metrics["baseline_autoencoder_kmeans"]["validation_input_space"],
}

checks = log["dec_label_change_checks"]
results["convergence"] = {
    "iterations": log["dec_iterations"],
    "max_iterations": dec15.HYPERPARAMETERS["dec_maxiter"],
    "converged": log["dec_converged"],
    "tolerance": dec15.HYPERPARAMETERS["dec_tol"],
    "label_change_checks": checks,
    "last_label_change_fraction": checks[-1]["label_change"] if checks else None,
    "last_label_change_sessions": int(round(checks[-1]["label_change"] * len(train))) if checks else None,
    "kl_loss_first": log["dec_loss_first"],
    "kl_loss_last": log["dec_loss_last"],
}

fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 3.8))
ax1.plot(log["ae_loss_per_epoch"], label="train (90%)")
ax1.plot(log["ae_val_loss_per_epoch"], label="Keras validation_split (10%)")
ax1.set_xlabel("epoch")
ax1.set_ylabel("MSE")
ax1.set_title("Autoencoder pre-training")
ax1.legend(fontsize=8)
ax2.plot(log["dec_loss_per_iteration"])
ax2.set_xlabel("DEC iteration")
ax2.set_ylabel("KL divergence")
ax2.set_title("DEC refinement")
ax3.plot([c["iteration"] for c in checks], [100 * c["label_change"] for c in checks], marker="o")
ax3.axhline(100 * dec15.HYPERPARAMETERS["dec_tol"], color="tab:red", linestyle="--", label="stopping tolerance")
ax3.set_xlabel("DEC iteration")
ax3.set_ylabel("% of training labels changed")
ax3.set_title("Label changes between target updates")
ax3.legend(fontsize=8)
guard.fig(10, "v2_deterministic_training_curves", fig,
          f"Deterministic run (single-threaded K-Means): autoencoder MSE {log['ae_loss_per_epoch'][0]:.3f} -> "
          f"{log['ae_loss_per_epoch'][-1]:.3f}; DEC ran {log['dec_iterations']} iterations "
          f"({'converged' if log['dec_converged'] else 'stopped at the 500-iteration limit'}), last check "
          f"{100 * checks[-1]['label_change']:.2f}% of training labels changing vs the "
          f"{100 * dec15.HYPERPARAMETERS['dec_tol']:.1f}% tolerance. A second same-seed run gave "
          f"{'identical' if reproducibility['weights_identical'] else 'different'} weights.")

# %% Step 10: save run A (new folder only) and reload through the existing inference loader
OUT.mkdir(parents=True)
shutil.copyfile(dec15.PREP_DIR / "scaler.joblib", OUT / "scaler.joblib")
shutil.copyfile(dec15.PREP_DIR / "medians.joblib", OUT / "medians.joblib")
config_out = dict(config)
config_out["architecture"] = {"encoder": [32, 16, 4], "decoder": [16, 32, len(FEATURES)]}
(OUT / "config.json").write_text(json.dumps(config_out, indent=4))
dec.save_weights(str(OUT / "cowrie_dec.weights.h5"))
centroids = dec.get_layer("clustering").get_weights()[0]
(OUT / "cluster_centroids.json").write_text(json.dumps({"latent_dim": int(centroids.shape[1]),
                                                        "centroids": centroids.tolist()}, indent=2))
shutil.copyfile(V1 / "split_session_ids.json", OUT / "split_session_ids.json")

from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.inference import CowrieDEC  # noqa: E402

loaded = CowrieDEC(str(OUT))
q_val = dec15.soft_assign(dec, X_val)
results["reload_via_CowrieDEC_identical_same_batch"] = bool(
    np.array_equal(loaded.model.predict(X_val, batch_size=256, verbose=0), q_val))
print("reloaded via CowrieDEC, identical predictions at the same batch size:",
      results["reload_via_CowrieDEC_identical_same_batch"])

# %% Step 11: hyperparameter tuning - none by design (only the K-Means threading changed)

# %% Step 12: validation evaluation of the deterministic model
z_val = encoder.predict(X_val, verbose=0)
val_labels = q_val.argmax(1)
conf_val = q_val.max(1)
q_train = dec15.soft_assign(dec, X_train)
results["dec_15_v2_deterministic"] = {
    "validation_latent_space": dec15.cluster_metrics(z_val, val_labels),
    "validation_input_space": dec15.cluster_metrics(X_val, val_labels),
    "validation_clusters": {str(k): int(v) for k, v in zip(*np.unique(val_labels, return_counts=True))},
    "validation_confidence": {"mean": float(conf_val.mean()), "median": float(np.median(conf_val)),
                              "min": float(conf_val.min()), "max": float(conf_val.max()),
                              "share_below_0.7": float(np.mean(conf_val < 0.7))},
    "train_clusters": {str(k): int(v) for k, v in zip(*np.unique(q_train.argmax(1), return_counts=True))},
    "train_confidence_mean": float(q_train.max(1).mean()),
    **dec15.reference_agreement(val_labels, ref_val),
}

# Previous 15-feature DEC (v1), rescored here on the same rows and preprocessing
v1_model = CowrieDEC(str(V1))
q_v1 = v1_model.model.predict(X_val, batch_size=256, verbose=0)
z_v1 = v1_model.encoder.predict(X_val, verbose=0)
v1_labels = q_v1.argmax(1)
mapping, agreement_val, table_val = dec15.align_clusters(v1_labels, val_labels)
_, agreement_train, _ = dec15.align_clusters(dec15.soft_assign(v1_model.model, X_train).argmax(1), q_train.argmax(1))
results["dec_15_v1_rescored"] = {
    "validation_latent_space": dec15.cluster_metrics(z_v1, v1_labels),
    "validation_input_space": dec15.cluster_metrics(X_val, v1_labels),
    "validation_clusters": {str(k): int(v) for k, v in zip(*np.unique(v1_labels, return_counts=True))},
    "validation_confidence": {"mean": float(q_v1.max(1).mean()), "median": float(np.median(q_v1.max(1))),
                              "min": float(q_v1.max(1).min()), "max": float(q_v1.max(1).max()),
                              "share_below_0.7": float(np.mean(q_v1.max(1) < 0.7))},
    **dec15.reference_agreement(v1_labels, ref_val),
    "matches_v1_recorded_input_space": bool(np.allclose(
        [dec15.cluster_metrics(X_val, v1_labels)[k] for k in ("silhouette", "davies_bouldin")],
        [v1_metrics["dec_15"]["validation_input_space"][k] for k in ("silhouette", "davies_bouldin")], atol=1e-9)),
}
results["v1_vs_v2"] = {
    "v2_to_v1_cluster_mapping": mapping,
    "agreement_after_alignment_validation": agreement_val,
    "agreement_after_alignment_train": agreement_train,
    "contingency_v1_rows_v2_cols_validation": table_val.tolist(),
    "max_abs_prob_diff_validation_after_alignment": max_diff(
        q_v1, q_val[:, [k for k, _ in sorted(((b, a) for b, a in mapping.items()), key=lambda t: t[1])]]),
}

# Integrity and stability checks (train + validation only)
q_full = dec15.soft_assign(dec, X_both, batch_size=len(X_both))
q_repeat = dec15.soft_assign(dec, X_both, batch_size=len(X_both))
batch_diffs = {}
for bs in (1, 3, 13, 32, 256):
    qb = dec15.soft_assign(dec, X_both, batch_size=bs)
    batch_diffs[bs] = {"max_abs_prob_diff": float(np.max(np.abs(qb - q_full))),
                       "assignments_equal": bool(np.array_equal(qb.argmax(1), q_full.argmax(1)))}
results["checks"] = {
    "weights_finite": bool(all(np.isfinite(w).all() for w in weights_a)),
    "latent_dim": int(z_val.shape[1]),
    "n_clusters_output": int(q_full.shape[1]),
    "occupied_clusters_validation": int(len(np.unique(val_labels))),
    "max_abs_prob_sum_error": float(np.max(np.abs(q_full.sum(1) - 1))),
    "repeat_inference_identical": bool(np.array_equal(q_full, q_repeat)),
    "batch_size_stability": batch_diffs,
}
print("checks:", json.dumps(results["checks"], indent=1))

# %% Step 12 figures
names = ["K-Means\n(15 inputs)", "AE + K-Means\n(v2 start)", "DEC v1\n(multithreaded)", "DEC v2\n(deterministic)"]
entries = [results["baseline_kmeans_inputs"], results["baseline_autoencoder_kmeans"],
           results["dec_15_v1_rescored"], results["dec_15_v2_deterministic"]]
sil = [e["validation_input_space"]["silhouette"] for e in entries]
dbi = [e["validation_input_space"]["davies_bouldin"] for e in entries]
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 3.8))
ax1.bar(names, sil)
ax1.set_title("Validation Silhouette, 15-d input space (higher better)")
ax2.bar(names, dbi, color="tab:orange")
ax2.set_title("Validation Davies-Bouldin (lower better)")
for ax in (ax1, ax2):
    ax.tick_params(axis="x", labelsize=8)
guard.fig(12, "v2_deterministic_validation_metrics", fig,
          f"Same 270 validation sessions, same 15-feature input space: Silhouette K-Means {sil[0]:.3f}, "
          f"AE+K-Means {sil[1]:.3f}, DEC v1 {sil[2]:.3f}, DEC v2 {sil[3]:.3f}; Davies-Bouldin {dbi[0]:.3f} / "
          f"{dbi[1]:.3f} / {dbi[2]:.3f} / {dbi[3]:.3f}. Latent-space scores are reported separately and are not "
          "comparable with these.")

fig, ax = plt.subplots(figsize=(5.5, 4.5))
image = ax.imshow(table_val, cmap="Greens")
for (i, j), v in np.ndenumerate(table_val):
    ax.text(j, i, str(v), ha="center", va="center")
ax.set_xlabel("DEC v2 cluster")
ax.set_ylabel("DEC v1 cluster")
ax.set_xticks(range(3))
ax.set_yticks(range(3))
fig.colorbar(image)
ax.set_title("Validation: v1 vs v2 assignments")
guard.fig(12, "v2_vs_v1_alignment", fig,
          f"v2 cluster IDs matched to v1 by the best one-to-one pairing {mapping}; after matching, "
          f"{agreement_val:.1%} of validation and {agreement_train:.1%} of training sessions get the same cluster. "
          "The two models differ only in K-Means threading.")


# %% Save metadata and results
def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


import keras  # noqa: E402
import sklearn  # noqa: E402
import tensorflow as tf  # noqa: E402
import threadpoolctl  # noqa: E402

state = json.loads((HERE / ".guard_state.json").read_text())
log_saved = {k: v for k, v in log.items() if k not in ("kmeans_init_labels", "kmeans_init_centers",
                                                         "eval_latent_init", "eval_init_labels")}
metadata = {
    "model": "DEC, 15 features (ct_srv_src and ct_src_ltm removed), single-threaded K-Means",
    "features": FEATURES,
    "removed_features": config["removed_features"],
    "hyperparameters": dec15.HYPERPARAMETERS,
    "change_from_dec_15_feature_v1": "K-Means initialisation (and the K-Means baseline) run under "
                                     "threadpoolctl.threadpool_limits(limits=1); everything else identical",
    "training_rows": len(train),
    "training_data": {"file": "model_selection/behavior_features.csv",
                      "sha256": sha256(REPO / "model_selection/behavior_features.csv"),
                      "split": "same split as dec_15_feature_v1 (guard.split stratified on attack_cat, test 0.15, "
                               "validation 0.15, seed 42)",
                      "test_fingerprint": state["test_fingerprint"]},
    "training_log": log_saved,
    "reproducibility": {k: reproducibility[k] for k in ("runs", "weights_identical", "max_weight_diff",
                                                        "final_centroids_identical",
                                                        "hard_assignments_train_plus_val_identical")},
    "environment": {"python": platform.python_version(), "tensorflow": tf.__version__, "keras": keras.__version__,
                    "scikit_learn": sklearn.__version__, "threadpoolctl": threadpoolctl.__version__,
                    "numpy": np.__version__, "pandas": pd.__version__},
    "artifact_sha256": {p.name: sha256(p) for p in sorted(OUT.iterdir()) if p.is_file()},
    "note": "Reproducible candidate. Not deployed. No test-set results here (test split frozen for step 14).",
}
(OUT / "training_metadata.json").write_text(json.dumps(metadata, indent=2))
(OUT / "reproducibility.json").write_text(json.dumps(reproducibility, indent=2))
(OUT / "metrics_validation.json").write_text(json.dumps(results, indent=2))
(HERE / "work" / "step12_v2_results.json").write_text(json.dumps(results, indent=2))
print("saved", sorted(p.name for p in OUT.iterdir()))
