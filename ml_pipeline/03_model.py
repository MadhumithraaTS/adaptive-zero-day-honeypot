# Steps 9-12 workbench: baselines, DEC training, (no) tuning, validation evaluation.
# Cell-based script ("# %%" cells). Run from the repository root with the DEC interpreter:
#   ml\cowrie_dec_integration_skeleton\.venv-dec-smoke\Scripts\python.exe ml_pipeline\03_model.py
# Uses train and validation only; the frozen test split is not scored here.
# Writes ml_pipeline/work/step12_results.json, ml_pipeline/figures/, and models/dec_15_feature_v1/.

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
OUT = REPO / "models" / "dec_15_feature_v1"
OLD_DIR = REPO / "ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/artifacts"
if OUT.exists():
    raise SystemExit(f"{OUT} already exists; refusing to overwrite a saved model.")

config, scaler, medians = dec15.load_preprocessing()
FEATURES = config["features"]
train, val = dec15.load_split("train"), dec15.load_split("val")
X_train = dec15.transform(train, config, scaler, medians)
X_val = dec15.transform(val, config, scaler, medians)
ref_train, ref_val = train["attack_cat"].to_numpy(), val["attack_cat"].to_numpy()
results = {"split_sizes": {"train": len(train), "validation": len(val)}}

# %% Step 9: baseline - K-Means (K=3) on the 15 scaled inputs, fitted on train
from sklearn.cluster import KMeans  # noqa: E402

km = KMeans(n_clusters=3, random_state=dec15.SEED, n_init=20).fit(X_train)
km_val = km.predict(X_val)
results["baseline_kmeans_inputs"] = {
    "validation_input_space": dec15.cluster_metrics(X_val, km_val),
    "validation_clusters": {str(k): int(v) for k, v in zip(*np.unique(km_val, return_counts=True))},
    **dec15.reference_agreement(km_val, ref_val),
}
print("baseline K-Means:", results["baseline_kmeans_inputs"])

# %% Step 10: DEC training (run A is kept; run B, same seed, checks reproducibility)
dec, encoder, log = dec15.train_dec(X_train, X_eval=X_val)
dec_b, _, log_b = dec15.train_dec(X_train)
weights_a, weights_b = dec.get_weights(), dec_b.get_weights()
training_reproducible = len(weights_a) == len(weights_b) and all(np.array_equal(a, b) for a, b in zip(weights_a, weights_b))
max_weight_diff = max(float(np.max(np.abs(a - b))) for a, b in zip(weights_a, weights_b))
print("training reproducible:", training_reproducible, "max weight diff:", max_weight_diff)
print("DEC iterations:", log["dec_iterations"], "converged:", log["dec_converged"], "seconds:", log["total_seconds"])

ae_val = log["eval_init_labels"]
results["baseline_autoencoder_kmeans"] = {
    "validation_input_space": dec15.cluster_metrics(X_val, ae_val),
    "validation_latent_space": dec15.cluster_metrics(log["eval_latent_init"], ae_val),
    "validation_clusters": {str(k): int(v) for k, v in zip(*np.unique(ae_val, return_counts=True))},
    **dec15.reference_agreement(ae_val, ref_val),
}

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 3.8))
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
guard.fig(10, "training_curves", fig,
          f"Autoencoder MSE fell from {log['ae_loss_per_epoch'][0]:.3f} to {log['ae_loss_per_epoch'][-1]:.3f} "
          f"(held-back 10%: {log['ae_val_loss_per_epoch'][-1]:.3f}); DEC ran {log['dec_iterations']} iterations "
          f"({'converged' if log['dec_converged'] else 'stopped at the 500-iteration limit'}), KL loss "
          f"{log['dec_loss_first']:.4f} -> {log['dec_loss_last']:.4f}. A second run with the same seed gave "
          f"{'identical' if training_reproducible else 'different'} weights.")

# %% Step 10: save artifacts (new folder only) and reload through the existing inference loader
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
split_ids = {name: dec15.load_split(name)["session_id"].tolist() for name in ("train", "val", "test")}
(OUT / "split_session_ids.json").write_text(json.dumps(split_ids, indent=1))

from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.inference import CowrieDEC  # noqa: E402

loaded = CowrieDEC(str(OUT))
c_loaded, conf_loaded, q_loaded = loaded.predict(val)
q_val = dec15.soft_assign(dec, X_val)
reload_identical = bool(np.array_equal(q_loaded, q_val))
print("reloaded via CowrieDEC, identical predictions:", reload_identical)

# %% Step 11: hyperparameter tuning - none by design (controlled experiment)

# %% Step 12: validation evaluation
z_val = encoder.predict(X_val, verbose=0)
val_labels = q_val.argmax(1)
conf_val = q_val.max(1)
q_train = dec15.soft_assign(dec, X_train)
results["dec_15"] = {
    "validation_latent_space": dec15.cluster_metrics(z_val, val_labels),
    "validation_input_space": dec15.cluster_metrics(X_val, val_labels),
    "validation_clusters": {str(k): int(v) for k, v in zip(*np.unique(val_labels, return_counts=True))},
    "validation_confidence": {"mean": float(conf_val.mean()), "min": float(conf_val.min()), "max": float(conf_val.max())},
    "train_clusters": {str(k): int(v) for k, v in zip(*np.unique(q_train.argmax(1), return_counts=True))},
    "train_confidence_mean": float(q_train.max(1).mean()),
    **dec15.reference_agreement(val_labels, ref_val),
}

# Integrity and stability checks (train + validation only)
X_both = np.vstack([X_train, X_val])
q_full = dec15.soft_assign(dec, X_both, batch_size=len(X_both))
q_repeat = dec15.soft_assign(dec, X_both, batch_size=len(X_both))
batch_diffs = {}
for bs in (1, 2, 3, 5, 13, 31, 64, 256):
    qb = dec15.soft_assign(dec, X_both, batch_size=bs)
    batch_diffs[bs] = {"max_abs_prob_diff": float(np.max(np.abs(qb - q_full))),
                       "assignments_equal": bool(np.array_equal(qb.argmax(1), q_full.argmax(1)))}
srt = np.sort(q_full, axis=1)
results["checks"] = {
    "weights_finite": bool(all(np.isfinite(w).all() for w in weights_a)),
    "scaler_finite": bool(np.isfinite(scaler.mean_).all() and np.isfinite(scaler.scale_).all()),
    "inputs_finite": bool(np.isfinite(X_both).all()),
    "latent_dim": int(z_val.shape[1]),
    "n_clusters_output": int(q_full.shape[1]),
    "max_abs_prob_sum_error": float(np.max(np.abs(q_full.sum(1) - 1))),
    "repeat_inference_identical": bool(np.array_equal(q_full, q_repeat)),
    "batch_size_stability": batch_diffs,
    "min_top1_top2_gap": float((srt[:, -1] - srt[:, -2]).min()),
    "training_reproducible_same_seed": training_reproducible,
    "max_weight_diff_between_runs": max_weight_diff,
    "reload_via_CowrieDEC_identical": reload_identical,
}
print("checks:", json.dumps(results["checks"], indent=1))

# Old 17-feature model vs new 15-feature model on all 1,800 original sessions (descriptive)
raw = pd.read_csv(REPO / "model_selection/behavior_features.csv", dtype={"session_id": str})
old = CowrieDEC(str(OLD_DIR))
old_c, old_conf, _ = old.predict(raw)
new_c, new_conf, _ = loaded.predict(raw)
mapping, agreement, table = dec15.align_clusters(old_c, new_c)
in_val = raw["session_id"].isin(set(val["session_id"])).to_numpy()
_, agreement_val, _ = dec15.align_clusters(old_c[in_val], new_c[in_val])
ct_shift = raw.copy()
ct_shift[["ct_srv_src", "ct_src_ltm"]] = 3125
new_shift = loaded.predict(ct_shift)[2]
old_shift_c = old.predict(ct_shift)[0]
results["old_vs_new_all_1800"] = {
    "old_clusters": {str(k): int(v) for k, v in zip(*np.unique(old_c, return_counts=True))},
    "new_clusters": {str(k): int(v) for k, v in zip(*np.unique(new_c, return_counts=True))},
    "old_confidence": {"mean": float(old_conf.mean()), "min": float(old_conf.min()), "max": float(old_conf.max())},
    "new_confidence": {"mean": float(new_conf.mean()), "min": float(new_conf.min()), "max": float(new_conf.max())},
    "new_to_old_cluster_mapping": mapping,
    "agreement_after_alignment_all": agreement,
    "agreement_after_alignment_validation_rows": agreement_val,
    "contingency_old_rows_new_cols": table.tolist(),
    "old_vs_attack_cat": dec15.reference_agreement(old_c, raw["attack_cat"]),
    "new_vs_attack_cat": dec15.reference_agreement(new_c, raw["attack_cat"]),
    "ct_set_to_3125_new_model_probabilities_unchanged": bool(np.array_equal(new_shift, loaded.predict(raw)[2])),
    "ct_set_to_3125_old_model_changed_pct": float(100 * np.mean(old_shift_c != old_c)),
}
profiles = {}
for name, labels in (("old", old_c), ("new_aligned", np.array([mapping[int(c)] for c in new_c]))):
    profiles[name] = raw.assign(cluster=labels).groupby("cluster")[FEATURES].mean().round(3).to_dict(orient="index")
results["old_vs_new_all_1800"]["cluster_feature_means"] = {k: {str(c): v for c, v in p.items()} for k, p in profiles.items()}
print("old vs new:", {k: v for k, v in results["old_vs_new_all_1800"].items() if k not in ("cluster_feature_means",)})

# %% Step 12 figures
names = ["K-Means\n(15 inputs)", "AE + K-Means\n(DEC start)", "DEC\n(15 features)"]
entries = [results["baseline_kmeans_inputs"], results["baseline_autoencoder_kmeans"], results["dec_15"]]
sil = [e["validation_input_space"]["silhouette"] for e in entries]
dbi = [e["validation_input_space"]["davies_bouldin"] for e in entries]
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 3.8))
ax1.bar(names, sil)
ax1.set_title("Validation Silhouette, 15-d input space (higher better)")
ax2.bar(names, dbi, color="tab:orange")
ax2.set_title("Validation Davies-Bouldin (lower better)")
for ax in (ax1, ax2):
    ax.tick_params(axis="x", labelsize=8)
guard.fig(12, "validation_metrics", fig,
          f"On the 270 validation sessions, measured in the same 15-feature space: Silhouette K-Means "
          f"{sil[0]:.3f}, AE+K-Means {sil[1]:.3f}, DEC {sil[2]:.3f}; Davies-Bouldin {dbi[0]:.3f} / {dbi[1]:.3f} / "
          f"{dbi[2]:.3f}. DEC's latent-space Silhouette is {results['dec_15']['validation_latent_space']['silhouette']:.3f}; "
          "latent and input scores are not comparable with each other.")

comp = pd.crosstab(pd.Series(ref_val, name="attack_cat"), pd.Series(val_labels, name="DEC cluster"))
fig, ax = plt.subplots(figsize=(6.5, 5))
image = ax.imshow(comp.to_numpy(), cmap="Blues")
ax.set_xticks(range(comp.shape[1]))
ax.set_xticklabels([f"cluster {c}" for c in comp.columns])
ax.set_yticks(range(comp.shape[0]))
ax.set_yticklabels(comp.index, fontsize=8)
for (i, j), v in np.ndenumerate(comp.to_numpy()):
    ax.text(j, i, str(v), ha="center", va="center", fontsize=8)
fig.colorbar(image)
ax.set_title("Validation: DEC clusters vs generator category")
guard.fig(12, "cluster_composition", fig,
          f"How the 270 validation sessions' generator categories fall into the 3 DEC clusters (ARI "
          f"{results['dec_15']['ari_vs_attack_cat']:.3f}, NMI {results['dec_15']['nmi_vs_attack_cat']:.3f}); with 8 "
          "categories and 3 clusters some categories must share a cluster. Descriptive only.")

fig, ax = plt.subplots(figsize=(7, 3.8))
ax.hist(old_conf, bins=40, alpha=0.6, label="old 17-feature")
ax.hist(new_conf, bins=40, alpha=0.6, label="new 15-feature")
ax.set_xlabel("confidence (largest soft-assignment probability)")
ax.set_title("Confidence on the 1,800 original sessions")
ax.legend()
o, n = results["old_vs_new_all_1800"]["old_confidence"], results["old_vs_new_all_1800"]["new_confidence"]
guard.fig(12, "confidence_old_vs_new", fig,
          f"Confidence on all 1,800 sessions: old mean {o['mean']:.3f} (min {o['min']:.3f}), new mean {n['mean']:.3f} "
          f"(min {n['min']:.3f}). The new model was fitted on 1,260 of these rows and the old on all 1,800, so this "
          "mixes the feature change with training-set and random-seed differences.")

fig, ax = plt.subplots(figsize=(5.5, 4.5))
image = ax.imshow(table, cmap="Greens")
for (i, j), v in np.ndenumerate(table):
    ax.text(j, i, str(v), ha="center", va="center")
ax.set_xlabel("new 15-feature cluster")
ax.set_ylabel("old 17-feature cluster")
ax.set_xticks(range(3))
ax.set_yticks(range(3))
fig.colorbar(image)
ax.set_title("Old vs new assignments (1,800 sessions)")
guard.fig(12, "old_vs_new_alignment", fig,
          f"Cluster IDs are arbitrary, so new clusters were matched to old ones by the best one-to-one pairing "
          f"{mapping}; after matching, {agreement:.1%} of all sessions (and {agreement_val:.1%} of validation "
          "sessions) get the same cluster from both models.")

# %% Save metadata and results
def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


import joblib  # noqa: E402,F401
import keras  # noqa: E402
import sklearn  # noqa: E402
import tensorflow as tf  # noqa: E402

state = json.loads((HERE / ".guard_state.json").read_text())
log_saved = {k: v for k, v in log.items() if k not in ("kmeans_init_labels", "kmeans_init_centers",
                                                         "eval_latent_init", "eval_init_labels")}
metadata = {
    "model": "DEC, 15 features (ct_srv_src and ct_src_ltm removed)",
    "features": FEATURES,
    "removed_features": config["removed_features"],
    "hyperparameters": dec15.HYPERPARAMETERS,
    "training_rows": len(train),
    "training_data": {"file": "model_selection/behavior_features.csv",
                      "sha256": sha256(REPO / "model_selection/behavior_features.csv"),
                      "split": "guard.split stratified on attack_cat, test 0.15, validation 0.15, seed 42",
                      "test_fingerprint": state["test_fingerprint"]},
    "training_log": log_saved,
    "reproducibility": {"second_run_identical_weights": training_reproducible,
                        "max_weight_diff_between_runs": max_weight_diff},
    "environment": {"python": platform.python_version(), "tensorflow": tf.__version__, "keras": keras.__version__,
                    "scikit_learn": sklearn.__version__, "numpy": np.__version__, "pandas": pd.__version__},
    "artifact_sha256": {p.name: sha256(p) for p in sorted(OUT.iterdir()) if p.is_file()},
    "note": "Exploratory controlled retraining. Not deployed. No test-set results here (test split frozen for step 14).",
}
(OUT / "training_metadata.json").write_text(json.dumps(metadata, indent=2))
(OUT / "metrics_validation.json").write_text(json.dumps(results, indent=2))
(HERE / "work" / "step12_results.json").write_text(json.dumps(results, indent=2))
print("saved", sorted(p.name for p in OUT.iterdir()))
