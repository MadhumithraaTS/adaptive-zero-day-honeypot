# Step 13 (validation only): error analysis for the provisional primary model, Autoencoder + K-Means.
# Cell-based script ("# %%" cells). Run from the repository root with the DEC interpreter:
#   ml\cowrie_dec_integration_skeleton\.venv-dec-smoke\Scripts\python.exe ml_pipeline\04_validation_error_analysis.py
# Read-only: no training, no fitting, no saved model changes. Loads the train and validation splits only;
# the test split is never loaded. Writes reports/validation_error_analysis_ae_kmeans_20261110/ only.
# The 15-feature Autoencoder + K-Means model has no saved per-session outputs (see the inventory cell), so
# its per-session analysis is reported as unsupported; model-independent checks use the saved data, and
# DEC v2 (saved) is analysed only as the research comparison.

# %% Setup
import hashlib
import json
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
OUT = REPO / "reports" / "validation_error_analysis_ae_kmeans_20261110"
if OUT.exists():
    raise SystemExit(f"{OUT} already exists; refusing to overwrite.")
V1, V2 = REPO / "models" / "dec_15_feature_v1", REPO / "models" / "dec_15_feature_v2_deterministic"

config, scaler, medians = dec15.load_preprocessing()
FEATURES = config["features"]
train, val = dec15.load_split("train"), dec15.load_split("val")
X_val = dec15.transform(val, config, scaler, medians)
cat_val = val["attack_cat"].to_numpy()
summary = {"scope": "validation split only (270 sessions); test split not loaded", "n_validation": len(val)}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# %% 1. Artifact inventory: what exists for the 15-feature Autoencoder + K-Means model
ae_v1 = json.loads((V1 / "metrics_validation.json").read_text())["baseline_autoencoder_kmeans"]
ae_v2 = json.loads((V2 / "metrics_validation.json").read_text())["baseline_autoencoder_kmeans"]
summary["ae_kmeans_inventory"] = {
    "saved_aggregate_metrics": {
        "models/dec_15_feature_v1/metrics_validation.json": {k: ae_v1[k] for k in ae_v1 if k.startswith(("validation", "ari", "nmi"))},
        "models/dec_15_feature_v2_deterministic/metrics_validation.json": "identical aggregate values (v2 run, single-threaded K-Means)",
        "aggregate_values_identical_v1_v2": all(ae_v1[k] == ae_v2[k] for k in ae_v1),
    },
    "not_saved": [
        "pre-DEC encoder weights (DEC refinement overwrites the encoder; only the refined DEC encoder is saved)",
        "K-Means centres fitted on the pre-DEC latent space",
        "per-session validation cluster assignments",
        "per-session validation embeddings",
        "any probability or confidence output (K-Means gives hard assignments; none was defined or saved)",
    ],
    "not_applicable_older_artifacts": {
        "model_selection/cowrie_encoder.keras": "17 inputs (with ct_*), 2-d latent, trained on all 1,800 rows incl. validation",
        "model_selection/cowrie_autoencoder.keras": "17 inputs, 2-d latent",
        "model_selection/dec_artifacts/encoder.weights.h5": "24 inputs (UNSW-NB15 notebook)",
        "model_selection/checkpoints/kmeans_best.pkl": "KMeans with 24 inputs (UNSW-NB15 notebook)",
    },
    "artifact_sha256": {str(p.relative_to(REPO)).replace("\\", "/"): sha256(p) for p in
                        (V1 / "metrics_validation.json", V2 / "metrics_validation.json")},
}

# %% 2. The no-command group (model-independent)
no_cmd = (val["spkts"] == 0).to_numpy()
signature_cols = ["spkts", "sbytes", "sload", "ackdat"]
summary["no_command_group"] = {
    "definition": "spkts == 0 (client sent no data packets after the handshake)",
    "n": int(no_cmd.sum()),
    "same_rows_have_zero": {c: bool(np.array_equal(no_cmd, (val[c] == 0).to_numpy())) for c in signature_cols},
    "by_generator_category": val.loc[no_cmd, "attack_cat"].value_counts().to_dict(),
    "share_of_each_category": (val.assign(n=no_cmd).groupby("attack_cat")["n"].mean().round(3).to_dict()),
    "cluster_size_119_in_saved_aggregates": {"ae_kmeans": ae_v1["validation_clusters"],
                                             "dec_v2": json.loads((V2 / "metrics_validation.json").read_text())
                                             ["dec_15_v2_deterministic"]["validation_clusters"]},
}

# %% 3. Input-space outliers (train-fitted scaler; model-independent)
abs_z = np.abs(X_val)
max_z = abs_z.max(1)
top = np.argsort(-max_z)[:8]
summary["input_space_outliers"] = {
    "measure": "largest |z| across the 15 scaled inputs (log1p + train-fitted StandardScaler)",
    "sessions_max_abs_z_above_3": int((max_z > 3).sum()),
    "sessions_max_abs_z_above_4": int((max_z > 4).sum()),
    "top_sessions": [{"session_id": val["session_id"].iat[i], "attack_cat": cat_val[i],
                      "max_abs_z": round(float(max_z[i]), 2), "feature": FEATURES[int(abs_z[i].argmax())],
                      "raw_value": float(val[FEATURES[int(abs_z[i].argmax())]].iat[i]),
                      "train_median": float(train[FEATURES[int(abs_z[i].argmax())]].median())} for i in top],
    "outliers_by_category_above_3": val.loc[max_z > 3, "attack_cat"].value_counts().to_dict(),
}

# %% 4. Generator artefacts and residual leakage checks (model-independent)
lookup = {}
for f in FEATURES:
    cats_per_value = train.groupby(f)["attack_cat"].nunique()
    single = set(cats_per_value[cats_per_value == 1].index)
    seen = val[f].isin(cats_per_value.index)
    hit = val[f].isin(single)
    value_to_cat = train[train[f].isin(single)].groupby(f)["attack_cat"].first()
    correct = val.loc[hit, f].map(value_to_cat) == val.loc[hit, "attack_cat"]
    lookup[f] = {"val_exact_value_seen_in_train": round(float(seen.mean()), 3),
                 "val_value_unique_to_one_train_category": round(float(hit.mean()), 3),
                 "lookup_category_correct_share_of_val": round(float(correct.sum() / len(val)), 3)}
ratio = (val["synack"] / val["tcprtt"])
dpkts_table = pd.crosstab(val["dpkts"], val["attack_cat"])
summary["generator_artefacts"] = {
    "exact_value_lookup": lookup,
    "synack_over_tcprtt": {"min": float(ratio.min()), "max": float(ratio.max())},
    "tcprtt_minus_synack_minus_ackdat_max_abs": float((val["tcprtt"] - val["synack"] - val["ackdat"]).abs().max()),
    "dpkts_distinct_values": sorted(int(v) for v in val["dpkts"].unique()),
    "dpkts_by_category": {str(k): v for k, v in dpkts_table.to_dict(orient="index").items()},
    "spkts_distinct_values": sorted(int(v) for v in val["spkts"].unique()),
}

# %% 5. Generator-category profiles on validation (descriptive; generator labels, not ground truth)
profile_cols = ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "tcprtt"]
summary["category_medians_validation"] = val.groupby("attack_cat")[profile_cols].median().round(4).to_dict(orient="index")

# %% 6. DEC v2 (research comparison only; its outputs are saved, inference only)
from sklearn.metrics import silhouette_samples  # noqa: E402

from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.inference import CowrieDEC  # noqa: E402

dec = CowrieDEC(str(V2))
q = dec.model.predict(X_val, batch_size=256, verbose=0)
dec_labels, dec_conf = q.argmax(1), q.max(1)
sil = silhouette_samples(X_val, dec_labels)
srt = np.sort(q, axis=1)
gap = srt[:, -1] - srt[:, -2]
summary["dec_v2_research_comparison"] = {
    "clusters": {str(k): int(v) for k, v in zip(*np.unique(dec_labels, return_counts=True))},
    "cluster_equal_to_no_command_group": {str(c): bool(np.array_equal(dec_labels == c, no_cmd)) for c in range(3)},
    "per_session_input_silhouette": {"negative": int((sil < 0).sum()), "below_0.1": int((sil < 0.1).sum()),
                                     "by_cluster_mean": {str(c): round(float(sil[dec_labels == c].mean()), 3) for c in range(3)}},
    "confidence_below_0.7": int((dec_conf < 0.7).sum()),
    "top1_top2_gap_below_0.2": int((gap < 0.2).sum()),
    "negative_silhouette_by_category": val.loc[sil < 0, "attack_cat"].value_counts().to_dict(),
    "contingency_category_by_cluster": {str(k): v for k, v in
                                        pd.crosstab(val["attack_cat"], dec_labels).to_dict(orient="index").items()},
    "note": "DEC is the research comparison, not the primary model; these numbers say nothing per-session about AE+K-Means.",
}

# %% Figures (saved to the new report folder only)
OUT.mkdir(parents=True)
figures = {}

fig, ax = plt.subplots(figsize=(8, 3.8))
share = pd.Series(summary["no_command_group"]["share_of_each_category"]).sort_values()
ax.barh(share.index, share.values)
ax.set_xlabel("share of the category's validation sessions with spkts = 0")
ax.set_title(f"No-command sessions: {int(no_cmd.sum())} of 270 validation sessions")
fig.savefig(OUT / "13_no_command_share_by_category.png", dpi=120, bbox_inches="tight")
plt.close(fig)
figures["13_no_command_share_by_category.png"] = (
    f"{int(no_cmd.sum())} validation sessions send no data (spkts, sbytes, sload and ackdat all 0). Every saved "
    "model has a validation cluster of exactly that size; the group mixes all 8 generator categories, so any "
    "cluster that captures it cannot separate those categories.")

fig, ax = plt.subplots(figsize=(7, 3.8))
ax.hist(max_z, bins=40)
ax.axvline(3, color="tab:red", linestyle="--")
ax.set_xlabel("largest |z| over the 15 scaled inputs")
ax.set_ylabel("validation sessions")
ax.set_title("Input-space outliers (train-fitted scaler)")
fig.savefig(OUT / "13_input_outliers.png", dpi=120, bbox_inches="tight")
plt.close(fig)
figures["13_input_outliers.png"] = (
    f"{int((max_z > 3).sum())} validation sessions have at least one input more than 3 training SDs from the "
    "training mean; these are the sessions most likely to sit far from any centre, whatever the model.")

fig, ax = plt.subplots(figsize=(8, 4))
lk = pd.DataFrame(lookup).T.sort_values("lookup_category_correct_share_of_val")
ax.barh(lk.index, lk["lookup_category_correct_share_of_val"], label="exact-value lookup gives the right category")
ax.barh(lk.index, lk["val_value_unique_to_one_train_category"], alpha=0.4, label="value unique to one train category")
ax.set_xlabel("share of 270 validation sessions")
ax.set_title("Exact-value lookup from training: residual generator fingerprints")
ax.legend(fontsize=8)
fig.savefig(OUT / "13_exact_value_lookup.png", dpi=120, bbox_inches="tight")
plt.close(fig)
figures["13_exact_value_lookup.png"] = (
    "For each input, the share of validation sessions whose exact value was seen in only one training category, "
    "and how often that lookup names the right generator category. High shares would indicate a generator "
    "fingerprint like the removed ct_* features.")

summary["figures"] = figures
(OUT / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
print(json.dumps(summary, indent=1, default=str))
