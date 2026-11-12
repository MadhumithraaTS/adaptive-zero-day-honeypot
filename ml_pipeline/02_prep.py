# Steps 4-8 workbench: cleaning, feature table, split, preprocessing for the 15-feature DEC.
# Cell-based script ("# %%" cells). Run from the repository root with the DEC interpreter:
#   ml\cowrie_dec_integration_skeleton\.venv-dec-smoke\Scripts\python.exe ml_pipeline\02_prep.py
# Reads model_selection/behavior_features.csv (read only); writes only to ml_pipeline/.

# %% Setup
import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO))
import guard  # noqa: E402
from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.preprocessing import preprocess  # noqa: E402

plt = guard._plt()
WORK = HERE / "work"
PREP_DIR = WORK / "preprocess"
SPLIT_FILES = {name: WORK / f"{name}.pkl" for name in ("train", "val", "test")}
if any(p.exists() for p in SPLIT_FILES.values()):
    raise SystemExit("Split already exists in ml_pipeline/work; refusing to re-split (the test set is frozen).")

CONFIG_17 = json.loads((REPO / "ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/artifacts/config.json").read_text())
REMOVED = ["ct_srv_src", "ct_src_ltm"]
FEATURES = [f for f in CONFIG_17["features"] if f not in REMOVED]
LOG_FEATURES = [f for f in CONFIG_17["log_features"] if f in FEATURES]
assert len(FEATURES) == 15 and not set(REMOVED) & set(FEATURES)
assert FEATURES == [f for f in CONFIG_17["features"] if f in FEATURES]  # original relative order
SEED = 42

raw = pd.read_csv(REPO / "model_selection/behavior_features.csv", dtype={"session_id": str})

# %% Step 4: data cleaning (rules are checks; nothing is expected to change)
values = raw[FEATURES]
rules = {
    "missing values": int(values.isna().sum().sum()),
    "+/-inf values": int(np.isinf(values.to_numpy(dtype=float)).sum()),
    "negative values in log1p features": int((raw[LOG_FEATURES] < 0).sum().sum()),
    "negative values in other inputs": int((raw[[f for f in FEATURES if f not in LOG_FEATURES]] < 0).sum().sum()),
    "duplicate session_id": int(raw["session_id"].duplicated().sum()),
    "duplicate 15-feature vectors": int(raw.duplicated(subset=FEATURES).sum()),
}
fig, ax = plt.subplots(figsize=(8, 3.5))
ax.barh(list(rules), list(rules.values()))
ax.set_xlabel("rows / cells affected")
ax.set_xlim(0, max(1, max(rules.values())))
ax.set_title("Step 4 cleaning checks (before = after: no rule fired)")
guard.fig(4, "cleaning_checks", fig,
          "Every cleaning rule found " + ("nothing to fix" if not any(rules.values()) else str(rules))
          + " in 1,800 rows, so the data is used unchanged: no rows dropped, no values imputed, and the "
          "original training's clip-at-0 before log1p is a no-op.")
print("cleaning:", rules)
assert not any(rules.values()), rules

# %% Step 5: data engineering - one row per session: id, 15 inputs, reference column
table = raw[["session_id", *FEATURES, "attack_cat"]].copy()
assert table["session_id"].is_unique and len(table) == 1800

# %% Step 6: stratified split, test set frozen by the guard
train, val, test = guard.split(table, target="attack_cat", test_size=0.15, val_size=0.15, seed=SEED)
WORK.mkdir(parents=True, exist_ok=True)
for name, frame in (("train", train), ("val", val), ("test", test)):
    frame.to_pickle(SPLIT_FILES[name])
shares = pd.DataFrame({name: frame["attack_cat"].value_counts(normalize=True)
                       for name, frame in (("train", train), ("val", val), ("test", test))})
fig, ax = plt.subplots(figsize=(9, 4))
shares.plot.bar(ax=ax)
ax.set_ylabel("share of split")
ax.set_title(f"Category share per split (train {len(train)}, validation {len(val)}, test {len(test)})")
ax.tick_params(axis="x", rotation=30, labelsize=8)
spread = float((shares.max(axis=1) - shares.min(axis=1)).max())
guard.fig(6, "split_balance", fig,
          f"Stratified split: {len(train)} / {len(val)} / {len(test)} sessions with every category's share "
          f"within {spread:.1%} across splits, so validation and test represent the same mix as training.")
print("split sizes:", len(train), len(val), len(test))

# %% Step 7: feature engineering - none (controlled experiment keeps the 15 inputs as they are)

# %% Step 8: preprocessing fitted on train only, applied through the inference function
train_inputs = train[FEATURES].replace([np.inf, -np.inf], np.nan)
medians = train_inputs.median()
logged = train_inputs.fillna(medians).copy()
for f in LOG_FEATURES:
    logged[f] = np.log1p(logged[f].clip(lower=0))
scaler = StandardScaler().fit(logged[FEATURES])
config = {
    "model_name": "DEC",
    "input_dim": len(FEATURES),
    "latent_dim": CONFIG_17["latent_dim"],
    "n_clusters": CONFIG_17["n_clusters"],
    "alpha": CONFIG_17.get("alpha", 1.0),
    "features": FEATURES,
    "log_features": LOG_FEATURES,
    "removed_features": REMOVED,
    "preprocessing": {"missing_value_strategy": "median (train split)", "log_transform": "log1p",
                      "scaler": "StandardScaler (train split)"},
}
PREP_DIR.mkdir(parents=True, exist_ok=True)
joblib.dump(scaler, PREP_DIR / "scaler.joblib")
joblib.dump(medians, PREP_DIR / "medians.joblib")
(PREP_DIR / "config.json").write_text(json.dumps(config, indent=4))

# The inference function must reproduce the training transform exactly.
X_train = preprocess(train, config, scaler, medians)
assert X_train.shape == (len(train), 15)
assert np.allclose(X_train, scaler.transform(logged[FEATURES]), atol=1e-6)
X_val = preprocess(val, config, scaler, medians)
assert np.isfinite(X_train).all() and np.isfinite(X_val).all()

fig, axes = plt.subplots(4, 4, figsize=(13, 10))
for i, (ax, col) in enumerate(zip(axes.ravel(), FEATURES)):
    ax.hist(X_train[:, i], bins=30, alpha=0.6, density=True, label="train")
    ax.hist(X_val[:, i], bins=30, alpha=0.6, density=True, label="validation")
    ax.set_title(col, fontsize=9)
axes.ravel()[0].legend(fontsize=7)
axes.ravel()[-1].axis("off")
val_mean = np.abs(X_val.mean(axis=0)).max()
guard.fig(8, "scaled_inputs_train_vs_val", fig,
          f"The 15 inputs after log1p and the train-fitted scaler: training has mean 0 / sd 1 per feature and "
          f"validation, transformed with the same fitted objects, stays close (largest validation mean "
          f"{val_mean:.2f} sd), so the scaler did not see validation or test data.")
print("features:", FEATURES)
print("scaler mean range:", scaler.mean_.min(), scaler.mean_.max(), "| finite:", np.isfinite(scaler.scale_).all())
