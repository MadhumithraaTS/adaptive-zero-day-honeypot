# Steps 1-3 workbench: data inspection and EDA for the 15-feature DEC retraining.
# Cell-based script ("# %%" cells). Run from the repository root with the DEC interpreter:
#   ml\cowrie_dec_integration_skeleton\.venv-dec-smoke\Scripts\python.exe ml_pipeline\01_eda.py
# Read only: it loads the training CSV and writes only to ml_pipeline/.

# %% Setup
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guard  # noqa: E402

plt = guard._plt()
DATA = Path("model_selection/behavior_features.csv")
REMOVED = ["ct_srv_src", "ct_src_ltm"]
CONFIG = json.loads(Path("ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/artifacts/config.json").read_text())
FEATURES_17 = CONFIG["features"]
FEATURES_15 = [f for f in FEATURES_17 if f not in REMOVED]
LOG_FEATURES = CONFIG["log_features"]

# %% Step 1: load read-only and profile
df = pd.read_csv(DATA, dtype={"session_id": str})
profile = guard.profile(df, target="attack_cat", time_col=None, group_col=None)
print(profile["shape"], profile["traits"])
print("leakage suspects:", profile["leakage_suspects"])

# %% Step 2: required EDA figures
paths = guard.eda_figures(df, target="attack_cat")
print([p.name for p in paths])

# %% Step 2: the 15 inputs in the model's space (after log1p where configured)
model_space = df[FEATURES_15].copy()
for f in LOG_FEATURES:
    model_space[f] = np.log1p(model_space[f].clip(lower=0))
fig, axes = plt.subplots(4, 4, figsize=(13, 10))
for ax, col in zip(axes.ravel(), FEATURES_15):
    ax.hist(model_space[col], bins=30)
    ax.set_title(col + (" (log1p)" if col in LOG_FEATURES else ""), fontsize=9)
axes.ravel()[-1].axis("off")
skew = model_space.skew().abs().sort_values(ascending=False)
guard.fig(2, "model_space_features", fig,
          f"The 15 retained inputs after the model's log1p step. Most remaining skewed: {skew.index[0]} "
          f"(|skew| {skew.iloc[0]:.1f}), {skew.index[1]} ({skew.iloc[1]:.1f}); several features have "
          f"spikes at 0 (sessions with no commands), consistent with the existing model placing all "
          f"no-command sessions in one cluster.")

# %% Step 2: why ct_srv_src / ct_src_ltm are removed
fig, ax = plt.subplots(figsize=(9, 4.5))
cats = sorted(df["attack_cat"].unique())
for i, cat in enumerate(cats):
    vals = df.loc[df["attack_cat"] == cat, "ct_src_ltm"]
    ax.scatter(np.full(len(vals), i) + np.random.default_rng(0).uniform(-0.25, 0.25, len(vals)), vals, s=4)
ax.set_xticks(range(len(cats)))
ax.set_xticklabels(cats, rotation=30, ha="right", fontsize=8)
ax.set_ylabel("ct_src_ltm (= ct_srv_src)")
ax.set_title("Removed feature by generator category")
per_ip = df.groupby("ct_src_ltm")["src_ip"].nunique().max()
single_cat = int((df.groupby("ct_src_ltm")["attack_cat"].nunique() == 1).sum())
guard.fig(2, "ct_by_category", fig,
          f"ct_src_ltm takes 13 values, each from exactly {per_ip} source IP; {single_cat} of the 13 values belong "
          "to a single category (e.g. each zero_day_* category has its own value), so the feature partly "
          "encodes the generator profile. In the Cowrie deployment it equals the log size instead.")

# %% Step 2: redundancy among the 15 retained inputs
corr = model_space.corr()
fig, ax = plt.subplots(figsize=(8, 7))
image = ax.imshow(corr.to_numpy(), vmin=-1, vmax=1, cmap="coolwarm")
ax.set_xticks(range(15))
ax.set_xticklabels(FEATURES_15, rotation=90, fontsize=7)
ax.set_yticks(range(15))
ax.set_yticklabels(FEATURES_15, fontsize=7)
fig.colorbar(image)
ax.set_title("Correlation of the 15 inputs (model space)")
pairs = [(a, b, corr.loc[a, b]) for i, a in enumerate(FEATURES_15) for b in FEATURES_15[i + 1:] if abs(corr.loc[a, b]) > 0.95]
ratio = (df["synack"] / df["tcprtt"]).replace([np.inf, -np.inf], np.nan).dropna()
guard.fig(2, "input_redundancy", fig,
          f"{len(pairs)} pairs of retained inputs correlate above 0.95: "
          + ", ".join(f"{a}/{b} ({c:.2f})" for a, b, c in pairs[:6])
          + f". synack/tcprtt ratio is {ratio.min():.3f}-{ratio.max():.3f} (synack is derived from tcprtt), "
          "so these inputs double-count information; kept unchanged in this controlled experiment.")

# %% Summary printed for the gate report
print("15 features:", FEATURES_15)
print("highly correlated pairs:", [(a, b, round(c, 3)) for a, b, c in pairs])
print("synack/tcprtt ratio range:", ratio.min(), ratio.max())
