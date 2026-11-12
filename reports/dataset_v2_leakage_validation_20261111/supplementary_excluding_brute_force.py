"""Supplementary to analyze_leakage_v2.py (not part of the Task 11 protocol): the same epsilon^2 (200 interaction
bootstraps) and depth-3 single-feature balanced accuracy (GroupKFold(5) by interaction) on logged-in sessions
WITHOUT the brute_force category (chance 1/5), to separate brute-force "no input" effects from content/timing effects
among the five command-running categories. Also repeated on sessions without the Cowrie `find / -name id_rsa` command.

    .venv/Scripts/python.exe reports/dataset_v2_leakage_validation_20261111/supplementary_excluding_brute_force.py
Output: tables/supplementary_excluding_brute_force.csv
"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.metrics import balanced_accuracy_score
from sklearn.model_selection import GroupKFold
from sklearn.tree import DecisionTreeClassifier

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
from scripts import extract_features_v2 as x2  # noqa: E402

DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
F = x2.MODEL_FEATURES
SEED = 0
np.random.seed(SEED)


def load(split):
    d = DS / "extraction" / split / "run1"
    X = pd.read_csv(d / "model_features.csv")
    M = pd.read_csv(d / "session_metadata.csv", keep_default_na=False)
    lab = pd.read_csv(DS / "labels" / f"{split}_session_labels.csv", dtype=str)
    df = pd.concat([M[["session_ref"]], X], axis=1).merge(lab, on="session_ref", validate="one_to_one")
    df = df[df.role == "logged_in"].copy()
    df["group"], df["category"] = df.interaction_id, df.attack_cat
    man = {f"{split}:{json.loads(l)['index']}": json.loads(l)
           for l in (DS / "runs" / split / "manifest.jsonl").read_text(encoding="utf-8").splitlines()}
    df["has_find"] = df.group.map(lambda g: any(c["command"].startswith("find / -name id_rsa") for c in man[g]["command_log"] if c["sent"]))
    return df.reset_index(drop=True)


def kruskal_eps(frame, feat):
    sub = frame[[feat, "category"]].dropna()
    groups = [g[feat].values for _, g in sub.groupby("category")]
    if len(groups) < 2 or sub[feat].nunique() < 2:
        return None
    h, _ = stats.kruskal(*groups)
    return float(h / (len(sub) - 1))


def boot(frame, feat, n=200):
    groups = frame.group.unique()
    by = frame.groupby("group").groups
    vals = [kruskal_eps(frame.loc[np.concatenate([by[g] for g in np.random.choice(groups, len(groups))])], feat) for _ in range(n)]
    vals = [v for v in vals if v is not None]
    return (float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))) if vals else (None, None)


def single_ba(frame, feat):
    x = frame[feat].values.astype(float)
    m = np.isnan(x)
    X = np.column_stack([np.where(m, -1e9, x), m.astype(float)])
    y, g = frame.category.values, frame.group.values
    pred = np.empty(len(y), dtype=object)
    for tr, te in GroupKFold(n_splits=5).split(X, y, g):
        pred[te] = DecisionTreeClassifier(max_depth=3, random_state=SEED).fit(X[tr], y[tr]).predict(X[te])
    return float(balanced_accuracy_score(y, pred))


rows = []
for split in ("train", "validation"):
    L = load(split)
    for subset, fr in (("no_brute_force", L[L.category != "brute_force"]),
                       ("no_brute_force_no_find", L[(L.category != "brute_force") & ~L.has_find])):
        fr = fr.reset_index(drop=True)
        for f in F:
            e = kruskal_eps(fr, f)
            lo, hi = boot(fr, f) if e is not None else (None, None)
            rows.append({"split": split, "subset": subset, "feature": f, "n": len(fr), "missing_pct": 100 * fr[f].isna().mean(),
                         "epsilon2": e, "ci_lo": lo, "ci_hi": hi, "single_feature_ba": single_ba(fr, f), "chance": 0.2})
out = pd.DataFrame(rows)
out.to_csv(HERE / "tables" / "supplementary_excluding_brute_force.csv", index=False, float_format="%.4f")
print(out[out.subset == "no_brute_force"].pivot(index="feature", columns="split", values=["epsilon2", "single_feature_ba", "missing_pct"]).round(3))
print(out[(out.subset == "no_brute_force_no_find") & (out.split == "train")][["feature", "epsilon2", "single_feature_ba"]].round(3))
