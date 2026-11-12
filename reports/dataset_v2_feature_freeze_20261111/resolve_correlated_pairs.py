"""Task 16, Phase 2: evidence for the two correlated feature pairs (descriptive only; no models, no scores).

    .venv/Scripts/python.exe reports/dataset_v2_feature_freeze_20261111/resolve_correlated_pairs.py

For each pair, on logged-in sessions (one per interaction), using the Task 15 statistics unchanged
(Kruskal-Wallis epsilon^2 = H/(n-1), OLS residual epsilon^2, 200 interaction bootstraps, seed 0):
  - Spearman rho per split (consistency);
  - what each member adds beyond the other: epsilon^2 of the OLS residual of log1p(member) on the other;
  - the derived quantity that separates them (repeated commands per line; mean bytes per line), as a mechanism check;
  - the same with brute force excluded (brute force runs at most one command).
Train is the evidence split; validation is reported only to show the same direction. No validation score selects anything.
Output: evidence/correlated_pairs.json
"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
SEED = 0


def load(split):
    d = DS / "extraction" / split / "run1"
    X = pd.read_csv(d / "model_features.csv")
    M = pd.read_csv(d / "session_metadata.csv", keep_default_na=False)
    lab = pd.read_csv(DS / "labels" / f"{split}_session_labels.csv", dtype=str)
    df = pd.concat([M[["session_ref"]], X], axis=1).merge(lab, on="session_ref", validate="one_to_one")
    df = df[df.role == "logged_in"].reset_index(drop=True)
    df["category"] = df.attack_cat
    return df


def eps2(values, cats):
    sub = pd.DataFrame({"v": values, "c": cats}).dropna()
    if sub.v.nunique() < 2:
        return None
    h, _ = stats.kruskal(*[g.v.values for _, g in sub.groupby("c")])
    return float(h / (len(sub) - 1))


def resid(y, x):
    sl, ic, *_ = stats.linregress(x, y)
    return y - (ic + sl * x)


def with_ci(fn, frame, n_boot=200):
    rng = np.random.RandomState(SEED)
    point = fn(frame)
    vals = [fn(frame.iloc[rng.randint(0, len(frame), len(frame))].reset_index(drop=True)) for _ in range(n_boot)]
    vals = [v for v in vals if v is not None]
    return {"epsilon2": point, "ci95": [float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))]}


MEASURES = {
    # pair 1: input_line_count vs unique_command_names (sessions with >= 1 line, so both are defined and > 0)
    "input_line_count": lambda f: eps2(f.input_line_count.values, f.category.values),
    "unique_command_names": lambda f: eps2(f.unique_command_names.values, f.category.values),
    "unique_names_residual_after_line_count": lambda f: eps2(
        resid(np.log1p(f.unique_command_names.values), np.log1p(f.input_line_count.values)), f.category.values),
    "line_count_residual_after_unique_names": lambda f: eps2(
        resid(np.log1p(f.input_line_count.values), np.log1p(f.unique_command_names.values)), f.category.values),
    "repeated_name_lines_(lines_minus_unique)": lambda f: eps2((f.input_line_count - f.unique_command_names).values, f.category.values),
    # pair 2: input_bytes_total vs input_line_max_bytes, and both against the retained count
    "input_bytes_total": lambda f: eps2(f.input_bytes_total.values, f.category.values),
    "input_line_max_bytes": lambda f: eps2(f.input_line_max_bytes.values, f.category.values),
    "bytes_total_residual_after_line_count": lambda f: eps2(
        resid(np.log1p(f.input_bytes_total.values), np.log1p(f.input_line_count.values)), f.category.values),
    "max_bytes_residual_after_bytes_total": lambda f: eps2(
        resid(np.log1p(f.input_line_max_bytes.values), np.log1p(f.input_bytes_total.values)), f.category.values),
    "bytes_total_residual_after_max_bytes": lambda f: eps2(
        resid(np.log1p(f.input_bytes_total.values), np.log1p(f.input_line_max_bytes.values)), f.category.values),
    "mean_bytes_per_line_(bytes_total/line_count)": lambda f: eps2((f.input_bytes_total / f.input_line_count).values, f.category.values),
}

out = {"note": "logged-in sessions with >= 1 input line; train = evidence, validation = consistency only", "splits": {}}
for split in ("train", "validation"):
    L = load(split)
    s = {"n_logged_in": len(L)}
    for subset, fr in (("all_categories", L[L.input_line_count > 0]),
                       ("excluding_brute_force", L[(L.input_line_count > 0) & (L.category != "brute_force")])):
        fr = fr.reset_index(drop=True)
        s[subset] = {"n": len(fr), "measures": {k: with_ci(fn, fr) for k, fn in MEASURES.items()}}
    s["spearman"] = {
        "input_line_count~unique_command_names": float(stats.spearmanr(L.input_line_count, L.unique_command_names).correlation),
        "input_bytes_total~input_line_max_bytes": float(stats.spearmanr(L.input_bytes_total, L.input_line_max_bytes, nan_policy="omit").correlation),
        "input_line_count~input_bytes_total": float(stats.spearmanr(L.input_line_count, L.input_bytes_total).correlation),
        "input_line_count~input_line_max_bytes": float(stats.spearmanr(L.input_line_count, L.input_line_max_bytes, nan_policy="omit").correlation),
    }
    w = L[L.input_line_count > 0]
    s["structure"] = {
        "unique_le_lines_all": bool((L.unique_command_names <= L.input_line_count).all()),
        "share_unique_equals_lines": float((w.unique_command_names == w.input_line_count).mean()),
        "lines_minus_unique_by_category_mean": w.assign(d=w.input_line_count - w.unique_command_names).groupby("category").d.mean().round(3).to_dict(),
        "mean_bytes_per_line_median_by_category": (w.input_bytes_total / w.input_line_count).groupby(w.category).median().round(2).to_dict(),
        "max_bytes_median_by_category": w.groupby("category").input_line_max_bytes.median().to_dict(),
    }
    out["splits"][split] = s
(HERE / "evidence").mkdir(exist_ok=True)
(HERE / "evidence" / "correlated_pairs.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
for split, s in out["splits"].items():
    print(split, s["spearman"], s["structure"]["share_unique_equals_lines"])
    for subset in ("all_categories", "excluding_brute_force"):
        for k, v in s[subset]["measures"].items():
            print(f"  {subset:22s} {k:46s} {v['epsilon2']:.3f} [{v['ci95'][0]:.3f}, {v['ci95'][1]:.3f}]")
    print(" ", s["structure"])
