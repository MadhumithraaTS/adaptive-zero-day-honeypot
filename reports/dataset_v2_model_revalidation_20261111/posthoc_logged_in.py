"""Task 17 post-hoc analysis (no model fitting): quality, stability and category structure WITHOUT the failed-login block.

    ml\\cowrie_dec_integration_skeleton\\.venv-dec-smoke\\Scripts\\python.exe reports\\dataset_v2_model_revalidation_20261111\\posthoc_logged_in.py

All-row metrics are dominated by the failed-login rows (identical vectors after imputation). This script re-scores
the saved seed-42 assignments on logged-in sessions only (one per interaction, so independent), and on the five
command-running categories (brute force excluded), using the saved train-fitted preprocessing. Labels post hoc only.
Output: outputs/posthoc_logged_in.json, outputs/category_by_cluster_logged_in_validation_k*.csv
"""
import json
import math
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import adjusted_rand_score as ARI, normalized_mutual_info_score as NMI
from sklearn.metrics import silhouette_score, davies_bouldin_score, calinski_harabasz_score

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
OUT = HERE / "outputs"
DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
MODELS = REPO / "models" / "dataset_v2_revalidation_20261111"
cfg = json.loads((MODELS / "ae_kmeans_k7_seed42" / "config.json").read_text())
FEATURES, LOGF = cfg["features"], cfg["log_features"]
scaler = joblib.load(MODELS / "ae_kmeans_k7_seed42" / "scaler.joblib")
medians = joblib.load(MODELS / "ae_kmeans_k7_seed42" / "medians.joblib")


def X_of(split):
    X = pd.read_csv(DS / "extraction" / split / "run1" / "model_features.csv")
    M = pd.read_csv(DS / "extraction" / split / "run1" / "session_metadata.csv", keep_default_na=False)
    x = X[FEATURES].astype(float).fillna(pd.Series(medians))
    for f in LOGF:
        x[f] = np.log1p(x[f].clip(lower=0))
    return pd.DataFrame(scaler.transform(x[FEATURES]), index=M.session_ref)


def boot_ci(fn, n_rows, n=200, seed=0):
    rng = np.random.RandomState(seed)
    vals = [fn(rng.randint(0, n_rows, n_rows)) for _ in range(n)]
    return [float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))]


def internal(Xs, lab):
    keep = pd.Series(lab).map(pd.Series(lab).value_counts()).values >= 2
    Xs, lab = Xs[keep], lab[keep]
    if len(np.unique(lab)) < 2:
        return None
    return {"n": int(len(lab)), "clusters": int(len(np.unique(lab))), "silhouette": float(silhouette_score(Xs, lab)),
            "davies_bouldin": float(davies_bouldin_score(Xs, lab)), "calinski_harabasz": float(calinski_harabasz_score(Xs, lab))}


out = {}
Xsp = {s: X_of(s) for s in ("train", "validation")}
for k in (3, 7):
    seeds = pd.read_csv(OUT / f"validation_assignments_all_seeds_k{k}.csv")
    for kind, col in (("ae_kmeans", "ae_kmeans_cluster"), ("dec", "dec_cluster")):
        res = {}
        for split in ("train", "validation"):
            a = pd.read_csv(OUT / f"assignments_embeddings_k{k}_seed42_{split}.csv")
            X = Xsp[split].loc[a.session_ref].values
            li = (a.role == "logged_in").values
            nb = li & (a.attack_cat_posthoc_only != "brute_force").values
            lab, cat = a[col].values, a.attack_cat_posthoc_only.values
            failed_cluster = pd.Series(lab[~li]).value_counts()
            r = {"failed_rows_in_their_modal_cluster_share": float(failed_cluster.max() / (~li).sum()),
                 "failed_modal_cluster": int(failed_cluster.idxmax()),
                 "logged_in_rows_in_failed_modal_cluster": int((lab[li] == failed_cluster.idxmax()).sum())}
            for name, m in (("logged_in", li), ("logged_in_excluding_brute_force", nb)):
                L, C = lab[m], cat[m]
                r[name] = {"rows": int(m.sum()), "occupied_clusters": int(len(np.unique(L))), "internal_input_space": internal(X[m], L),
                           "ari_vs_category": float(ARI(C, L)), "nmi_vs_category": float(NMI(C, L)),
                           "ari_ci95_bootstrap": boot_ci(lambda p: ARI(C[p], L[p]), int(m.sum()))}
                if kind == "dec":
                    conf = a.dec_confidence.values[m]
                    r[name]["dec_confidence"] = {"mean": float(conf.mean()), "median": float(np.median(conf)), "min": float(conf.min()),
                                                 "share_below_0.7": float((conf < 0.7).mean())}
                if split == "validation":
                    t = pd.crosstab(C, L)
                    norm = t.div(t.sum(axis=1), axis=0)
                    prior = pd.Series(C).value_counts(normalize=True)
                    lift = t.div(t.sum(axis=0), axis=1).div(prior, axis=0)
                    r[name]["max_category_share_in_any_cluster"] = norm.max(axis=1).round(3).to_dict()
                    r[name]["cluster_purity"] = t.max(axis=0).div(t.sum(axis=0)).round(3).to_dict()
                    r[name]["max_lift_by_category"] = lift.max(axis=1).round(2).to_dict()
                    if name == "logged_in":
                        pd.concat({"count": t, "row_share": norm.round(3)}, axis=1).to_csv(OUT / f"category_by_cluster_logged_in_validation_k{k}_{kind}.csv")
            res[split] = r
        cols = [c for c in seeds.columns if c.startswith(kind + "_seed")]
        a = pd.read_csv(OUT / f"assignments_embeddings_k{k}_seed42_validation.csv")
        li = (a.role == "logged_in").values
        assert (seeds.session_ref.values == a.session_ref.values).all()
        pair = [ARI(seeds[c1].values[li], seeds[c2].values[li]) for i, c1 in enumerate(cols) for c2 in cols[i + 1:]]
        res["seed_stability_validation_logged_in"] = {"mean_pairwise_ari": float(np.mean(pair)), "min_pairwise_ari": float(np.min(pair)),
                                                      "pairs": [round(p, 4) for p in pair]}
        out[f"{kind}_k{k}"] = res


def clean(o):
    if isinstance(o, dict):
        return {str(k): clean(v) for k, v in o.items()}
    if isinstance(o, list):
        return [clean(v) for v in o]
    if isinstance(o, float):
        return None if math.isnan(o) else round(o, 6)
    return o


(OUT / "posthoc_logged_in.json").write_text(json.dumps(clean(out), indent=2), encoding="utf-8")
for name, r in out.items():
    v = r["validation"]
    print(name, "| logged-in sil", round(v["logged_in"]["internal_input_space"]["silhouette"], 3), "ARI", round(v["logged_in"]["ari_vs_category"], 3),
          v["logged_in"]["ari_ci95_bootstrap"], "| noBF ARI", round(v["logged_in_excluding_brute_force"]["ari_vs_category"], 3),
          "NMI", round(v["logged_in_excluding_brute_force"]["nmi_vs_category"], 3), "sil", round(v["logged_in_excluding_brute_force"]["internal_input_space"]["silhouette"], 3),
          "| seedARI logged", round(r["seed_stability_validation_logged_in"]["mean_pairwise_ari"], 3), r["seed_stability_validation_logged_in"]["min_pairwise_ari"].__round__(3),
          "| failed in modal", v["failed_rows_in_their_modal_cluster_share"], v["logged_in_rows_in_failed_modal_cluster"],
          "| conf", v["logged_in"].get("dec_confidence"))
    print("   max lift", v["logged_in_excluding_brute_force"]["max_lift_by_category"], "purity", v["logged_in_excluding_brute_force"]["cluster_purity"])
