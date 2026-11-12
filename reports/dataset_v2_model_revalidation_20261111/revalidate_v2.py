"""Task 17: revalidate Autoencoder + K-Means and DEC on the frozen Dataset V2 features (train/validation only).

Run from the repository root with the DEC interpreter (TensorFlow):
    ml\\cowrie_dec_integration_skeleton\\.venv-dec-smoke\\Scripts\\python.exe reports\\dataset_v2_model_revalidation_20261111\\revalidate_v2.py

Existing implementation reused unchanged: build_dec() from ml/cowrie_dec_integration_skeleton (encoder input-32-16-4,
Student-t clustering layer), the decoder / pre-training / K-Means initialisation / DEC loop of ml_pipeline/dec15.py
(train_dec) with its HYPERPARAMETERS, single-threaded K-Means (models/dec_15_feature_v2_deterministic), TensorFlow
op determinism, and dec15's metric helpers. Only the input mapping changes (8 frozen features instead of 15), plus
saving what dec15 discarded (pre-DEC autoencoder, K-Means centres, per-session outputs).

Preprocessing (train only): per-feature median of non-missing training values -> impute train and validation ->
log1p on the continuous time/byte features (the existing rule: continuous features logged, counts not) ->
StandardScaler fitted on imputed+logged training data. No missingness indicators.
Labels (attack_cat), roles, interaction IDs and manifest `find` flags are post-hoc metadata only.
No test data is read (audit hook). Outputs: this directory and models/dataset_v2_revalidation_20261111/.
"""
import hashlib
import json
import math
import platform
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "ml_pipeline"))
OPENED = []


def _audit(event, args):
    if event == "open" and args and isinstance(args[0], (str, Path)):
        p = str(args[0]).replace("\\", "/").lower()
        if "ml_pipeline/work/test" in p or "sealed" in p or "/runs/test" in p:
            raise RuntimeError(f"test-set access blocked: {p}")
        OPENED.append(p)


sys.addaudithook(_audit)

import dec15  # noqa: E402
from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.model import build_dec, build_encoder  # noqa: E402

DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
FROZEN = REPO / "configs" / "model_features_v2_frozen.json"
MODELS = REPO / "models" / "dataset_v2_revalidation_20261111"
OUT = HERE / "outputs"
FIG = HERE / "figures"
HP = dict(dec15.HYPERPARAMETERS)          # existing hyperparameters, unchanged except n_clusters / seed per run
SEEDS = [42, 43, 44, 45, 46]              # 42 = existing project seed (primary); 43-46 for stability only
K_RANGE = [2, 3, 4, 5, 6, 7, 8]
K_EXISTING = HP["n_clusters"]             # 3
LOG_FEATURES = ["session_duration_s", "time_to_first_input_s", "inter_input_mean_s", "inter_input_std_s", "tty_output_bytes"]
EXPECTED = {"frozen": "8ae17612eabbbc46240aa1011aff8d6e3617df85380b3daa523201675fc3c288"}
for d in (OUT, FIG):
    d.mkdir(exist_ok=True)
if MODELS.exists():
    sys.exit(f"{MODELS} exists; refusing to overwrite saved models")
T0 = time.time()


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def clean(o):
    if isinstance(o, dict):
        return {str(k): clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [clean(v) for v in o]
    if isinstance(o, np.ndarray):
        return clean(o.tolist())
    if isinstance(o, (np.floating, float)):
        return None if math.isnan(float(o)) else round(float(o), 6)
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, np.bool_):
        return bool(o)
    return o


def dump(name, obj):
    (OUT / name).write_text(json.dumps(clean(obj), indent=2), encoding="utf-8")


# =================================================================================================================
# 0. Inputs
# =================================================================================================================
assert sha(FROZEN) == EXPECTED["frozen"], "frozen configuration changed"
frozen = json.loads(FROZEN.read_text(encoding="utf-8"))
FEATURES = frozen["model_input_features"]
assert len(FEATURES) == 8 and "input_bytes_total" not in FEATURES
assert set(LOG_FEATURES) <= set(FEATURES)


def load(split):
    d = DS / "extraction" / split / "run1"
    X = pd.read_csv(d / "model_features.csv")
    M = pd.read_csv(d / "session_metadata.csv", keep_default_na=False)
    lab = pd.read_csv(DS / "labels" / f"{split}_session_labels.csv", dtype=str)
    df = pd.concat([M[["session_ref"]], X], axis=1).merge(lab, on="session_ref", validate="one_to_one")
    man = {f"{split}:{json.loads(l)['index']}": json.loads(l)
           for l in (DS / "runs" / split / "manifest.jsonl").read_text(encoding="utf-8").splitlines()}
    df["has_find"] = [r.role == "logged_in" and any(c["command"].startswith("find / -name id_rsa")
                                                     for c in man[r.interaction_id]["command_log"] if c["sent"])
                      for r in df.itertuples()]
    return df.reset_index(drop=True)


train, val = load("train"), load("validation")
assert len(train) == 3190 and len(val) == 1257
assert not set(train.interaction_id) & set(val.interaction_id)
CATS = sorted(train.attack_cat.unique())

# =================================================================================================================
# 1. Preprocessing (train only)
# =================================================================================================================
raw_train, raw_val = train[FEATURES].astype(float), val[FEATURES].astype(float)
valid_counts = raw_train.notna().sum()
if (valid_counts == 0).any():
    sys.exit(f"STOP: features with no valid training observations: {list(valid_counts[valid_counts == 0].index)}")
medians = raw_train.median()                       # pandas median skips NaN: non-missing training values only


def transform(raw, scaler=None):
    x = raw.fillna(medians).copy()
    for f in LOG_FEATURES:
        x[f] = np.log1p(x[f].clip(lower=0))
    return x if scaler is None else scaler.transform(x[FEATURES]).astype(np.float32)


from sklearn.preprocessing import StandardScaler  # noqa: E402
scaler = StandardScaler().fit(transform(raw_train)[FEATURES])
X_train, X_val = transform(raw_train, scaler), transform(raw_val, scaler)
assert np.isfinite(X_train).all() and np.isfinite(X_val).all()
imputed_train, imputed_val = raw_train.isna(), raw_val.isna()
prep = {
    "features": FEATURES, "log1p_features": LOG_FEATURES,
    "log_rule": "existing implementation: continuous time/byte features log1p (as dur/bytes/times in the 15-feature model), counts and indicators not (as spkts/dpkts)",
    "order": ["median imputation (train medians)", "log1p", "StandardScaler (train)"],
    "medians_from_train_nonmissing": medians.to_dict(), "train_valid_counts": valid_counts.to_dict(),
    "scaler_mean": dict(zip(FEATURES, scaler.mean_)), "scaler_scale": dict(zip(FEATURES, scaler.scale_)),
    "imputed_counts": {"train": imputed_train.sum().to_dict(), "validation": imputed_val.sum().to_dict()},
    "imputed_by_role_train": {f: train.assign(m=imputed_train[f]).groupby("role").m.mean().to_dict() for f in FEATURES if imputed_train[f].any()},
    "imputed_by_category_train": {f: train.assign(m=imputed_train[f]).groupby("attack_cat").m.mean().to_dict() for f in FEATURES if imputed_train[f].any()},
    "rows_with_any_imputed": {"train": int(imputed_train.any(axis=1).sum()), "validation": int(imputed_val.any(axis=1).sum())},
    "imputed_rows_failed_login": {"train": int((imputed_train.any(axis=1) & (train.login_success == 0)).sum()),
                                  "validation": int((imputed_val.any(axis=1) & (val.login_success == 0)).sum())},
    "imputed_rows_logged_in_no_commands": {"train": int((imputed_train.any(axis=1) & (train.login_success == 1) & (train.input_line_count == 0)).sum())},
    "validation_scaled_mean": dict(zip(FEATURES, X_val.mean(0))), "validation_scaled_sd": dict(zip(FEATURES, X_val.std(0))),
    "distinct_train_vectors": int(pd.DataFrame(X_train).round(6).drop_duplicates().shape[0]),
    "largest_identical_vector_group_train": int(pd.DataFrame(X_train).round(6).value_counts().max()),
}
dump("preprocessing.json", prep)

# =================================================================================================================
# Model training (dec15.train_dec procedure, with pre-DEC artefacts kept)
# =================================================================================================================
import tensorflow as tf  # noqa: E402
from sklearn.cluster import KMeans  # noqa: E402
from tensorflow.keras import Model  # noqa: E402
from tensorflow.keras.layers import Dense  # noqa: E402
from tensorflow.keras.optimizers import Adam  # noqa: E402


def pretrain(X, seed):
    tf.keras.backend.clear_session()
    tf.keras.utils.set_random_seed(seed)
    tf.config.experimental.enable_op_determinism()
    return None


def build_and_pretrain(X, k, seed):
    pretrain(X, seed)
    dec_model, encoder = build_dec(input_dim=X.shape[1], latent_dim=HP["latent_dim"], n_clusters=k, alpha=HP["alpha"])
    x = encoder.output
    for units in HP["decoder"]:
        x = Dense(units, activation=HP["activation"])(x)
    recon = Dense(X.shape[1], activation="linear", name="reconstruction")(x)
    ae = Model(encoder.input, recon, name="cowrie_autoencoder")
    ae.compile(optimizer=Adam(learning_rate=HP["ae_learning_rate"]), loss=HP["ae_loss"])
    t = time.time()
    hist = ae.fit(X, X, epochs=HP["ae_epochs"], batch_size=HP["ae_batch_size"], validation_split=HP["ae_validation_split"], verbose=0)
    return dec_model, encoder, ae, hist, time.time() - t


def recon_err(ae, X):
    return np.mean((ae.predict(X, batch_size=HP["predict_batch_size"], verbose=0) - X) ** 2, axis=1)


def run(X, Xv, k, seed, keep=False):
    """Returns AE+K-Means and DEC outputs for train (X) and validation (Xv)."""
    t_all = time.time()
    dec_model, encoder, ae, hist, ae_s = build_and_pretrain(X, k, seed)
    r = {"seed": seed, "k": k, "ae_seconds": ae_s, "ae_loss": hist.history["loss"], "ae_val_loss": hist.history["val_loss"]}
    r["recon_train"], r["recon_val"] = recon_err(ae, X), recon_err(ae, Xv)
    z0, z0v = encoder.predict(X, batch_size=HP["predict_batch_size"], verbose=0), encoder.predict(Xv, batch_size=HP["predict_batch_size"], verbose=0)
    if keep:
        r["ae_weights"] = [w.copy() for w in ae.get_weights()]
    t = time.time()
    km = KMeans(n_clusters=k, random_state=seed, n_init=HP["kmeans_n_init"])
    with dec15.kmeans_threads(True):
        lab = km.fit_predict(z0)
        labv = km.predict(z0v)
        dist, distv = km.transform(z0), km.transform(z0v)
    r.update({"km_seconds": time.time() - t, "z0": z0, "z0v": z0v, "ae_km_train": lab, "ae_km_val": labv,
              "ae_km_dist": dist, "ae_km_distv": distv, "km_centres": km.cluster_centers_, "km_inertia": km.inertia_, "km": km})
    # DEC refinement (dec15.train_dec loop)
    t = time.time()
    dec_model.get_layer("clustering").set_weights([km.cluster_centers_.astype(np.float32)])
    dec_model.compile(optimizer=Adam(learning_rate=HP["dec_learning_rate"]), loss=HP["dec_loss"])
    q = dec_model.predict(X, batch_size=HP["predict_batch_size"], verbose=0)
    y_last = q.argmax(1)
    deltas, losses, iterations, converged = [], [], 0, False
    for ite in range(HP["dec_maxiter"]):
        if ite % HP["dec_update_interval"] == 0:
            q = dec_model.predict(X, batch_size=HP["predict_batch_size"], verbose=0)
            p = dec15.target_distribution(q)
            y_pred = q.argmax(1)
            if ite > 0:
                delta = float(np.mean(y_pred != y_last))
                deltas.append({"iteration": ite, "label_change": delta})
                if delta < HP["dec_tol"]:
                    converged, iterations = True, ite
                    break
            y_last = y_pred.copy()
        loss = dec_model.train_on_batch(X, p)
        losses.append(float(loss if np.isscalar(loss) else np.asarray(loss).ravel()[0]))
        iterations = ite + 1
    r.update({"dec_seconds": time.time() - t, "dec_iterations": iterations, "dec_converged": converged,
              "dec_label_changes": deltas, "dec_kl": losses,
              "q_train": dec_model.predict(X, batch_size=HP["predict_batch_size"], verbose=0),
              "q_val": dec_model.predict(Xv, batch_size=HP["predict_batch_size"], verbose=0),
              "z_train": encoder.predict(X, batch_size=HP["predict_batch_size"], verbose=0),
              "z_val": encoder.predict(Xv, batch_size=HP["predict_batch_size"], verbose=0),
              "total_seconds": time.time() - t_all})
    r["dec_train"], r["dec_val"] = r["q_train"].argmax(1), r["q_val"].argmax(1)
    if keep:
        r["dec_model"], r["encoder"], r["ae"] = dec_model, encoder, ae
    return r


# =================================================================================================================
# 2. Cluster count: small range on TRAINING data only (no labels)
# =================================================================================================================
from sklearn.metrics import adjusted_rand_score as ARI, normalized_mutual_info_score as NMI  # noqa: E402
from sklearn.metrics import silhouette_score, davies_bouldin_score, calinski_harabasz_score  # noqa: E402

krows = []
k_labels = {k: [] for k in K_RANGE}
for seed in SEEDS:
    _, encoder, ae, hist, _ = build_and_pretrain(X_train, K_EXISTING, seed)
    z = encoder.predict(X_train, batch_size=HP["predict_batch_size"], verbose=0)
    for k in K_RANGE:
        with dec15.kmeans_threads(True):
            lab = KMeans(n_clusters=k, random_state=seed, n_init=HP["kmeans_n_init"]).fit_predict(z)
        k_labels[k].append(lab)
        sizes = np.bincount(lab, minlength=k)
        krows.append({"seed": seed, "k": k, "silhouette_input": float(silhouette_score(X_train, lab)),
                      "silhouette_latent": float(silhouette_score(z, lab)),
                      "davies_bouldin_input": float(davies_bouldin_score(X_train, lab)),
                      "calinski_harabasz_input": float(calinski_harabasz_score(X_train, lab)),
                      "min_cluster_share": float(sizes.min() / len(lab)), "occupied": int((sizes > 0).sum())})
kdf = pd.DataFrame(krows)
kdf.to_csv(OUT / "k_range_train_per_seed.csv", index=False, float_format="%.5f")
ksum = kdf.groupby("k").agg(silhouette_input=("silhouette_input", "mean"), silhouette_input_sd=("silhouette_input", "std"),
                            silhouette_latent=("silhouette_latent", "mean"), davies_bouldin_input=("davies_bouldin_input", "mean"),
                            calinski_harabasz_input=("calinski_harabasz_input", "mean"), min_cluster_share=("min_cluster_share", "min"))
ksum["seed_stability_mean_pairwise_ari"] = [float(np.mean([ARI(a, b) for i, a in enumerate(k_labels[k]) for b in k_labels[k][i + 1:]])) for k in ksum.index]
eligible_k = ksum[(ksum.seed_stability_mean_pairwise_ari >= 0.8) & (ksum.min_cluster_share >= 0.01)]
if len(eligible_k):
    best = eligible_k.silhouette_input.max()
    K_SEL = int(min(k for k in eligible_k.index if eligible_k.loc[k, "silhouette_input"] >= best - 0.01))
else:
    K_SEL = K_EXISTING
ksum.to_csv(OUT / "k_range_train_summary.csv", float_format="%.5f")
k_rule = ("Training data only. Range 2-8 (existing K=3; upper end covers the six generator categories plus a failed-login "
          "mode without using labels). Rule fixed before running: among K with mean pairwise seed ARI >= 0.8 and every "
          "cluster >= 1% of training rows, take the highest mean input-space silhouette over 5 seeds; any K within 0.01 "
          "of the best -> the smallest such K. If no K qualifies, keep the existing K=3.")
print("K selection:", K_SEL, "\n", ksum.round(3))
K_RUNS = sorted({K_SEL, K_EXISTING})

# =================================================================================================================
# 3. Main runs: K_RUNS x 5 seeds; seed 42 is the primary (artefacts saved)
# =================================================================================================================
runs = {}
for k in K_RUNS:
    for seed in SEEDS:
        runs[(k, seed)] = run(X_train, X_val, k, seed, keep=(seed == 42))
        r = runs[(k, seed)]
        print(f"K={k} seed={seed}: AE {r['ae_loss'][0]:.3f}->{r['ae_loss'][-1]:.3f}, DEC it {r['dec_iterations']} conv {r['dec_converged']}, {r['total_seconds']:.1f}s")

# reproducibility: rerun the primary once and compare
rep = run(X_train, X_val, K_SEL, 42, keep=False)
prim = runs[(K_SEL, 42)]
reproducibility = {"ae_kmeans_val_identical": bool(np.array_equal(rep["ae_km_val"], prim["ae_km_val"])),
                   "dec_q_val_identical": bool(np.array_equal(rep["q_val"], prim["q_val"])),
                   "dec_q_train_identical": bool(np.array_equal(rep["q_train"], prim["q_train"])),
                   "max_abs_q_diff": float(np.max(np.abs(rep["q_val"] - prim["q_val"]))),
                   "recon_identical": bool(np.array_equal(rep["recon_val"], prim["recon_val"]))}


# =================================================================================================================
# 4. Evaluation
# =================================================================================================================
def cmetrics(space, labels):
    return dec15.cluster_metrics(space, labels)


def sizes(labels, k):
    return np.bincount(labels, minlength=k).tolist()


def grouped_boot(fn, frame_groups, n=200, seed=0):
    rng = np.random.RandomState(seed)
    groups = np.unique(frame_groups)
    idx = {g: np.where(frame_groups == g)[0] for g in groups}
    vals = []
    for _ in range(n):
        pick = np.concatenate([idx[g] for g in rng.choice(groups, len(groups))])
        v = fn(pick)
        if v is not None:
            vals.append(v)
    return [float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))]


def posthoc(labels, frame):
    li = (frame.role == "logged_in").values
    out = {"all_rows": {"ari": ARI(frame.attack_cat, labels), "nmi": NMI(frame.attack_cat, labels)},
           "logged_in_one_per_interaction": {"ari": ARI(frame.attack_cat[li], labels[li]), "nmi": NMI(frame.attack_cat[li], labels[li])},
           "ari_vs_login_success": ARI(frame.login_success, labels)}
    g = frame.interaction_id.values
    out["all_rows"]["ari_ci95_interaction_bootstrap"] = grouped_boot(lambda p: ARI(frame.attack_cat.values[p], labels[p]), g)
    out["logged_in_one_per_interaction"]["ari_ci95_bootstrap"] = grouped_boot(
        lambda p: ARI(frame.attack_cat.values[li][p], labels[li][p]), np.arange(li.sum()))
    return out


def contingency(labels, frame, k, mask=None):
    f = frame if mask is None else frame[mask]
    lab = labels if mask is None else labels[mask]
    t = pd.crosstab(f.attack_cat.values, lab).reindex(columns=range(k), fill_value=0)
    t.index.name, t.columns.name = "attack_cat", "cluster"
    return t


def leakage_diag(labels, frame, Xs, raw, imputed, k):
    from scipy.stats import chi2_contingency
    tab = pd.crosstab(labels, frame.login_success)
    if tab.shape[0] > 1 and tab.shape[1] > 1:
        chi2 = chi2_contingency(tab)[0]
        v = math.sqrt(chi2 / (tab.values.sum() * (min(tab.shape) - 1)))
    else:
        v = None
    eta = {}
    for j, f in enumerate(FEATURES):
        x = Xs[:, j]
        ss_t = ((x - x.mean()) ** 2).sum()
        ss_b = sum(((x[labels == c].mean() - x.mean()) ** 2) * (labels == c).sum() for c in np.unique(labels))
        eta[f] = float(ss_b / ss_t) if ss_t > 0 else None
    per = {}
    for c in range(k):
        m = labels == c
        if not m.any():
            per[c] = {"n": 0}
            continue
        per[c] = {"n": int(m.sum()), "share": float(m.mean()), "failed_login_share": float((frame.login_success[m] == 0).mean()),
                  "no_input_share": float((frame.input_line_count[m] == 0).mean()),
                  "any_imputed_share": float(imputed[m].any(axis=1).mean()),
                  "find_sessions": int(frame.has_find[m].sum()),
                  "median_raw": raw[m].median().to_dict(),
                  "category_share": frame.attack_cat[m].value_counts(normalize=True).round(4).to_dict()}
    imp_any = imputed.any(axis=1).values
    return {"cluster_vs_login_success_cramers_v": v, "eta2_feature_by_cluster": eta, "per_cluster": per,
            "imputed_rows_vs_cluster_ari": ARI(imp_any, labels),
            "failed_login_rows_in_single_cluster_share": float(pd.Series(labels[frame.login_success == 0]).value_counts(normalize=True).max()) if (frame.login_success == 0).any() else None}


def single_feature_reproduction(lab_train, lab_val):
    """Depth-3 tree on ONE scaled input predicting the cluster: fitted on train clusters, scored on validation clusters."""
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.metrics import balanced_accuracy_score
    out = {}
    for j, f in enumerate(FEATURES):
        clf = DecisionTreeClassifier(max_depth=3, random_state=0).fit(X_train[:, [j]], lab_train)
        out[f] = float(balanced_accuracy_score(lab_val, clf.predict(X_val[:, [j]])))
    return out


def model_eval(kind, k, r):
    if kind == "ae_kmeans":
        lt, lv, zt, zv = r["ae_km_train"], r["ae_km_val"], r["z0"], r["z0v"]
    else:
        lt, lv, zt, zv = r["dec_train"], r["dec_val"], r["z_train"], r["z_val"]
    e = {"k": k, "seed": r["seed"]}
    for split, lab, X, z, frame in (("train", lt, X_train, zt, train), ("validation", lv, X_val, zv, val)):
        e[split] = {"input_space": cmetrics(X, lab), "latent_space": cmetrics(z, lab), "cluster_sizes": sizes(lab, k),
                    "cluster_shares": (np.array(sizes(lab, k)) / len(lab)).round(4).tolist(),
                    "reconstruction_mse": {"mean": float(r["recon_train" if split == "train" else "recon_val"].mean()),
                                           "median": float(np.median(r["recon_train" if split == "train" else "recon_val"]))},
                    "posthoc": posthoc(lab, frame)}
        if kind == "dec":
            q = r["q_train" if split == "train" else "q_val"]
            conf = q.max(1)
            srt = np.sort(q, 1)
            e[split]["confidence"] = {"mean": float(conf.mean()), "median": float(np.median(conf)), "min": float(conf.min()),
                                      "p05": float(np.percentile(conf, 5)), "share_below_0.7": float((conf < 0.7).mean()),
                                      "share_below_0.9": float((conf < 0.9).mean()),
                                      "min_top1_top2_gap": float((srt[:, -1] - srt[:, -2]).min()),
                                      "by_category_mean": frame.assign(c=conf).groupby("attack_cat").c.mean().to_dict()}
        else:
            d = r["ae_km_dist" if split == "train" else "ae_km_distv"]
            ds = np.sort(d, 1)
            e[split]["distances"] = {"note": "K-Means has no probabilistic confidence; distances to centres in the latent space are reported instead (not a confidence)",
                                     "to_assigned_centre_median": float(np.median(ds[:, 0])), "to_assigned_centre_p95": float(np.percentile(ds[:, 0], 95)),
                                     "margin_second_minus_first_median": float(np.median(ds[:, 1] - ds[:, 0])) if k > 1 else None,
                                     "margin_p05": float(np.percentile(ds[:, 1] - ds[:, 0], 5)) if k > 1 else None}
    e["train_vs_validation"] = {"max_abs_cluster_share_diff": float(np.max(np.abs(np.array(e["train"]["cluster_shares"]) - np.array(e["validation"]["cluster_shares"])))),
                                "silhouette_input_diff": (e["validation"]["input_space"]["silhouette"] or 0) - (e["train"]["input_space"]["silhouette"] or 0)}
    return e, lt, lv


def stability(kind, k):
    key_t, key_v = ("ae_km_train", "ae_km_val") if kind == "ae_kmeans" else ("dec_train", "dec_val")
    rs = [runs[(k, s)] for s in SEEDS]
    pair = lambda key: [ARI(a[key], b[key]) for i, a in enumerate(rs) for b in rs[i + 1:]]  # noqa: E731
    ag = []
    for b in rs[1:]:
        _, acc, _ = dec15.align_clusters(rs[0][key_v], b[key_v], k=k)
        ag.append(acc)
    out = {"pairwise_ari_train": pair(key_t), "pairwise_ari_validation": pair(key_v),
           "mean_pairwise_ari_train": float(np.mean(pair(key_t))), "mean_pairwise_ari_validation": float(np.mean(pair(key_v))),
           "min_pairwise_ari_validation": float(np.min(pair(key_v))),
           "aligned_agreement_vs_seed42_validation": ag,
           "validation_silhouette_input_by_seed": [cmetrics(X_val, r[key_v])["silhouette"] for r in rs],
           "validation_ari_vs_attack_cat_by_seed": [ARI(val.attack_cat, r[key_v]) for r in rs],
           "cluster_sizes_validation_by_seed": [sizes(r[key_v], k) for r in rs]}
    if kind == "dec":
        out["converged_by_seed"] = [r["dec_converged"] for r in rs]
        out["iterations_by_seed"] = [r["dec_iterations"] for r in rs]
        out["confidence_mean_validation_by_seed"] = [float(r["q_val"].max(1).mean()) for r in rs]
        out["confidence_min_validation_by_seed"] = [float(r["q_val"].max(1).min()) for r in rs]
    return out


results = {"k_selection": {"rule": k_rule, "selected_k": K_SEL, "existing_k": K_EXISTING, "k_runs": K_RUNS,
                           "summary": ksum.reset_index().to_dict(orient="records")},
           "reproducibility_primary": reproducibility, "models": {}}
assign_rows = {"train": [], "validation": []}
for k in K_RUNS:
    r = runs[(k, 42)]
    # plain K-Means on the 8 scaled inputs: the existing step-9 baseline
    with dec15.kmeans_threads(True):
        km_in = KMeans(n_clusters=k, random_state=42, n_init=HP["kmeans_n_init"]).fit(X_train)
    bl_t, bl_v = km_in.labels_, km_in.predict(X_val)
    results["models"][f"baseline_kmeans_inputs_k{k}"] = {
        "train": {"input_space": cmetrics(X_train, bl_t), "cluster_sizes": sizes(bl_t, k), "posthoc": posthoc(bl_t, train)},
        "validation": {"input_space": cmetrics(X_val, bl_v), "cluster_sizes": sizes(bl_v, k), "posthoc": posthoc(bl_v, val)}}
    for kind in ("ae_kmeans", "dec"):
        e, lt, lv = model_eval(kind, k, r)
        e["stability"] = stability(kind, k)
        e["leakage_diagnostics"] = {"train": leakage_diag(lt, train, X_train, raw_train, imputed_train, k),
                                    "validation": leakage_diag(lv, val, X_val, raw_val, imputed_val, k),
                                    "single_feature_reproduces_cluster_ba_validation": single_feature_reproduction(lt, lv)}
        e["contingency_validation_all_rows"] = contingency(lv, val, k).to_dict()
        e["contingency_validation_logged_in"] = contingency(lv, val, k, (val.role == "logged_in").values).to_dict()
        e["contingency_validation_failed_rows"] = contingency(lv, val, k, (val.role != "logged_in").values).to_dict()
        e["contingency_train_logged_in"] = contingency(lt, train, k, (train.role == "logged_in").values).to_dict()
        pe = (val.attack_cat == "privilege_escalation").values
        e["find_sessions_validation"] = {"find_clusters": pd.Series(lv[val.has_find.values]).value_counts().to_dict(),
                                         "pe_non_find_logged_in_clusters": pd.Series(lv[pe & ~val.has_find.values & (val.role == "logged_in").values]).value_counts().to_dict()}
        if kind == "dec":
            e["training"] = {"iterations": r["dec_iterations"], "converged": r["dec_converged"], "tolerance": HP["dec_tol"],
                             "label_change_checks": r["dec_label_changes"], "kl_first": r["dec_kl"][0], "kl_last": r["dec_kl"][-1],
                             "kl_min": min(r["dec_kl"]), "seconds": r["dec_seconds"]}
        else:
            e["training"] = {"ae_loss_first": r["ae_loss"][0], "ae_loss_last": r["ae_loss"][-1], "ae_val_loss_last": r["ae_val_loss"][-1],
                             "ae_seconds": r["ae_seconds"], "kmeans_inertia": r["km_inertia"], "kmeans_seconds": r["km_seconds"]}
        results["models"][f"{kind}_k{k}"] = e
    # per-session assignments (primary seed) and embeddings
    for split, frame, sfx in (("train", train, ""), ("validation", val, "v")):
        q = r["q_train"] if split == "train" else r["q_val"]
        d = r["ae_km_dist"] if split == "train" else r["ae_km_distv"]
        z0 = r["z0"] if split == "train" else r["z0v"]
        zd = r["z_train"] if split == "train" else r["z_val"]
        df = pd.DataFrame({"session_ref": frame.session_ref, "interaction_id": frame.interaction_id, "role": frame.role,
                           "attack_cat_posthoc_only": frame.attack_cat, "has_find_posthoc_only": frame.has_find,
                           "ae_kmeans_cluster": r["ae_km_train"] if split == "train" else r["ae_km_val"],
                           "ae_kmeans_dist_assigned": d.min(1), "ae_kmeans_margin": np.sort(d, 1)[:, 1] - np.sort(d, 1)[:, 0],
                           "ae_reconstruction_mse": r["recon_train"] if split == "train" else r["recon_val"],
                           "dec_cluster": q.argmax(1), "dec_confidence": q.max(1)})
        for c in range(k):
            df[f"dec_q{c}"] = q[:, c]
        for j in range(z0.shape[1]):
            df[f"ae_z{j}"] = z0[:, j]
        for j in range(zd.shape[1]):
            df[f"dec_z{j}"] = zd[:, j]
        df.to_csv(OUT / f"assignments_embeddings_k{k}_seed42_{split}.csv", index=False, float_format="%.6g")
    seed_tab = pd.DataFrame({f"{kind}_seed{s}": runs[(k, s)][key] for s in SEEDS
                             for kind, key in (("ae_kmeans", "ae_km_val"), ("dec", "dec_val"))})
    seed_tab.insert(0, "session_ref", val.session_ref)
    seed_tab.to_csv(OUT / f"validation_assignments_all_seeds_k{k}.csv", index=False)

# =================================================================================================================
# 5. find sensitivity: retrain primary configuration without the 30 training find sessions (diagnostic only)
# =================================================================================================================
keep = ~train.has_find.values
raw_tr2 = raw_train[keep]
med2 = raw_tr2.median()


def transform2(raw, sc=None):
    x = raw.fillna(med2).copy()
    for f in LOG_FEATURES:
        x[f] = np.log1p(x[f].clip(lower=0))
    return x if sc is None else sc.transform(x[FEATURES]).astype(np.float32)


sc2 = StandardScaler().fit(transform2(raw_tr2)[FEATURES])
r_nf = run(transform2(raw_tr2, sc2), transform2(raw_val, sc2), K_SEL, 42)
nf_val_mask = ~val.has_find.values
results["find_sensitivity"] = {
    "note": "Diagnostic retrain (K, seed, hyperparameters unchanged) with the 30 training sessions containing `find / -name id_rsa` removed; dataset files unchanged.",
    "train_rows": int(keep.sum()), "find_sessions_removed": int((~keep).sum()),
    "ae_kmeans_validation_ari_full_vs_nofind": ARI(prim["ae_km_val"], r_nf["ae_km_val"]),
    "dec_validation_ari_full_vs_nofind": ARI(prim["dec_val"], r_nf["dec_val"]),
    "ae_kmeans_validation_ari_full_vs_nofind_excluding_find_rows": ARI(prim["ae_km_val"][nf_val_mask], r_nf["ae_km_val"][nf_val_mask]),
    "dec_validation_ari_full_vs_nofind_excluding_find_rows": ARI(prim["dec_val"][nf_val_mask], r_nf["dec_val"][nf_val_mask]),
    "seed_variation_reference_mean_pairwise_ari_validation": {
        "ae_kmeans": results["models"][f"ae_kmeans_k{K_SEL}"]["stability"]["mean_pairwise_ari_validation"],
        "dec": results["models"][f"dec_k{K_SEL}"]["stability"]["mean_pairwise_ari_validation"]},
    "nofind_validation_silhouette_input": {"ae_kmeans": cmetrics(X_val, r_nf["ae_km_val"])["silhouette"], "dec": cmetrics(X_val, r_nf["dec_val"])["silhouette"]},
    "full_validation_silhouette_input_excluding_find_rows": {
        "ae_kmeans": cmetrics(X_val[nf_val_mask], prim["ae_km_val"][nf_val_mask])["silhouette"],
        "dec": cmetrics(X_val[nf_val_mask], prim["dec_val"][nf_val_mask])["silhouette"]},
}

# =================================================================================================================
# 6. Save primary models (new isolated directory) and verify reload
# =================================================================================================================
import joblib  # noqa: E402
from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.inference import CowrieDEC  # noqa: E402

MODELS.mkdir(parents=True)
saved = {}
for k in K_RUNS:
    r = runs[(k, 42)]
    # DEC first: restoring the pre-DEC autoencoder below rewrites the encoder layers DEC shares
    for kind in ("dec", "ae_kmeans"):
        d = MODELS / f"{kind}_k{k}_seed42"
        d.mkdir()
        joblib.dump(scaler, d / "scaler.joblib")
        joblib.dump(medians.to_dict(), d / "medians.joblib")
        cfg = {"model_name": "AE+K-Means" if kind == "ae_kmeans" else "DEC", "input_dim": len(FEATURES), "latent_dim": HP["latent_dim"],
               "n_clusters": k, "alpha": HP["alpha"], "features": FEATURES, "log_features": LOG_FEATURES,
               "feature_config": "configs/model_features_v2_frozen.json", "feature_config_sha256": sha(FROZEN),
               "spec_revision": "2.0.0-draft.4 (configs/feature_spec_v2_draft4.json)",
               "preprocessing": {"missing_value_strategy": "median (train split, non-missing values)", "log_transform": "log1p",
                                 "scaler": "StandardScaler (train split)"},
               "hyperparameters": {**HP, "n_clusters": k, "seed": 42, "kmeans_random_state": 42},
               "architecture": {"encoder": [32, 16, HP["latent_dim"]], "decoder": [16, 32, len(FEATURES)]},
               "training_data": "reports/dataset_v2_training_validation_20261110 (train split, all 3,190 sessions)"}
        (d / "config.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        if kind == "dec":
            r["dec_model"].save_weights(str(d / "cowrie_dec.weights.h5"))
            (d / "cluster_centroids.json").write_text(json.dumps({"latent_dim": HP["latent_dim"], "centroids":
                                                                  r["dec_model"].get_layer("clustering").get_weights()[0].tolist()}, indent=2))
            loaded = CowrieDEC(str(d))
            saved[f"dec_k{k}_reload_identical"] = bool(np.array_equal(loaded.model.predict(X_val, batch_size=256, verbose=0), r["q_val"]))
            # end to end through the unchanged inference preprocess() on the raw extracted validation features
            cl, cf, _ = loaded.predict(val[FEATURES])
            saved[f"dec_k{k}_end_to_end_raw_assignments_identical"] = bool(np.array_equal(cl, r["dec_val"]))
            saved[f"dec_k{k}_end_to_end_max_conf_diff"] = float(np.max(np.abs(cf - r["q_val"].max(1))))
        else:
            r["ae"].set_weights(r["ae_weights"])          # restore the pre-DEC autoencoder (DEC fine-tuned the shared encoder)
            r["ae"].save_weights(str(d / "autoencoder_preDEC.weights.h5"))
            joblib.dump(r["km"], d / "kmeans.joblib")
            (d / "kmeans_centres.json").write_text(json.dumps({"latent_dim": HP["latent_dim"], "centres": r["km_centres"].tolist()}, indent=2))
            z_chk = Model(r["ae"].input, r["ae"].get_layer("latent").output).predict(X_val, verbose=0)
            saved[f"ae_kmeans_k{k}_reload_latent_identical"] = bool(np.allclose(z_chk, r["z0v"], atol=1e-6))
            saved[f"ae_kmeans_k{k}_reload_assignments_identical"] = bool(np.array_equal(r["km"].predict(z_chk), r["ae_km_val"]))
        (d / "artifact_sha256.json").write_text(json.dumps({p.name: sha(p) for p in sorted(d.iterdir()) if p.is_file()}, indent=2))
results["saved_models"] = {"directory": str(MODELS.relative_to(REPO)), "checks": saved}

# runtime and training logs
results["runtime_seconds"] = {f"k{k}_seed{s}": {"ae": runs[(k, s)]["ae_seconds"], "kmeans": runs[(k, s)]["km_seconds"],
                                                "dec": runs[(k, s)]["dec_seconds"], "total": runs[(k, s)]["total_seconds"]}
                              for k in K_RUNS for s in SEEDS}
results["training_logs_primary"] = {f"k{k}": {"ae_loss": runs[(k, 42)]["ae_loss"], "ae_val_loss": runs[(k, 42)]["ae_val_loss"],
                                              "dec_kl": runs[(k, 42)]["dec_kl"], "dec_label_changes": runs[(k, 42)]["dec_label_changes"]} for k in K_RUNS}
import keras  # noqa: E402
import sklearn  # noqa: E402
results["environment"] = {"python": platform.python_version(), "tensorflow": tf.__version__, "keras": keras.__version__,
                          "scikit_learn": sklearn.__version__, "numpy": np.__version__, "pandas": pd.__version__,
                          "interpreter": "ml/cowrie_dec_integration_skeleton/.venv-dec-smoke"}
results["hyperparameters_existing"] = HP
results["inputs"] = {"frozen_config_sha256": sha(FROZEN), "dataset_SHA256SUMS_sha256": sha(DS / "SHA256SUMS"),
                     "train_rows": len(train), "validation_rows": len(val), "features": FEATURES}
results["test_like_paths_opened"] = [p for p in OPENED if "test" in p.rsplit("/", 1)[-1] and p.endswith((".pkl", ".csv", ".json", ".jsonl"))]
results["wall_seconds"] = time.time() - T0
dump("results.json", results)

# =================================================================================================================
# 7. Figures
# =================================================================================================================
import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

fig, axes = plt.subplots(1, 3, figsize=(14, 3.6))
axes[0].errorbar(ksum.index, ksum.silhouette_input, yerr=ksum.silhouette_input_sd, marker="o")
axes[0].set_title("Train silhouette (8-d input space), mean ± sd over 5 seeds")
axes[1].plot(ksum.index, ksum.seed_stability_mean_pairwise_ari, marker="o", color="tab:green")
axes[1].axhline(0.8, ls="--", c="grey")
axes[1].set_title("Seed stability (mean pairwise ARI, train)")
axes[2].plot(ksum.index, ksum.min_cluster_share, marker="o", color="tab:orange")
axes[2].axhline(0.01, ls="--", c="grey")
axes[2].set_title("Smallest cluster share (train)")
for a in axes:
    a.set_xlabel("K")
fig.tight_layout()
fig.savefig(FIG / "k_range_train.png", dpi=120)
plt.close(fig)

for k in K_RUNS:
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))
    for ax, kind in zip(axes, ("ae_kmeans", "dec")):
        t = pd.DataFrame(results["models"][f"{kind}_k{k}"]["contingency_validation_all_rows"]).fillna(0)
        t = t.reindex(index=CATS)
        norm = t.div(t.sum(1), axis=0)
        ax.imshow(norm.values, cmap="Blues", vmin=0, vmax=1)
        for (i, j), v in np.ndenumerate(t.values):
            ax.text(j, i, int(v), ha="center", va="center", fontsize=8)
        ax.set_xticks(range(t.shape[1]), [str(c) for c in t.columns])
        ax.set_yticks(range(len(CATS)), CATS, fontsize=8)
        ax.set_xlabel("cluster")
        ax.set_title(f"{kind} K={k}: validation rows by category (post hoc)")
    fig.tight_layout()
    fig.savefig(FIG / f"cluster_by_category_validation_k{k}.png", dpi=120)
    plt.close(fig)
    r = runs[(k, 42)]
    fig, axes = plt.subplots(1, 3, figsize=(14, 3.6))
    axes[0].plot(r["ae_loss"], label="train 90%")
    axes[0].plot(r["ae_val_loss"], label="Keras validation_split 10%")
    axes[0].set_title(f"AE pre-training MSE (K={k}, seed 42)")
    axes[0].legend(fontsize=8)
    axes[1].plot(r["dec_kl"])
    axes[1].set_title("DEC KL divergence")
    axes[2].hist(r["q_val"].max(1), bins=40)
    axes[2].set_title("DEC confidence, validation")
    fig.tight_layout()
    fig.savefig(FIG / f"training_and_confidence_k{k}.png", dpi=120)
    plt.close(fig)
print(json.dumps(clean({"k": K_SEL, "repro": reproducibility, "saved": saved, "wall": results["wall_seconds"]}), indent=1))
