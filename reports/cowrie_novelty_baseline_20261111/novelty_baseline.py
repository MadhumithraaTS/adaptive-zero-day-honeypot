"""Task 18: Cowrie session novelty-scoring baseline on Dataset V2 logged-in sessions (train/validation only).

Run from the repository root with the DEC interpreter (TensorFlow):
    ml\\cowrie_dec_integration_skeleton\\.venv-dec-smoke\\Scripts\\python.exe reports\\cowrie_novelty_baseline_20261111\\novelty_baseline.py

Design fixed before running (also written to configs/cowrie_novelty_baseline_v1.json):
  population   logged-in sessions (one per interaction): train 1,500, validation 600; data_exfiltration absent
  inputs       7: session_duration_s, input_line_count, shell_operator_lines, time_to_first_input_s,
               inter_input_mean_s, inter_input_std_s, tty_output_bytes (login_success constant -> dropped)
  preprocess   medians of non-missing logged-in TRAIN values -> impute -> log1p on the 5 continuous time/byte inputs
               (Task 17 rule) -> StandardScaler fitted on logged-in train; no missingness indicators
  A            autoencoder reconstruction MSE (existing encoder build_encoder: in-32-16-4; decoder 4-16-32-in;
               dec15 pre-training hyperparameters: Adam 1e-3, MSE, 20 epochs, batch 256, validation_split 0.1)
  B            mean Euclidean distance to the k=5 nearest TRAINING points in the 4-d AE latent space
  C            mean Euclidean distance to the k=5 nearest TRAINING points in the 7-d scaled input space
               (training scores for B and C are leave-one-out: the point itself is excluded)
  threshold    provisional: 99th percentile of the method's TRAINING scores (target 1% flag rate on known sessions);
               validation measures the realised rate. 95th and 99.5th reported for context only, not selected.
  seeds        42 (primary) and 43-46 for repeatability (A, B; C has no randomness)
No cluster labels are used. Categories, interaction IDs, manifest timings and `find` flags are post-hoc metadata.
No test data is read (audit hook). Outputs: this directory, models/cowrie_novelty_baseline_20261111/.
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

import dec15  # noqa: E402  (hyperparameters only)
from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.model import build_encoder  # noqa: E402

DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
FROZEN = REPO / "configs" / "model_features_v2_frozen_v1.1.0.json"   # Task 19A: versioned path (canonical path holds 1.0.0)
NCFG = REPO / "configs" / "cowrie_novelty_baseline_v1.json"
MODELS = REPO / "models" / "cowrie_novelty_baseline_20261111"
OUT, FIG = HERE / "outputs", HERE / "figures"
HP = {k: dec15.HYPERPARAMETERS[k] for k in ("latent_dim", "encoder", "decoder", "activation", "ae_learning_rate", "ae_loss",
                                             "ae_epochs", "ae_batch_size", "ae_validation_split", "predict_batch_size")}
FEATURES = ["session_duration_s", "input_line_count", "shell_operator_lines", "time_to_first_input_s",
            "inter_input_mean_s", "inter_input_std_s", "tty_output_bytes"]
LOG_FEATURES = ["session_duration_s", "time_to_first_input_s", "inter_input_mean_s", "inter_input_std_s", "tty_output_bytes"]
K_NN = 5
Q_PRIMARY, Q_CONTEXT = 0.99, (0.95, 0.995)
SEEDS = [42, 43, 44, 45, 46]
METHODS = {"A_ae_reconstruction": "AE reconstruction MSE (scaled space)",
           "B_latent_knn": f"mean distance to {K_NN} nearest training points, AE latent (4-d)",
           "C_input_knn": f"mean distance to {K_NN} nearest training points, scaled input space (7-d)"}
FROZEN_SHA = "18a4ab2be8d0d71148212e3306c9cf318075eac63c999e24cefb39564c84d299"
for d in (OUT, FIG):
    d.mkdir(exist_ok=True)
if MODELS.exists():
    sys.exit(f"{MODELS} exists; refusing to overwrite")
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
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.bool_):
        return bool(o)
    return o


def dump(name, obj):
    (OUT / name).write_text(json.dumps(clean(obj), indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------------------------------------------
# 0. Inputs (frozen config checked; novelty inputs = frozen inputs minus the constant login_success)
# ---------------------------------------------------------------------------------------------------------------
assert sha(FROZEN) == FROZEN_SHA
frozen = json.loads(FROZEN.read_text(encoding="utf-8"))
assert FEATURES == [f for f in frozen["model_input_features"] if f != "login_success"]


def load(split):
    d = DS / "extraction" / split / "run1"
    X = pd.read_csv(d / "model_features.csv")
    M = pd.read_csv(d / "session_metadata.csv", keep_default_na=False)
    lab = pd.read_csv(DS / "labels" / f"{split}_session_labels.csv", dtype=str)
    df = pd.concat([M[["session_ref", "unknown_command_events"]], X], axis=1).merge(lab, on="session_ref", validate="one_to_one")
    df = df[df.role == "logged_in"].reset_index(drop=True)
    man = {f"{split}:{json.loads(l)['index']}": json.loads(l)
           for l in (DS / "runs" / split / "manifest.jsonl").read_text(encoding="utf-8").splitlines()}
    sent = [[c for c in man[i]["command_log"] if c["sent"]] for i in df.interaction_id]
    df["has_find"] = [any(c["command"].startswith("find / -name id_rsa") for c in s) for s in sent]
    df["exec_sum_s"] = [sum(c["wait_s"] for c in s) for s in sent]
    df["slow_exec_s"] = [sum(c["wait_s"] for c in s if c["wait_s"] >= 5) for s in sent]
    df["think_sum_s"] = [sum(c["think_time_s"] for c in s) for s in sent]
    return df


train, val = load("train"), load("validation")
assert len(train) == 1500 and len(val) == 600 and (train.login_success == 1).all() and (val.login_success == 1).all()
assert train.interaction_id.is_unique and val.interaction_id.is_unique
assert not ({"exfiltration", "data_exfiltration"} & (set(train.attack_cat) | set(val.attack_cat)))
CATS = sorted(train.attack_cat.unique())

# ---------------------------------------------------------------------------------------------------------------
# 1. Preprocessing (logged-in train only)
# ---------------------------------------------------------------------------------------------------------------
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.neighbors import NearestNeighbors  # noqa: E402


def fit_prep(raw):
    valid = raw.notna().sum()
    if (valid == 0).any():
        sys.exit(f"STOP: no valid training observations for {list(valid[valid == 0].index)}")
    med = raw.median()
    x = raw.fillna(med).copy()
    for f in LOG_FEATURES:
        x[f] = np.log1p(x[f].clip(lower=0))
    return med, StandardScaler().fit(x[FEATURES]), valid


def apply_prep(raw, med, sc):
    x = raw.fillna(med).copy()
    for f in LOG_FEATURES:
        x[f] = np.log1p(x[f].clip(lower=0))
    return sc.transform(x[FEATURES]).astype(np.float32)


raw_t, raw_v = train[FEATURES].astype(float), val[FEATURES].astype(float)
med, sc, valid = fit_prep(raw_t)
Xt, Xv = apply_prep(raw_t, med, sc), apply_prep(raw_v, med, sc)
imp_t, imp_v = raw_t.isna(), raw_v.isna()
prep = {"features": FEATURES, "log1p_features": LOG_FEATURES, "medians_logged_in_train": med.to_dict(),
        "train_valid_counts": valid.to_dict(), "scaler_mean": dict(zip(FEATURES, sc.mean_)), "scaler_scale": dict(zip(FEATURES, sc.scale_)),
        "imputed_counts": {"train": imp_t.sum().to_dict(), "validation": imp_v.sum().to_dict()},
        "imputed_by_category_train": {f: train.assign(m=imp_t[f]).groupby("attack_cat").m.sum().to_dict() for f in FEATURES if imp_t[f].any()},
        "imputation_reason": {"time_to_first_input_s": "no input line (brute-force logins without a command)",
                              "inter_input_mean_s": "fewer than 2 input lines", "inter_input_std_s": "fewer than 3 input lines"},
        "imputed_rows_by_input_line_count_train": train[imp_t.any(axis=1)].input_line_count.value_counts().sort_index().to_dict(),
        "largest_identical_vector_group_train": int(pd.DataFrame(Xt).round(6).value_counts().max()),
        "distinct_vectors_train": int(pd.DataFrame(Xt).round(6).drop_duplicates().shape[0]),
        "validation_scaled_mean": dict(zip(FEATURES, Xv.mean(0))), "validation_scaled_sd": dict(zip(FEATURES, Xv.std(0)))}
dump("preprocessing.json", prep)
pd.DataFrame({"session_ref": train.session_ref, **{f"imputed_{f}": imp_t[f] for f in FEATURES if imp_t[f].any()}}).to_csv(OUT / "imputation_log_train.csv", index=False)
pd.DataFrame({"session_ref": val.session_ref, **{f"imputed_{f}": imp_v[f] for f in FEATURES if imp_v[f].any()}}).to_csv(OUT / "imputation_log_validation.csv", index=False)

# ---------------------------------------------------------------------------------------------------------------
# 2. Scoring methods
# ---------------------------------------------------------------------------------------------------------------
import tensorflow as tf  # noqa: E402
from tensorflow.keras import Model  # noqa: E402
from tensorflow.keras.layers import Dense  # noqa: E402
from tensorflow.keras.optimizers import Adam  # noqa: E402


def knn_scores(ref, query, loo):
    nn = NearestNeighbors(n_neighbors=K_NN + (1 if loo else 0)).fit(ref)
    d, _ = nn.kneighbors(query)
    return (d[:, 1:] if loo else d).mean(1)


def train_ae(X, seed):
    tf.keras.backend.clear_session()
    tf.keras.utils.set_random_seed(seed)
    tf.config.experimental.enable_op_determinism()
    encoder = build_encoder(X.shape[1], HP["latent_dim"])
    x = encoder.output
    for u in HP["decoder"]:
        x = Dense(u, activation=HP["activation"])(x)
    ae = Model(encoder.input, Dense(X.shape[1], activation="linear", name="reconstruction")(x), name="novelty_autoencoder")
    ae.compile(optimizer=Adam(learning_rate=HP["ae_learning_rate"]), loss=HP["ae_loss"])
    t = time.time()
    h = ae.fit(X, X, epochs=HP["ae_epochs"], batch_size=HP["ae_batch_size"], validation_split=HP["ae_validation_split"], verbose=0)
    return ae, encoder, h, time.time() - t


def score_all(Xtr, Xva, seed):
    ae, enc, h, secs = train_ae(Xtr, seed)
    rt, rv = ae.predict(Xtr, batch_size=HP["predict_batch_size"], verbose=0), ae.predict(Xva, batch_size=HP["predict_batch_size"], verbose=0)
    zt, zv = enc.predict(Xtr, batch_size=HP["predict_batch_size"], verbose=0), enc.predict(Xva, batch_size=HP["predict_batch_size"], verbose=0)
    t = time.time()
    s = {"A_ae_reconstruction": (((rt - Xtr) ** 2).mean(1), ((rv - Xva) ** 2).mean(1)),
         "B_latent_knn": (knn_scores(zt, zt, True), knn_scores(zt, zv, False))}
    return {"scores": s, "per_feature_sq_err_val": (rv - Xva) ** 2, "zt": zt, "zv": zv, "ae": ae, "encoder": enc,
            "ae_loss": h.history["loss"], "ae_val_loss": h.history["val_loss"], "ae_seconds": secs, "knn_seconds": time.time() - t}


runs = {s: score_all(Xt, Xv, s) for s in SEEDS}
t = time.time()
C = (knn_scores(Xt, Xt, True), knn_scores(Xt, Xv, False))
c_seconds = time.time() - t
for s in SEEDS:
    runs[s]["scores"]["C_input_knn"] = C
rep = score_all(Xt, Xv, 42)
repro = {m: bool(np.array_equal(rep["scores"][m][1], runs[42]["scores"][m][1])) for m in ("A_ae_reconstruction", "B_latent_knn")}

# ---------------------------------------------------------------------------------------------------------------
# 3. Thresholds, flags, false-positive analysis
# ---------------------------------------------------------------------------------------------------------------
from scipy import stats  # noqa: E402


def boot_rate(flags, n=1000, seed=0):
    rng = np.random.RandomState(seed)
    return [float(np.percentile([flags[rng.randint(0, len(flags), len(flags))].mean() for _ in range(n)], q)) for q in (2.5, 97.5)]


def q_summary(v):
    return {"n": int(len(v)), "min": float(np.min(v)), "p05": float(np.percentile(v, 5)), "p25": float(np.percentile(v, 25)),
            "median": float(np.median(v)), "p75": float(np.percentile(v, 75)), "p95": float(np.percentile(v, 95)),
            "p99": float(np.percentile(v, 99)), "max": float(np.max(v))}


res = {"design": {"population": "logged-in sessions", "features": FEATURES, "methods": METHODS, "k_nn": K_NN,
                  "threshold_rule": f"{Q_PRIMARY:.0%} quantile of the method's training scores (kNN: leave-one-out); fixed before running",
                  "context_quantiles": Q_CONTEXT, "seeds": SEEDS, "hyperparameters": HP},
       "reproducibility_seed42_rerun_identical": repro, "methods": {}}
score_rows_v = pd.DataFrame({"session_ref": val.session_ref, "interaction_id": val.interaction_id,
                             "attack_cat_posthoc_only": val.attack_cat, "has_find_posthoc_only": val.has_find})
score_rows_t = pd.DataFrame({"session_ref": train.session_ref, "interaction_id": train.interaction_id,
                             "attack_cat_posthoc_only": train.attack_cat, "has_find_posthoc_only": train.has_find})
for m in METHODS:
    st, sv = runs[42]["scores"][m]
    thr = float(np.quantile(st, Q_PRIMARY))
    flags = sv > thr
    e = {"description": METHODS[m],
         "train_scores": q_summary(st), "validation_scores": q_summary(sv),
         "train_vs_validation_ks": {"D": float(stats.ks_2samp(st, sv).statistic), "p": float(stats.ks_2samp(st, sv).pvalue)},
         "threshold_primary": thr, "train_flag_rate": float((st > thr).mean()),
         "validation_flagged": int(flags.sum()), "validation_flag_rate": float(flags.mean()),
         "validation_flag_rate_ci95_bootstrap": boot_rate(flags),
         "validation_flag_rate_binomial_p_vs_1pct": float(stats.binomtest(int(flags.sum()), len(flags), 0.01).pvalue),
         "validation_quantile_equivalent_to_threshold": float((sv <= thr).mean()),
         "context_thresholds": {str(q): {"threshold": float(np.quantile(st, q)), "validation_flag_rate": float((sv > np.quantile(st, q)).mean())} for q in Q_CONTEXT},
         "validation_1pct_quantile_for_reference": float(np.quantile(sv, 0.99)),
         "per_category_validation": {}}
    for c in CATS:
        mk = (val.attack_cat == c).values
        e["per_category_validation"][c] = {"n": int(mk.sum()), "median_score": float(np.median(sv[mk])),
                                           "flagged": int(flags[mk].sum()), "flag_rate": float(flags[mk].mean()),
                                           "share_of_all_flags": float(flags[mk].sum() / max(flags.sum(), 1))}
    e["per_category_train_median"] = {c: float(np.median(st[(train.attack_cat == c).values])) for c in CATS}
    e["kruskal_eps2_category_validation"] = float(stats.kruskal(*[sv[(val.attack_cat == c).values] for c in CATS]).statistic / (len(sv) - 1))
    # artefact sensitivity (post hoc)
    fm = val.has_find.values
    e["find"] = {"validation_find_sessions": int(fm.sum()), "find_flagged": int(flags[fm].sum()),
                 "find_median_percentile_in_validation": float(np.mean([stats.percentileofscore(sv, x) for x in sv[fm]])) if fm.any() else None,
                 "non_find_pe_median_percentile": float(np.mean([stats.percentileofscore(sv, x) for x in sv[(val.attack_cat == "privilege_escalation").values & ~fm]])),
                 "flags_that_are_find_sessions_share": float(flags[fm].sum() / max(flags.sum(), 1)),
                 "train_find_scores_above_threshold": int((st[train.has_find.values] > thr).sum()), "train_find_sessions": int(train.has_find.sum())}
    e["cowrie_artefacts_spearman_validation"] = {k: float(stats.spearmanr(sv, val[k]).correlation) for k in
                                                ("exec_sum_s", "slow_exec_s", "unknown_command_events", "tty_output_bytes", "session_duration_s",
                                                 "input_line_count", "think_sum_s")}
    e["unknown_command_sessions_flag_rate"] = {"with_unknown_command": float(flags[val.unknown_command_events.values > 0].mean()),
                                               "without": float(flags[val.unknown_command_events.values == 0].mean())}
    e["imputed_rows_flag_rate"] = {"imputed": float(flags[imp_v.any(axis=1).values].mean()) if imp_v.any(axis=1).any() else None,
                                   "not_imputed": float(flags[~imp_v.any(axis=1).values].mean())}
    e["flagged_sessions_feature_medians"] = raw_v[flags].median().to_dict()
    e["all_validation_feature_medians"] = raw_v.median().to_dict()
    # seed repeatability
    if m != "C_input_knn":
        sv_all = [runs[s]["scores"][m][1] for s in SEEDS]
        thr_all = [float(np.quantile(runs[s]["scores"][m][0], Q_PRIMARY)) for s in SEEDS]
        fl_all = [x > th for x, th in zip(sv_all, thr_all)]
        jac = [float((a & b).sum() / max((a | b).sum(), 1)) for i, a in enumerate(fl_all) for b in fl_all[i + 1:]]
        sp = [float(stats.spearmanr(a, b).correlation) for i, a in enumerate(sv_all) for b in sv_all[i + 1:]]
        e["seed_stability"] = {"validation_score_spearman_pairwise": sp, "spearman_mean": float(np.mean(sp)), "spearman_min": float(np.min(sp)),
                               "thresholds_by_seed": thr_all, "validation_flag_rate_by_seed": [float(f.mean()) for f in fl_all],
                               "flag_set_jaccard_pairwise": jac, "flag_jaccard_mean": float(np.mean(jac)), "flag_jaccard_min": float(np.min(jac)),
                               "flagged_by_all_5_seeds": int(np.all(fl_all, axis=0).sum()), "flagged_by_any_seed": int(np.any(fl_all, axis=0).sum())}
        for s in SEEDS:
            score_rows_v[f"{m}_seed{s}"] = runs[s]["scores"][m][1]
    else:
        e["seed_stability"] = {"note": "deterministic (no random state)"}
        score_rows_v[m] = sv
    score_rows_v[f"{m}_flag_seed42"] = flags
    score_rows_t[m] = st
    res["methods"][m] = e
names = list(METHODS)
sv42 = {m: runs[42]["scores"][m][1] for m in names}
fl42 = {m: sv42[m] > res["methods"][m]["threshold_primary"] for m in names}
res["method_agreement_validation"] = {
    "score_spearman": {f"{a}~{b}": float(stats.spearmanr(sv42[a], sv42[b]).correlation) for i, a in enumerate(names) for b in names[i + 1:]},
    "flag_jaccard": {f"{a}~{b}": float((fl42[a] & fl42[b]).sum() / max((fl42[a] | fl42[b]).sum(), 1)) for i, a in enumerate(names) for b in names[i + 1:]},
    "flagged_by_all_three": int((fl42[names[0]] & fl42[names[1]] & fl42[names[2]]).sum())}
# AE: which inputs drive reconstruction error among flagged validation sessions
pfe = runs[42]["per_feature_sq_err_val"]
fa = fl42["A_ae_reconstruction"]
res["methods"]["A_ae_reconstruction"]["error_share_by_feature_flagged"] = dict(zip(FEATURES, (pfe[fa].sum(0) / pfe[fa].sum()).round(4)))
res["methods"]["A_ae_reconstruction"]["error_share_by_feature_all_validation"] = dict(zip(FEATURES, (pfe.sum(0) / pfe.sum()).round(4)))

# ---------------------------------------------------------------------------------------------------------------
# 4. find sensitivity: refit preprocessing + all methods without the 30 training find sessions (seed 42)
# ---------------------------------------------------------------------------------------------------------------
keep = ~train.has_find.values
med2, sc2, _ = fit_prep(raw_t[keep])
Xt2, Xv2 = apply_prep(raw_t[keep], med2, sc2), apply_prep(raw_v, med2, sc2)
r2 = score_all(Xt2, Xv2, 42)
r2["scores"]["C_input_knn"] = (knn_scores(Xt2, Xt2, True), knn_scores(Xt2, Xv2, False))
fs = {}
for m in names:
    st2, sv2 = r2["scores"][m]
    thr2 = float(np.quantile(st2, Q_PRIMARY))
    f2 = sv2 > thr2
    fm = val.has_find.values
    fs[m] = {"validation_score_spearman_full_vs_nofind": float(stats.spearmanr(sv42[m], sv2).correlation),
             "threshold_full": res["methods"][m]["threshold_primary"], "threshold_nofind": thr2,
             "validation_flag_rate_nofind": float(f2.mean()), "find_flagged_full": int(fl42[m][fm].sum()), "find_flagged_nofind": int(f2[fm].sum()),
             "flag_jaccard_full_vs_nofind": float((fl42[m] & f2).sum() / max((fl42[m] | f2).sum(), 1)),
             "non_find_flag_rate_full": float(fl42[m][~fm].mean()), "non_find_flag_rate_nofind": float(f2[~fm].mean())}
res["find_sensitivity"] = {"note": "Diagnostic refit excluding the 30 training sessions with `find / -name id_rsa`; data unchanged.", "methods": fs}

# ---------------------------------------------------------------------------------------------------------------
# 5. Save model artefacts, configuration, scores
# ---------------------------------------------------------------------------------------------------------------
import joblib  # noqa: E402
MODELS.mkdir(parents=True)
r = runs[42]
r["ae"].save_weights(str(MODELS / "autoencoder.weights.h5"))
joblib.dump(sc, MODELS / "scaler.joblib")
joblib.dump(med.to_dict(), MODELS / "medians.joblib")
np.save(MODELS / "reference_latent_train.npy", r["zt"])
np.save(MODELS / "reference_scaled_train.npy", Xt)
thresholds = {m: res["methods"][m]["threshold_primary"] for m in names}
ncfg = {"config_name": "cowrie_novelty_baseline", "config_version": "1.0.0-provisional", "status": "provisional - not frozen; freeze needs approval",
        "date": "2026-11-11", "task": "Task 18",
        "relation_to_clustering_config": {"path": "configs/model_features_v2_frozen_v1.1.0.json", "config_version": frozen["config_version"],
                                          "sha256": sha(FROZEN), "note": "separate configuration; the frozen 8-feature clustering configuration is not modified"},
        "population": "logged-in Cowrie sessions (login_success = 1)", "features": FEATURES, "excluded_from_frozen_inputs": {"login_success": "constant in the logged-in population"},
        "preprocessing": {"imputation": "median of non-missing logged-in training values", "medians": med.to_dict(), "log1p": LOG_FEATURES,
                          "scaler": "StandardScaler on logged-in training data", "scaler_mean": dict(zip(FEATURES, sc.mean_)),
                          "scaler_scale": dict(zip(FEATURES, sc.scale_)), "missingness_indicators": False},
        "methods": METHODS, "k_nn": K_NN, "autoencoder": {**HP, "seed": 42, "architecture": {"encoder": [32, 16, HP["latent_dim"]], "decoder": [16, 32, len(FEATURES)]}},
        "threshold_rule": res["design"]["threshold_rule"], "thresholds_seed42": thresholds,
        "artefacts": {"directory": str(MODELS.relative_to(REPO)).replace("\\", "/")},
        "training_data": {"dataset": "reports/dataset_v2_training_validation_20261110", "split": "train", "rows": len(train),
                          "dataset_SHA256SUMS_sha256": sha(DS / "SHA256SUMS")},
        "held_out_experiment": "data_exfiltration is absent from training and validation; the sealed test set has not been accessed."}
(MODELS / "config.json").write_text(json.dumps(clean(ncfg), indent=2), encoding="utf-8")
# reload check
from tensorflow.keras.layers import Input  # noqa: E402,F401
ae2, enc2, _, _ = train_ae(Xt[:10], 42)            # fresh graph with the same architecture
ae2.load_weights(str(MODELS / "autoencoder.weights.h5"))
reload_ok = bool(np.allclose(((ae2.predict(Xv, verbose=0) - Xv) ** 2).mean(1), sv42["A_ae_reconstruction"], atol=1e-7))
(MODELS / "artifact_sha256.json").write_text(json.dumps({p.name: sha(p) for p in sorted(MODELS.iterdir()) if p.is_file()}, indent=2))
NCFG.write_text(json.dumps(clean({**ncfg, "artefact_sha256": json.loads((MODELS / "artifact_sha256.json").read_text())}), indent=2) + "\n", encoding="utf-8")
(HERE / "config").mkdir(exist_ok=True)
(HERE / "config" / "cowrie_novelty_baseline_v1.json").write_text(NCFG.read_text(encoding="utf-8"), encoding="utf-8")
score_rows_v.to_csv(OUT / "validation_scores.csv", index=False, float_format="%.6g")
score_rows_t.to_csv(OUT / "train_scores_seed42.csv", index=False, float_format="%.6g")
res["saved"] = {"directory": str(MODELS.relative_to(REPO)), "ae_reload_reproduces_validation_scores": reload_ok}
res["runtime_seconds"] = {"ae_by_seed": {s: runs[s]["ae_seconds"] for s in SEEDS}, "latent_knn_by_seed": {s: runs[s]["knn_seconds"] for s in SEEDS},
                          "input_knn": c_seconds, "wall": time.time() - T0}
res["training_logs_seed42"] = {"ae_loss": r["ae_loss"], "ae_val_loss": r["ae_val_loss"]}
import keras  # noqa: E402
import sklearn  # noqa: E402
res["environment"] = {"python": platform.python_version(), "tensorflow": tf.__version__, "keras": keras.__version__,
                      "scikit_learn": sklearn.__version__, "numpy": np.__version__, "pandas": pd.__version__}
res["test_like_paths_opened"] = [p for p in OPENED if "test" in p.rsplit("/", 1)[-1] and p.endswith((".pkl", ".csv", ".json", ".jsonl"))]
dump("results.json", res)

# ---------------------------------------------------------------------------------------------------------------
# 6. Figures
# ---------------------------------------------------------------------------------------------------------------
import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

fig, axes = plt.subplots(1, 3, figsize=(15, 3.8))
for ax, m in zip(axes, names):
    st, sv = runs[42]["scores"][m]
    bins = np.linspace(0, max(np.percentile(st, 99.7), np.percentile(sv, 99.7)), 60)
    ax.hist(st, bins=bins, alpha=0.5, density=True, label="train")
    ax.hist(sv, bins=bins, alpha=0.5, density=True, label="validation")
    ax.axvline(thresholds[m], color="red", ls="--", label="train p99 threshold")
    ax.set_title(m)
    ax.legend(fontsize=7)
fig.tight_layout()
fig.savefig(FIG / "score_distributions_train_vs_validation.png", dpi=120)
plt.close(fig)
fig, axes = plt.subplots(1, 3, figsize=(15, 4))
for ax, m in zip(axes, names):
    sv = sv42[m]
    ax.boxplot([sv[(val.attack_cat == c).values] for c in CATS], showfliers=True, flierprops={"markersize": 2})
    ax.scatter(np.full(val.has_find.sum(), CATS.index("privilege_escalation") + 1.25), sv[val.has_find.values], marker="x", c="red", s=14, label="find sessions")
    ax.axhline(thresholds[m], color="red", ls="--")
    ax.set_xticks(range(1, len(CATS) + 1), [c.replace("_", "\n") for c in CATS], fontsize=7)
    ax.set_yscale("log")
    ax.set_title(f"{m}: validation by category (post hoc)")
    ax.legend(fontsize=7)
fig.tight_layout()
fig.savefig(FIG / "validation_scores_by_category.png", dpi=120)
plt.close(fig)
print(json.dumps(clean({m: {k: res["methods"][m][k] for k in ("threshold_primary", "validation_flagged", "validation_flag_rate", "validation_flag_rate_ci95_bootstrap")}
                        for m in names}), indent=1))
print("repro", repro, "reload", reload_ok, "wall", round(time.time() - T0, 1))
