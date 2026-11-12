"""Task 19A: audit the frozen Cowrie novelty baseline from its saved artefacts (no training, no refitting, no test data).

    ml\\cowrie_dec_integration_skeleton\\.venv-dec-smoke\\Scripts\\python.exe reports\\cowrie_novelty_freeze_audit_20261111\\audit_novelty_freeze.py

Everything is recomputed from the saved artefacts in models/cowrie_novelty_baseline_20261111/ (autoencoder weights
loaded into the existing architecture, saved scaler/medians, saved reference arrays) plus the raw Dataset V2
train/validation extraction, and compared with the saved Task 18 outputs. Training-only parameters are checked by
arithmetic (median, mean, population SD) without fitting any estimator. k-NN distances are exact queries against the
saved reference arrays. A Python audit hook aborts on any test-like path and records every file opened.
Output: evidence/novelty_audit.json
"""
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
OPENED = []


def _audit(event, args):
    if event == "open" and args and isinstance(args[0], (str, Path)):
        p = str(args[0]).replace("\\", "/").lower()
        if "ml_pipeline/work/test" in p or "sealed" in p or "/runs/test" in p or "exfil" in p.rsplit("/", 1)[-1]:
            raise RuntimeError(f"test-set access blocked: {p}")
        OPENED.append(p)


sys.addaudithook(_audit)

T18 = REPO / "reports" / "cowrie_novelty_baseline_20261111"
MODELS = REPO / "models" / "cowrie_novelty_baseline_20261111"
NCFG = REPO / "configs" / "cowrie_novelty_baseline_v1.json"
V110 = REPO / "configs" / "model_features_v2_frozen_v1.1.0.json"
DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
EXPECTED_FEATURES = ["session_duration_s", "input_line_count", "shell_operator_lines", "time_to_first_input_s",
                     "inter_input_mean_s", "inter_input_std_s", "tty_output_bytes"]
SEEDS = [42, 43, 44, 45, 46]
METHODS = ["A_ae_reconstruction", "B_latent_knn", "C_input_knn"]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def close(a, b):
    """CSV scores were written with float_format '%.6g'. Exact check at the stored precision: the recomputed value,
    formatted the same way, must equal the stored value for every session. Also returns the max absolute difference."""
    a, b = np.asarray(a, float), np.asarray(b, float)
    exact = all(float("%.6g" % x) == y for x, y in zip(a, b))
    return bool(exact), float(np.max(np.abs(a - b))) if len(a) else 0.0


R = {}
# ------------------------------------------------------------------ 1. hashes of artefacts and configuration
art = json.loads((MODELS / "artifact_sha256.json").read_text())
ncfg = json.loads(NCFG.read_text(encoding="utf-8"))
R["hashes"] = {
    "model_artifacts_match_artifact_sha256_json": {k: sha(MODELS / k) == v for k, v in art.items()},
    "novelty_config_artefact_sha256_matches_files": {k: sha(MODELS / k) == v for k, v in ncfg["artefact_sha256"].items()},
    "novelty_config_sha256": sha(NCFG),
    "novelty_config_report_copy_identical": sha(NCFG) == sha(T18 / "config" / "cowrie_novelty_baseline_v1.json"),
    "model_config_json_equals_novelty_config_minus_artefact_hashes":
        json.loads((MODELS / "config.json").read_text()) == {k: v for k, v in ncfg.items() if k != "artefact_sha256"},
    "clustering_config_recorded_in_novelty_config": ncfg["relation_to_clustering_config"],
    "recorded_clustering_sha_is_v1_1_0": ncfg["relation_to_clustering_config"]["sha256"] == sha(V110),
}

# ------------------------------------------------------------------ 2. inputs, order, no indicators
import joblib  # noqa: E402
scaler = joblib.load(MODELS / "scaler.joblib")
medians = joblib.load(MODELS / "medians.joblib")
v110 = json.loads(V110.read_text(encoding="utf-8"))
R["inputs"] = {
    "config_features": ncfg["features"], "exact_expected_order": ncfg["features"] == EXPECTED_FEATURES,
    "equals_v1_1_0_inputs_minus_login_success": ncfg["features"] == [f for f in v110["model_input_features"] if f != "login_success"],
    "scaler_feature_names_in_order": list(getattr(scaler, "feature_names_in_", [])) == EXPECTED_FEATURES,
    "scaler_n_features_in": int(scaler.n_features_in_), "medians_keys_in_order": list(medians) == EXPECTED_FEATURES,
    "missingness_indicators_flag": ncfg["preprocessing"]["missingness_indicators"],
    "no_indicator_like_inputs": not any(("missing" in f or "nan" in f or "imputed" in f) for f in ncfg["features"]),
    "reference_arrays_width": {"scaled": int(np.load(MODELS / "reference_scaled_train.npy").shape[1]),
                               "latent": int(np.load(MODELS / "reference_latent_train.npy").shape[1])},
}


# ------------------------------------------------------------------ 3. training-only parameters (arithmetic check)
def load(split):
    d = DS / "extraction" / split / "run1"
    X = pd.read_csv(d / "model_features.csv")
    M = pd.read_csv(d / "session_metadata.csv", keep_default_na=False)
    lab = pd.read_csv(DS / "labels" / f"{split}_session_labels.csv", dtype=str)
    df = pd.concat([M[["session_ref"]], X], axis=1).merge(lab[["session_ref", "role"]], on="session_ref", validate="one_to_one")
    return df[df.role == "logged_in"].reset_index(drop=True)


tr, va = load("train"), load("validation")
F, LOGF = ncfg["features"], ncfg["preprocessing"]["log1p"]
raw_t, raw_v = tr[F].astype(float), va[F].astype(float)


def prep(raw):
    x = raw.fillna(pd.Series(medians)).copy()
    for f in LOGF:
        x[f] = np.log1p(x[f].clip(lower=0))
    return x


med_train = raw_t.median()
med_trval = pd.concat([raw_t, raw_v]).median()
xt = prep(raw_t)
mean_chk, sd_chk = xt[F].mean().values, xt[F].std(ddof=0).values
Xt = scaler.transform(xt[F]).astype(np.float32)
Xv = scaler.transform(prep(raw_v)[F]).astype(np.float32)
ref_scaled = np.load(MODELS / "reference_scaled_train.npy")
R["training_only_parameters"] = {
    "train_rows": len(tr), "validation_rows": len(va),
    "medians_equal_logged_in_train_medians": {f: bool(np.isclose(medians[f], med_train[f])) for f in F},
    "medians_would_differ_if_validation_included": {f: float(med_trval[f]) for f in F if not np.isclose(med_trval[f], med_train[f])},
    "scaler_mean_equals_train_mean": bool(np.allclose(scaler.mean_, mean_chk, rtol=1e-9, atol=1e-12)),
    "scaler_scale_equals_train_population_sd": bool(np.allclose(scaler.scale_, sd_chk, rtol=1e-9, atol=1e-12)),
    "scaler_n_samples_seen": int(scaler.n_samples_seen_) if np.ndim(scaler.n_samples_seen_) == 0 else int(scaler.n_samples_seen_[0]),
    "config_medians_equal_saved_medians": all(np.isclose(ncfg["preprocessing"]["medians"][f], medians[f]) for f in F),
    "reference_scaled_train_equals_reprocessed_train": bool(np.array_equal(ref_scaled, Xt)),
}

# ------------------------------------------------------------------ 4. imputation records complete
logs = {s: pd.read_csv(T18 / "outputs" / f"imputation_log_{s}.csv") for s in ("train", "validation")}
imp = {}
for s, raw, frame in (("train", raw_t, tr), ("validation", raw_v, va)):
    lg = logs[s]
    cols = {c.replace("imputed_", ""): c for c in lg.columns if c.startswith("imputed_")}
    imp[s] = {"rows_equal": len(lg) == len(frame), "session_refs_equal_in_order": lg.session_ref.tolist() == frame.session_ref.tolist(),
              "features_logged": sorted(cols),
              "features_with_nan": sorted(f for f in F if raw[f].isna().any()),
              "per_feature_log_equals_nan_mask": {f: bool((lg[cols[f]].astype(bool).values == raw[f].isna().values).all()) for f in cols},
              "nan_counts": {f: int(raw[f].isna().sum()) for f in F}}
    imp[s]["complete"] = imp[s]["rows_equal"] and imp[s]["session_refs_equal_in_order"] and imp[s]["features_logged"] == imp[s]["features_with_nan"] \
        and all(imp[s]["per_feature_log_equals_nan_mask"].values())
R["imputation_records"] = imp

# ------------------------------------------------------------------ 5. reproduce scores, thresholds, flags from saved artefacts
import tensorflow as tf  # noqa: E402
from tensorflow.keras import Model  # noqa: E402
from tensorflow.keras.layers import Dense  # noqa: E402
from sklearn.neighbors import NearestNeighbors  # noqa: E402
from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.model import build_encoder  # noqa: E402

hp = ncfg["autoencoder"]
encoder = build_encoder(len(F), hp["latent_dim"])
x = encoder.output
for u in hp["decoder"]:
    x = Dense(u, activation=hp["activation"])(x)
ae = Model(encoder.input, Dense(len(F), activation="linear", name="reconstruction")(x))
ae.load_weights(str(MODELS / "autoencoder.weights.h5"))      # weights loaded; no compile, no fit
ref_lat = np.load(MODELS / "reference_latent_train.npy")
K = ncfg["k_nn"]


def knn(ref, q, loo):
    d, _ = NearestNeighbors(n_neighbors=K + (1 if loo else 0)).fit(ref).kneighbors(q)   # exact index over the saved reference
    return (d[:, 1:] if loo else d).mean(1)


BS = hp["predict_batch_size"]   # Task 18 predicted with this batch size; float32 results depend on it
zt = encoder.predict(Xt, batch_size=BS, verbose=0)
zv = encoder.predict(Xv, batch_size=BS, verbose=0)
scores = {"A_ae_reconstruction": (((ae.predict(Xt, batch_size=BS, verbose=0) - Xt) ** 2).mean(1), ((ae.predict(Xv, batch_size=BS, verbose=0) - Xv) ** 2).mean(1)),
          "B_latent_knn": (knn(ref_lat, ref_lat, True), knn(ref_lat, zv, False)),
          "C_input_knn": (knn(ref_scaled, ref_scaled, True), knn(ref_scaled, Xv, False))}
saved_t = pd.read_csv(T18 / "outputs" / "train_scores_seed42.csv")
saved_v = pd.read_csv(T18 / "outputs" / "validation_scores.csv")
res18 = json.loads((T18 / "outputs" / "results.json").read_text())
assert saved_v.session_ref.tolist() == va.session_ref.tolist() and saved_t.session_ref.tolist() == tr.session_ref.tolist()
rep = {"latent_of_reference_scaled_equals_saved_reference_latent": bool(np.allclose(zt, ref_lat, atol=1e-6))}
for m in METHODS:
    st, sv = scores[m]
    vcol = m if m == "C_input_knn" else f"{m}_seed42"
    thr = float(np.quantile(st, 0.99))
    thr_cfg = ncfg["thresholds_seed42"][m]
    flags = sv > thr_cfg
    rep[m] = {"train_scores_match_saved": close(st, saved_t[m]), "validation_scores_match_saved": close(sv, saved_v[vcol]),
              "recomputed_p99_threshold": thr, "config_threshold": thr_cfg, "results_threshold": res18["methods"][m]["threshold_primary"],
              "threshold_matches_config": bool(abs(thr - thr_cfg) <= 1e-6), "threshold_matches_results": bool(abs(thr - res18["methods"][m]["threshold_primary"]) <= 1e-6),
              "validation_flags_match_saved": bool(np.array_equal(flags, saved_v[f"{m}_flag_seed42"].astype(bool).values)),
              "validation_flagged": int(flags.sum()), "validation_flag_rate": float(flags.mean()),
              "saved_validation_flagged": res18["methods"][m]["validation_flagged"],
              "flags_with_recomputed_threshold_equal": bool(np.array_equal(sv > thr, flags))}
rep["C_input_knn"]["deterministic_repeat_identical"] = bool(np.array_equal(knn(ref_scaled, Xv, False), scores["C_input_knn"][1]))
R["reproduction_seed42"] = rep

# ------------------------------------------------------------------ 6. five-seed stability preserved (recomputed from saved per-seed scores)
from scipy import stats  # noqa: E402
stab = {}
for m in ("A_ae_reconstruction", "B_latent_knn"):
    s = res18["methods"][m]["seed_stability"]
    cols = [f"{m}_seed{x}" for x in SEEDS]
    sv_all = [saved_v[c].values for c in cols]
    sp = [float(stats.spearmanr(a, b).correlation) for i, a in enumerate(sv_all) for b in sv_all[i + 1:]]
    fl = [v > t for v, t in zip(sv_all, s["thresholds_by_seed"])]
    jac = [float((a & b).sum() / max((a | b).sum(), 1)) for i, a in enumerate(fl) for b in fl[i + 1:]]
    stab[m] = {"per_seed_columns_present": all(c in saved_v for c in cols),
               "spearman_mean_recomputed": float(np.mean(sp)), "spearman_mean_saved": s["spearman_mean"],
               "spearman_matches": bool(abs(np.mean(sp) - s["spearman_mean"]) < 1e-4),
               "flag_rates_recomputed": [float(f.mean()) for f in fl], "flag_rates_saved": s["validation_flag_rate_by_seed"],
               "flag_rates_match": bool(np.allclose([f.mean() for f in fl], s["validation_flag_rate_by_seed"], atol=1e-6)),
               "jaccard_mean_recomputed": float(np.mean(jac)), "jaccard_mean_saved": s["flag_jaccard_mean"],
               "jaccard_matches": bool(abs(np.mean(jac) - s["flag_jaccard_mean"]) < 1e-4),
               "flagged_by_all_5": int(np.all(fl, axis=0).sum()), "flagged_by_any": int(np.any(fl, axis=0).sum()),
               "note": "per-seed thresholds are taken from results.json (only seed-42 training scores and weights were saved)"}
R["seed_stability"] = stab

# ------------------------------------------------------------------ 7. test data untouched
R["test_set"] = {
    "files_opened_matching_test_or_exfiltration": [p for p in OPENED if ("test" in p.rsplit("/", 1)[-1] and p.endswith((".pkl", ".csv", ".json", ".jsonl"))) or "exfil" in p],
    "dataset_v2_run_directories": sorted(p.name for p in (DS / "runs").iterdir() if p.is_dir()),
    "categories_in_scored_data": None,
    "files_opened_total": len(OPENED),
}
lab_t = pd.read_csv(DS / "labels" / "train_session_labels.csv", dtype=str)
lab_v = pd.read_csv(DS / "labels" / "validation_session_labels.csv", dtype=str)
R["test_set"]["categories_in_scored_data"] = sorted(set(lab_t.attack_cat) | set(lab_v.attack_cat))
R["test_set"]["held_out_rows_in_train_validation"] = int((lab_t.held_out == "True").sum() + (lab_v.held_out == "True").sum())

checks = {
    "artefact_hashes": all(R["hashes"]["model_artifacts_match_artifact_sha256_json"].values()) and all(R["hashes"]["novelty_config_artefact_sha256_matches_files"].values()),
    "novelty_config_consistent": R["hashes"]["novelty_config_report_copy_identical"] and R["hashes"]["model_config_json_equals_novelty_config_minus_artefact_hashes"],
    "seven_inputs_exact_order": R["inputs"]["exact_expected_order"] and R["inputs"]["equals_v1_1_0_inputs_minus_login_success"] and R["inputs"]["scaler_feature_names_in_order"],
    "no_missingness_indicators": R["inputs"]["missingness_indicators_flag"] is False and R["inputs"]["no_indicator_like_inputs"] and R["inputs"]["scaler_n_features_in"] == 7,
    "training_only_medians_and_scaling": all(R["training_only_parameters"]["medians_equal_logged_in_train_medians"].values())
        and R["training_only_parameters"]["scaler_mean_equals_train_mean"] and R["training_only_parameters"]["scaler_scale_equals_train_population_sd"]
        and R["training_only_parameters"]["scaler_n_samples_seen"] == 1500 and R["training_only_parameters"]["reference_scaled_train_equals_reprocessed_train"],
    "imputation_records_complete": imp["train"]["complete"] and imp["validation"]["complete"],
    "method_C_deterministic_threshold_saved": rep["C_input_knn"]["threshold_matches_config"] and rep["C_input_knn"]["deterministic_repeat_identical"],
    "methods_A_B_thresholds_retained": all(rep[m]["threshold_matches_config"] and rep[m]["threshold_matches_results"] for m in ("A_ae_reconstruction", "B_latent_knn")),
    "validation_scores_reproduce": all(rep[m]["validation_scores_match_saved"][0] and rep[m]["train_scores_match_saved"][0] for m in METHODS),
    "validation_flags_reproduce_exactly": all(rep[m]["validation_flags_match_saved"] for m in METHODS),
    "five_seed_stability_preserved": all(v["spearman_matches"] and v["flag_rates_match"] and v["jaccard_matches"] for v in stab.values()),
    "no_test_or_exfiltration_files_opened": R["test_set"]["files_opened_matching_test_or_exfiltration"] == [],
    "only_train_validation_runs_exist_for_dataset_v2": R["test_set"]["dataset_v2_run_directories"] == ["train", "validation"],
}
R["checks"], R["all_pass"] = checks, all(checks.values())


def clean(o):
    if isinstance(o, dict):
        return {str(k): clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [clean(v) for v in o]
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, np.bool_):
        return bool(o)
    return o


(HERE / "evidence").mkdir(exist_ok=True)
(HERE / "evidence" / "novelty_audit.json").write_text(json.dumps(clean(R), indent=2), encoding="utf-8")
print(json.dumps(clean({"checks": checks, "all_pass": R["all_pass"], "reproduction": {m: {k: rep[m][k] for k in ("validation_scores_match_saved", "validation_flagged", "threshold_matches_config", "validation_flags_match_saved")} for m in METHODS}}), indent=1))
sys.exit(0 if R["all_pass"] else 1)
