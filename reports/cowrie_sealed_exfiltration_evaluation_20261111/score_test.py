"""Task 19B: the SINGLE approved scoring of the sealed data_exfiltration test run with the frozen novelty baseline.

    ml\\cowrie_dec_integration_skeleton\\.venv-dec-smoke\\Scripts\\python.exe reports\\cowrie_sealed_exfiltration_evaluation_20261111\\score_test.py

Refuses to run twice (evidence/SCORING_DONE.lock). Uses only frozen artefacts: saved medians/scaler (no fitting),
autoencoder weights loaded into the existing architecture (inference batch 256), saved training reference arrays for the
k=5 distances, saved thresholds. Test data never fits anything. Population = logged-in test sessions (frozen novelty
population); failed-login test sessions are counted but not scored. Sessions with Cowrie command failures are kept.
Flag classification follows evidence/preregistered_classification_rules.json (hash checked).
"""
import hashlib
import json
import math
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
LOCK = HERE / "evidence" / "SCORING_DONE.lock"
if LOCK.exists() or (HERE / "test_scores.csv").exists():
    sys.exit("test already scored once; refusing a second evaluation")
NCFG = REPO / "configs" / "cowrie_novelty_baseline_v1.json"
MODELS = REPO / "models" / "cowrie_novelty_baseline_20261111"
T18 = REPO / "reports" / "cowrie_novelty_baseline_20261111"
DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
FIG = HERE / "figures"
FIG.mkdir(exist_ok=True)
RULES_SHA = "cb599d219554f2536d1581c0b0b646f62c97b3bd70d565086f84e6371dc33c06"
METHODS = ["A_ae_reconstruction", "B_latent_knn", "C_input_knn"]
SHORT = {"A_ae_reconstruction": "A - reconstruction error", "B_latent_knn": "B - latent distance", "C_input_knn": "C - input distance"}
GROUPS = {"timing": ["time_to_first_input_s", "inter_input_mean_s", "inter_input_std_s"], "duration": ["session_duration_s"],
          "command_structure": ["input_line_count", "shell_operator_lines"], "output_volume": ["tty_output_bytes"]}
CATEGORY_NAMES = {1: "behavioural novelty (input structure)", 2: "Cowrie emulation failure/limitation",
                  3: "generator pacing/timing anomaly", 4: "ambiguous/insufficient evidence"}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


# ---- preconditions: freeze verification passed, sealed evidence unchanged, rules unchanged
fv = json.loads((HERE / "evidence" / "freeze_verification.json").read_text())
assert fv["all_pass"], "freeze verification did not pass"
assert sha(HERE / "evidence" / "preregistered_classification_rules.json") == RULES_SHA, "pre-registered rules changed"
for line in (HERE / "evidence" / "sealed_raw_hashes.txt").read_text().splitlines()[1:]:
    h, p = line.split(maxsplit=1)
    assert sha(REPO / p.lstrip("*")) == h, f"sealed raw evidence changed: {p}"
seal = json.loads((HERE / "evidence" / "sealed_extraction_hashes.json").read_text())
EXT = HERE / "extraction" / "test" / "run1"
assert seal["deterministic_two_runs"] and all(sha(EXT / f) == h for f, h in seal["outputs_sha256"].items())
for k, v in fv["hashes"].items():
    assert sha(REPO / k) == v, f"frozen artefact changed since verification: {k}"
ncfg = json.loads(NCFG.read_text(encoding="utf-8"))
F, LOGF, K, BS = ncfg["features"], ncfg["preprocessing"]["log1p"], ncfg["k_nn"], ncfg["autoencoder"]["predict_batch_size"]
THR = ncfg["thresholds_seed42"]
assert BS == 256 and K == 5

# ---- frozen pipeline (no fitting): saved medians/scaler, AE weights in the existing architecture, saved references
import joblib  # noqa: E402
from tensorflow.keras import Model  # noqa: E402
from tensorflow.keras.layers import Dense  # noqa: E402
from sklearn.neighbors import NearestNeighbors  # noqa: E402
from ml.cowrie_dec_integration_skeleton.ml.cowrie_dec.model import build_encoder  # noqa: E402
scaler, medians = joblib.load(MODELS / "scaler.joblib"), joblib.load(MODELS / "medians.joblib")
hp = ncfg["autoencoder"]
encoder = build_encoder(len(F), hp["latent_dim"])
h = encoder.output
for u in hp["decoder"]:
    h = Dense(u, activation=hp["activation"])(h)
ae = Model(encoder.input, Dense(len(F), activation="linear", name="reconstruction")(h))
ae.load_weights(str(MODELS / "autoencoder.weights.h5"))
ref_s, ref_z = np.load(MODELS / "reference_scaled_train.npy"), np.load(MODELS / "reference_latent_train.npy")
nn_s = NearestNeighbors(n_neighbors=K).fit(ref_s)      # exact index over the saved training reference (no parameters)
nn_z = NearestNeighbors(n_neighbors=K).fit(ref_z)


def frozen_score(raw):
    x = raw.fillna(pd.Series(medians))
    for f in LOGF:
        x[f] = np.log1p(x[f].clip(lower=0))
    Xs = scaler.transform(x[F]).astype(np.float32)
    recon = ae.predict(Xs, batch_size=BS, verbose=0)
    z = encoder.predict(Xs, batch_size=BS, verbose=0)
    dC, iC = nn_s.kneighbors(Xs)
    dB, iB = nn_z.kneighbors(z)
    sq = (recon - Xs) ** 2
    sc = {"A_ae_reconstruction": sq.mean(1), "B_latent_knn": dB.mean(1), "C_input_knn": dC.mean(1)}
    contrib = {"A_ae_reconstruction": sq, "B_latent_knn": (Xs - ref_s[iB].mean(1)) ** 2, "C_input_knn": (Xs - ref_s[iC].mean(1)) ** 2}
    return sc, {m: sc[m] > THR[m] for m in METHODS}, contrib, iB, iC, Xs


# ---- pipeline self-check BEFORE touching test features: this exact code path must reproduce the published Task 18
#      validation scores and flags (no new information; validation results are already reported)
vd = DS / "extraction" / "validation" / "run1"
vX = pd.read_csv(vd / "model_features.csv")
vM = pd.read_csv(vd / "session_metadata.csv", keep_default_na=False)
vl = pd.read_csv(DS / "labels" / "validation_session_labels.csv", dtype=str)
vrows = pd.concat([vM[["session_ref"]], vX], axis=1).merge(vl[["session_ref", "role"]], on="session_ref")
vrows = vrows[vrows.role == "logged_in"].reset_index(drop=True)
saved_v = pd.read_csv(T18 / "outputs" / "validation_scores.csv")
assert saved_v.session_ref.tolist() == vrows.session_ref.tolist()
vs, vf, _, _, _, _ = frozen_score(vrows[F].astype(float))
selfcheck = {m: {"scores_equal_at_stored_precision": all(float("%.6g" % a) == b for a, b in zip(vs[m], saved_v[m if m == "C_input_knn" else f"{m}_seed42"])),
                 "flags_equal": bool(np.array_equal(vf[m], saved_v[f"{m}_flag_seed42"].astype(bool).values))} for m in METHODS}
if not all(v["scores_equal_at_stored_precision"] and v["flags_equal"] for v in selfcheck.values()):
    sys.exit(f"pipeline self-check failed; test NOT scored: {selfcheck}")

# ---- the single test scoring (lock written first)
started = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
LOCK.write_text(started + "\n")
X = pd.read_csv(EXT / "model_features.csv")
M = pd.read_csv(EXT / "session_metadata.csv", keep_default_na=False)
lab = pd.read_csv(HERE / "labels" / "test_session_labels.csv", dtype=str)
allrows = pd.concat([M[["session_ref", "unknown_command_events"]], X], axis=1).merge(lab, on="session_ref", validate="one_to_one")
assert set(allrows.attack_cat) == {"exfiltration"} and set(allrows.held_out) == {"True"}
test = allrows[allrows.role == "logged_in"].reset_index(drop=True)
raw = test[F].astype(float)
scores, flags, contrib, iB, iC, Xs = frozen_score(raw)
core = pd.DataFrame({"session_ref": test.session_ref, "interaction_id": test.interaction_id})
for m in METHODS:
    core[m] = scores[m]
    core[f"{m}_flag"] = flags[m]
for f in F:
    core[f"imputed_{f}"] = raw[f].isna().values
core.to_csv(HERE / "evidence" / "test_scores_core.csv", index=False, float_format="%.9g")
np.savez(HERE / "evidence" / "test_score_internals.npz", Xs=Xs, iB=iB, iC=iC, **{f"contrib_{m}": contrib[m] for m in METHODS},
         **{f"score_{m}": scores[m] for m in METHODS})
rec = {"scoring_started_utc": started, "scoring_finished_utc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
       "single_approved_evaluation": True, "pipeline_selfcheck_on_published_validation": selfcheck,
       "test_rows_total": len(allrows), "scored_logged_in": len(test), "not_scored_failed_login_rows": int((allrows.role != "logged_in").sum()),
       "flagged": {m: int(flags[m].sum()) for m in METHODS}, "thresholds": THR, "inference_batch_size": BS,
       "outputs_sha256": {"evidence/test_scores_core.csv": sha(HERE / "evidence" / "test_scores_core.csv"),
                          "evidence/test_score_internals.npz": sha(HERE / "evidence" / "test_score_internals.npz")}}
(HERE / "evidence" / "scoring_record.json").write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
print(json.dumps(rec, indent=1))

