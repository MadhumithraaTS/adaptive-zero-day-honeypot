"""Task 19B: analysis of the single sealed-test scoring. Reads ONLY saved outputs (no model, no re-scoring).

    ml\\cowrie_dec_integration_skeleton\\.venv-dec-smoke\\Scripts\\python.exe reports\\cowrie_sealed_exfiltration_evaluation_20261111\\analyse_test.py

Inputs: evidence/test_scores_core.csv and evidence/test_score_internals.npz (hash-checked against evidence/scoring_record.json),
the sealed raw evidence (manifest, terminal output, Cowrie slice) for per-session interaction evidence, the Task 18
validation scores as the reference, and the pre-registered classification rules. Writes test_scores.csv,
flagged_session_analysis.csv, method_comparison.csv, test_feature_summary.csv, figures/, evidence/scoring_summary.json.
"""
import hashlib
import json
import math
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
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


rec = json.loads((HERE / "evidence" / "scoring_record.json").read_text())
for p, h in rec["outputs_sha256"].items():
    assert sha(HERE / p) == h, f"saved scoring output changed: {p}"
assert sha(HERE / "evidence" / "preregistered_classification_rules.json") == RULES_SHA
ncfg = json.loads(NCFG.read_text(encoding="utf-8"))
F, THR = ncfg["features"], ncfg["thresholds_seed42"]
import joblib  # noqa: E402
medians = joblib.load(MODELS / "medians.joblib")
core = pd.read_csv(HERE / "evidence" / "test_scores_core.csv")
npz = np.load(HERE / "evidence" / "test_score_internals.npz")
EXT = HERE / "extraction" / "test" / "run1"
X = pd.read_csv(EXT / "model_features.csv")
M = pd.read_csv(EXT / "session_metadata.csv", keep_default_na=False)
lab = pd.read_csv(HERE / "labels" / "test_session_labels.csv", dtype=str)
allrows = pd.concat([M[["session_ref", "unknown_command_events"]], X], axis=1).merge(lab, on="session_ref", validate="one_to_one")
test = allrows[allrows.role == "logged_in"].reset_index(drop=True)
not_scored = allrows[allrows.role != "logged_in"]
assert test.session_ref.tolist() == core.session_ref.tolist()
raw = test[F].astype(float)
imputed = raw.isna()
scores = {m: npz[f"score_{m}"] for m in METHODS}
flags = {m: core[f"{m}_flag"].astype(bool).values for m in METHODS}
assert all(np.array_equal(flags[m], scores[m] > THR[m]) for m in METHODS)
shares = {m: npz[f"contrib_{m}"] / np.maximum(npz[f"contrib_{m}"].sum(1, keepdims=True), 1e-12) for m in METHODS}
started = rec["scoring_started_utc"]
from scipy import stats  # noqa: E402,F401

# ---- per-session interaction evidence (manifest, terminal output, Cowrie events; never model inputs)
man = {f"test:{json.loads(l)['index']}": json.loads(l) for l in (HERE / "runs" / "test" / "manifest.jsonl").read_text(encoding="utf-8").splitlines()}
term = {}
for l in (HERE / "runs" / "test" / "terminal_output.jsonl").read_text(encoding="utf-8").splitlines():
    t = json.loads(l)
    term[(t["index"], str(t["step"]))] = t["output"]
events = {}
for l in (HERE / "raw" / "test" / "cowrie_slice.json").read_text(encoding="utf-8").splitlines():
    e = json.loads(l)
    events.setdefault(e.get("session"), []).append(e)
train_cmds = pd.read_csv(DS / "evidence" / "train_command_log.csv")
train_names = {c.split()[0] for c in train_cmds.command if c.split()}
THINK_P99 = float(train_cmds[train_cmds.sent].think_time_s.quantile(0.99))
val_cmds = pd.read_csv(DS / "evidence" / "validation_command_log.csv")
val_names = {c.split()[0] for c in val_cmds.command if c.split()}


def evidence(row):
    e = man[row.interaction_id]
    idx = e["index"]
    sent = [c for c in e["command_log"] if c["sent"]]
    out = {c["seq"]: term.get((idx, str(c["seq"])), "") for c in sent}
    failed_inputs = [ev.get("input", "") for ev in events.get(row.session_ref, []) if ev["eventid"] == "cowrie.command.failed"]
    tar = [c for c in sent if c["command"].startswith("tar ")]
    curlT = [c for c in sent if c["command"].startswith("curl -T")]
    finds = [c for c in sent if c["command"].startswith("find ")]
    lsx = [c for c in sent if c["command"].startswith("ls -la")]

    def listed(o):
        lines = [l for l in o.splitlines()[1:-1] if l.strip()]
        return [l for l in lines if not l.rstrip().endswith((" .", " .."))]
    return {
        "commands": " ; ".join(c["command"] for c in sent), "n_commands": len(sent),
        "tar_present": bool(tar), "tar_failed": any(("Cannot open" in out[c["seq"]]) or ("Error is not recoverable" in out[c["seq"]])
                                                     or c["command"] in failed_inputs for c in tar),
        "tar_output": " | ".join(out[c["seq"]].splitlines()[1] if len(out[c["seq"]].splitlines()) > 1 else "" for c in tar),
        "curl_T_present": bool(curlT), "curl_T_failed": any("option -T not recognized" in out[c["seq"]] for c in curlT),
        "curl_T_output": " | ".join(out[c["seq"]].splitlines()[1] if len(out[c["seq"]].splitlines()) > 1 else "" for c in curlT),
        "find_present": bool(finds), "find_printed_paths": any(len([l for l in out[c["seq"]].splitlines()[1:-1] if l.strip()]) > 0 for c in finds),
        "ls_listed_entries": sum(len(listed(out[c["seq"]])) for c in lsx),
        "command_failed_events": len(failed_inputs), "command_failed_inputs": " | ".join(failed_inputs),
        "max_wait_s": max([c["wait_s"] for c in sent], default=0.0), "slow_cowrie_execution": any(c["wait_s"] >= 5 for c in sent),
        "slow_commands": " | ".join(c["command"] for c in sent if c["wait_s"] >= 5),
        "max_think_s": max([c["think_time_s"] for c in sent], default=0.0), "pacing_anomaly": any(c["think_time_s"] > THINK_P99 for c in sent),
        "unseen_command_names": " ".join(sorted({c["command"].split()[0] for c in sent if c["command"].split()} - train_names)),
        "termination": e["termination"],
    }


ev = pd.DataFrame([evidence(r) for r in test.itertuples()])


def classify(m, i):
    sh = shares[m][i]
    g = {k: float(sum(sh[F.index(f)] for f in v)) for k, v in GROUPS.items()}
    dom = max(g, key=g.get) if max(g.values()) >= 0.5 else "mixed"
    e = ev.iloc[i]
    emu_fail = bool(e.tar_failed or e.curl_T_failed or e.command_failed_events > 0)
    if dom in ("timing", "duration") and e.pacing_anomaly and not e.slow_cowrie_execution:
        cat = 3
    elif dom in ("timing", "duration") and e.slow_cowrie_execution and not e.pacing_anomaly:
        cat = 2
    elif dom == "output_volume" and emu_fail:
        cat = 2
    elif dom == "command_structure":
        cat = 1
    else:
        cat = 4
    return dom, g, cat, emu_fail


# ---- outputs
ts = pd.DataFrame({"session_ref": test.session_ref, "interaction_id": test.interaction_id})
for m in METHODS:
    ts[m] = scores[m]
    ts[f"{m}_flag"] = flags[m]
for f in F:
    ts[f"imputed_{f}"] = imputed[f].values
ts = pd.concat([ts, ev[["n_commands", "tar_failed", "curl_T_present", "curl_T_failed", "command_failed_events", "slow_cowrie_execution", "pacing_anomaly", "unseen_command_names"]]], axis=1)
ts.to_csv(HERE / "test_scores.csv", index=False, float_format="%.6g")
rows = []
for m in METHODS:
    for i in np.where(flags[m])[0]:
        dom, g, cat, emu = classify(m, i)
        e = ev.iloc[i]
        top = sorted(zip(F, shares[m][i]), key=lambda t: -t[1])[:3]
        rows.append({"method": m, "session_ref": test.session_ref[i], "interaction_id": test.interaction_id[i], "score": float(scores[m][i]),
                     "threshold": THR[m], "dominant_driver": dom, **{f"share_{k}": round(v, 4) for k, v in g.items()},
                     "top_inputs": "; ".join(f"{f} {s:.2f}" for f, s in top),
                     "raw_values": "; ".join(f"{f}={raw.iloc[i][f]}" for f in F),
                     "classification": cat, "classification_name": CATEGORY_NAMES[cat], "any_emulation_failure_in_session": emu,
                     **{k: e[k] for k in ("tar_present", "tar_failed", "tar_output", "curl_T_present", "curl_T_failed", "curl_T_output", "find_present",
                                          "find_printed_paths", "ls_listed_entries", "command_failed_events", "command_failed_inputs",
                                          "slow_cowrie_execution", "slow_commands", "max_wait_s", "pacing_anomaly", "max_think_s",
                                          "unseen_command_names", "n_commands", "commands")}})
fsa = pd.DataFrame(rows)
fsa.to_csv(HERE / "flagged_session_analysis.csv", index=False, float_format="%.6g")

from scipy import stats  # noqa: E402
val = pd.read_csv(T18 / "outputs" / "validation_scores.csv")
res18 = json.loads((T18 / "outputs" / "results.json").read_text())


def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    hw = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - hw), min(1.0, c + hw)]


comp = []
for m in METHODS:
    kv, nv = int(val[f"{m}_flag_seed42"].sum()), len(val)
    kt, nt = int(flags[m].sum()), len(test)
    sub = fsa[fsa.method == m] if len(fsa) else fsa
    cc = Counter(sub.classification) if len(sub) else Counter()
    comp.append({"method": m, "label": SHORT[m], "role": "primary" if m == "C_input_knn" else "secondary", "threshold": THR[m],
                 "validation_scored": nv, "validation_flagged": kv, "validation_flag_rate": kv / nv, "validation_rate_ci95_wilson": wilson(kv, nv),
                 "test_scored": nt, "test_flagged": kt, "test_flag_rate": kt / nt, "test_rate_ci95_wilson": wilson(kt, nt),
                 "rate_ratio_test_over_validation": (kt / nt) / (kv / nv) if kv else None,
                 "fisher_exact_p_two_sided": float(stats.fisher_exact([[kt, nt - kt], [kv, nv - kv]])[1]),
                 "cat1_behavioural_input_structure": cc.get(1, 0), "cat2_cowrie_emulation": cc.get(2, 0), "cat3_generator_pacing": cc.get(3, 0),
                 "cat4_ambiguous": cc.get(4, 0), "test_score_median": float(np.median(scores[m])), "validation_score_median": float(val[m if m == "C_input_knn" else f"{m}_seed42"].median()),
                 "score_ks_test_vs_validation_D": float(stats.ks_2samp(scores[m], val[m if m == "C_input_knn" else f"{m}_seed42"]).statistic),
                 "score_ks_p": float(stats.ks_2samp(scores[m], val[m if m == "C_input_knn" else f"{m}_seed42"]).pvalue),
                 "flagged_session_refs": " ".join(test.session_ref[flags[m]])})
pd.DataFrame(comp).to_csv(HERE / "method_comparison.csv", index=False, float_format="%.6g")
fl = {m: set(test.session_ref[flags[m]]) for m in METHODS}
agreement = {"flagged_by_all_three": sorted(fl[METHODS[0]] & fl[METHODS[1]] & fl[METHODS[2]]),
             "flagged_by_any": len(fl[METHODS[0]] | fl[METHODS[1]] | fl[METHODS[2]]),
             "jaccard": {f"{a}~{b}": (len(fl[a] & fl[b]) / len(fl[a] | fl[b])) if (fl[a] | fl[b]) else None for i, a in enumerate(METHODS) for b in METHODS[i + 1:]},
             "score_spearman": {f"{a}~{b}": float(stats.spearmanr(scores[a], scores[b]).correlation) for i, a in enumerate(METHODS) for b in METHODS[i + 1:]}}

# ---- feature summary: test vs validation (logged-in) and train reference
def load_split(split):
    d = DS / "extraction" / split / "run1"
    Xx = pd.read_csv(d / "model_features.csv")
    Mm = pd.read_csv(d / "session_metadata.csv", keep_default_na=False)
    ll = pd.read_csv(DS / "labels" / f"{split}_session_labels.csv", dtype=str)
    df = pd.concat([Mm[["session_ref"]], Xx], axis=1).merge(ll, on="session_ref")
    return df[df.role == "logged_in"]


vraw = load_split("validation")
fs_rows = []
for f in F:
    a, b = raw[f].dropna(), vraw[f].astype(float).dropna()
    ks = stats.ks_2samp(a, b) if len(a) and len(b) else None
    fs_rows.append({"feature": f, "test_n": int(raw[f].notna().sum()), "test_missing": int(raw[f].isna().sum()),
                    "test_median": float(a.median()) if len(a) else None, "test_q1": float(a.quantile(.25)) if len(a) else None,
                    "test_q3": float(a.quantile(.75)) if len(a) else None, "test_min": float(a.min()) if len(a) else None, "test_max": float(a.max()) if len(a) else None,
                    "validation_median": float(b.median()), "validation_q1": float(b.quantile(.25)), "validation_q3": float(b.quantile(.75)),
                    "validation_missing": int(vraw[f].isna().sum()), "train_median_used_for_imputation": float(medians[f]),
                    "ks_D_test_vs_validation": float(ks.statistic) if ks else None, "ks_p": float(ks.pvalue) if ks else None,
                    "test_share_above_validation_p99": float((a > b.quantile(.99)).mean()) if len(a) else None})
pd.DataFrame(fs_rows).to_csv(HERE / "test_feature_summary.csv", index=False, float_format="%.6g")

artefacts = {"all_test_sessions": {k: (float(ev[k].mean()) if ev[k].dtype == bool else float((ev[k] > 0).mean())) for k in
                                   ("tar_present", "tar_failed", "curl_T_present", "curl_T_failed", "find_present", "find_printed_paths",
                                    "command_failed_events", "slow_cowrie_execution", "pacing_anomaly")},
             "tar_failed_given_present": float(ev.tar_failed[ev.tar_present].mean()) if ev.tar_present.any() else None,
             "curl_T_failed_given_present": float(ev.curl_T_failed[ev.curl_T_present].mean()) if ev.curl_T_present.any() else None,
             "sessions_with_unseen_command_names": float((ev.unseen_command_names != "").mean()),
             "unseen_command_name_counts": dict(Counter(n for s in ev.unseen_command_names for n in s.split())),
             "command_names_unseen_in_train_and_validation": sorted({n for s in ev.unseen_command_names for n in s.split()} - val_names),
             "terminations": dict(Counter(ev.termination)), "think_p99_train_s": THINK_P99}
for m in METHODS:
    f_ = flags[m]
    artefacts[f"{m}_flagged_vs_unflagged"] = {k: [float(ev[k][f_].astype(float).gt(0).mean()) if f_.any() else None, float(ev[k][~f_].astype(float).gt(0).mean())]
                                              for k in ("slow_cowrie_execution", "pacing_anomaly", "command_failed_events")}

# ---- figures
import matplotlib  # noqa: E402
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
fig, axes = plt.subplots(1, 3, figsize=(15, 3.8))
for ax, m in zip(axes, METHODS):
    vs = val[m if m == "C_input_knn" else f"{m}_seed42"].values
    bins = np.linspace(0, max(np.percentile(vs, 99.9), np.percentile(scores[m], 99.9)) * 1.05, 60)
    ax.hist(vs, bins=bins, alpha=0.5, density=True, label="validation (known, n=600)")
    ax.hist(scores[m], bins=bins, alpha=0.5, density=True, label=f"test exfiltration (n={len(test)})")
    ax.axvline(THR[m], color="red", ls="--", label="frozen threshold")
    ax.set_title(SHORT[m] + (" [primary]" if m == "C_input_knn" else ""))
    ax.legend(fontsize=7)
fig.tight_layout()
fig.savefig(FIG / "score_distributions_validation_vs_test.png", dpi=120)
plt.close(fig)
fig, axes = plt.subplots(2, 4, figsize=(16, 6.5))
for ax, f in zip(axes.ravel(), F):
    a, b = raw[f].dropna(), vraw[f].astype(float).dropna()
    hi = max(np.percentile(a, 99.5) if len(a) else 1, np.percentile(b, 99.5))
    bins = np.linspace(0, hi * 1.05 if hi > 0 else 1, 40)
    ax.hist(b, bins=bins, alpha=0.5, density=True, label="validation")
    ax.hist(a, bins=bins, alpha=0.5, density=True, label="test")
    ax.set_title(f, fontsize=9)
axes.ravel()[0].legend(fontsize=7)
axes.ravel()[-1].axis("off")
fig.tight_layout()
fig.savefig(FIG / "feature_distributions_validation_vs_test.png", dpi=120)
plt.close(fig)

summary = {"scoring_started_utc": started, "scoring_finished_utc": rec["scoring_finished_utc"],
           "single_approved_evaluation": True, "population": "logged-in test sessions", "scored": len(test),
           "not_scored_failed_login_sessions": len(not_scored), "imputed_counts": imputed.sum().to_dict(),
           "method_comparison": comp, "agreement": agreement, "artefacts": artefacts,
           "classification_counts": {m: dict(Counter(fsa[fsa.method == m].classification)) if len(fsa) else {} for m in METHODS},
           "outputs_sha256": {p: sha(HERE / p) for p in ("test_scores.csv", "flagged_session_analysis.csv", "method_comparison.csv", "test_feature_summary.csv")}}
(HERE / "evidence" / "scoring_summary.json").write_text(json.dumps(summary, indent=2, default=float) + "\n", encoding="utf-8")
print(json.dumps({k: summary[k] for k in ("scored", "not_scored_failed_login_sessions", "classification_counts", "agreement")}, indent=1, default=float))
print(pd.DataFrame(comp)[["method", "validation_flag_rate", "test_flagged", "test_scored", "test_flag_rate", "fisher_exact_p_two_sided", "cat2_cowrie_emulation"]].to_string())
