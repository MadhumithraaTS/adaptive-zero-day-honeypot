"""Dataset V2 feature leakage audit (L1-L7, C1-C4) on the authoritative labelled training run.

    .venv/Scripts/python.exe reports/v2_feature_leakage_validation/analyze_leakage.py

Training evidence: dataset_builder/runs/train_v1/raw/cowrie_thisrun.json (features via the unmodified V2 extractor)
with labels from dataset_builder/runs/train_v2_corrected/label_assignments.csv (labelling v2) and the train_v1
manifest (audit evidence only; never a feature input). Unit of independence: the generated interaction
(source_index); all cross-validation is GroupKFold by interaction. Category = source_attack_cat (generation intent).
eval_v1 is read only to count timestamp anomalies (data quality), never for feature decisions. No test set is read.
Outputs: extraction/, tables/.
"""
import csv
import json
import math
import random
import shutil
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.model_selection import GroupKFold
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
from scripts import extract_features_v2 as x2  # noqa: E402

RUNS = REPO / "dataset_builder" / "runs"
TRAIN_LOG = RUNS / "train_v1" / "raw" / "cowrie_thisrun.json"
LABELS = RUNS / "train_v2_corrected" / "label_assignments.csv"
MANIFEST = RUNS / "train_v1" / "manifest.jsonl"
PROFILES = REPO / "dataset_builder" / "profiles_v2.json"   # the profile file train_v1 was generated with (2.0.0)
CONFIRMATION_LOG = REPO / "reports" / "cowrie_compatibility_confirmation" / "evidence" / "cowrie_confirmation_slice.json"
CONFIRMATION_RUNS = REPO / "reports" / "cowrie_compatibility_confirmation" / "runs"
EVAL_LOG = RUNS / "eval_v1" / "raw" / "cowrie_thisrun.json"
EVAL_LABELS = RUNS / "eval_v2_corrected" / "label_assignments.csv"
OUT = HERE / "tables"
F = x2.MODEL_FEATURES
GROUP = {"login_success": "core", "login_failed_count": "C1", "session_duration_s": "C3", "input_line_count": "core",
         "input_bytes_total": "core", "input_line_max_bytes": "core", "unique_command_names": "core",
         "shell_operator_lines": "C4", "download_command_lines": "C4", "time_to_first_input_s": "C2",
         "inter_input_mean_s": "C2", "inter_input_std_s": "C2", "tty_output_bytes": "core"}
SEED = 0
random.seed(SEED)
np.random.seed(SEED)


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def clean(o):
    if isinstance(o, dict):
        return {str(k): clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [clean(v) for v in o]
    if isinstance(o, (np.floating, float)):
        return None if math.isnan(float(o)) else round(float(o), 6)
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.bool_):
        return bool(o)
    return o


# --- 1. extraction (unmodified V2 extractor) and label join ------------------------------------------------
for name, log in (("train_v1", TRAIN_LOG), ("confirmation_task9", CONFIRMATION_LOG)):
    target = HERE / "extraction" / name
    shutil.rmtree(target, ignore_errors=True)
    x2.extract([str(log)], str(target))
OUT.mkdir(exist_ok=True)


def load_extraction(name):
    d = HERE / "extraction" / name
    X = pd.read_csv(d / "model_features.csv")
    M = pd.read_csv(d / "session_metadata.csv", keep_default_na=False)
    return pd.concat([M[["session_ref", "warnings"]], X, M[x2.DESCRIPTIVE_FIELDS]], axis=1)


ext = load_extraction("train_v1")
labels = pd.read_csv(LABELS, dtype=str)
extra = sorted(set(ext.session_ref) - set(labels.session_id))
missing_in_ext = sorted(set(labels.session_id) - set(ext.session_ref))
df = ext.merge(labels, left_on="session_ref", right_on="session_id", how="inner")
df = df[df.source_status == "assigned"].copy()
df["group"] = df.source_index.astype(int)
df["category"] = df.source_attack_cat
CATS = sorted(df.category.unique())
LOGIN = df[df.auth_outcome == "success"].copy()
FAILED = df[df.auth_outcome == "failed"].copy()

manifest = {json.loads(l)["index"]: json.loads(l) for l in MANIFEST.read_text(encoding="utf-8").splitlines()}
profiles = {p["name"]: p for p in json.loads(PROFILES.read_text(encoding="utf-8"))["profiles"]}
raw_inputs = defaultdict(list)
raw_events = defaultdict(list)
for line in TRAIN_LOG.read_text(encoding="utf-8").splitlines():
    e = json.loads(line)
    raw_events[e["session"]].append(e)
for sid, evs in raw_events.items():
    evs.sort(key=lambda e: (ts(e["timestamp"]),))
    raw_inputs[sid] = [e["input"] for e in evs if e["eventid"] == "cowrie.command.input"
                       and e["input"].strip() not in ("exit", "logout")]

provenance = {
    "training_log": str(TRAIN_LOG.relative_to(REPO)), "labels": str(LABELS.relative_to(REPO)),
    "extracted_sessions": len(ext), "label_rows": len(labels),
    "extracted_not_in_labels": len(extra), "extracted_not_in_labels_note": "train_v1 raw slice includes eval_v1 sessions after its baseline; excluded",
    "labels_not_extracted": len(missing_in_ext),
    "excluded_inconsistent": int((labels.source_status == "inconsistent").sum()),
    "analysed_sessions": len(df), "interactions": int(df.group.nunique()),
    "logged_in_sessions": len(LOGIN), "failed_only_sessions": len(FAILED),
    "sessions_per_interaction": dict(Counter(Counter(df.group).values())),
    "logged_in_sessions_per_interaction": dict(Counter(Counter(LOGIN.group).values())),
    "conflicting_labels_per_session": int(labels.session_id.duplicated().sum()),
    "conflicting_categories_per_interaction": int((df.groupby("group").category.nunique() > 1).sum()),
    "category_counts_all": df.category.value_counts().to_dict(), "category_counts_logged_in": LOGIN.category.value_counts().to_dict(),
    "interactions_per_category": df.groupby("category").group.nunique().to_dict(),
}
(OUT / "data_provenance.json").write_text(json.dumps(clean(provenance), indent=2), encoding="utf-8")


# --- 2. per-feature statistics, L1, L2 -----------------------------------------------------------------------
def kruskal_eps(frame, feat):
    sub = frame[[feat, "category"]].dropna()
    groups = [g[feat].values for _, g in sub.groupby("category") if len(g) > 0]
    if len(groups) < 2 or sub[feat].nunique() < 2:
        return None, None, len(sub)
    h, p = stats.kruskal(*groups)
    return float(h / (len(sub) - 1)), float(p), len(sub)


def group_bootstrap_eps(frame, feat, n_boot=200):
    groups = frame.group.unique()
    by = {g: idx for g, idx in frame.groupby("group").groups.items()}
    vals = []
    for _ in range(n_boot):
        pick = np.random.choice(groups, size=len(groups), replace=True)
        sample = frame.loc[np.concatenate([by[g] for g in pick])]
        e, _, _ = kruskal_eps(sample, feat)
        if e is not None:
            vals.append(e)
    return (float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5))) if vals else (None, None)


def single_feature_ba(frame, feat):
    x = frame[feat].values.astype(float)
    nanmask = np.isnan(x)
    X = np.column_stack([np.where(nanmask, -1e9, x), nanmask.astype(float)])
    y, g = frame.category.values, frame.group.values
    preds = np.empty(len(y), dtype=object)
    for tr, te in GroupKFold(n_splits=5).split(X, y, g):
        clf = DecisionTreeClassifier(max_depth=3, random_state=SEED).fit(X[tr], y[tr])
        preds[te] = clf.predict(X[te])
    return float(balanced_accuracy_score(y, preds))


def exact_lookup(frame, keyfunc):
    """Fold-based exact-value lookup: key -> majority category on training folds; accuracy on held-out matches."""
    keys = frame.apply(keyfunc, axis=1).values
    y, g = frame.category.values, frame.group.values
    covered = correct = 0
    for tr, te in GroupKFold(n_splits=5).split(keys, y, g):
        table = defaultdict(Counter)
        for k, c in zip(keys[tr], y[tr]):
            table[k][c] += 1
        for k, c in zip(keys[te], y[te]):
            if k in table:
                covered += 1
                correct += table[k].most_common(1)[0][0] == c
    return {"covered_share": covered / len(frame), "correct_share_of_all": correct / len(frame),
            "accuracy_when_covered": correct / covered if covered else None}


def l1_constants(frame, feat):
    out = {}
    modal = {}
    for c, g in frame.groupby("category"):
        v = g[feat].fillna(-1.0e9)
        mode_val = v.mode().iloc[0]
        modal[c] = (mode_val, float((v == mode_val).mean()))
    for c, (mv, share) in modal.items():
        others = [o for o in modal if o != c]
        others_with_same_mode = [o for o in others if modal[o][0] == mv]
        vals = frame.loc[frame.category == c, feat].dropna()
        rest = frame.loc[frame.category != c, feat].dropna()
        outside = float(((vals < rest.min()) | (vals > rest.max())).mean()) if len(vals) and len(rest) else None
        out[c] = {"modal_value": None if mv == -1.0e9 else float(mv), "modal_share": share,
                  "near_constant": share >= 0.95, "modal_unique_to_category": share >= 0.95 and not others_with_same_mode,
                  "share_outside_other_categories_range": outside}
    return out


def describe(frame, feat):
    rows = {}
    for c, g in frame.groupby("category"):
        v = g[feat]
        nn = v.dropna()
        rows[c] = {"n": int(len(v)), "missing_pct": float(100 * v.isna().mean()),
                   "median": float(nn.median()) if len(nn) else None,
                   "q1": float(nn.quantile(0.25)) if len(nn) else None, "q3": float(nn.quantile(0.75)) if len(nn) else None,
                   "mean": float(nn.mean()) if len(nn) else None, "min": float(nn.min()) if len(nn) else None,
                   "max": float(nn.max()) if len(nn) else None}
    return rows


def missingness_assoc(frame, feat):
    tab = pd.crosstab(frame.category, frame[feat].isna())
    if tab.shape[1] < 2:
        return {"chi2": None, "p": None, "cramers_v": 0.0}
    chi2, p, _, _ = stats.chi2_contingency(tab)
    v = math.sqrt(chi2 / (tab.values.sum() * (min(tab.shape) - 1)))
    return {"chi2": float(chi2), "p": float(p), "cramers_v": float(v)}


per_feature = {}
dist_rows = []
for feat in F:
    entry = {"group": GROUP[feat]}
    for setname, frame in (("logged_in", LOGIN), ("all_sessions", df)):
        eps, p, n = kruskal_eps(frame, feat)
        lo, hi = group_bootstrap_eps(frame, feat) if eps is not None else (None, None)
        entry[setname] = {
            "n_nonmissing": n, "missing_pct": float(100 * frame[feat].isna().mean()),
            "kruskal_epsilon2": eps, "kruskal_p": p, "epsilon2_ci95_group_bootstrap": [lo, hi],
            "single_feature_balanced_accuracy_groupkfold": single_feature_ba(frame, feat),
            "chance_balanced_accuracy": 1 / frame.category.nunique(),
            "exact_value_lookup": exact_lookup(frame, lambda r, f=feat: None if pd.isna(r[f]) else round(float(r[f]), 6)),
            "missingness_vs_category": missingness_assoc(frame, feat),
            "l1": l1_constants(frame, feat),
        }
        for c, d in describe(frame, feat).items():
            dist_rows.append({"set": setname, "feature": feat, "category": c, **d})
    per_feature[feat] = entry
pd.DataFrame(dist_rows).to_csv(OUT / "category_distributions.csv", index=False, float_format="%.6g")

# Multi-feature context (all 13 together), upper bound on category information in the features.
def multi_ba(frame, feats):
    X = frame[feats].astype(float).fillna(-1e9).values
    y, g = frame.category.values, frame.group.values
    preds = np.empty(len(y), dtype=object)
    for tr, te in GroupKFold(n_splits=5).split(X, y, g):
        preds[te] = RandomForestClassifier(n_estimators=200, random_state=SEED).fit(X[tr], y[tr]).predict(X[te])
    return float(balanced_accuracy_score(y, preds))


context = {"all_13_features_rf_balanced_accuracy_logged_in": multi_ba(LOGIN, F),
           "core_6_rf_balanced_accuracy_logged_in": multi_ba(LOGIN, [f for f in F if GROUP[f] == "core"]),
           "without_C2_C3_rf_balanced_accuracy_logged_in": multi_ba(LOGIN, [f for f in F if GROUP[f] not in ("C2", "C3")]),
           "chance": 1 / LOGIN.category.nunique()}

# --- 3. correlation -----------------------------------------------------------------------------------------
corr = LOGIN[F].astype(float).corr(method="spearman")
corr.to_csv(OUT / "correlation_spearman_logged_in.csv", float_format="%.4f")
high_pairs = [(a, b, float(corr.loc[a, b])) for i, a in enumerate(F) for b in F[i + 1:]
              if not math.isnan(corr.loc[a, b]) and abs(corr.loc[a, b]) >= 0.8]

# --- 4. L3, L4, L5, L6, L7 -------------------------------------------------------------------------------------
# L3: invariance of features to identifiers/credentials/labels (re-extract a perturbed copy of the training log).
tmp = HERE / "extraction" / "_l3_perturbed"
shutil.rmtree(tmp, ignore_errors=True)
tmp.mkdir(parents=True)
pert_log = tmp / "perturbed.json"
with open(TRAIN_LOG, encoding="utf-8") as src, open(pert_log, "w", encoding="utf-8") as dst:
    for line in src:
        e = json.loads(line)
        for k in ("src_ip", "src_port", "dst_ip", "dst_port", "username", "password", "sensor", "uuid", "hassh", "version"):
            if k in e:
                e[k] = f"X-{k}"
        e["attack_cat"], e["label"], e["profile"] = "PERTURBED", 99, "PERTURBED"
        dst.write(json.dumps(e) + "\n")
x2.extract([str(pert_log)], str(tmp / "out"))
a = pd.read_csv(HERE / "extraction" / "train_v1" / "model_features.csv")
b = pd.read_csv(tmp / "out" / "model_features.csv")
l3_invariant = bool(a.equals(b))
shutil.rmtree(tmp)
src_text = (REPO / "scripts" / "extract_features_v2.py").read_text(encoding="utf-8")
l3 = {"features_invariant_to_identifiers_credentials_labels": l3_invariant,
      "extractor_source_mentions": {k: (k in src_text) for k in ("manifest", "terminal_output", "attack_cat", "label_assignments", "profile")},
      "reserved_test_marker_sessions": int(ext.warnings.str.contains("reserved_test_marker_present").sum()),
      "session_id_used_as_feature": False,
      "note": "extractor reads only --input logs and the specification (tests/test_extract_features_v2.py; extractor_v2 validation audit hook)"}

# L4: duplicates and grouping.
seq = LOGIN.session_ref.map(lambda s: tuple(raw_inputs[s]))
dup_seq_share = float(seq.map(seq.value_counts()).gt(1).mean())
seq_cats = defaultdict(set)
for s, c in zip(seq, LOGIN.category):
    seq_cats[s].add(c)
cross_cat_seq = float(seq.map(lambda s: len(seq_cats[s]) > 1).mean())
fv = LOGIN[F].astype(float).fillna(-1e9).round(6).apply(tuple, axis=1)
l4 = {"session_ids_unique": bool(ext.session_ref.is_unique), "duplicate_records_removed_by_extractor": int(
          json.loads((HERE / "extraction" / "train_v1" / "extraction_summary.json").read_text())["duplicate_records_removed"]),
      "extracted_sessions_excluded_not_in_training_labels": len(extra),
      "max_sessions_per_interaction": int(Counter(df.group).most_common(1)[0][1]),
      "logged_in_sessions_per_interaction_max": int(Counter(LOGIN.group).most_common(1)[0][1]),
      "logged_in_identical_feature_vectors_share": float(fv.map(fv.value_counts()).gt(1).mean()),
      "logged_in_identical_recorded_input_sequence_share": dup_seq_share,
      "logged_in_sequence_shared_across_categories_share": cross_cat_seq,
      "independence_unit": "source_index (generated interaction); all CV GroupKFold by interaction"}

# L5: profile fingerprints (templates).
l5 = {"exact_input_sequence_lookup": exact_lookup(LOGIN, lambda r: tuple(raw_inputs[r.session_ref])),
      "command_name_set_lookup": exact_lookup(LOGIN, lambda r: frozenset(t.split()[0] for t in raw_inputs[r.session_ref] if t.split())),
      "first_command_name_lookup": exact_lookup(LOGIN, lambda r: (raw_inputs[r.session_ref][0].split() or [""])[0] if raw_inputs[r.session_ref] else None),
      "failed_sessions_per_interaction_by_category": df.assign(f=df.auth_outcome.eq("failed")).groupby(["category", "group"]).f.sum()
          .groupby("category").agg(["mean", "min", "max"]).to_dict(orient="index"),
      "profile_failed_attempts_setting": {p["attack_cat"]: p["credentials"]["failed_attempts"] for p in profiles.values()}}

# L6: client/server contamination (manifest = audit evidence only).
l6_rows = []
for _, r in LOGIN.iterrows():
    sent = [c.strip() for c in manifest[int(r.source_index)]["commands_sent"]]
    rec = [c.strip() for c in raw_inputs[r.session_ref]]
    remaining = list(sent)
    extra_lines = 0
    for c in rec:
        if c in remaining:
            remaining.remove(c)
        else:
            extra_lines += 1
    l6_rows.append({"category": r.category, "sent": len(sent), "missing": len(remaining), "extra": extra_lines,
                    "any_missing": len(remaining) > 0, "tty": r.tty_output_bytes, "in_bytes": r.input_bytes_total})
l6df = pd.DataFrame(l6_rows)
tab = pd.crosstab(l6df.category, l6df.any_missing)
chi2, p, _, _ = stats.chi2_contingency(tab)
l6 = {"by_category": l6df.groupby("category").apply(lambda g: {
          "sessions": len(g), "manifest_lines": int(g.sent.sum()), "lines_missing_from_cowrie": int(g.missing.sum()),
          "missing_share": float(g.missing.sum() / max(g.sent.sum(), 1)), "sessions_with_loss_share": float(g.any_missing.mean()),
          "extra_lines": int(g.extra.sum())}).to_dict(),
      "loss_vs_category_chi2_p": float(p), "loss_vs_category_cramers_v": float(math.sqrt(chi2 / (tab.values.sum() * (min(tab.shape) - 1)))),
      "tty_vs_input_bytes_spearman": float(stats.spearmanr(l6df.tty, l6df.in_bytes, nan_policy="omit").correlation)}

# L7: training (generator 2.0, non-isolated, speed 8) vs generator 2.1 compat confirmation (isolated, speed 1). Descriptive only.
conf = load_extraction("confirmation_task9")
conf_logged = conf[conf.login_success == 1]
l7 = {"note": "No real-attacker deployment logs exist; L7 compares the training run with the generator-2.1 confirmation "
              "(14 logged-in sessions) descriptively. Not used for selection.",
      "feature_medians": {f: {"train_logged_in": float(LOGIN[f].median()), "gen21_logged_in": float(conf_logged[f].median()),
                              "train_missing_pct": float(100 * LOGIN[f].isna().mean()),
                              "gen21_missing_pct": float(100 * conf_logged[f].isna().mean())} for f in F},
      "failed_login_duration_median": {"train": float(FAILED.session_duration_s.median()),
                                       "gen21": float(conf[conf.login_success == 0].session_duration_s.median())},
      "downloads": {"train_url_download_events": int(df.url_download_events.sum()),
                    "gen21_url_download_events": int(conf.url_download_events.sum())}}

# --- 5. conditional groups -----------------------------------------------------------------------------------
delay_mid = {p["attack_cat"]: sum(p["delay_range"]) / 2 for p in profiles.values()}
LOGIN["delay_mid"] = LOGIN.category.map(delay_mid)
groups = {
    "C1": {"spearman_login_failed_vs_login_success_all": float(stats.spearmanr(df.login_failed_count, df.login_success).correlation),
           "login_failed_count_values_logged_in": LOGIN.login_failed_count.value_counts().to_dict(),
           "login_failed_count_values_failed": FAILED.login_failed_count.value_counts().to_dict(),
           "equals_one_minus_login_success_share": float((df.login_failed_count == 1 - df.login_success).mean())},
    "C2": {"time_to_first_cv_logged_in": float(LOGIN.time_to_first_input_s.std() / LOGIN.time_to_first_input_s.mean()),
           "time_to_first_median_by_category": LOGIN.groupby("category").time_to_first_input_s.median().to_dict(),
           "generator20_post_shell_wait_s": 0.5 / 8,
           "inter_mean_vs_profile_delay_mid_spearman": float(stats.spearmanr(LOGIN.inter_input_mean_s, LOGIN.delay_mid, nan_policy="omit").correlation),
           "profile_delay_range": {p["attack_cat"]: p["delay_range"] for p in profiles.values()},
           "inter_mean_median_by_category_x_speed8": (LOGIN.groupby("category").inter_input_mean_s.median() * 8).to_dict()},
}
dur = df.session_duration_s
groups["C3"] = {
    "share_within_1s_of_120_by_category_all": df.assign(n=(dur - 120).abs() <= 1).groupby("category").n.mean().to_dict(),
    "share_within_1s_of_180_all": float(((dur - 180).abs() <= 1).mean()),
    "failed_session_duration_median_by_category": FAILED.groupby("category").session_duration_s.median().to_dict(),
}
lg = LOGIN.dropna(subset=["session_duration_s"])
slope, intercept, *_ = stats.linregress(lg.input_line_count, np.log1p(lg.session_duration_s))
resid = np.log1p(lg.session_duration_s) - (intercept + slope * lg.input_line_count)
h, pr = stats.kruskal(*[resid[lg.category == c] for c in CATS])
groups["C3"]["logged_in_duration_residual_after_line_count_epsilon2"] = float(h / (len(lg) - 1))
groups["C4"] = {f: LOGIN.assign(n=LOGIN[f] > 0).groupby("category").n.mean().to_dict() for f in ("shell_operator_lines", "download_command_lines")}
groups["tty_output_bytes"] = {
    "median_by_category": LOGIN.groupby("category").tty_output_bytes.median().to_dict(),
    "spearman_with_input_bytes": float(stats.spearmanr(LOGIN.tty_output_bytes, LOGIN.input_bytes_total, nan_policy="omit").correlation),
    "within_category_iqr": LOGIN.groupby("category").tty_output_bytes.apply(lambda v: float(v.quantile(.75) - v.quantile(.25))).to_dict(),
    "residual_after_input_bytes_epsilon2": None,
}
lt = LOGIN.dropna(subset=["tty_output_bytes"])
s2, i2, *_ = stats.linregress(np.log1p(lt.input_bytes_total), np.log1p(lt.tty_output_bytes))
r2 = np.log1p(lt.tty_output_bytes) - (i2 + s2 * np.log1p(lt.input_bytes_total))
h2, _ = stats.kruskal(*[r2[lt.category == c] for c in CATS])
groups["tty_output_bytes"]["residual_after_input_bytes_epsilon2"] = float(h2 / (len(lt) - 1))

# --- 6. timestamp anomalies --------------------------------------------------------------------------------------
def anomalies(log_path, label_path):
    lab = {r["session_id"]: r for r in csv.DictReader(open(label_path, encoding="utf-8"))}
    ev = defaultdict(list)
    for line in Path(log_path).read_text(encoding="utf-8").splitlines():
        e = json.loads(line)
        ev[e["session"]].append(e)
    neg, before_params, n_logged = [], 0, 0
    for sid, es in ev.items():
        login = [ts(e["timestamp"]) for e in es if e["eventid"] == "cowrie.login.success"]
        inputs = sorted(ts(e["timestamp"]) for e in es if e["eventid"] == "cowrie.command.input")
        params = [ts(e["timestamp"]) for e in es if e["eventid"] == "cowrie.session.params"]
        if login and inputs:
            n_logged += 1
            if inputs[0] < login[0]:
                neg.append({"session": sid, "lag_s": (inputs[0] - login[0]).total_seconds(),
                            "category": lab.get(sid, {}).get("source_attack_cat"), "first_command": next(
                                e["input"] for e in sorted(es, key=lambda e: ts(e["timestamp"])) if e["eventid"] == "cowrie.command.input")})
            if params and inputs[0] < params[0]:
                before_params += 1
    return {"logged_in_sessions_with_input": n_logged, "first_input_before_login": neg,
            "first_input_before_session_params": before_params}


ts_anom = {"train_v1": anomalies(TRAIN_LOG, LABELS),
           "eval_v1_data_quality_only": anomalies(EVAL_LOG, EVAL_LABELS),
           "generator21_confirmation": anomalies(CONFIRMATION_LOG, LABELS)}
neg_ids = {a["session"] for a in ts_anom["train_v1"]["first_input_before_login"]}
e_all, p_all, _ = kruskal_eps(LOGIN, "time_to_first_input_s")
e_ex, p_ex, _ = kruskal_eps(LOGIN[~LOGIN.session_ref.isin(neg_ids)], "time_to_first_input_s")
ts_anom["time_to_first_epsilon2_with_vs_without_anomalies"] = {"with": e_all, "without": e_ex, "excluded": len(neg_ids)}

# --- 7. eligibility under several thresholds -------------------------------------------------------------------
def tier(feat, eps_t, ba_margin):
    st = per_feature[feat]["logged_in"]
    eps, ba, chance = st["kruskal_epsilon2"] or 0.0, st["single_feature_balanced_accuracy_groupkfold"], st["chance_balanced_accuracy"]
    mv = st["missingness_vs_category"]["cramers_v"]
    if eps >= eps_t or ba >= chance + ba_margin or mv >= 0.5:
        return "flag"
    return "below"


sensitivity = {f"eps>={e}|BA>=chance+{m}": {f: tier(f, e, m) for f in F} for e in (0.06, 0.14, 0.26, 0.5) for m in (0.10, 0.20, 0.35)}

results = {"provenance": provenance, "per_feature": per_feature, "multi_feature_context": context,
           "correlation_high_pairs_abs_ge_0.8": high_pairs, "L3": l3, "L4": l4, "L5": l5, "L6": l6, "L7": l7,
           "conditional_groups": groups, "timestamp_anomalies": ts_anom, "threshold_sensitivity": sensitivity}
(OUT / "leakage_results.json").write_text(json.dumps(clean(results), indent=2), encoding="utf-8")
print(json.dumps(clean({k: results[k] for k in ("provenance", "multi_feature_context", "correlation_high_pairs_abs_ge_0.8", "L3", "L4")}), indent=1))
for feat in F:
    s = per_feature[feat]["logged_in"]
    print(f"{feat:24s} {GROUP[feat]:4s} miss={s['missing_pct']:5.1f}% eps2={s['kruskal_epsilon2'] if s['kruskal_epsilon2'] is None else round(s['kruskal_epsilon2'],3)} "
          f"CI={[None if v is None else round(v,3) for v in s['epsilon2_ci95_group_bootstrap']]} BA={s['single_feature_balanced_accuracy_groupkfold']:.3f} "
          f"lookup_acc={s['exact_value_lookup']['correct_share_of_all']:.3f} missV={s['missingness_vs_category']['cramers_v']:.2f}")
