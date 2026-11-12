"""Task 15: Dataset V2 feature leakage validation (L1-L7, C1-C4) on the generator-2.1 training/validation splits.

    .venv/Scripts/python.exe reports/dataset_v2_leakage_validation_20261111/analyze_leakage_v2.py

Methods are copied unchanged from reports/v2_feature_leakage_validation/analyze_leakage.py (Task 11):
Kruskal-Wallis epsilon^2 with 200 interaction-bootstrap CIs, depth-3 single-feature tree with GroupKFold(5) by
interaction, fold-based exact-value lookup, L1 modal/range checks, chi^2/Cramer's V missingness, Spearman correlation,
OLS residual epsilon^2, random-forest context, and the same threshold grid. Differences from Task 11 are only those
forced by the data (documented in report.md section 3): labels come from the Task 14B reconciliation, the group is
interaction_id, there is a validation split (analysed with the same methods, plus train->validation transfer), and
the revised profiles have no delay_range.

Inputs (read-only): reports/dataset_v2_training_validation_20261110/ (verified against its SHA256SUMS first).
Diagnostics only: the classifiers here measure category information in single features; they are not models.
Manifests, terminal output and labels are audit evidence, never feature inputs. No test set is read (audit hook).
Outputs: tables/, figures/.
"""
import hashlib
import json
import math
import random
import shutil
import sys
from collections import Counter, defaultdict
from datetime import datetime
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.model_selection import GroupKFold
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score, accuracy_score, recall_score

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
from scripts import extract_features_v2 as x2  # noqa: E402

# --- test-set guard: record every file opened; any path under ml_pipeline/work/test* or a sealed test run aborts --
OPENED = []


def _audit(event, args):
    if event == "open" and args and isinstance(args[0], (str, Path)):
        p = str(args[0]).replace("\\", "/").lower()
        OPENED.append(p)
        if "ml_pipeline/work/test" in p or "sealed" in p or "/runs/test" in p:
            raise RuntimeError(f"test-set access blocked: {p}")


sys.addaudithook(_audit)

DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
OLD = REPO / "reports" / "v2_feature_leakage_validation"
OLD_TRAIN_LOG = REPO / "dataset_builder" / "runs" / "train_v1" / "raw" / "cowrie_thisrun.json"
OLD_LABELS = REPO / "dataset_builder" / "runs" / "train_v2_corrected" / "label_assignments.csv"
PROFILES = REPO / "dataset_builder" / "profiles_v2_revised.json"
SPEC = REPO / "configs" / "feature_spec_v2.json"
OUT = HERE / "tables"
FIG = HERE / "figures"
SPLITS = ("train", "validation")
F = x2.MODEL_FEATURES
GROUP = {"login_success": "core", "login_failed_count": "C1", "session_duration_s": "C3", "input_line_count": "core",
         "input_bytes_total": "core", "input_line_max_bytes": "core", "unique_command_names": "core",
         "shell_operator_lines": "C4", "download_command_lines": "C4", "time_to_first_input_s": "C2",
         "inter_input_mean_s": "C2", "inter_input_std_s": "C2", "tty_output_bytes": "core"}
TIMING = ["session_duration_s", "time_to_first_input_s", "inter_input_mean_s", "inter_input_std_s"]
SLOW = 5.0
SEED = 0
random.seed(SEED)
np.random.seed(SEED)
OUT.mkdir(exist_ok=True)



def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def clean(o):
    if isinstance(o, dict):
        return {str(k): clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set, frozenset)):
        return [clean(v) for v in o]
    if isinstance(o, (np.floating, float)):
        return None if math.isnan(float(o)) else round(float(o), 6)
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.bool_):
        return bool(o)
    return o


# =================================================================================================================
# Phase 1: freeze and verify inputs
# =================================================================================================================
sums = {}
for line in (DS / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    h, name = line.split(maxsplit=1)
    sums[name.lstrip("*").lstrip("./")] = h
hash_fail = [n for n, h in sums.items() if sha(DS / n) != h]
if hash_fail:
    raise SystemExit(f"input hash mismatch: {hash_fail}")
spec = json.loads(SPEC.read_text(encoding="utf-8"))
input_hashes = {"profiles_v2_revised.json": sha(PROFILES), "feature_spec_v2.json": sha(SPEC),
                "extract_features_v2.py": sha(REPO / "scripts" / "extract_features_v2.py"),
                "dataset_SHA256SUMS": sha(DS / "SHA256SUMS")}


def load(split):
    d = DS / "extraction" / split / "run1"
    X = pd.read_csv(d / "model_features.csv")
    M = pd.read_csv(d / "session_metadata.csv", keep_default_na=False)
    ext = pd.concat([M[["session_ref", "warnings", "extraction_status"]], X, M[x2.DESCRIPTIVE_FIELDS]], axis=1)
    lab = pd.read_csv(DS / "labels" / f"{split}_session_labels.csv", dtype=str)
    df = ext.merge(lab, on="session_ref", how="inner", validate="one_to_one").reset_index(drop=True)
    df["group"] = df.interaction_id
    df["category"] = df.attack_cat
    return list(X.columns), ext, lab, df


COLS, EXT, LAB, DF = {}, {}, {}, {}
for s in SPLITS:
    COLS[s], EXT[s], LAB[s], DF[s] = load(s)
LOGIN = {s: DF[s][DF[s].role == "logged_in"].reset_index(drop=True) for s in SPLITS}
FAILED = {s: DF[s][DF[s].role != "logged_in"].reset_index(drop=True) for s in SPLITS}

# raw recorded inputs (exit/logout excluded, as in Task 11) and events, per session; manifests (audit only)
RAW_EV, RAW_IN = {}, {}
for s in SPLITS:
    for n, line in enumerate((DS / "raw" / s / "cowrie_slice.json").read_text(encoding="utf-8").splitlines()):
        e = json.loads(line)
        e["_n"] = n
        RAW_EV.setdefault(e["session"], []).append(e)
for sid, evs in RAW_EV.items():
    evs.sort(key=lambda e: (ts(e["timestamp"]), e["_n"]))
    RAW_IN[sid] = [e["input"] for e in evs if e["eventid"] == "cowrie.command.input"
                   and e["input"].strip() not in ("exit", "logout")]
MAN = {}
for s in SPLITS:
    for line in (DS / "runs" / s / "manifest.jsonl").read_text(encoding="utf-8").splitlines():
        e = json.loads(line)
        MAN[f"{s}:{e['index']}"] = e
profiles = {p["name"]: p for p in json.loads(PROFILES.read_text(encoding="utf-8"))["profiles"]}

verification = {
    "dataset_files_hash_checked": len(sums), "hash_mismatches": hash_fail, "input_hashes": input_hashes,
    "spec_version": spec.get("spec_version"),
    "model_feature_columns_equal_spec": {s: COLS[s] == [f["name"] for f in spec["features"]] == F for s in SPLITS},
    "descriptive_metadata_separate": {s: not (set(x2.DESCRIPTIVE_FIELDS) & set(COLS[s])) for s in SPLITS},
    "categories": {s: sorted(DF[s].category.unique()) for s in SPLITS},
    "n_categories": {s: int(DF[s].category.nunique()) for s in SPLITS},
    "exfiltration_rows": {s: int(DF[s].category.isin(["exfiltration", "data_exfiltration"]).sum()) for s in SPLITS},
    "held_out_rows": {s: int((DF[s].held_out == "True").sum()) for s in SPLITS},
    "rows": {s: len(DF[s]) for s in SPLITS}, "feature_rows": {s: len(EXT[s]) for s in SPLITS},
    "interactions": {s: int(DF[s].group.nunique()) for s in SPLITS},
    "shared_interaction_ids": len(set(DF["train"].group) & set(DF["validation"].group)),
    "shared_session_refs": len(set(DF["train"].session_ref) & set(DF["validation"].session_ref)),
    "logged_in_per_interaction_max": {s: int(LOGIN[s].group.value_counts().max()) for s in SPLITS},
}
(OUT / "input_verification.json").write_text(json.dumps(clean(verification), indent=2), encoding="utf-8")
assert all(verification["model_feature_columns_equal_spec"].values())
assert verification["n_categories"] == {"train": 6, "validation": 6}
assert verification["exfiltration_rows"] == {"train": 0, "validation": 0}
assert verification["shared_interaction_ids"] == 0 and verification["shared_session_refs"] == 0


# =================================================================================================================
# Phase 2: Task 11 functions (unchanged)
# =================================================================================================================
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


def _xnan(frame, feat):
    x = frame[feat].values.astype(float)
    nanmask = np.isnan(x)
    return np.column_stack([np.where(nanmask, -1e9, x), nanmask.astype(float)])


def single_feature_ba(frame, feat):
    X = _xnan(frame, feat)
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


def multi_ba(frame, feats):
    X = frame[feats].astype(float).fillna(-1e9).values
    y, g = frame.category.values, frame.group.values
    preds = np.empty(len(y), dtype=object)
    for tr, te in GroupKFold(n_splits=5).split(X, y, g):
        preds[te] = RandomForestClassifier(n_estimators=200, random_state=SEED).fit(X[tr], y[tr]).predict(X[te])
    return float(balanced_accuracy_score(y, preds))


# --- additions for the validation split (train -> validation transfer; same model classes and keys) -------------
def transfer_single_ba(fit_frame, eval_frame, feat):
    clf = DecisionTreeClassifier(max_depth=3, random_state=SEED).fit(_xnan(fit_frame, feat), fit_frame.category.values)
    return float(balanced_accuracy_score(eval_frame.category.values, clf.predict(_xnan(eval_frame, feat))))


def transfer_lookup(fit_frame, eval_frame, keyfunc):
    table = defaultdict(Counter)
    for k, c in zip(fit_frame.apply(keyfunc, axis=1).values, fit_frame.category.values):
        table[k][c] += 1
    covered = correct = 0
    for k, c in zip(eval_frame.apply(keyfunc, axis=1).values, eval_frame.category.values):
        if k in table:
            covered += 1
            correct += table[k].most_common(1)[0][0] == c
    return {"covered_share": covered / len(eval_frame), "correct_share_of_all": correct / len(eval_frame),
            "accuracy_when_covered": correct / covered if covered else None}


def transfer_multi(fit_frame, eval_frame, feats):
    clf = RandomForestClassifier(n_estimators=200, random_state=SEED)
    clf.fit(fit_frame[feats].astype(float).fillna(-1e9).values, fit_frame.category.values)
    pred = clf.predict(eval_frame[feats].astype(float).fillna(-1e9).values)
    return float(balanced_accuracy_score(eval_frame.category.values, pred))


val_key = lambda f: (lambda r: None if pd.isna(r[f]) else round(float(r[f]), 6))  # noqa: E731
seq_key = lambda r: tuple(RAW_IN.get(r.session_ref, []))  # noqa: E731
nameset_key = lambda r: frozenset(t.split()[0] for t in RAW_IN.get(r.session_ref, []) if t.split())  # noqa: E731
first_key = lambda r: (RAW_IN[r.session_ref][0].split() or [""])[0] if RAW_IN.get(r.session_ref) else None  # noqa: E731

# --- per-feature statistics, L1, L2 --------------------------------------------------------------------------------
per_feature = {s: {} for s in SPLITS}
dist_rows, summary_rows = [], []
for s in SPLITS:
    for feat in F:
        entry = {"group": GROUP[feat]}
        for setname, frame in (("logged_in", LOGIN[s]), ("all_sessions", DF[s])):
            eps, p, n = kruskal_eps(frame, feat)
            lo, hi = group_bootstrap_eps(frame, feat) if eps is not None else (None, None)
            st = {
                "n_rows": len(frame), "n_groups": int(frame.group.nunique()),
                "n_nonmissing": n, "missing_pct": float(100 * frame[feat].isna().mean()),
                "kruskal_epsilon2": eps, "kruskal_p": p, "epsilon2_ci95_group_bootstrap": [lo, hi],
                "single_feature_balanced_accuracy_groupkfold": single_feature_ba(frame, feat),
                "chance_balanced_accuracy": 1 / frame.category.nunique(),
                "exact_value_lookup": exact_lookup(frame, val_key(feat)),
                "missingness_vs_category": missingness_assoc(frame, feat),
                "l1": l1_constants(frame, feat),
            }
            if s == "validation":
                fit = LOGIN["train"] if setname == "logged_in" else DF["train"]
                st["train_to_validation_single_feature_ba"] = transfer_single_ba(fit, frame, feat)
                st["train_to_validation_exact_value_lookup"] = transfer_lookup(fit, frame, val_key(feat))
            entry[setname] = st
            for c, d in describe(frame, feat).items():
                dist_rows.append({"split": s, "set": setname, "feature": feat, "category": c, **d})
            summary_rows.append({
                "split": s, "set": setname, "feature": feat, "group": GROUP[feat], "n_rows": len(frame),
                "n_interactions": st["n_groups"], "missing_pct": st["missing_pct"], "epsilon2": eps,
                "epsilon2_ci_lo": lo, "epsilon2_ci_hi": hi, "kruskal_p": p,
                "single_feature_ba_groupkfold": st["single_feature_balanced_accuracy_groupkfold"],
                "exact_lookup_correct_share": st["exact_value_lookup"]["correct_share_of_all"],
                "missingness_cramers_v": st["missingness_vs_category"]["cramers_v"],
                "train_to_val_ba": st.get("train_to_validation_single_feature_ba"),
                "train_to_val_lookup_correct_share": (st.get("train_to_validation_exact_value_lookup") or {}).get("correct_share_of_all"),
                "max_share_outside_other_categories_range": max((v["share_outside_other_categories_range"] or 0) for v in st["l1"].values()),
                "near_constant_categories": ";".join(c for c, v in st["l1"].items() if v["near_constant"]),
            })
        per_feature[s][feat] = entry
pd.DataFrame(dist_rows).to_csv(OUT / "category_distributions.csv", index=False, float_format="%.6g")
pd.DataFrame(summary_rows).to_csv(OUT / "per_feature_statistics.csv", index=False, float_format="%.6g")

core = [f for f in F if GROUP[f] == "core"]
no_c2c3 = [f for f in F if GROUP[f] not in ("C2", "C3")]
context = {}
for s in SPLITS:
    context[s] = {"all_13_features_rf_balanced_accuracy_logged_in": multi_ba(LOGIN[s], F),
                  "core_6_rf_balanced_accuracy_logged_in": multi_ba(LOGIN[s], core),
                  "without_C2_C3_rf_balanced_accuracy_logged_in": multi_ba(LOGIN[s], no_c2c3),
                  "chance": 1 / LOGIN[s].category.nunique()}
context["train_to_validation"] = {"all_13": transfer_multi(LOGIN["train"], LOGIN["validation"], F),
                                  "core_6": transfer_multi(LOGIN["train"], LOGIN["validation"], core),
                                  "without_C2_C3": transfer_multi(LOGIN["train"], LOGIN["validation"], no_c2c3)}

# --- correlation ---------------------------------------------------------------------------------------------------
high_pairs = {}
for s in SPLITS:
    corr = LOGIN[s][F].astype(float).corr(method="spearman")
    corr.to_csv(OUT / f"correlation_spearman_logged_in_{s}.csv", float_format="%.4f")
    high_pairs[s] = [(a, b, float(corr.loc[a, b])) for i, a in enumerate(F) for b in F[i + 1:]
                     if not math.isnan(corr.loc[a, b]) and abs(corr.loc[a, b]) >= 0.8]

# =================================================================================================================
# L3-L7
# =================================================================================================================
# L3: features invariant to identifiers/credentials/labels (perturbed re-extraction into a temporary directory).
l3 = {"features_invariant_to_identifiers_credentials_labels": {}}
for s in SPLITS:
    tmp = HERE / "extraction" / f"_l3_perturbed_{s}"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True)
    pert = tmp / "perturbed.json"
    with open(DS / "raw" / s / "cowrie_slice.json", encoding="utf-8") as src, open(pert, "w", encoding="utf-8") as dst:
        for line in src:
            e = json.loads(line)
            for k in ("src_ip", "src_port", "dst_ip", "dst_port", "username", "password", "sensor", "uuid", "hassh", "version"):
                if k in e:
                    e[k] = f"X-{k}"
            e["attack_cat"], e["label"], e["profile"] = "PERTURBED", 99, "PERTURBED"
            dst.write(json.dumps(e) + "\n")
    x2.extract([str(pert)], str(tmp / "out"))
    a = pd.read_csv(DS / "extraction" / s / "run1" / "model_features.csv")
    b = pd.read_csv(tmp / "out" / "model_features.csv")
    l3["features_invariant_to_identifiers_credentials_labels"][s] = bool(a.equals(b))
    shutil.rmtree(tmp)
shutil.rmtree(HERE / "extraction", ignore_errors=True)
src_text = (REPO / "scripts" / "extract_features_v2.py").read_text(encoding="utf-8")
l3.update({"extractor_source_mentions": {k: (k in src_text) for k in ("manifest", "terminal_output", "attack_cat", "label_assignments", "profile")},
           "reserved_test_marker_sessions": {s: int(EXT[s].warnings.str.contains("reserved_test_marker_present").sum()) for s in SPLITS},
           "session_id_used_as_feature": False})

# L4: duplicates and grouping.
l4 = {}
for s in SPLITS:
    L = LOGIN[s]
    seq = L.session_ref.map(lambda r: tuple(RAW_IN.get(r, [])))
    seq_cats = defaultdict(set)
    for q, c in zip(seq, L.category):
        seq_cats[q].add(c)
    fv = L[F].astype(float).fillna(-1e9).round(6).apply(tuple, axis=1)
    summ = json.loads((DS / "extraction" / s / "run1" / "extraction_summary.json").read_text(encoding="utf-8"))
    slice_lines = sum(1 for _ in open(DS / "raw" / s / "cowrie_slice.json", encoding="utf-8"))
    l4[s] = {"session_ids_unique": bool(EXT[s].session_ref.is_unique),
             "duplicate_records_removed_by_extractor": int(summ["duplicate_records_removed"]),
             "sum_event_count_equals_slice_lines": int(EXT[s].event_count.sum()) == slice_lines,
             "extracted_sessions_without_label": len(set(EXT[s].session_ref) - set(LAB[s].session_ref)),
             "max_sessions_per_interaction": int(DF[s].group.value_counts().max()),
             "logged_in_sessions_per_interaction_max": int(L.group.value_counts().max()),
             "logged_in_identical_feature_vectors_share": float(fv.map(fv.value_counts()).gt(1).mean()),
             "logged_in_identical_recorded_input_sequence_share": float(seq.map(seq.value_counts()).gt(1).mean()),
             "logged_in_sequence_shared_across_categories_share": float(seq.map(lambda q: len(seq_cats[q]) > 1).mean()),
             "logged_in_with_commands_sequence_shared_across_categories_share": float(
                 seq[seq.map(len) > 0].map(lambda q: len(seq_cats[q]) > 1).mean()),
             "independence_unit": "interaction_id (generated interaction); all CV GroupKFold by interaction"}
l4["session_ids_unique_across_splits"] = verification["shared_session_refs"] == 0

# L5: profile fingerprints.
l5 = {}
for s in SPLITS:
    L = LOGIN[s]
    l5[s] = {"exact_input_sequence_lookup": exact_lookup(L, seq_key),
             "command_name_set_lookup": exact_lookup(L, nameset_key),
             "first_command_name_lookup": exact_lookup(L, first_key),
             "failed_sessions_per_interaction_by_category": DF[s].assign(f=DF[s].role.ne("logged_in"))
                 .groupby(["category", "group"]).f.sum().groupby("category").agg(["mean", "min", "max"]).to_dict(orient="index")}
    # the same lookups restricted to sessions that sent at least one command (brute force has many empty sessions)
    Lc = L[L.input_line_count > 0].reset_index(drop=True)
    l5[s]["with_commands_only"] = {"n": len(Lc), "exact_input_sequence_lookup": exact_lookup(Lc, seq_key),
                                   "command_name_set_lookup": exact_lookup(Lc, nameset_key),
                                   "first_command_name_lookup": exact_lookup(Lc, first_key)}
Lt, Lv = LOGIN["train"], LOGIN["validation"]
Lvc = Lv[Lv.input_line_count > 0].reset_index(drop=True)
Ltc = Lt[Lt.input_line_count > 0].reset_index(drop=True)
l5["train_to_validation"] = {k: transfer_lookup(Lt, Lv, f) for k, f in
                             (("exact_input_sequence_lookup", seq_key), ("command_name_set_lookup", nameset_key),
                              ("first_command_name_lookup", first_key))}
l5["train_to_validation_with_commands_only"] = {k: transfer_lookup(Ltc, Lvc, f) for k, f in
                                                (("exact_input_sequence_lookup", seq_key), ("command_name_set_lookup", nameset_key),
                                                 ("first_command_name_lookup", first_key))}
l5["profile_failed_attempts_setting"] = {p["attack_cat"]: p["credentials"]["failed_attempts"] for p in profiles.values()}
l5["reserved_markers"] = l3["reserved_test_marker_sessions"]


# first-command lookup recall per category (GroupKFold on train; transfer on validation)
def first_cmd_per_category(fit, ev):
    table = defaultdict(Counter)
    for k, c in zip(fit.apply(first_key, axis=1), fit.category):
        table[k][c] += 1
    out = {}
    for c in sorted(ev.category.unique()):
        sub = ev[ev.category == c]
        keys = sub.apply(first_key, axis=1)
        out[c] = float(np.mean([k in table and table[k].most_common(1)[0][0] == c for k in keys]))
    return out


l5["first_command_recall_by_category_train_to_validation"] = first_cmd_per_category(Lt, Lv)

# L6: client/server contamination (manifest = audit evidence only).
l6 = {}
for s in SPLITS:
    rows = []
    for _, r in LOGIN[s].iterrows():
        sent = [c.strip() for c in MAN[r.group]["commands_sent"]]
        rec = [c.strip() for c in RAW_IN.get(r.session_ref, [])]
        remaining = list(sent)
        extra = 0
        for c in rec:
            if c in remaining:
                remaining.remove(c)
            else:
                extra += 1
        rows.append({"category": r.category, "sent": len(sent), "missing": len(remaining), "extra": extra,
                     "any_missing": len(remaining) > 0, "tty": r.tty_output_bytes, "in_bytes": r.input_bytes_total})
    d6 = pd.DataFrame(rows)
    tab = pd.crosstab(d6.category, d6.any_missing)
    if tab.shape[1] > 1:
        chi2, p, _, _ = stats.chi2_contingency(tab)
        v = math.sqrt(chi2 / (tab.values.sum() * (min(tab.shape) - 1)))
    else:
        p, v = None, 0.0
    l6[s] = {"by_category": {c: {"sessions": len(g), "manifest_lines": int(g.sent.sum()), "lines_missing_from_cowrie": int(g.missing.sum()),
                                 "sessions_with_loss_share": float(g.any_missing.mean()), "extra_lines": int(g.extra.sum())}
                             for c, g in d6.groupby("category")},
             "total_lines": int(d6.sent.sum()), "missing_lines": int(d6.missing.sum()), "extra_lines": int(d6.extra.sum()),
             "loss_vs_category_chi2_p": p, "loss_vs_category_cramers_v": v,
             "tty_vs_input_bytes_spearman": float(stats.spearmanr(d6.tty, d6.in_bytes, nan_policy="omit").correlation)}


# L7: invariants (common feature specification L7) and training/live comparison.
def invariants(s):
    failed_without_prior_input = params_missing = 0
    for sid in DF[s].session_ref:
        evs = RAW_EV[sid]
        seen_input = False
        for e in evs:
            if e["eventid"] == "cowrie.command.input":
                seen_input = True
            elif e["eventid"] == "cowrie.command.failed" and not seen_input:
                failed_without_prior_input += 1
        if any(e["eventid"] == "cowrie.login.success" for e in evs) and not any(e["eventid"] == "cowrie.session.params" for e in evs):
            params_missing += 1
    L = LOGIN[s]
    return {"command_failed_without_prior_input": failed_without_prior_input,
            "logins_without_session_params": params_missing,
            "logged_in_tty_lt_input_bytes": int((L.tty_output_bytes < L.input_bytes_total).sum())}


old = json.loads((OLD / "tables" / "leakage_results.json").read_text(encoding="utf-8"))
l7 = {"note": "No real-attacker deployment logs exist: deployment L7 is untestable. Generated runs are compared descriptively.",
      "invariants": {s: invariants(s) for s in SPLITS},
      "feature_medians_logged_in": {f: {"task11_gen20_train": old["L7"]["feature_medians"][f]["train_logged_in"],
                                        "task9_gen21_confirmation": old["L7"]["feature_medians"][f]["gen21_logged_in"],
                                        "v2_train": float(Lt[f].median()), "v2_validation": float(Lv[f].median())} for f in F},
      "failed_login_duration_median": {"task11_gen20_train": old["L7"]["failed_login_duration_median"]["train"],
                                       **{f"v2_{s}": float(FAILED[s].session_duration_s.median()) for s in SPLITS}},
      "url_download_events": {s: int(DF[s].url_download_events.sum()) for s in SPLITS}}

# =================================================================================================================
# Conditional groups (C1-C4) and core residuals, per split
# =================================================================================================================


def exec_decomp(L):
    """Per logged-in session: think, execution and slow-command execution from the manifest (audit evidence)."""
    rows = []
    for _, r in L.iterrows():
        sent = [c for c in MAN[r.group]["command_log"] if c["sent"]]
        rows.append({"think_sum_s": sum(c["think_time_s"] for c in sent),
                     "think_mean_s": float(np.mean([c["think_time_s"] for c in sent])) if sent else np.nan,
                     "exec_sum_s": sum(c["wait_s"] for c in sent),
                     "slow_exec_s": sum(c["wait_s"] for c in sent if c["wait_s"] >= SLOW),
                     "has_find": any(c["command"].startswith("find / -name id_rsa") for c in sent),
                     "has_slow": any(c["wait_s"] >= SLOW for c in sent)})
    return pd.concat([L, pd.DataFrame(rows, index=L.index)], axis=1)


LX = {s: exec_decomp(LOGIN[s]) for s in SPLITS}
groups = {}
for s in SPLITS:
    D, L, FL = DF[s], LX[s], FAILED[s]
    g = {}
    g["C1"] = {"spearman_login_failed_vs_login_success_all": float(stats.spearmanr(D.login_failed_count, D.login_success).correlation),
               "login_failed_count_values_logged_in": L.login_failed_count.value_counts().to_dict(),
               "login_failed_count_values_failed": FL.login_failed_count.value_counts().to_dict(),
               "equals_one_minus_login_success_share": float((D.login_failed_count == 1 - D.login_success).mean()),
               "sessions_with_more_than_one_failed_login": int((D.login_failed_count > 1).sum())}
    e_th, p_th, _ = kruskal_eps(L.assign(x=L.think_mean_s), "x")
    g["C2"] = {"time_to_first_cv_logged_in": float(L.time_to_first_input_s.std() / L.time_to_first_input_s.mean()),
               "time_to_first_median_by_category": L.groupby("category").time_to_first_input_s.median().to_dict(),
               "profiles_have_delay_range": any("delay_range" in p for p in profiles.values()),
               "generator_pacing": "category-independent PacingPolicy (lognormal median 1.5 s, sigma 0.75, [0.2, 15] s), prompt-gated, speed 1",
               "manifest_think_mean_per_session_epsilon2": e_th, "manifest_think_mean_per_session_p": p_th,
               "inter_mean_median_by_category": L.groupby("category").inter_input_mean_s.median().to_dict(),
               "inter_mean_epsilon2_excluding_find_sessions": kruskal_eps(L[~L.has_find], "inter_input_mean_s")[0],
               "inter_std_epsilon2_excluding_find_sessions": kruskal_eps(L[~L.has_find], "inter_input_std_s")[0]}
    dur = D.session_duration_s
    g["C3"] = {"share_within_1s_of_120_by_category_all": D.assign(n=(dur - 120).abs() <= 1).groupby("category").n.mean().to_dict(),
               "share_within_1s_of_180_all": float(((dur - 180).abs() <= 1).mean()),
               "failed_session_duration_median_by_category": FL.groupby("category").session_duration_s.median().to_dict(),
               "failed_session_duration_max": float(FL.session_duration_s.max())}
    lg = L.dropna(subset=["session_duration_s"])

    def resid_eps(y, frame):
        sl, ic, *_ = stats.linregress(frame.input_line_count, np.log1p(y))
        res = np.log1p(y) - (ic + sl * frame.input_line_count)
        h, _ = stats.kruskal(*[res[frame.category == c] for c in sorted(frame.category.unique())])
        return float(h / (len(frame) - 1))
    g["C3"]["logged_in_duration_residual_after_line_count_epsilon2"] = resid_eps(lg.session_duration_s, lg)
    g["C4"] = {f: L.assign(n=L[f] > 0).groupby("category").n.mean().to_dict() for f in ("shell_operator_lines", "download_command_lines")}
    g["C4_distinct_values_by_category"] = {f: L.groupby("category")[f].nunique().to_dict() for f in ("shell_operator_lines", "download_command_lines")}
    lt = L.dropna(subset=["tty_output_bytes"])
    s2, i2, *_ = stats.linregress(np.log1p(lt.input_bytes_total), np.log1p(lt.tty_output_bytes))
    r2 = np.log1p(lt.tty_output_bytes) - (i2 + s2 * np.log1p(lt.input_bytes_total))
    h2, _ = stats.kruskal(*[r2[lt.category == c] for c in sorted(lt.category.unique())])
    g["tty_output_bytes"] = {"median_by_category": L.groupby("category").tty_output_bytes.median().to_dict(),
                             "spearman_with_input_bytes": float(stats.spearmanr(L.tty_output_bytes, L.input_bytes_total, nan_policy="omit").correlation),
                             "within_category_iqr": L.groupby("category").tty_output_bytes.apply(lambda v: float(v.quantile(.75) - v.quantile(.25))).to_dict(),
                             "residual_after_input_bytes_epsilon2": float(h2 / (len(lt) - 1))}

    # --- Phase 3B: Cowrie `find` execution artefact (diagnostic copies; recorded values untouched) ---------------
    variants = {
        "recorded_session_duration_s": L.session_duration_s,
        "duration_minus_slow_command_execution_s": L.session_duration_s - L.slow_exec_s,
        "duration_minus_all_command_execution_s": L.session_duration_s - L.exec_sum_s,
        "think_sum_s_manifest": L.think_sum_s,
        "exec_sum_s_manifest": L.exec_sum_s,
        "exec_sum_s_excluding_slow": L.exec_sum_s - L.slow_exec_s,
    }
    fb = {}
    for name, v in variants.items():
        fr = L.assign(_v=v.values)
        e, p, n = kruskal_eps(fr, "_v")
        lo, hi = group_bootstrap_eps(fr, "_v")
        fb[name] = {"epsilon2": e, "ci95": [lo, hi], "single_feature_ba": single_feature_ba(fr, "_v"),
                    "median_by_category": fr.groupby("category")._v.median().to_dict()}
    nf = L[~L.has_find].reset_index(drop=True)
    e_nf, _, _ = kruskal_eps(nf, "session_duration_s")
    lo_nf, hi_nf = group_bootstrap_eps(nf, "session_duration_s")
    pe = L[L.category == "privilege_escalation"]
    nonpe = L[L.category != "privilege_escalation"].session_duration_s
    p95 = float(nonpe.quantile(0.95))
    fb.update({
        "excluding_find_sessions": {"n": len(nf), "epsilon2": e_nf, "ci95": [lo_nf, hi_nf],
                                    "single_feature_ba": single_feature_ba(nf, "session_duration_s"),
                                    "residual_after_line_count_epsilon2": resid_eps(nf.session_duration_s, nf)},
        "find_sessions_by_category": L[L.has_find].category.value_counts().to_dict(),
        "slow_command_sessions_by_category": L[L.has_slow].category.value_counts().to_dict(),
        "pe_sessions": len(pe), "pe_find_sessions": int(pe.has_find.sum()),
        "pe_duration_quantiles": {k: pe[pe.has_find == k].session_duration_s.quantile([.05, .5, .95]).round(3).tolist() for k in (True, False)},
        "non_pe_duration_p95": p95,
        "share_above_non_pe_p95_by_category": L.assign(a=L.session_duration_s > p95).groupby("category").a.mean().to_dict(),
        "pe_find_sessions_above_non_pe_p95": int((pe[pe.has_find].session_duration_s > p95).sum()),
        "pe_duration_minus_find_exec_median": float((pe[pe.has_find].session_duration_s - pe[pe.has_find].slow_exec_s).median()),
        "inter_input_mean_s_median_find_vs_not": [float(L[L.has_find].inter_input_mean_s.median()), float(L[~L.has_find].inter_input_mean_s.median())],
        "inter_input_mean_s_max_non_find": float(L[~L.has_find].inter_input_mean_s.max()),
        "inter_input_mean_s_find_min": float(L[L.has_find].inter_input_mean_s.min()) if L.has_find.any() else None,
    })
    g["find_artifact"] = fb
    groups[s] = g

# timestamp anomalies (first input before login.success)
ts_anom = {}
for s in SPLITS:
    neg, n_logged = [], 0
    for sid in LOGIN[s].session_ref:
        es = RAW_EV[sid]
        login = [ts(e["timestamp"]) for e in es if e["eventid"] == "cowrie.login.success"]
        inputs = sorted(ts(e["timestamp"]) for e in es if e["eventid"] == "cowrie.command.input")
        if login and inputs:
            n_logged += 1
            if inputs[0] < login[0]:
                neg.append(sid)
    ts_anom[s] = {"logged_in_sessions_with_input": n_logged, "first_input_before_login": neg,
                  "timestamp_order_mismatch_sessions": int((EXT[s].timestamp_order_mismatch != 0).sum())}

# threshold sensitivity (unchanged grid), train logged-in (as Task 11) and validation logged-in
def tier(s, feat, eps_t, ba_margin):
    st = per_feature[s][feat]["logged_in"]
    eps, ba, chance = st["kruskal_epsilon2"] or 0.0, st["single_feature_balanced_accuracy_groupkfold"], st["chance_balanced_accuracy"]
    mv = st["missingness_vs_category"]["cramers_v"]
    return "flag" if (eps >= eps_t or ba >= chance + ba_margin or mv >= 0.5) else "below"


sensitivity = {s: {f"eps>={e}|BA>=chance+{m}": {f: tier(s, f, e, m) for f in F}
                   for e in (0.06, 0.14, 0.26, 0.5) for m in (0.10, 0.20, 0.35)} for s in SPLITS}
flag_counts = {s: {f: sum(v[f] == "flag" for v in sensitivity[s].values()) for f in F} for s in SPLITS}

# =================================================================================================================
# Phase 3 investigations A, C, D, E
# =================================================================================================================
# A. repeated sequences and vocabulary overlap
train_seq_cats = defaultdict(Counter)
for _, r in Lt.iterrows():
    train_seq_cats[tuple(RAW_IN.get(r.session_ref, []))][r.category] += 1
rep_rows = []
for _, r in Lv[Lv.input_line_count > 0].iterrows():
    q = tuple(RAW_IN[r.session_ref])
    if q in train_seq_cats:
        rep_rows.append({"validation_interaction": r.group, "category": r.category, "sequence": " ; ".join(q),
                         "train_categories": dict(train_seq_cats[q]), "same_category_only": set(train_seq_cats[q]) == {r.category}})
rep = pd.DataFrame(rep_rows)
rep.to_csv(OUT / "repeated_sequences_validation_in_train.csv", index=False)
with_cmds_v = Lv[Lv.input_line_count > 0]
repeat = {"validation_with_commands_by_category": with_cmds_v.category.value_counts().to_dict(),
          "validation_repeating_train_sequence_by_category": rep.category.value_counts().to_dict() if len(rep) else {},
          "distinct_repeated_sequences": int(rep.sequence.nunique()) if len(rep) else 0,
          "repeated_sequences_seen_in_other_category_in_train": int((~rep.same_category_only).sum()) if len(rep) else 0,
          "share_of_validation_with_commands": len(rep) / len(with_cmds_v),
          "share_excluding_brute_force": float(len(rep[rep.category != "brute_force"]) / (with_cmds_v.category != "brute_force").sum()) if len(rep) else 0.0,
          "train_internal_repeat_share_by_category": Lt[Lt.input_line_count > 0].assign(
              k=lambda d: d.session_ref.map(lambda x: tuple(RAW_IN[x]))).groupby("category").k.apply(lambda k: float(k.duplicated(keep=False).mean())).to_dict(),
          "brute_force_post_login_pool": sorted({" ; ".join(RAW_IN[x]) for x in Lt[(Lt.category == "brute_force") & (Lt.input_line_count > 0)].session_ref})}


def vocab(frame, inputs, cat_col="category"):
    names = defaultdict(Counter)
    for _, r in frame.iterrows():
        for t in inputs.get(r.session_ref, []):
            if t.split():
                names[r[cat_col]][t.split()[0]] += 1
    cats = sorted(names)
    sets = {c: set(names[c]) for c in cats}
    allnames = sorted(set().union(*sets.values()))
    shared = [n for n in allnames if sum(n in sets[c] for c in cats) >= 2]
    jacc = [len(sets[a] & sets[b]) / len(sets[a] | sets[b]) for a, b in combinations(cats, 2)]
    zero_pairs = sum(len(sets[a] & sets[b]) == 0 for a, b in combinations(cats, 2))
    matrix = pd.DataFrame({c: [names[c][n] for n in allnames] for c in cats}, index=allnames)
    return {"names": len(allnames), "names_shared_by_2plus_categories": len(shared),
            "names_unique_to_one_category": len(allnames) - len(shared), "mean_pairwise_jaccard": float(np.mean(jacc)),
            "category_pairs_sharing_no_name": zero_pairs, "pairs": len(jacc)}, matrix


vocab_new, mat_new = vocab(Lt, RAW_IN)
mat_new.to_csv(OUT / "vocabulary_command_by_category_train.csv")
vocab_val, _ = vocab(Lv, RAW_IN)
# Task 11 (generator 2.0) training run, read-only, same definition, for the empirical before/after
old_lab = pd.read_csv(OLD_LABELS, dtype=str)
old_lab = old_lab[(old_lab.source_status == "assigned") & (old_lab.auth_outcome == "success")]
old_in = defaultdict(list)
old_ev = defaultdict(list)
for n, line in enumerate(OLD_TRAIN_LOG.read_text(encoding="utf-8").splitlines()):
    e = json.loads(line)
    old_ev[e["session"]].append((ts(e["timestamp"]), n, e))
for sid, es in old_ev.items():
    es.sort(key=lambda t: (t[0], t[1]))
    old_in[sid] = [e["input"] for _, _, e in es if e["eventid"] == "cowrie.command.input" and e["input"].strip() not in ("exit", "logout")]
old_frame = pd.DataFrame({"session_ref": old_lab.session_id, "category": old_lab.source_attack_cat})
vocab_old, _ = vocab(old_frame, old_in)
first_old = old_frame.assign(k=old_frame.session_ref.map(lambda x: (old_in[x][0].split() or [""])[0] if old_in.get(x) else None))
vocabulary = {"task11_gen20_train_logged_in": vocab_old, "v2_train_logged_in": vocab_new, "v2_validation_logged_in": vocab_val,
              "first_command_distribution_v2_train": Lt.assign(k=Lt.apply(first_key, axis=1)).groupby("category").k.apply(
                  lambda k: k.value_counts(normalize=True).head(5).round(3).to_dict()).to_dict()}

# C. class imbalance and row-level domination
imb = {}
for s in SPLITS:
    D = DF[s]
    inter = D.groupby("category").group.nunique()
    rows = D.category.value_counts()
    imb[s] = {"interactions_by_category": inter.to_dict(), "interaction_share": (inter / inter.sum()).round(4).to_dict(),
              "session_rows_by_category": rows.to_dict(), "row_share": (rows / rows.sum()).round(4).to_dict(),
              "logged_in_rows_by_category": D[D.role == "logged_in"].category.value_counts().to_dict(),
              "failed_rows_by_category": D[D.role != "logged_in"].category.value_counts().to_dict(),
              "rows_per_interaction_by_category": (rows / inter).round(3).to_dict(),
              "imbalance_ratio_interactions_max_min": float(inter.max() / inter.min()),
              "imbalance_ratio_rows_max_min": float(rows.max() / rows.min())}
# row-level vs balanced metrics, all sessions (diagnostic RF on all 13 features, GroupKFold by interaction)
Dt = DF["train"]
X = Dt[F].astype(float).fillna(-1e9).values
y, gg = Dt.category.values, Dt.group.values
pred = np.empty(len(y), dtype=object)
for tr, te in GroupKFold(n_splits=5).split(X, y, gg):
    pred[te] = RandomForestClassifier(n_estimators=200, random_state=SEED).fit(X[tr], y[tr]).predict(X[te])
cats = sorted(Dt.category.unique())
imb["row_vs_balanced_all_sessions_train"] = {
    "accuracy_row_level": float(accuracy_score(y, pred)), "balanced_accuracy": float(balanced_accuracy_score(y, pred)),
    "recall_by_category": dict(zip(cats, recall_score(y, pred, labels=cats, average=None).round(4).tolist())),
    "brute_force_share_of_correct_rows": float(((pred == y) & (y == "brute_force")).sum() / (pred == y).sum()),
    "majority_rule_accuracy": float(pd.Series(y).value_counts(normalize=True).max())}
pd.DataFrame([{"split": s, "category": c, "interactions": imb[s]["interactions_by_category"].get(c, 0),
               "session_rows": imb[s]["session_rows_by_category"].get(c, 0),
               "logged_in_rows": imb[s]["logged_in_rows_by_category"].get(c, 0),
               "failed_guess_rows": imb[s]["failed_rows_by_category"].get(c, 0),
               "interaction_share": imb[s]["interaction_share"].get(c, 0), "row_share": imb[s]["row_share"].get(c, 0)}
              for s in SPLITS for c in cats]).to_csv(OUT / "category_counts.csv", index=False)

# D. missingness
NANF = ["input_line_max_bytes", "time_to_first_input_s", "inter_input_mean_s", "inter_input_std_s", "session_duration_s", "tty_output_bytes"]
miss = {}
miss_rows = []
for s in SPLITS:
    D = DF[s]
    m = {"by_feature": {}, "unexplained_nan": {}, "extraction_status_not_ok": int((EXT[s].extraction_status != "ok").sum()),
         "sessions_with_warnings": int((EXT[s].warnings != "").sum())}
    for f in NANF:
        m["by_feature"][f] = {"all_sessions_cramers_v": missingness_assoc(D, f)["cramers_v"],
                              "logged_in_cramers_v": missingness_assoc(LOGIN[s], f)["cramers_v"],
                              "nan_share_by_role": D.groupby("role")[f].apply(lambda v: float(v.isna().mean())).to_dict()}
        for c, sub in D.groupby("category"):
            for role, sr in sub.groupby("role"):
                miss_rows.append({"split": s, "feature": f, "category": c, "role": role, "rows": len(sr), "nan_share": float(sr[f].isna().mean())})
    lines, login = D.input_line_count, D.login_success
    rules = {"input_line_max_bytes": lines == 0, "time_to_first_input_s": (lines == 0) | (login == 0),
             "inter_input_mean_s": lines < 2, "inter_input_std_s": lines < 3, "session_duration_s": D.session_closed_observed == 0,
             "tty_output_bytes": pd.Series(False, index=D.index)}
    m["unexplained_nan"] = {f: int((D[f].isna() & ~rules[f]).sum()) for f in NANF}
    m["values_where_rule_expects_nan"] = {f: int((~D[f].isna() & rules[f]).sum()) for f in NANF if f != "tty_output_bytes"}
    # NaN pattern alone as a category signal (diagnostic: how strong the shortcut is; not a feature)
    pat = D[["input_line_max_bytes", "time_to_first_input_s", "inter_input_mean_s", "inter_input_std_s"]].isna().astype(int)
    for setname, fr in (("all_sessions", D), ("logged_in", LOGIN[s])):
        P = fr[["input_line_max_bytes", "time_to_first_input_s", "inter_input_mean_s", "inter_input_std_s"]].isna().astype(float).values
        yy, g2 = fr.category.values, fr.group.values
        pr = np.empty(len(yy), dtype=object)
        for tr, te in GroupKFold(n_splits=5).split(P, yy, g2):
            pr[te] = DecisionTreeClassifier(max_depth=3, random_state=SEED).fit(P[tr], yy[tr]).predict(P[te])
        m[f"nan_pattern_only_ba_{setname}"] = float(balanced_accuracy_score(yy, pr))
    m["login_success_only_ba_all_sessions"] = per_feature[s]["login_success"]["all_sessions"]["single_feature_balanced_accuracy_groupkfold"]
    m["logged_in_no_input_by_category"] = LOGIN[s].assign(z=LOGIN[s].input_line_count == 0).groupby("category").z.mean().to_dict()
    m["nan_pattern_counts"] = pat.astype(str).agg("".join, axis=1).value_counts().to_dict()
    miss[s] = m
pd.DataFrame(miss_rows).to_csv(OUT / "missingness_by_category_role.csv", index=False, float_format="%.4f")

# E. capture-day comparison (train 2026-11-10 vs validation 2026-11-11). Logged-in sessions are one per interaction.
cap_rows = []
for f in F:
    a, b = Lt[f].dropna(), Lv[f].dropna()
    if a.nunique() > 1 or b.nunique() > 1:
        ks = stats.ks_2samp(a, b)
        d_all, p_all = float(ks.statistic), float(ks.pvalue)
    else:
        d_all, p_all = 0.0, 1.0
    per_cat = {}
    for c in cats:
        aa, bb = Lt.loc[Lt.category == c, f].dropna(), Lv.loc[Lv.category == c, f].dropna()
        if len(aa) > 5 and len(bb) > 5 and (aa.nunique() > 1 or bb.nunique() > 1):
            k = stats.ks_2samp(aa, bb)
            per_cat[c] = (float(k.statistic), float(k.pvalue))
    cap_rows.append({"feature": f, "train_median": float(a.median()) if len(a) else None, "validation_median": float(b.median()) if len(b) else None,
                     "train_missing_pct": float(100 * Lt[f].isna().mean()), "validation_missing_pct": float(100 * Lv[f].isna().mean()),
                     "ks_D_pooled": d_all, "ks_p_pooled": p_all,
                     "ks_D_max_within_category": max((v[0] for v in per_cat.values()), default=None),
                     "category_of_max_D": max(per_cat, key=lambda c: per_cat[c][0]) if per_cat else None,
                     "within_category_p_lt_0.01_count": sum(v[1] < 0.01 for v in per_cat.values()),
                     "within_category_tests": len(per_cat)})
cap = pd.DataFrame(cap_rows)
cap.to_csv(OUT / "capture_day_ks_logged_in.csv", index=False, float_format="%.5g")
cmdlog = {s: pd.read_csv(DS / "evidence" / f"{s}_command_log.csv") for s in SPLITS}
both = set(cmdlog["train"].command) & set(cmdlog["validation"].command)
per_cmd = []
for c in sorted(both):
    t_, v_ = (cmdlog[s][cmdlog[s].command == c] for s in SPLITS)
    per_cmd.append({"command": c, "n_train": len(t_), "n_validation": len(v_),
                    "wait_median_train": t_.wait_s.median(), "wait_median_validation": v_.wait_s.median(),
                    "output_chars_median_train": t_.output_chars.median(), "output_chars_median_validation": v_.output_chars.median(),
                    "output_chars_identical_sets": set(t_.output_chars) == set(v_.output_chars)})
pc = pd.DataFrame(per_cmd)
pc.to_csv(OUT / "capture_day_per_command.csv", index=False, float_format="%.5g")
recon = {s: json.loads((DS / "evidence" / f"{s}_reconciliation.json").read_text(encoding="utf-8")) for s in SPLITS}
capture = {
    "features_logged_in": cap_rows,
    "failed_sessions": {f: {"train_median": float(FAILED["train"][f].median()), "validation_median": float(FAILED["validation"][f].median()),
                            "ks_D": float(stats.ks_2samp(FAILED["train"][f], FAILED["validation"][f]).statistic)}
                        for f in ("session_duration_s", "tty_output_bytes")},
    "execution_delay_median_s": {s: float(cmdlog[s].wait_s.median()) for s in SPLITS},
    "execution_delay_p95_s_excluding_slow": {s: float(cmdlog[s][cmdlog[s].wait_s < SLOW].wait_s.quantile(.95)) for s in SPLITS},
    "think_time_median_s": {s: float(cmdlog[s][cmdlog[s].sent].think_time_s.median()) for s in SPLITS},
    "commands_in_both": len(both),
    "commands_output_chars_median_equal": int((pc.output_chars_median_train == pc.output_chars_median_validation).sum()),
    "commands_output_chars_median_differ": pc[pc.output_chars_median_train != pc.output_chars_median_validation][
        ["command", "output_chars_median_train", "output_chars_median_validation"]].to_dict(orient="records"),
    "command_failed_per_command_sent": {s: recon[s]["eventid_counts"].get("cowrie.command.failed", 0) / int(cmdlog[s].sent.sum()) for s in SPLITS},
    "eventid_per_interaction": {s: {k: round(v / verification["interactions"][s], 4) for k, v in sorted(recon[s]["eventid_counts"].items())} for s in SPLITS},
    "failed_guesses_per_interaction_by_category": {s: l5[s]["failed_sessions_per_interaction_by_category"] for s in SPLITS},
    "login_success_rate_rows": {s: float(DF[s].login_success.mean()) for s in SPLITS},
    "excluded_banner_events": {
        "train_baseline_lines_968_969": [json.loads(l)["eventid"] + " " + json.loads(l)["session"] + " " + json.loads(l)["timestamp"]
                                         for l in (DS / "raw" / "train" / "cowrie_before.json").read_text(encoding="utf-8").splitlines()[967:969]],
        "validation_baseline_lines_1_2": [json.loads(l)["eventid"] + " " + json.loads(l)["session"] + " " + json.loads(l)["timestamp"]
                                          for l in (DS / "raw" / "validation" / "cowrie_before.json").read_text(encoding="utf-8").splitlines()],
    },
}
banner_sessions = {x.split()[1] for v in capture["excluded_banner_events"].values() for x in v}
capture["banner_sessions_in_any_slice_or_label"] = sorted(banner_sessions & (set(RAW_EV) | set(DF["train"].session_ref) | set(DF["validation"].session_ref)))

# =================================================================================================================
# Phase 5: before/after
# =================================================================================================================
ba_rows = []
for f in F:
    o = old["per_feature"][f]["logged_in"]
    t = per_feature["train"][f]["logged_in"]
    v = per_feature["validation"][f]["logged_in"]
    ba_rows.append({"feature": f, "group": GROUP[f],
                    "task11_eps2": o["kruskal_epsilon2"], "v2_train_eps2": t["kruskal_epsilon2"],
                    "v2_train_eps2_ci": t["epsilon2_ci95_group_bootstrap"], "v2_val_eps2": v["kruskal_epsilon2"],
                    "task11_ba": o["single_feature_balanced_accuracy_groupkfold"], "v2_train_ba": t["single_feature_balanced_accuracy_groupkfold"],
                    "v2_val_ba": v["single_feature_balanced_accuracy_groupkfold"], "v2_train_to_val_ba": v["train_to_validation_single_feature_ba"],
                    "task11_lookup": o["exact_value_lookup"]["correct_share_of_all"], "v2_train_lookup": t["exact_value_lookup"]["correct_share_of_all"],
                    "v2_train_to_val_lookup": v["train_to_validation_exact_value_lookup"]["correct_share_of_all"],
                    "task11_missV": o["missingness_vs_category"]["cramers_v"], "v2_train_missV": t["missingness_vs_category"]["cramers_v"],
                    "v2_val_missV": v["missingness_vs_category"]["cramers_v"],
                    "task11_flags_of_12": sum(old["threshold_sensitivity"][k][f] == "flag" for k in old["threshold_sensitivity"]),
                    "v2_train_flags_of_12": flag_counts["train"][f], "v2_val_flags_of_12": flag_counts["validation"][f]})
pd.DataFrame(ba_rows).to_csv(OUT / "before_after_per_feature.csv", index=False, float_format="%.4f")
before_after = {
    "per_feature": ba_rows,
    "L5": {"task11": {k: old["L5"][k] for k in ("exact_input_sequence_lookup", "command_name_set_lookup", "first_command_name_lookup")},
           "v2_train": {k: l5["train"][k] for k in ("exact_input_sequence_lookup", "command_name_set_lookup", "first_command_name_lookup")},
           "v2_train_to_validation": l5["train_to_validation"]},
    "L4_cross_category_sequence_share": {"task11": old["L4"]["logged_in_sequence_shared_across_categories_share"],
                                         "v2_train": l4["train"]["logged_in_sequence_shared_across_categories_share"]},
    "context_rf": {"task11": old["multi_feature_context"], "v2": context},
    "C1": {"task11": old["conditional_groups"]["C1"], "v2_train": groups["train"]["C1"]},
    "C3_residual": {"task11": old["conditional_groups"]["C3"]["logged_in_duration_residual_after_line_count_epsilon2"],
                    "v2_train": groups["train"]["C3"]["logged_in_duration_residual_after_line_count_epsilon2"]},
    "tty_residual": {"task11": old["conditional_groups"]["tty_output_bytes"]["residual_after_input_bytes_epsilon2"],
                     "v2_train": groups["train"]["tty_output_bytes"]["residual_after_input_bytes_epsilon2"]},
    "L6_cramers_v": {"task11": old["L6"]["loss_vs_category_cramers_v"], "v2_train": l6["train"]["loss_vs_category_cramers_v"]},
    "vocabulary": {"task11_empirical": vocab_old, "v2_train_empirical": vocab_new},
}

# =================================================================================================================
# figures
# =================================================================================================================
try:
    import matplotlib  # noqa: E402
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt  # noqa: E402
    FIGURES = "written to figures/"
except ImportError:
    plt = None
    FIGURES = "not produced: matplotlib is not installed in .venv (not installed, to leave the environment unchanged)"
if plt is not None:
    FIG.mkdir(exist_ok=True)

    bdf = pd.DataFrame(ba_rows).set_index("feature")
    fig, ax = plt.subplots(figsize=(9, 4.5))
    xs = np.arange(len(F))
    ax.bar(xs - 0.27, bdf.task11_eps2.fillna(0), 0.27, label="Task 11 (generator 2.0)", color="#9aa5b1")
    ax.bar(xs, bdf.v2_train_eps2.fillna(0), 0.27, label="V2 train (generator 2.1)", color="#3b6ea5")
    ax.bar(xs + 0.27, bdf.v2_val_eps2.fillna(0), 0.27, label="V2 validation", color="#8fb8de")
    ax.axhline(0.14, ls=":", c="k", lw=0.8)
    ax.set_xticks(xs, F, rotation=60, ha="right", fontsize=8)
    ax.set_ylabel("Kruskal–Wallis ε² (logged-in)")
    ax.set_title("Category dependence per feature, before and after")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(FIG / "eps2_before_after.png", dpi=130)
    plt.close(fig)

    fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)
    for ax, (title, col) in zip(axes, (("recorded session_duration_s", "session_duration_s"),
                                       ("duration minus slow-command execution (diagnostic)", None))):
        L = LX["train"]
        vals = L.session_duration_s if col else L.session_duration_s - L.slow_exec_s
        ax.boxplot([vals[L.category == c] for c in cats], showfliers=True, flierprops={"markersize": 2})
        ax.set_xticks(range(1, len(cats) + 1), [c.replace("_", "\n") for c in cats], fontsize=7)
        ax.set_title(title, fontsize=9)
    axes[0].set_ylabel("seconds (train, logged-in)")
    fig.tight_layout()
    fig.savefig(FIG / "duration_find_artifact_train.png", dpi=130)
    plt.close(fig)

    mr = pd.DataFrame(miss_rows)
    piv = mr[(mr.split == "train") & (mr.feature == "time_to_first_input_s")].pivot(index="category", columns="role", values="nan_share")
    fig, ax = plt.subplots(figsize=(7, 3.5))
    piv.plot.bar(ax=ax, color=["#d08c60", "#9aa5b1", "#3b6ea5"][:piv.shape[1]])
    ax.set_ylabel("share NaN: time_to_first_input_s")
    ax.set_title("Missingness by category and login role (train)")
    ax.tick_params(axis="x", labelrotation=30, labelsize=8)
    fig.tight_layout()
    fig.savefig(FIG / "missingness_by_category_role_train.png", dpi=130)
    plt.close(fig)

results = {"verification": verification, "per_feature": per_feature, "multi_feature_context": context,
           "correlation_high_pairs_abs_ge_0.8": high_pairs, "L3": l3, "L4": l4, "L5": l5, "L6": l6, "L7": l7,
           "conditional_groups": groups, "timestamp_anomalies": ts_anom, "threshold_sensitivity": sensitivity,
           "threshold_flag_counts_of_12": flag_counts, "repeated_sequences": repeat, "vocabulary": vocabulary,
           "imbalance": imb, "missingness": miss, "figures": FIGURES, "capture_day": capture, "before_after": before_after,
           "test_set_paths_opened": [p for p in OPENED if "test" in p.rsplit("/", 1)[-1] and p.endswith((".pkl", ".csv", ".json", ".jsonl"))]}
(OUT / "leakage_results.json").write_text(json.dumps(clean(results), indent=2), encoding="utf-8")
print("done; test-like paths opened:", results["test_set_paths_opened"])
