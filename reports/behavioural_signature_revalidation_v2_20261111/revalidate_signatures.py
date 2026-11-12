"""Task 20: read-only revalidation of the existing behavioural signatures on Cowrie Dataset V2 (train/validation only).

    .venv/Scripts/python.exe reports/behavioural_signature_revalidation_v2_20261111/revalidate_signatures.py

The existing implementation is imported and called UNCHANGED:
  scripts/behaviour_pattern_analysis.py   CATEGORY_KEYWORDS, classify_command, infer_session_interpretation,
                                          build_session_profiles, cluster statistics
  scripts/behaviour_signature_generation.py  build_signatures (signature definition)
  scripts/novelty_assessment.py           compare_session_to_signature / assess_session_against_signatures (matching),
                                          DEFAULT_THRESHOLDS, _reference_only_signatures
Evaluations:
  E1  stored catalogue reports/behaviour_signatures/behaviour_signatures.json (3 signatures) vs V2 sessions
  E2  session-level keyword/interpretation rules on V2 recorded commands
  E3  existing reference-only signature builder on V2 TRAIN sessions with the saved Task 17 DEC K=3 seed-42 train
      assignments (existing project K; no model is trained), matched against V2 VALIDATION sessions
Labels (attack_cat), interaction IDs and the manifest are post-hoc metadata only. No test data is read (audit hook).
Nothing outside this directory is written.
"""
import hashlib
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
OPENED = []


def _audit(event, args):
    if event == "open" and args and isinstance(args[0], (str, Path)):
        p = str(args[0]).replace("\\", "/").lower()
        if "ml_pipeline/work/test" in p or "sealed" in p or "/runs/test" in p or "cowrie_sealed_exfiltration" in p:
            raise RuntimeError(f"test-set access blocked: {p}")
        OPENED.append(p)


sys.addaudithook(_audit)

from scripts import behaviour_pattern_analysis as bpa  # noqa: E402
from scripts import behaviour_signature_generation as bsg  # noqa: E402
from scripts import novelty_assessment as na  # noqa: E402

DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
T17 = REPO / "reports" / "dataset_v2_model_revalidation_20261111" / "outputs"
CATALOGUE = REPO / "reports" / "behaviour_signatures" / "behaviour_signatures.json"
FROZEN = REPO / "configs" / "model_features_v2_frozen.json"
OUT = HERE / "evidence"
OUT.mkdir(exist_ok=True)
SPLITS = ("train", "validation")
EXIT = ("exit", "logout")


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def clean(o):
    if isinstance(o, dict):
        return {str(k): clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [clean(v) for v in o]
    if isinstance(o, float):
        return None if math.isnan(o) else round(o, 6)
    return o


# ---- inputs (verified)
src_hashes = {p: sha(REPO / p) for p in ("scripts/behaviour_pattern_analysis.py", "scripts/behaviour_signature_generation.py",
                                         "scripts/novelty_assessment.py", "reports/behaviour_signatures/behaviour_signatures.json",
                                         "configs/model_features_v2_frozen.json")}
for line in (DS / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    h, name = line.split(maxsplit=1)
    assert sha(DS / name.lstrip("*").lstrip("./")) == h, f"Dataset V2 file changed: {name}"
FEATURES13 = json.loads(FROZEN.read_text(encoding="utf-8"))["specification"]["extracted_features_in_order"]
FROZEN8 = json.loads(FROZEN.read_text(encoding="utf-8"))["model_input_features"]


def load(split):
    d = DS / "extraction" / split / "run1"
    X = pd.read_csv(d / "model_features.csv")
    M = pd.read_csv(d / "session_metadata.csv", keep_default_na=False)
    lab = pd.read_csv(DS / "labels" / f"{split}_session_labels.csv", dtype=str)
    df = pd.concat([M[["session_ref"]], X], axis=1).merge(lab, on="session_ref", validate="one_to_one")
    inputs = defaultdict(list)
    for n, line in enumerate((DS / "raw" / split / "cowrie_slice.json").read_text(encoding="utf-8").splitlines()):
        e = json.loads(line)
        if e["eventid"] == "cowrie.command.input" and e["input"].strip() not in EXIT:
            inputs[e["session"]].append((e["timestamp"], n, e["input"]))
    df["commands"] = df.session_ref.map(lambda s: [c for _, _, c in sorted(inputs.get(s, []))])
    return df.reset_index(drop=True)


DF = {s: load(s) for s in SPLITS}
assert not set(DF["train"].interaction_id) & set(DF["validation"].interaction_id)


def records(df, numeric_cols):
    """Session records in the shape novelty_assessment expects: features dict + commands + auth_success."""
    out = {}
    for r in df.itertuples():
        feats = {c: (None if pd.isna(getattr(r, c)) else float(getattr(r, c))) for c in numeric_cols}
        feats["session_id"] = r.session_ref
        out[r.session_ref] = {"session_id": r.session_ref, "features": feats, "commands": list(r.commands),
                              "auth_success": int(r.login_success), "session_duration": r.session_duration_s}
    return out


# =================================================================================================================
# Inventory
# =================================================================================================================
catalogue = json.loads(CATALOGUE.read_text(encoding="utf-8"))
inventory = []
for s in catalogue["signatures"]:
    feats = [f["feature"] for f in s["feature_profile"]["selected_features"]]
    inventory.append({
        "item": s["signature_id"], "type": "stored catalogue signature (DEC cluster summary)", "name_or_label": s["behaviour_label"],
        "source": "reports/behaviour_signatures/behaviour_signatures.json", "created_at": s["created_at"],
        "dec_cluster": s["cluster_id"], "supporting_sessions": s["session_count"], "confidence": s["confidence"],
        "numeric_features": " ".join(feats), "numeric_features_in_dataset_v2": " ".join(f for f in feats if f in FEATURES13),
        "command_categories": " ".join(s["command_categories"]), "auth_success_rate_pct": s["authentication_profile"].get("success_rate"),
        "built_from": "; ".join(s["source_files"][:4]), "depends_on_dec": True, "depends_on_novelty_or_confidence": False,
        "response_action": "none implemented"})
for cat, kws in bpa.CATEGORY_KEYWORDS.items():
    inventory.append({"item": f"keyword_category:{cat}", "type": "command keyword category (substring match)", "name_or_label": cat,
                      "source": "scripts/behaviour_pattern_analysis.py CATEGORY_KEYWORDS", "keywords": " | ".join(kws),
                      "numeric_features": "", "depends_on_dec": False, "depends_on_novelty_or_confidence": False, "response_action": "none implemented"})
for label in ("Credential-attack behaviour", "Persistence-related activity", "Download or payload retrieval",
              "Command execution / privilege escalation", "Reconnaissance", "Command execution", "Mixed/Unclassified", "Insufficient Evidence"):
    inventory.append({"item": f"interpretation:{label}", "type": "session interpretation rule (infer_session_interpretation)", "name_or_label": label,
                      "source": "scripts/behaviour_pattern_analysis.py infer_session_interpretation", "numeric_features": "",
                      "depends_on_dec": False, "depends_on_novelty_or_confidence": False, "response_action": "none implemented"})
inventory.append({"item": "matching:assess_session_against_signatures", "type": "signature matching", "name_or_label": "Known-like / Ambiguous / Potentially Novel / Insufficient Evidence",
                  "source": "scripts/novelty_assessment.py", "keywords": f"weights features 0.70, command categories 0.20, auth 0.10; thresholds {na.DEFAULT_THRESHOLDS}",
                  "numeric_features": "signature feature_profile names (raw values, z-distance to cluster mean/std)",
                  "depends_on_dec": True, "depends_on_novelty_or_confidence": False, "response_action": "none implemented"})
pd.DataFrame(inventory).to_csv(HERE / "signature_inventory.csv", index=False)

# =================================================================================================================
# E1: stored catalogue vs V2 sessions (all 13 extracted V2 features offered as numeric evidence)
# =================================================================================================================
e1 = {}
e1_rows = []
for s in SPLITS:
    recs = records(DF[s], FEATURES13)
    res = [na.assess_session_against_signatures(r, catalogue["signatures"]) for r in recs.values()]
    df = DF[s].assign(assessment=[x["assessment_category"] for x in res], closest=[x.get("closest_signature_id") for x in res],
                      comparable=[x.get("comparable_feature_count", 0) for x in res], score=[x["score"] for x in res])
    e1[s] = {"assessment_counts": df.assessment.value_counts().to_dict(),
             "max_comparable_features": int(df.comparable.max()), "max_score": float(df.score.max()),
             "assessment_by_category": pd.crosstab(df.attack_cat, df.assessment).to_dict()}
    for c in catalogue["signatures"]:
        e1_rows.append({"split": s, "signature": c["signature_id"], "label": c["behaviour_label"],
                        "known_like_matches": int(((df.assessment == "Known-like") & (df.closest == c["signature_id"])).sum()),
                        "closest_any": int((df.closest == c["signature_id"]).sum())})

# =================================================================================================================
# E2: session-level keyword categories and interpretation rules (unchanged functions)
# =================================================================================================================


def keyword_hits(cmd):
    norm = cmd.strip().lower()
    return [(cat, kw) for cat, kws in bpa.CATEGORY_KEYWORDS.items() for kw in kws if kw in norm]


def token_level(cat, kw, cmd):
    """Diagnostic only: does the keyword occur as a whole command word (not inside another word or path)?"""
    norm = cmd.strip().lower()
    if " " in kw.strip() or "/" in kw or "+" in kw or "=" in kw:
        return kw.strip() in norm
    return re.search(r"(^|[\s;|&])" + re.escape(kw.strip()) + r"($|[\s;|&])", norm) is not None


e2 = {}
interp_rows, kw_rows = [], []
for s in SPLITS:
    D = DF[s]
    dec_like = D[["session_ref"]].rename(columns={"session_ref": "session_id"}).assign(dec_cluster=0)
    details = {r.session_ref: {"commands": list(r.commands), "auth_success": int(r.login_success), "session_duration": r.session_duration_s}
               for r in D.itertuples()}
    profiles, _ = bpa.build_session_profiles(dec_like, details, {})
    D = D.assign(interpretation=profiles.behavioural_interpretation.values,
                 categories=[[c for c in dict.fromkeys(c for cmd in r.commands for c in bpa.classify_command(cmd))] for r in D.itertuples()])
    DF[s] = D
    li = D.role == "logged_in"
    for setname, m in (("logged_in_one_per_interaction", li), ("failed_guess_sessions", ~li), ("all_sessions", D.role.notna())):
        t = pd.crosstab(D.interpretation[m], D.attack_cat[m])
        for lab_, row in t.iterrows():
            interp_rows.append({"split": s, "set": setname, "interpretation": lab_, "sessions": int(row.sum()),
                                "interactions": int(D[m & (D.interpretation == lab_)].interaction_id.nunique()),
                                **{f"n_{c}": int(row.get(c, 0)) for c in sorted(D.attack_cat.unique())}})
    # keyword category firing on logged-in sessions, and what fired it
    fired = defaultdict(Counter)
    whole_word = defaultdict(lambda: [0, 0])
    for r in D[li].itertuples():
        for cmd in r.commands:
            for cat, kw in keyword_hits(cmd):
                fired[cat][kw] += 1
                ww = token_level(cat, kw, cmd)
                whole_word[(cat, kw)][0] += 1
                whole_word[(cat, kw)][1] += int(ww)
    for cat in bpa.CATEGORY_KEYWORDS:
        m = D[li].categories.map(lambda cs, c=cat: c in cs)
        kw_rows.append({"split": s, "keyword_category": cat, "logged_in_sessions_matched": int(m.sum()),
                        "share_of_logged_in": float(m.mean()),
                        **{f"share_{c}": float(m[D[li].attack_cat == c].mean()) for c in sorted(D.attack_cat.unique())},
                        "top_firing_keywords": "; ".join(f"{k}:{n}" for k, n in fired[cat].most_common(6)),
                        "hits_not_whole_word_share": (1 - sum(v[1] for k, v in whole_word.items() if k[0] == cat) /
                                                      max(1, sum(v[0] for k, v in whole_word.items() if k[0] == cat)))})
    e2[s] = {"interpretation_counts_logged_in": D[li].interpretation.value_counts().to_dict(),
             "interpretation_counts_failed": D[~li].interpretation.value_counts().to_dict(),
             "keyword_false_substring_examples": sorted({f"{kw!r} in {cmd!r}" for r in D[li].itertuples() for cmd in r.commands
                                                         for cat, kw in keyword_hits(cmd) if not token_level(cat, kw, cmd)})[:40]}
pd.DataFrame(kw_rows).to_csv(OUT / "keyword_category_by_attack_cat.csv", index=False, float_format="%.4f")
interp_df = pd.DataFrame(interp_rows)
interp_df.to_csv(OUT / "interpretation_by_attack_cat.csv", index=False)

# transfer consistency: interpretation label -> category composition, train vs validation (logged-in)
consistency = {}
for lab_ in sorted(set(DF["train"].interpretation) | set(DF["validation"].interpretation)):
    comp = {}
    for s in SPLITS:
        D = DF[s][DF[s].role == "logged_in"]
        sub = D[D.interpretation == lab_]
        comp[s] = {"n": len(sub), "category_share": sub.attack_cat.value_counts(normalize=True).round(3).to_dict()}
    consistency[lab_] = comp

# =================================================================================================================
# E3: existing reference-only signature builder on V2 train (saved Task 17 DEC K=3 seed-42 assignments) -> validation
# =================================================================================================================
asg = pd.read_csv(T17 / "assignments_embeddings_k3_seed42_train.csv")
tr = DF["train"].merge(asg[["session_ref", "dec_cluster", "dec_confidence"]], on="session_ref", validate="one_to_one")
ref_dec = tr[["session_ref", "dec_cluster", "dec_confidence"] + FROZEN8].rename(columns={"session_ref": "session_id"})
ref_details = {r.session_ref: {"commands": list(r.commands), "auth_success": int(r.login_success), "session_duration": r.session_duration_s}
               for r in tr.itertuples()}
v2_signatures = na._reference_only_signatures(ref_dec, ref_details, Path("T17 dec_k3_seed42 train assignments"), Path("Dataset V2 train"))
for sig in v2_signatures:                                # created_at is wall-clock; drop for reproducible evidence
    sig.pop("created_at", None)
(OUT / "v2_reference_signatures_e3.json").write_text(json.dumps(clean(v2_signatures), indent=2, default=str), encoding="utf-8")
e3 = {"signatures": [{"signature_id": s_["signature_id"], "dec_cluster": s_["cluster_id"], "label": s_["behaviour_label"],
                      "sessions": s_["session_count"], "confidence": s_["confidence"],
                      "features": [f["feature"] for f in s_["feature_profile"]["selected_features"]],
                      "command_categories": s_["command_categories"], "auth_success_rate": s_["authentication_profile"]["success_rate"],
                      "train_category_share": tr[tr.dec_cluster == s_["cluster_id"]].attack_cat.value_counts(normalize=True).round(3).to_dict()}
                     for s_ in v2_signatures]}
match_rows = []
for s in SPLITS:
    recs = records(DF[s], FROZEN8)
    res = [na.assess_session_against_signatures(r, v2_signatures) for r in recs.values()]
    D = DF[s].assign(assessment=[x["assessment_category"] for x in res], closest_label=[x.get("best_signature_label") for x in res],
                     closest=[x.get("closest_signature_id") for x in res], score=[x["score"] for x in res],
                     contradiction=[";".join(x.get("contradictory_evidence") or []) for x in res])
    DF[s] = D
    li = D.role == "logged_in"
    e3[s] = {"role": "reference (in-sample)" if s == "train" else "evaluation (out-of-sample)",
             "assessment_counts_all": D.assessment.value_counts().to_dict(),
             "assessment_counts_logged_in": D[li].assessment.value_counts().to_dict(),
             "assessment_by_category_logged_in": pd.crosstab(D.attack_cat[li], D.assessment[li]).to_dict(),
             "assessment_by_category_failed": pd.crosstab(D.attack_cat[~li], D.assessment[~li]).to_dict(),
             "closest_label_by_category_logged_in": pd.crosstab(D.attack_cat[li], D.closest_label[li]).to_dict(),
             "contradictions_logged_in": D[li].contradiction.value_counts().to_dict(),
             "score_median_by_category_logged_in": D[li].groupby("attack_cat").score.median().round(4).to_dict()}
    for sig in v2_signatures:
        m = D.closest == sig["signature_id"]
        kl = m & (D.assessment == "Known-like")
        match_rows.append({"split": s, "signature": sig["signature_id"], "label": sig["behaviour_label"], "dec_cluster": sig["cluster_id"],
                           "closest_sessions": int(m.sum()), "known_like_sessions": int(kl.sum()),
                           "known_like_logged_in_interactions": int(D[kl & li].interaction_id.nunique()),
                           **{f"known_like_{c}": int((kl & (D.attack_cat == c)).sum()) for c in sorted(D.attack_cat.unique())}})
pd.DataFrame(match_rows).to_csv(OUT / "e3_signature_matches_by_category.csv", index=False)

# per-session evidence for validation (post hoc)
DF["validation"][["session_ref", "interaction_id", "role", "attack_cat", "interpretation", "assessment", "closest_label", "score", "contradiction"]].assign(
    categories=DF["validation"].categories.map(" ".join), commands=DF["validation"].commands.map(" ; ".join)
).to_csv(OUT / "validation_session_signature_results.csv", index=False)

# artefact dependence of E3 numeric matching: which frozen features the V2 signatures use, and score vs Cowrie timing
cmdlog = pd.read_csv(DS / "evidence" / "validation_command_log.csv")
slow = set(cmdlog[cmdlog.wait_s >= 5].interaction_id)
v = DF["validation"]
vli = v[v.role == "logged_in"].assign(slow_find=lambda d: d.interaction_id.isin(slow))
artefact = {"validation_slow_find_sessions": int(vli.slow_find.sum()),
            "assessment_of_slow_find_sessions": vli[vli.slow_find].assessment.value_counts().to_dict(),
            "assessment_of_pe_non_find_sessions": vli[(vli.attack_cat == "privilege_escalation") & ~vli.slow_find].assessment.value_counts().to_dict(),
            "score_spearman_vs_session_duration": float(vli.score.corr(vli.session_duration_s, method="spearman")),
            "score_spearman_vs_tty_output_bytes": float(vli.score.corr(vli.tty_output_bytes, method="spearman"))}

results = {"source_hashes": src_hashes, "dataset_v2_verified": True,
           "rows": {s: len(DF[s]) for s in SPLITS}, "logged_in": {s: int((DF[s].role == "logged_in").sum()) for s in SPLITS},
           "E1_stored_catalogue": {"per_split": e1, "per_signature": e1_rows},
           "E2_rules": e2, "E2_label_consistency_train_vs_validation": consistency,
           "E3_v2_reference_signatures": e3, "E3_artefact_dependence_validation": artefact,
           "thresholds": na.DEFAULT_THRESHOLDS,
           "test_like_paths_opened": [p for p in OPENED if "test" in p.rsplit("/", 1)[-1] and p.endswith((".pkl", ".csv", ".json", ".jsonl"))]}
(OUT / "results.json").write_text(json.dumps(clean(results), indent=2, default=str), encoding="utf-8")
print(json.dumps(clean({"E1": e1, "E2": {s: {k: v for k, v in e2[s].items() if k != "keyword_false_substring_examples"} for s in SPLITS},
                        "E3_sigs": e3["signatures"], "E3_val": e3["validation"], "artefact": artefact,
                        "test_paths": results["test_like_paths_opened"]}), indent=1, default=str)[:9000])
