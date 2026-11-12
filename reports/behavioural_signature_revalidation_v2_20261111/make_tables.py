"""Task 20: build signature_validation_results.csv, feature_dependency_matrix.csv and false_positive_analysis.csv
from evidence/ produced by revalidate_signatures.py (no recomputation of matches).

    .venv/Scripts/python.exe reports/behavioural_signature_revalidation_v2_20261111/make_tables.py

Classification codes: 1 supported; 2 partially supported (qualified); 3 generator/template-dependent;
4 Cowrie-emulation/timing-dependent; 5 unsupported or non-functional; 6 cannot be evaluated with available telemetry.
Classifications are analyst judgements recorded with their evidence in report.md; category labels are reference only.
"""
import json
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
EV = HERE / "evidence"
R = json.loads((EV / "results.json").read_text(encoding="utf-8"))
kw = pd.read_csv(EV / "keyword_category_by_attack_cat.csv")
it = pd.read_csv(EV / "interpretation_by_attack_cat.csv")
e3m = pd.read_csv(EV / "e3_signature_matches_by_category.csv")
inv = pd.read_csv(HERE / "signature_inventory.csv")
val = pd.read_csv(EV / "validation_session_signature_results.csv", keep_default_na=False)
CATS = ["benign", "botnet", "brute_force", "lateral_movement", "privilege_escalation", "reconnaissance"]

CLASS = {
    # item: (code, short reason)
    "stored_catalogue": (6, "all 8 numeric profile features are V1 UNSW-style (ackdat, ct_*, dbytes, dinpkt); none exists in Dataset V2, so 0 comparable features and every session is 'Insufficient Evidence'"),
    "keyword_category:reconnaissance": (5, "fires in 89% of logged-in sessions across all categories; 'w' matches any command containing the letter w"),
    "keyword_category:credential_attack": (5, "fires from substrings ('.ssh', '/etc/passwd', '/root'); 0% of brute-force logins"),
    "keyword_category:file_transfer": (3, "100% botnet but also 14-40% of benign/recon/lateral via template wget/curl/nc lines; no transfer ever succeeds in Cowrie"),
    "keyword_category:file_system": (5, "fires in ~70% of logged-in sessions of every command-running category; not discriminative"),
    "keyword_category:persistence": (5, "59-63% of benign sessions (service/systemctl administration) vs 0% botnet/lateral/recon; benign-dominated"),
    "keyword_category:privilege_escalation": (2, "100% of PE and 0% benign, but 41-51% of botnet/recon and 17-20% of brute force; 37% of hits are substrings (su in /etc/issue)"),
    "keyword_category:networking": (5, "61-63% of logged-in sessions; 36-39% of hits are substrings ('ssh' in '~/.ssh')"),
    "keyword_category:evasion": (3, "botnet 76-82% and PE 51-52% from template cleanup lines; 'rm ' matches 'perm' in find -perm"),
    "interpretation:Credential-attack behaviour": (3, "assigned to 100% of failed-guess sessions of every category (generator makes 0-5 failed connections per interaction by design); logged-in matches are only lateral movement"),
    "interpretation:Persistence-related activity": (5, "77-89% benign"),
    "interpretation:Download or payload retrieval": (2, "72% botnet in both splits, but means a download COMMAND: 0 download events in Cowrie (isolated); 10-14% benign/recon"),
    "interpretation:Command execution / privilege escalation": (3, "PE 44-48% but brute force 28-35% from its one-command template pool (whoami)"),
    "interpretation:Reconnaissance": (5, "53-57% benign; reconnaissance only 16-18%"),
    "interpretation:Command execution": (3, "90-100% brute force, from single template commands (echo ok)"),
    "interpretation:Mixed/Unclassified": (5, "catch-all for ~half of logged-in sessions; category mix equals the population"),
    "interpretation:Insufficient Evidence": (2, "correct abstention: 95-98% brute-force logins with no command"),
    "matching:assess_session_against_signatures": (4, "on V2 re-instantiated signatures: all 9 validation slow-find sessions 'Potentially Novel' (vs 0 of 60 other PE logins); 27% of known logged-in validation sessions 'Potentially Novel'; scores driven by duration/timing"),
}

rows = []
for r in inv.itertuples():
    key = "stored_catalogue" if r.item.startswith("sig-") else r.item
    code, reason = CLASS[key]
    row = {"item": r.item, "type": r.type, "label": r.name_or_label, "executes_on_v2": True, "classification": code, "reason": reason}
    if r.item.startswith("sig-"):
        per = {x["split"]: x for x in R["E1_stored_catalogue"]["per_signature"] if x["signature"] == r.item}
        row.update({"required_telemetry": r.numeric_features, "telemetry_available_in_v2": "no (0 of 8 features)",
                    "train_matches": per["train"]["known_like_matches"], "validation_matches": per["validation"]["known_like_matches"],
                    "validation_match_category_distribution": "{}", "match_definition": "Known-like assessment",
                    "executes_on_v2": "yes, but every session returns 'Insufficient Evidence'"})
    elif r.item.startswith("keyword_category:"):
        cat = r.name_or_label
        t, v = (kw[(kw.split == s) & (kw.keyword_category == cat)].iloc[0] for s in ("train", "validation"))
        row.update({"required_telemetry": "recorded command.input text", "telemetry_available_in_v2": "yes",
                    "train_matches": int(t.logged_in_sessions_matched), "validation_matches": int(v.logged_in_sessions_matched),
                    "validation_match_category_distribution": json.dumps({c: round(float(v[f"share_{c}"]), 3) for c in CATS}),
                    "match_definition": "logged-in sessions with >=1 command in the category (share = fraction of that category's sessions)",
                    "substring_not_whole_word_hit_share_validation": round(float(v.hits_not_whole_word_share), 3),
                    "top_firing_keywords_validation": v.top_firing_keywords})
    elif r.item.startswith("interpretation:"):
        lab = r.name_or_label
        g = lambda s, setname: it[(it.split == s) & (it.set == setname) & (it.interpretation == lab)]  # noqa: E731
        tl, vl, va = g("train", "logged_in_one_per_interaction"), g("validation", "logged_in_one_per_interaction"), g("validation", "all_sessions")
        dist = {c: int(va[f"n_{c}"].iloc[0]) if len(va) else 0 for c in CATS}
        row.update({"required_telemetry": "recorded commands + login outcome", "telemetry_available_in_v2": "yes",
                    "train_matches": int(tl.sessions.iloc[0]) if len(tl) else 0, "validation_matches": int(vl.sessions.iloc[0]) if len(vl) else 0,
                    "validation_failed_guess_matches": int(g("validation", "failed_guess_sessions").sessions.sum()),
                    "validation_match_category_distribution": json.dumps(dist),
                    "match_definition": "logged-in sessions (one per interaction); category distribution = all validation sessions"})
    else:
        v3 = R["E3_v2_reference_signatures"]["validation"]
        row.update({"required_telemetry": "signature feature_profile names + command categories + auth", "telemetry_available_in_v2": "only for signatures built on V2 features (E3)",
                    "train_matches": int(R["E3_v2_reference_signatures"]["train"]["assessment_counts_all"].get("Known-like", 0)),
                    "validation_matches": int(v3["assessment_counts_all"].get("Known-like", 0)),
                    "validation_match_category_distribution": json.dumps(v3["assessment_by_category_logged_in"]),
                    "match_definition": "Known-like (E3, re-instantiated V2 signatures); distribution = logged-in assessments by category"})
    rows.append(row)
for r in e3m[e3m.split == "validation"].itertuples():
    t = e3m[(e3m.split == "train") & (e3m.signature == r.signature)].iloc[0]
    code, reason = ((3, "cluster of failed logins: Known-like for 99.8% of failed-guess sessions of every category; label 'Credential-attack' applied to benign failed guesses")
                    if r.label == "Credential-attack behaviour" else
                    (5, "label 'Mixed/Unclassified'; category mix of matches equals the logged-in population (benign ~40%)"))
    rows.append({"item": f"E3:{r.signature}", "type": "re-instantiated V2 reference signature (existing builder, Task 17 DEC K=3 train assignments)",
                 "label": r.label, "executes_on_v2": True, "classification": code, "reason": reason,
                 "required_telemetry": "frozen 8 V2 features + commands + auth", "telemetry_available_in_v2": "yes",
                 "train_matches": int(t.known_like_sessions), "validation_matches": int(r.known_like_sessions),
                 "validation_match_category_distribution": json.dumps({c: int(getattr(r, f"known_like_{c}")) for c in CATS}),
                 "match_definition": "Known-like with this signature closest (all sessions)"})
res = pd.DataFrame(rows)
res.to_csv(HERE / "signature_validation_results.csv", index=False)

# feature / telemetry dependency matrix
deps = ["V1_UNSW_features", "V2_frozen_numeric_features", "recorded_command_text", "login_outcome", "DEC_cluster_assignment",
        "DEC_confidence_or_novelty_score", "Cowrie_execution_timing", "Cowrie_output_volume", "generator_command_templates", "response_action"]
dm = []
for r in res.itertuples():
    t = r.type
    d = dict.fromkeys(deps, "no")
    if r.item.startswith("sig-"):
        d.update(V1_UNSW_features="yes (all 8 numeric)", recorded_command_text="yes (categories)", login_outcome="yes", DEC_cluster_assignment="yes (built per V1 DEC cluster)")
    elif "keyword" in t:
        d.update(recorded_command_text="yes (substring)", generator_command_templates="yes (fixed profile strings)")
    elif "interpretation" in t:
        d.update(recorded_command_text="yes", login_outcome="yes", generator_command_templates="yes")
    elif r.item.startswith("E3:"):
        d.update(V2_frozen_numeric_features="yes", recorded_command_text="yes", login_outcome="yes", DEC_cluster_assignment="yes (Task 17 K=3)",
                 Cowrie_execution_timing="yes (session_duration_s, inter-input timing)", Cowrie_output_volume="yes (tty_output_bytes)", generator_command_templates="yes")
    else:
        d.update(V1_UNSW_features="via stored catalogue", V2_frozen_numeric_features="via E3 signatures", recorded_command_text="yes", login_outcome="yes",
                 DEC_cluster_assignment="yes (signatures are per cluster)", Cowrie_execution_timing="yes", Cowrie_output_volume="yes")
    d["response_action"] = "none implemented (configs/defence_policy.json is read by no code)"
    dm.append({"item": r.item, **d})
pd.DataFrame(dm).to_csv(HERE / "feature_dependency_matrix.csv", index=False)

# false-positive analysis (validation; benign as the known-non-attack reference, not ground truth for novelty)
li = val.role == "logged_in"
b = val[li & (val.attack_cat == "benign")]
fp = []
for lab, n in b.interpretation.value_counts().items():
    fp.append({"evidence": "E2 interpretation of benign logged-in validation sessions", "label_or_outcome": lab, "sessions": int(n),
               "share_of_benign_logged_in": round(n / len(b), 4), "attack_implying_label": lab not in ("Mixed/Unclassified", "Insufficient Evidence", "Command execution")})
bf = val[~li & (val.attack_cat == "benign")]
fp.append({"evidence": "E2 interpretation of benign FAILED-GUESS validation sessions", "label_or_outcome": "Credential-attack behaviour",
           "sessions": int((bf.interpretation == "Credential-attack behaviour").sum()), "share_of_benign_failed": round(float((bf.interpretation == "Credential-attack behaviour").mean()), 4),
           "attack_implying_label": True})
for c in CATS:
    sub = val[li & (val.attack_cat == c)]
    fp.append({"evidence": "E3 'Potentially Novel' on KNOWN-category logged-in validation sessions", "label_or_outcome": c,
               "sessions": int((sub.assessment == "Potentially Novel").sum()), "share_of_category_logged_in": round(float((sub.assessment == "Potentially Novel").mean()), 4),
               "attack_implying_label": "novelty claim on a trained category"})
art = R["E3_artefact_dependence_validation"]
fp.append({"evidence": "E3 assessment of the 9 validation slow-find (Cowrie 11-12 s execution) sessions", "label_or_outcome": json.dumps(art["assessment_of_slow_find_sessions"]),
           "sessions": art["validation_slow_find_sessions"], "attack_implying_label": "novelty driven by Cowrie timing"})
fp.append({"evidence": "E3 assessment of the other privilege-escalation logged-in sessions", "label_or_outcome": json.dumps(art["assessment_of_pe_non_find_sessions"]),
           "sessions": sum(art["assessment_of_pe_non_find_sessions"].values()), "attack_implying_label": "reference"})
pd.DataFrame(fp).to_csv(HERE / "false_positive_analysis.csv", index=False)
print(res[["item", "classification", "train_matches", "validation_matches"]].to_string())
