"""Task 23: read-only dry run of the PROPOSED severity model and policy states on existing evidence records.

    .venv/Scripts/python.exe reports/threat_assessment_design_20261111/dry_run_mapping.py

Input: Task 22 primary-configuration records (train + validation) produced by the unchanged behavioural_evidence
package. The oracle-source records are NOT used (synthetic interaction-derived sources are not identities).
Nothing is scored for production, no policy is loaded or activated, and no file outside this directory is written.
Labels are joined only for the post-hoc tables.
"""
import json
from collections import Counter
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SRC = REPO / "reports" / "behavioural_evidence_framework_implementation_20261111" / "evidence"
DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
OUT = HERE / "evidence"

SEVERITY = {  # proposed in severity_model.md; fixed per interpretation, independent of evidence level
    "repeated authentication failures": "S1", "credential guessing followed by login": "S2",
    "privilege-context reconnaissance attempt": "S2", "credential-material access attempt": "S3",
    "download attempt": "S2", "download-and-execute attempt": "S3", "upload attempt": "S3",
    "archive-and-upload attempt": "S3", "history tampering attempt": "S2", "persistence modification attempt": "S3",
    "network probing attempt": "S2"}
ORDER = ["S0", "S1", "S2", "S3"]
RELAYS = {"172.22.0.2"}
PROTECTED = ["127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10", "172.19.0.0/16", "172.22.0.0/16"]


def attributable(r):
    import ipaddress
    ip = r["src_ip"]
    if not ip:
        return "unattributed:no_source"
    if ip in RELAYS:
        return "unattributed:trusted_proxy"
    if any(ipaddress.ip_address(ip) in ipaddress.ip_network(n) for n in PROTECTED):
        return "unattributed:protected_network"
    return "attributable"


CRED_HIGH_DETAILS = {"credential file path", "find for credential file name"}   # shadow, private keys, authorized_keys, history


def severity(i, r):
    """Fixed per interpretation; credential-material refined by the CRED-1 match detail already in the record."""
    if i["name"] == "credential-material access attempt":
        details = {m["detail"] for ind in r["indicators"] if ind["id"] == "CRED-1" for m in ind["matches"]}
        return "S3" if details & CRED_HIGH_DETAILS else "S2"
    return SEVERITY[i["name"]]


def assess(r):
    findings = [{"interpretation": i["name"], "severity": severity(i, r), "evidence_level": i["evidence_level"],
                 "scope": i["scope"], "support": i["supporting_action_indicators"]} for i in r["interpretations"]]
    attr = attributable(r)
    # gate (b): distinct action IDs across the S2+/E2+ findings only
    action_ids = {a for f in findings if f["evidence_level"] in ("E2", "E3") and ORDER.index(f["severity"]) >= 2 for a in f["support"]}
    if r["behavioural_status"] in ("indeterminate", "insufficient_evidence"):
        state, why = "abstain", r["behavioural_status"]
    elif not findings:
        state, why = "record", "context only (S0)"
    else:
        top = max(ORDER.index(f["severity"]) for f in findings)
        strong = [f for f in findings if f["evidence_level"] in ("E2", "E3") and ORDER.index(f["severity"]) >= 2]
        if len(action_ids) >= 2 and strong and top >= 2 and r["authentication_status"] != "below_threshold":
            if attr != "attributable":
                state, why = "review", f"meets evidence/severity gate but {attr}: no action can be proposed"
            elif r["n_input_lines"] == 0:
                state, why = "review", "no successful-login evidence"
            else:
                state, why = "propose_for_manual_approval", ">= 2 distinct action indicators, E2+, S2+, attributable"
        elif top >= 2:
            state, why = "review", "S2+ finding below the evidence gate"
        else:
            state, why = "record", "low severity"
    return findings, attr, state, why


rows = []
for split in ("train", "validation"):
    lab = pd.read_csv(DS / "labels" / f"{split}_session_labels.csv", dtype=str).set_index("session_ref")
    for line in open(SRC / f"{split}_primary_records.jsonl", encoding="utf-8"):
        r = json.loads(line)
        findings, attr, state, why = assess(r)
        top = max([f["severity"] for f in findings], key=ORDER.index) if findings else ("S0" if r["behavioural_status"] == "system_discovery_only" else "n/a")
        rows.append({"split": split, "session_ref": r["session_ref"], "attack_cat_posthoc": lab.loc[r["session_ref"], "attack_cat"],
                     "role_posthoc": lab.loc[r["session_ref"], "role"], "behavioural_status": r["behavioural_status"],
                     "evidence_level": r["evidence_level"], "top_severity": top, "n_findings": len(findings),
                     "attribution": attr, "policy_state": state, "reason": why,
                     "has_novelty_flag": bool(r["statistical_novelty"] and r["statistical_novelty"]["value"].get("C_flag")),
                     "caveats": ";".join(r["caveat_indicators"])})
df = pd.DataFrame(rows)
df.to_csv(OUT / "dry_run_session_assessments.csv", index=False)
v = df[df.split == "validation"]
summary = {
    "note": "dry run of the proposed design on unchanged Task 22 records; lab relay => every session unattributed, so no session can reach 'propose_for_manual_approval'",
    "severity_by_evidence_level_validation": pd.crosstab(v.top_severity, v.evidence_level).to_dict(),
    "policy_state_validation": v.policy_state.value_counts().to_dict(),
    "policy_state_by_category_validation": pd.crosstab(v.attack_cat_posthoc, v.policy_state).to_dict(),
    "benign_review_or_propose_validation": int(((v.attack_cat_posthoc == "benign") & v.policy_state.isin(["review", "propose_for_manual_approval"])).sum()),
    "novelty_flag_sessions_validation": int(v.has_novelty_flag.sum()),
    "novelty_flag_sessions_by_state": v[v.has_novelty_flag].policy_state.value_counts().to_dict(),
    "art1_sessions_by_state": v[v.caveats.str.contains("ART-1")].policy_state.value_counts().to_dict(),
    "attribution_validation": v.attribution.value_counts().to_dict(),
    "finding_severity_by_finding_level_validation": pd.DataFrame([{"interp": f["interpretation"], "sev": f["severity"], "lvl": f["evidence_level"]}
        for l in open(SRC / "validation_primary_records.jsonl", encoding="utf-8") for r in [json.loads(l)] for f in assess(r)[0]])
        .groupby(["interp", "sev", "lvl"]).size().reset_index(name="n").to_dict(orient="records"),
    "policy_state_train": df[df.split == "train"].policy_state.value_counts().to_dict(),
}
(OUT / "dry_run_summary.json").write_text(json.dumps(summary, indent=2, default=int), encoding="utf-8")
print(json.dumps(summary, indent=1, default=int))
