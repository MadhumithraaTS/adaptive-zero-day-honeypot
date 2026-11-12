"""Task 26A: verify relay records, correlate with Cowrie, assess the five demo sessions, and run failure-case variants.

Inputs (captured read-only into evidence/): Cowrie events after the pre-session baseline (21,854 lines) and a copy of the
relay's signed mapping log. Uses the unchanged behavioural_evidence configuration exactly as Task 24 built it.
No signing key is loaded here; failure variants that need a "wrong key" use a throwaway key generated in memory.
Nothing is executed or enforced.
"""
import copy
import csv
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from behavioural_evidence import EvidenceConfig, EvidenceEngine  # noqa: E402
from behavioural_evidence.calibration import load_calibration  # noqa: E402
from behavioural_evidence.engine import read_jsonl  # noqa: E402
from client_attribution import VERSION as CA_VERSION, correlate, load_attribution_v2  # noqa: E402
from client_attribution.correlate import canonical_digest  # noqa: E402
from client_attribution.records import load_public_key, ts, verify_records  # noqa: E402
from threat_assessment import ASSESSMENT_VERSION, AuditLog, ThreatAssessor, load_attribution_config, load_policy, verify_chain  # noqa: E402
from threat_assessment.audit import read_log  # noqa: E402

EV = HERE / "evidence"
DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
T22 = REPO / "reports" / "behavioural_evidence_framework_implementation_20261111"
ATT_PATH = REPO / "configs" / "threat_attribution_v2.json"
POL_PATH = REPO / "configs" / "defence_policy_v2_1.json"
DIAG = ("99732d516898", "b806554e19b9")
EVAL_TIME = datetime(2026, 11, 11, 17, 30, 0, tzinfo=timezone.utc)   # fixed: reproducible; records are ~10 min old
RUN_TS = "2026-11-11T17:30:00Z"
LABELS = {"9441bcce555c": "S1 published-path banner (host)", "acc2bad4a442": "S2 test client banner",
          "d588636ce120": "S3 control client banner", "3eede5e19e25": "S4 test client shell",
          "4542a85f37ec": "S5 control client shell"}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def write_jsonl(p, rows):
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")


def write_csv(p, rows):
    with open(p, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


# ------------------------------------------------------------------------------------------------ inputs
events = read_jsonl(EV / "cowrie_events_after_baseline.jsonl")
lines = (EV / "relay_mapping.jsonl").read_text(encoding="utf-8").splitlines()
att = load_attribution_config(ATT_PATH)
cfg = load_attribution_v2(ATT_PATH)
pol = load_policy(POL_PATH)
pub_pem = (REPO / cfg.doc["proxy_client_mapping"]["public_key_path"]).read_bytes()
assert att.digest == cfg.digest == pol.attribution_digest
assert not set(DIAG) & {e["session"] for e in events}, "diagnostic sessions must not be in the input"

# ------------------------------------------------------------------------------------------------ verification + correlation
pub, pub_sha = load_public_key(pub_pem)
ver = verify_records(lines, pub, pub_sha, cfg.key_not_before, cfg.key_not_after)
ca = correlate(events, lines, pub_pem, cfg, evaluation_time=EVAL_TIME)
(EV / "record_verification.json").write_text(json.dumps({k: v for k, v in ver.items() if k != "records"}, indent=2) + "\n", encoding="utf-8")
(EV / "correlation_result.json").write_text(json.dumps(ca, indent=2, sort_keys=True) + "\n", encoding="utf-8")

# ------------------------------------------------------------------------------------------------ evidence + assessment
cal = load_calibration(T22 / "config" / "sensor_calibration_lab_train.json")
train = read_jsonl(DS / "raw" / "train" / "cowrie_slice.json")
ref_seq = frozenset(tuple(v) for v in pd.DataFrame(
    [(e["session"], e["timestamp"], e["input"]) for e in train
     if e["eventid"] == "cowrie.command.input" and e["input"].strip() not in ("exit", "logout")],
    columns=["s", "t", "i"]).sort_values(["s", "t"], kind="stable").groupby("s").i.apply(tuple))
ecfg = EvidenceConfig(relay_sources=frozenset(att.relay_strings), internal_networks=att.internal_cidr_strings, calibration=cal,
                      reference_sequences=ref_seq)
evidence = EvidenceEngine(ecfg).evaluate(events)["sessions"]
assessor = ThreatAssessor(att, pol, ecfg)
assessed = [assessor.assess(r, ca) for r in evidence]
without = [assessor.assess(r) for r in evidence]
write_jsonl(EV / "demo_evidence.jsonl", evidence)
write_jsonl(EV / "demo_assessments.jsonl", assessed)

audit_path = EV / "demo_audit.jsonl"
if audit_path.exists():
    audit_path.unlink()                                   # this run's own output only (re-created deterministically)
log = AuditLog("task26a-demo", path=audit_path, clock=lambda: RUN_TS)
for a in assessed:
    log.append(a)
ck = log.checkpoint()
(EV / "demo_audit_checkpoint.json").write_text(json.dumps(ck, indent=2) + "\n", encoding="utf-8")
audit_ok = verify_chain(read_log(audit_path), ck)

rows = []
for a, b in zip(assessed, without):
    sid, m = a["session_ref"], ca["sessions"].get(a["session_ref"], {})
    sa = a["session_attribution"]
    rows.append({"session": sid, "label": LABELS.get(sid, "?"), "cowrie_src": m.get("cowrie_src"), "listener": m.get("listener"),
                 "client_ip": m.get("client_ip"), "client_port": m.get("client_port"), "client_role": m.get("client_role"),
                 "correlation_state": m.get("state"), "close_check": m.get("close_check"), "attribution_state": sa["state"],
                 "behavioural_status": a["behavioural_status"], "authentication_status": a["authentication_status"],
                 "findings": "; ".join(f"{f['interpretation']}={f['severity']}/{f['evidence_level']}" for f in a["findings"]),
                 "tier": a["tier"], "failed_gates": ",".join(k for k, v in a["gates"].items() if not v),
                 "proposal_subject": (a["proposed_action"] or {}).get("subject"), "proposal_mode": (a["proposed_action"] or {}).get("mode"),
                 "manual_approval": (a["proposed_action"] or {}).get("manual_approval"),
                 "execution": (a["proposed_action"] or {}).get("execution"),
                 "tier_without_mapping": b["tier"], "attribution_without_mapping": b["session_attribution"]["state"],
                 "findings_identical_without_mapping": [{k: v for k, v in f.items() if k != "attribution"} for f in a["findings"]]
                 == [{k: v for k, v in f.items() if k != "attribution"} for f in b["findings"]]})
write_csv(HERE / "demo_session_results.csv", rows)


# ------------------------------------------------------------------------------------------------ failure-case variants
def cfg_with(mut):
    doc = copy.deepcopy(cfg.doc)
    mut(doc)
    p = EV / "_tmp_cfg.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    try:
        return load_attribution_v2(p)
    finally:
        p.unlink()


def states(out):
    return {LABELS[s][:2]: r["state"] for s, r in sorted(out["sessions"].items(), key=lambda kv: LABELS.get(kv[0], kv[0]))}


def mod_line(ls, pred, fn):
    out = []
    for l in ls:
        r = json.loads(l)
        if pred(r):
            fn(r)
            l = json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        out.append(l)
    return out


s4_open = lambda r: r["record_type"] == "connection_open" and r["client_ip"] == "10.250.25.3" and r["upstream_local_port"] == 59090
other_key = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
shift = lambda sid, sec: [dict(e, timestamp=(ts(e["timestamp"]) + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
                          if e["session"] == sid and e["eventid"] == "cowrie.session.closed" else e for e in events]
variants = [
    ("baseline (captured data)", events, lines, pub_pem, cfg, EVAL_TIME),
    ("modified client_ip in S4 open record (10.250.25.3 -> .4)", events, mod_line(lines, s4_open, lambda r: r.__setitem__("client_ip", "10.250.25.4")), pub_pem, cfg, EVAL_TIME),
    ("S4 open record deleted", events, [l for l in lines if not s4_open(json.loads(l))], pub_pem, cfg, EVAL_TIME),
    ("records reordered (seq 4 <-> 5)", events, lines[:3] + [lines[4], lines[3]] + lines[5:], pub_pem, cfg, EVAL_TIME),
    ("signature removed from one record", events, mod_line(lines, s4_open, lambda r: r.pop("signature")), pub_pem, cfg, EVAL_TIME),
    ("log truncated mid-record", events, lines[:-1] + [lines[-1][:40]], pub_pem, cfg, EVAL_TIME),
    ("verified with an unpinned public key", events, lines, other_key, cfg, EVAL_TIME),
    ("mapping log unavailable", events, None, pub_pem, cfg, EVAL_TIME),
    ("evaluated 25 h later (record expiry 24 h)", events, lines, pub_pem, cfg, EVAL_TIME + timedelta(hours=25)),
    ("key validity ended before records were written", events, lines, pub_pem,
     cfg_with(lambda d: d["proxy_client_mapping"]["key_validity"].__setitem__("not_after", "2026-11-11T17:00:00Z")), EVAL_TIME),
    ("test client removed from registry", events, lines, pub_pem,
     cfg_with(lambda d: d["proxy_client_mapping"]["client_registry"].pop("10.250.25.3")), EVAL_TIME),
    ("demo listener not configured", events, lines, pub_pem, cfg_with(lambda d: d["proxy_client_mapping"].__setitem__("demo_listeners", [])), EVAL_TIME),
    ("S4 Cowrie src_port altered", [dict(e, src_port=59091) if e["session"] == "3eede5e19e25" and "src_port" in e else e for e in events],
     lines, pub_pem, cfg, EVAL_TIME),
    ("S4 Cowrie connect shifted +5 s (outside 2 s skew)", [dict(e, timestamp=(ts(e["timestamp"]) + timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
                                                         if e["session"] == "3eede5e19e25" and e["eventid"] == "cowrie.session.connect" else e for e in events],
     lines, pub_pem, cfg, EVAL_TIME),
    ("S4 Cowrie close shifted +10 s", shift("3eede5e19e25", 10), lines, pub_pem, cfg, EVAL_TIME),
    ("S4 close events attached to S5 session ID", [dict(e, session="4542a85f37ec") if e["session"] == "3eede5e19e25" and e["eventid"] == "cowrie.session.closed"
                                                  else e for e in events], lines, pub_pem, cfg, EVAL_TIME),
    ("S4 duplicated session.connect", events + [e for e in events if e["session"] == "3eede5e19e25" and e["eventid"] == "cowrie.session.connect"],
     lines, pub_pem, cfg, EVAL_TIME),
    ("S4 session ID registered as diagnostic", events, lines, pub_pem,
     cfg_with(lambda d: d.__setitem__("excluded_diagnostic_sessions", list(DIAG) + ["3eede5e19e25"])), EVAL_TIME),
]
vrows = []
for name, evs, ls, pem, c, t in variants:
    out = correlate(evs, ls, pem, c, evaluation_time=t)
    st = states(out)
    vrows.append({"variant": name, "verification": out["verification"]["reason"], **{k: st.get(k, "-") for k in ("S1", "S2", "S3", "S4", "S5")},
                  "attributed_sessions": sum(v == "attributable_via_proxy_mapping" for v in st.values())})
write_csv(HERE / "correlation_tests.csv", vrows)

# assessment-side failure cases on the real S4 record
s4 = next(r for r in evidence if r["session_ref"] == "3eede5e19e25")
arows = []
for name, mapping in [("verified mapping", ca), ("no mapping supplied", None), ("mapping digest from another config", dict(ca, config_digest="0" * 64)),
                      ("mapping from tampered log", correlate(events, variants[1][2], pub_pem, cfg, evaluation_time=EVAL_TIME)),
                      ("mapping evaluated after expiry", correlate(events, lines, pub_pem, cfg, evaluation_time=EVAL_TIME + timedelta(hours=25)))]:
    a = assessor.assess(s4, mapping)
    arows.append({"case": name, "attribution_state": a["session_attribution"]["state"], "tier": a["tier"],
                  "failed_gates": ",".join(k for k, v in a["gates"].items() if not v),
                  "proposal_subject": (a["proposed_action"] or {}).get("subject")})
write_csv(HERE / "assessment_integration_tests.csv", arows)

summary = {"run_timestamp": RUN_TS, "evaluation_time": EVAL_TIME.isoformat(), "assessment_version": ASSESSMENT_VERSION,
           "client_attribution_version": CA_VERSION, "attribution_config_digest": att.digest, "policy_digest": pol.digest,
           "evidence_config_digest": ecfg.digest(), "public_key_sha256": pub_sha, "record_verification": ver["reason"],
           "record_count": ver.get("count"), "record_chain_head": ver.get("chain_head"), "audit_chain": audit_ok,
           "input_sha256": {"cowrie_events_after_baseline.jsonl": sha(EV / "cowrie_events_after_baseline.jsonl"),
                            "relay_mapping.jsonl": sha(EV / "relay_mapping.jsonl")},
           "tiers": {r["session"]: r["tier"] for r in rows}}
(EV / "run_summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=1))
for r in rows:
    print(r["label"], "|", r["correlation_state"], "|", r["attribution_state"], "|", r["tier"], "|", r["failed_gates"], "|", r["proposal_subject"])
for r in vrows:
    print(r)
for r in arows:
    print(r)
