"""Task 26B read-only audit checks. All tampering, forging and gate probes act on in-memory copies only.

Reads: Task 26A captured evidence and outputs, configs, the Task 22 calibration file, prior SHA256SUMS manifests.
Never reads Dataset V2, Task 24 evidence derived from it, or sealed test data. Writes only into this directory.
"""
import copy
import hashlib
import json
import sys
from datetime import timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))

from behavioural_evidence import EvidenceConfig, EvidenceEngine  # noqa: E402
from behavioural_evidence.calibration import load_calibration  # noqa: E402
from behavioural_evidence.engine import read_jsonl  # noqa: E402
from client_attribution import correlate, load_attribution_v2  # noqa: E402
from client_attribution.records import load_public_key, ts, verify_records  # noqa: E402
from threat_assessment import ThreatAssessor, load_attribution_config, load_policy  # noqa: E402
from threat_assessment.assessment import LEVELS, LOGIN_STATUSES  # noqa: E402
from threat_assessment.audit import read_log, verify_chain  # noqa: E402
from threat_assessment.severity import ORDER as SEV_ORDER  # noqa: E402

A26 = REPO / "reports" / "client_attribution_implementation_20261111"
EV = A26 / "evidence"
T22 = REPO / "reports" / "behavioural_evidence_framework_implementation_20261111"
T24 = REPO / "reports" / "threat_assessment_implementation_20261111"
S4, S5 = "3eede5e19e25", "4542a85f37ec"
DEMO = ("9441bcce555c", "acc2bad4a442", "d588636ce120", S4, S5)
DIAG = ("99732d516898", "b806554e19b9")
OUT = {}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def manifest(path, select=lambda n: True):
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        h, n = line.split(maxsplit=1)
        n = n.lstrip("*")
        if not select(n):
            continue
        p = (Path(path).parent / n).resolve()
        rows.append({"file": n, "match": p.exists() and sha(p) == h})
    return rows


# ------------------------------------------------------------------------------------------------ inputs (26A, hash-checked)
m26 = manifest(A26 / "SHA256SUMS")
OUT["26A_manifest"] = {"checked": len(m26), "mismatched": [r["file"] for r in m26 if not r["match"]]}
events = read_jsonl(EV / "cowrie_events_after_baseline.jsonl")
lines = (EV / "relay_mapping.jsonl").read_text(encoding="utf-8").splitlines()
stored_ca = json.loads((EV / "correlation_result.json").read_text(encoding="utf-8"))
stored_ev = {r["session_ref"]: r for r in map(json.loads, open(EV / "demo_evidence.jsonl", encoding="utf-8"))}
stored_as = {r["session_ref"]: r for r in map(json.loads, open(EV / "demo_assessments.jsonl", encoding="utf-8"))}
ATT = REPO / "configs" / "threat_attribution_v2.json"
att, cfg, pol = load_attribution_config(ATT), load_attribution_v2(ATT), load_policy(REPO / "configs" / "defence_policy_v2_1.json")
pub_pem = (REPO / cfg.doc["proxy_client_mapping"]["public_key_path"]).read_bytes()
EVAL = ts("2026-11-11T17:30:00Z")

# ------------------------------------------------------------------------------------------------ Area 1: reproduction
ca = correlate(events, lines, pub_pem, cfg, evaluation_time=EVAL)
OUT["correlation_reproduced_identical"] = ca == stored_ca

# Independent re-evaluation of every policy condition from the stored S4 evidence record (not via ThreatAssessor)
r4, a4, c = stored_ev[S4], stored_as[S4], pol.conditions
by_id = {i["id"]: i for i in r4["indicators"]}
sev = {f["interpretation"]: f["severity"] for f in a4["findings"]}       # severity re-derived below via severity module
from threat_assessment.severity import finding_severity  # noqa: E402
indep = []
for it in r4["interpretations"]:
    s, basis = finding_severity(it, by_id)
    indep.append({"interpretation": it["name"], "severity": s, "basis": basis, "level": it["evidence_level"],
                  "support": it["supporting_action_indicators"], "matches_stored": sev.get(it["name"]) == s})
qual = [f for f in indep if SEV_ORDER.index(f["severity"]) >= SEV_ORDER.index(c["min_finding_severity"])
        and LEVELS.index(f["level"]) >= LEVELS.index(c["min_interpretation_evidence_level"])]
distinct = sorted({a for f in qual for a in f["support"]})
m4 = ca["sessions"][S4]
raw4 = [e for e in events if e["session"] == S4]
login_success_events = [e for e in raw4 if e["eventid"] == "cowrie.login.success"]
conds = [
    ("min_finding_severity >= S2", any(SEV_ORDER.index(f["severity"]) >= 2 for f in indep), f"severities {[f['severity'] for f in indep]}"),
    ("min_interpretation_evidence_level >= E2 on an S2+ finding", bool(qual), f"qualifying {[(f['interpretation'], f['severity'], f['level']) for f in qual]}"),
    ("min_distinct_action_indicators >= 2", len(distinct) >= c["min_distinct_action_indicators"], f"{distinct}"),
    ("require_successful_login (implemented basis)", r4["authentication_status"] in LOGIN_STATUSES or r4["n_input_lines"] > 0,
     f"authentication_status={r4['authentication_status']}; n_input_lines={r4['n_input_lines']}; basis=command input"),
    ("require_successful_login (Task 23 design wording: cowrie.login.success)", bool(login_success_events),
     f"raw telemetry: {len(login_success_events)} cowrie.login.success for {S4} at {[e['timestamp'] for e in login_success_events]}; not carried in the evidence record"),
    ("require_attributable_source", m4["state"] == "attributable_via_proxy_mapping" and m4["client_ip"] in cfg.registry,
     f"{m4['state']} -> {m4['client_ip']} ({cfg.registry.get(m4['client_ip'], {}).get('role')}), close {m4.get('close_check')}"),
    ("exclude_protected_and_shared_sources (+ enforcement_excluded)",
     not any(__import__('ipaddress').ip_address(m4["client_ip"]) in n for n in att.protected + att.shared_sources + att.enforcement_excluded),
     "10.250.25.3 not in protected/shared/excluded lists"),
    ("require_verified_configuration_digests", r4["config_digest"] == a4["versions"]["evidence_config_digest_expected"]
     and pol.attribution_digest == att.digest == ca["config_digest"] and all(a4["versions"]["configuration_checks"].values()),
     f"evidence {r4['config_digest']} (recorded expected {a4['versions']['evidence_config_digest_expected']}; reference-sequence component not recomputable without Dataset V2); attribution {att.digest[:16]} pinned by policy and in correlation"),
    ("require_no_processing_errors", not a4["processing_errors"], "none"),
    ("behavioural_status not indeterminate/insufficient", r4["behavioural_status"] == "interpreted", r4["behavioural_status"]),
]
OUT["S4_independent_conditions"] = [{"condition": n, "satisfied": bool(v), "detail": d} for n, v, d in conds]
OUT["S4_findings_independent"] = indep
OUT["S4_stored"] = {"tier": a4["tier"], "gates": a4["gates"], "proposal": a4["proposed_action"], "login_basis": a4["successful_login_basis"]}

# Engine re-run without Dataset V2 reference sequences (calibration from Task 22 config only)
att_strings = att.relay_strings
cal = load_calibration(T22 / "config" / "sensor_calibration_lab_train.json")
ecfg_noref = EvidenceConfig(relay_sources=frozenset(att_strings), internal_networks=att.internal_cidr_strings, calibration=cal)
re_ev = {r["session_ref"]: r for r in EvidenceEngine(ecfg_noref).evaluate(events)["sessions"]}
strip = lambda r: {k: v for k, v in r.items() if k not in ("config_digest",)}
OUT["evidence_rerun_without_reference_sequences"] = {
    sid: {"identical_except_config_digest": strip(re_ev[sid]) == strip(stored_ev[sid]),
          "stored_digest": stored_ev[sid]["config_digest"], "rerun_digest": re_ev[sid]["config_digest"]} for sid in DEMO}
assr = ThreatAssessor(att, pol, ecfg_noref)
re4 = assr.assess(re_ev[S4], ca)
OUT["S4_reassessed_self_consistent_config"] = {"tier": re4["tier"], "failed": [k for k, v in re4["gates"].items() if not v],
                                               "subject": (re4["proposed_action"] or {}).get("subject"),
                                               "findings_equal_stored": [{k: v for k, v in f.items()} for f in re4["findings"]] == a4["findings"]}
st4 = assr.assess(stored_ev[S4], ca)       # stored record (digest 95183d7f…) against a config without reference sequences
OUT["S4_stored_record_vs_noref_config"] = {"tier": st4["tier"], "failed": [k for k, v in st4["gates"].items() if not v]}

# ------------------------------------------------------------------------------------------------ Area 1: authentication probes
probes = []
def probe(name, rec, mapping=ca):
    o = assr.assess(rec, mapping)
    probes.append({"probe": name, "authentication_status": rec.get("authentication_status"), "n_input_lines": rec.get("n_input_lines"),
                   "gate4": o["gates"]["4_successful_login"], "login_basis": o["successful_login_basis"], "tier": o["tier"]})
probe("S4 as captured", re_ev[S4])
probe("S4 with n_input_lines=0 (status indeterminate)", dict(re_ev[S4], n_input_lines=0))
probe("S4 with status success_without_repeated_failures, n_input_lines=0", dict(re_ev[S4], n_input_lines=0, authentication_status="success_without_repeated_failures"))
probe("S4 with status no_authentication_events, input kept", dict(re_ev[S4], authentication_status="no_authentication_events"))
probe("S2 banner (indeterminate? no auth events)", re_ev["acc2bad4a442"])
r_before = copy.deepcopy(re_ev[S4])
o_with, o_without = assr.assess(re_ev[S4], ca), assr.assess(re_ev[S4])
OUT["auth_probes"] = probes
OUT["attribution_does_not_change_authentication"] = {
    "record_unchanged_after_assess": re_ev[S4] == r_before,
    "authentication_status_with_mapping": o_with["authentication_status"], "without_mapping": o_without["authentication_status"],
    "login_basis_with": o_with["successful_login_basis"], "login_basis_without": o_without["successful_login_basis"]}
# evidence engine is independent of attribution: relay sessions are indeterminate whatever the client
OUT["engine_auth_status_for_relay_sessions"] = {sid: re_ev[sid]["authentication_status"] for sid in DEMO}

# ------------------------------------------------------------------------------------------------ Area 1/4: trust boundary of the correlation result
forged_rows = []
def forged(name, sid, client):
    f = copy.deepcopy(ca)
    f["sessions"][sid] = {**f["sessions"][sid], "state": "attributable_via_proxy_mapping", "client_ip": client, "client_role": "forged"}
    o = assr.assess(re_ev[sid], f)
    forged_rows.append({"case": name, "session": sid, "claimed_client": client, "attribution": o["session_attribution"]["state"],
                        "tier": o["tier"], "subject": (o["proposed_action"] or {}).get("subject")})
forged("unsigned forged result maps S5 (control) to test client", S5, "10.250.25.3")
forged("unsigned forged result maps S4 to unregistered 203.0.113.9", S4, "203.0.113.9")
forged("unsigned forged result maps S4 to control client", S4, "10.250.25.4")
forged("unsigned forged result maps S4 to demo relay", S4, "10.250.25.2")
OUT["forged_correlation_result"] = forged_rows

# ------------------------------------------------------------------------------------------------ Area 3: record integrity (in-memory)
pub, pub_sha = load_public_key(pub_pem)
def V(ls, **kw):
    return verify_records(ls, pub, pub_sha, cfg.key_not_before, cfg.key_not_after, **kw)
def edit(i, fn):
    ls = list(lines); r = json.loads(ls[i]); fn(r); ls[i] = json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False); return ls
def states(ls, t=EVAL):
    return {s: v["state"] for s, v in correlate(events, ls, pub_pem, cfg, evaluation_time=t)["sessions"].items()}
integ = []
def case(name, ls, t=EVAL):
    v = V(ls) if ls is not None else {"ok": False, "reason": "n/a"}
    st = states(ls, t)
    integ.append({"case": name, "verifies": v["ok"], "reason": v["reason"], "S4": st[S4], "S5": st[S5],
                  "attributed": sum(x == "attributable_via_proxy_mapping" for x in st.values())})
case("unmodified log", lines)
case("altered field (S4 client_port)", edit(7, lambda r: r.__setitem__("client_port", 1)))
case("altered field with record_hash recomputed (no key)", edit(7, lambda r: (r.__setitem__("client_ip", "10.250.25.4"),
     r.__setitem__("record_hash", hashlib.sha256(json.dumps({k: v for k, v in r.items() if k not in ("record_hash", "signature")},
     sort_keys=True, separators=(",", ":")).encode()).hexdigest()))))
case("reordered (seq 8 <-> 9)", lines[:7] + [lines[8], lines[7]] + lines[9:])
case("duplicated record (seq 8 replayed)", lines[:9] + [lines[7]] + lines[9:])
case("duplicated record appended at end", lines + [lines[7]])
case("record age > 24 h (evaluated +25 h)", lines, EVAL + timedelta(hours=25))
case("record outside key validity (not_after moved before records)", lines)  # placeholder replaced below
integ.pop()
c2 = load_attribution_v2(ATT); object.__setattr__(c2, "key_not_after", ts("2026-11-11T17:00:00Z"))
v_kv = verify_records(lines, pub, pub_sha, c2.key_not_before, c2.key_not_after)
integ.append({"case": "record written after key validity end", "verifies": v_kv["ok"], "reason": v_kv["reason"], "S4": "-", "S5": "-", "attributed": 0})
for n in (1, 2, 4):
    case(f"TAIL DELETION: last {n} record(s) removed", lines[:-n])
case("TAIL DELETION: everything after S4 close removed", lines[:9])
case("TAIL DELETION: everything after relay_start removed", lines[:1])
OUT["integrity"] = integ

# ------------------------------------------------------------------------------------------------ Area 4: regression
be = manifest(T22 / "SHA256SUMS", lambda n: "behavioural_evidence/" in n)
ta = manifest(T24 / "SHA256SUMS", lambda n: "threat_assessment/" in n)
OUT["regression"] = {
    "behavioural_evidence_package_vs_task22": {"checked": len(be), "mismatched": [r["file"] for r in be if not r["match"]]},
    "threat_assessment_vs_task24": {r["file"].split("threat_assessment/")[1]: r["match"] for r in ta},
    "v1_configs": {"threat_attribution_v1.json": sha(REPO / "configs/threat_attribution_v1.json"),
                   "defence_policy_v2.json": sha(REPO / "configs/defence_policy_v2.json"),
                   "defence_policy.json": sha(REPO / "configs/defence_policy.json")},
    "regression_v1_results_26A": json.loads((A26 / "regression_v1_results.json").read_text(encoding="utf-8")),
    "diagnostic_in_config": sorted(cfg.excluded_sessions), "diagnostic_in_demo_input": sorted(set(DIAG) & {e["session"] for e in events}),
    "audit_chain_26A": verify_chain(read_log(EV / "demo_audit.jsonl"), json.loads((EV / "demo_audit_checkpoint.json").read_text())),
    "audit_execution_status": sorted({json.dumps(e.get("execution_status", e.get("assessment", {}).get("proposed_action"))) for e in read_log(EV / "demo_audit.jsonl")}),
    "control_client_states": {sid: stored_as[sid]["session_attribution"]["state"] for sid in ("d588636ce120", S5)},
    "control_client_tiers": {sid: stored_as[sid]["tier"] for sid in ("d588636ce120", S5)},
}
(HERE / "audit_results.json").write_text(json.dumps(OUT, indent=2, default=str) + "\n", encoding="utf-8")
print(json.dumps(OUT, indent=1, default=str))
