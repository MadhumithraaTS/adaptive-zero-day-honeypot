"""Academic demonstration presentation (Task 29F) - READ-ONLY.

Displays the ten-stage demonstration for session 42ee73a7cbbd using ONLY saved evidence files. Before displaying anything
it re-verifies every SHA256SUMS manifest, session-ID consistency, the signed-attribution signature (saved DEMO public key),
the proposal/approval/feedback hashes and their audit references, the response audit chain, the global exclusions and the
single-session demonstration exception. It writes nothing, starts no process, opens no network connection and loads no
production key or trust configuration.

  python reports/academic_demo_readiness_20261112/demo_presentation.py            # verify, then display
  python reports/academic_demo_readiness_20261112/demo_presentation.py --verify   # verification only

Labels:  [OBSERVED] actual Cowrie behaviour   [MODEL] ML-branch outputs   [DECISION] threat-assessment decisions
         [SIMULATED] dry-run response outcomes   [VERIFIED] integrity checks made now
"""
import argparse
import csv
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.dont_write_bytecode = True                # read-only: no __pycache__ in the evidence folder
sys.path.insert(0, str(REPO))

try:
    from cryptography.hazmat.primitives import serialization  # noqa: E402

    from client_attribution.records import canonical  # noqa: E402
    from dynamic_response import verify_response_log  # noqa: E402
    from dynamic_response.approval import approval_hash  # noqa: E402
    from dynamic_response.common import sha256_hex  # noqa: E402
    from session_exclusions import load_exclusions  # noqa: E402
    from threat_assessment import verify_chain  # noqa: E402
    from threat_assessment.audit import read_log  # noqa: E402
except ImportError as _exc:
    print(f"ENVIRONMENT ERROR: {_exc} (interpreter: {sys.executable})")
    print(r"Run with the project interpreter:  .\.venv\Scripts\python.exe reports\academic_demo_readiness_20261112\demo_presentation.py")
    print("Fallback: show demo_transcript_29f.txt (DEMO_GUIDE.md, section 5).")
    sys.exit(2)

SID = "42ee73a7cbbd"
LIVE = HERE / "live" / "20261112T070531Z-670781"              # Task 29C: fresh session, ML branch
ASSESS_29D = HERE / "assessment" / "20261112T072217Z-034f7b"  # Task 29D: first signed attribution + assessment (expired result)
RESP = HERE / "assessment" / "20261112T073151Z-ba1005"        # Task 29E: refreshed assessment + dry-run response + feedback
FW = HERE / "final_validation_29f" / "firewall_check.txt"
PRIOR_EXCLUDED = ("99732d516898", "b806554e19b9", "9441bcce555c", "acc2bad4a442", "d588636ce120", "3eede5e19e25", "4542a85f37ec")
CHECKS = []


def ok(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    return bool(cond)


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def jl(p):
    return [json.loads(l) for l in Path(p).read_text(encoding="utf-8").splitlines() if l.strip()]


def js(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def manifest(path, base):
    rows = [l.split(" *", 1) for l in Path(path).read_text(encoding="utf-8").splitlines() if " *" in l]
    bad = [f for h, f in rows if not (base / f).is_file() or sha(base / f) != h]
    return len(rows), bad


# ============================================================================================ load + verify
def load_and_verify():
    E = {}
    # ---- manifests
    n, bad = manifest(HERE / "SHA256SUMS", HERE)
    ok("top-level SHA256SUMS", not bad, f"{n - len(bad)}/{n} files match" + (f"; mismatched {bad}" if bad else ""))
    for m in sorted(HERE.rglob("SHA256SUMS")):
        if m.parent == HERE:
            continue
        n, bad = manifest(m, m.parent)
        ok(f"section SHA256SUMS {m.parent.relative_to(HERE).as_posix()}", not bad, f"{n - len(bad)}/{n} files match" + (f"; mismatched {bad}" if bad else ""))

    # ---- ML branch evidence (29C)
    E["live"] = js(LIVE / "run_summary.json")
    E["slice"] = jl(LIVE / "artifacts/raw/cowrie_slice.json")
    E["details"] = js(LIVE / "artifacts/ml/pipeline/parsed/session_details.json")
    with open(LIVE / "artifacts/ml/pipeline/parsed/behavior_features.csv", encoding="utf-8") as f:
        E["feat"] = list(csv.DictReader(f))
    with open(LIVE / "artifacts/ml/pipeline/processed/dec_results.csv", encoding="utf-8") as f:
        E["dec"] = list(csv.DictReader(f))
    E["dec_cfg"] = js(REPO / "ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/artifacts/config.json")
    E["sig"] = js(LIVE / "artifacts/ml/behaviour_signatures/behaviour_signatures.json")
    E["nov"] = js(LIVE / "artifacts/ml/novelty/novelty_assessment_results.json")
    E["nov_sum"] = js(LIVE / "artifacts/ml/novelty/novelty_assessment_summary.json")

    # ---- rules branch evidence (29E)
    E["resp_run"] = js(RESP / "run_summary.json")
    a = RESP / "artifacts"
    E["events_in"] = next(a.glob("input_cowrie_events_DEMO-*.jsonl"))
    E["evidence"] = next(r for r in jl(a / "assessment/evidence.jsonl") if r["session_ref"] == SID)
    E["assess"] = next(r for r in jl(a / "assessment/assessments.jsonl") if r["session_ref"] == SID)
    E["assess_audit"] = read_log(a / "assessment/audit.jsonl")
    E["signed"] = js(next(a.glob("input_signed_result_DEMO-*.json")))
    E["result_pub"] = next(a.glob("input_attribution_result_DEMO-*.pub.pem")).read_bytes()
    E["proposal"] = js(a / "response/proposal.json")
    E["approval"] = js(a / "response/approval.json")
    E["neg"] = js(a / "response/approval_negative_tests.json")
    E["raudit"] = jl(a / "response/response_audit.jsonl")
    E["fb"] = js(a / "response/feedback_record.json")
    E["fb_sha"] = sha(a / "response/feedback_record.json")

    # ---- session consistency (both branches, same session, same bytes)
    slice_sha = sha(LIVE / "artifacts/raw/cowrie_slice.json")
    ids = {"29C run": E["live"]["session_id"], "Cowrie slice": sorted({e["session"] for e in E["slice"]}),
           "reconstruction": sorted(E["details"]), "features": [r["session_id"] for r in E["feat"]], "DEC": [r["session_id"] for r in E["dec"]],
           "novelty": [r["session_id"] for r in E["nov"]["results"]], "29E run": E["resp_run"]["session_id"],
           "evidence": E["evidence"]["session_ref"], "assessment": E["assess"]["session_ref"],
           "signed result": [s["cowrie_session_id"] for s in E["signed"]["sessions"]], "proposal": E["proposal"]["session_ref"],
           "feedback": E["fb"]["session_id"]}
    flat = {k: (v if isinstance(v, list) else [v]) for k, v in ids.items()}
    ok("session ID identical in all 12 places (ML and rules branches)", all(v == [SID] for v in flat.values()),
       "; ".join(f"{k}={v}" for k, v in flat.items() if v != [SID]) or SID)
    ok("both branches consumed the same captured bytes", sha(E["events_in"]) == slice_sha,
       f"slice {slice_sha[:16]} = rules-branch input {sha(E['events_in'])[:16]}")
    ok("29D run used the same captured bytes", sha(next((ASSESS_29D / "artifacts").glob("input_cowrie_events_DEMO-*.jsonl"))) == slice_sha)

    # ---- signed attribution: offline signature verification with the saved DEMO public key
    s = E["signed"]
    body = {k: v for k, v in s.items() if k not in ("result_hash", "signature")}
    pub = serialization.load_pem_public_key(E["result_pub"])
    pin = hashlib.sha256(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
    rh = hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()
    try:
        pub.verify(bytes.fromhex(s["signature"]), s["result_hash"].encode("ascii"))
        sig_ok = True
    except Exception:                                                        # noqa: BLE001
        sig_ok = False
    ok("signed attribution: result_hash recomputes and Ed25519 signature verifies with the saved DEMO public key",
       rh == s["result_hash"] and sig_ok and pin == s["signer"]["public_key_sha256"], f"{s['result_id']} / {s['result_hash'][:16]}")
    accepted = E["assess"]["versions"]["attribution_results"]["accepted"]
    ok("assessment accepted exactly this signed result", [x["result_id"] for x in accepted] == [s["result_id"]]
       and accepted[0]["result_hash"] == s["result_hash"])
    E["sig_ok"] = sig_ok

    # ---- assessment audit, proposal, approval, response audit, feedback
    ok("assessment audit chain verifies", verify_chain(E["assess_audit"])["ok"])
    p = E["proposal"]
    ok("proposal_hash recomputes", sha256_hex({k: v for k, v in p.items() if k != "proposal_hash"}) == p["proposal_hash"], p["proposal_hash"][:16])
    ok("proposal -> signed result ID and hash", p["attribution"]["result_id"] == s["result_id"] and p["attribution"]["result_hash"] in (None, s["result_hash"]))
    ae = next(e for e in E["assess_audit"] if e["record_id"] == p["assessment_audit"]["record_id"])
    ok("proposal -> assessment audit record hash", ae["record_hash"] == p["assessment_audit"]["record_hash"] and ae["session_ref"] == SID)
    ap = E["approval"]
    ok("approval_hash recomputes and names this proposal hash", approval_hash(ap) == ap["approval_hash"] and ap["proposal_hash"] == p["proposal_hash"]
       and ap["proposal_id"] == p["proposal_id"])
    ra = E["raudit"]
    v = verify_response_log(ra, {"entries": len(ra), "last_hash": ra[-1]["record_hash"]})
    ok("response/feedback audit chain and transitions verify", v["ok"], v["reason"])
    ev = {e["event"]: e for e in ra if e["event"] != "operation_rejected"}
    ok("audit approval_recorded references this approval", ev["approval_recorded"]["refs"]["approval_hash"] == ap["approval_hash"]
       and ev["approval_recorded"]["refs"]["approval_id"] == ap["approval_id"])
    ok("audit proposal_created references this proposal hash and signed result", ev["proposal_created"]["refs"]["proposal_hash"] == p["proposal_hash"]
       and ev["proposal_created"]["refs"]["attribution_result_id"] == s["result_id"])
    fb = E["fb"]
    core = {k: v for k, v in fb.items() if k not in ("feedback_core_sha256", "annotation", "response_audit_checkpoint", "metrics", "review_queue")}
    core_hash = hashlib.sha256(canonical(core).encode("utf-8")).hexdigest()
    ann = ev["annotation_recorded"]
    ok("feedback core hash recomputes and is cited in the audit annotation", core_hash == fb["feedback_core_sha256"]
       and core_hash in ann["details"]["note"] and ann["record_hash"] == fb["annotation"]["record_hash"])
    ok("feedback references match the audit (approval, simulated, verification, rollback)",
       fb["approval"]["audit_record_hash"] == ev["approval_recorded"]["record_hash"]
       and fb["simulated_response"]["audit_record_hash"] == ev["simulated"]["record_hash"]
       and fb["operator_verification"]["audit_record_hash"] == ev["verification_passed"]["record_hash"]
       and fb["simulated_rollback"]["audit_record_hash"] == ev["rollback_verified"]["record_hash"]
       and fb["proposal"]["proposal_hash"] == p["proposal_hash"] and fb["threat_assessment"]["signed_result_id"] == s["result_id"])
    ok("every response audit entry is dry_run mode", all(e["mode"] == "dry_run" for e in ra))

    # ---- exclusions + demonstration exception
    ex = load_exclusions()
    ok("all eight exclusions active (v2.0.0)", ex.version == "2.0.0" and ex.ids == frozenset(PRIOR_EXCLUDED + (SID,)), f"{len(ex.ids)} IDs, digest {ex.digest[:16]}")
    spec = importlib.util.spec_from_file_location("demo_orchestrator", HERE / "demo_orchestrator.py")
    orch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(orch)
    refused = 0
    for other in PRIOR_EXCLUDED:
        for req in (other, SID, None):
            try:
                orch.demo_session_exception([other], req)
            except SystemExit:
                refused += 1
    for req in (None, "aaaaaaaaaaaa", PRIOR_EXCLUDED[0]):
        try:
            orch.demo_session_exception([SID], req)
        except SystemExit:
            refused += 1
    ok("demonstration exception admits only 42ee73a7cbbd, only when named", refused == 24 and orch.DEMO_EXCEPTION_SID == SID
       and orch.demo_session_exception([SID], SID)["session_id"] == SID, f"{refused}/24 misuse attempts refused")

    # ---- safety evidence
    runs = [LIVE, ASSESS_29D, RESP]
    cmds = [c for r in runs for c in js(r / "run_summary.json")["subprocess_commands"]]
    risky = [c for c in cmds if any(w in " ".join(c).lower() for w in ("iptables", "nft", "firewall", "cowrie-demo", "relay", "netsh"))]
    ok("no firewall/relay/client command in any run (subprocesses: pipeline scripts, one read-only slice exec, assessment container)", not risky,
       f"{len(cmds)} subprocesses")
    opened = [f.replace("\\", "/").lower() for r in runs for f in js(r / "opened_files_host.json")]
    forbidden = [f for f in opened if any(x in f for x in ("/secrets/", "ml_pipeline/work", "dataset_v2", "sealed", "/data/raw/", "/cowrie.json"))
                 or ("/configs/" in f and not f.endswith("configs/session_exclusions_v2.json"))]
    ok("no production config, private key, Cowrie log, Dataset V2 or sealed path opened by any run", not forbidden, str(forbidden[:3]))
    ok("enforcement interface never called", fb["enforcement_calls"] == [] and E["resp_run"]["rules_branch"]["response"]["enforcement_calls"] == [])
    fw = FW.read_text(encoding="utf-8")
    ok("host firewall: no rule mentions 10.250.25.3/.4; no witness container (29F read-only check)",
       "rules mentioning demo client IPs (any table):\n(end)" in fw and "10.250.25.3/.4: 0" in fw and fw.rstrip().endswith("0"))
    base = js(REPO / "data/parsed/session_details.json")
    ok("novelty reference baseline contains no excluded session", not (set(base) & ex.ids) and len(base) == 5, f"{len(base)} baseline sessions")
    ok("fresh session is not an evaluation input (novelty mode independent, 0 overlap; exclusion registered after the demo run)",
       E["nov_sum"]["evaluation_mode"] == "independent" and E["nov_sum"]["overlapping_session_count"] == 0)
    return E


# ============================================================================================ display
def show(E):
    w = 78
    line = lambda c="-": print(c * w)                                         # noqa: E731
    head = lambda t: (print(), line("="), print(t), line("="))                 # noqa: E731
    kv = lambda k, v, tag="": print(f"  {tag:<12}{k:<34}{v}")                 # noqa: E731
    sl = [e for e in E["slice"] if e["session"] == SID]
    by = lambda eid: [e for e in sl if e["eventid"] == eid]                   # noqa: E731
    d = E["details"][SID]
    head(f"ADAPTIVE ZERO-DAY HONEYPOT - ACADEMIC DEMONSTRATION      session {SID}")
    print("  Evidence: live/20261112T070531Z-670781 (ML branch)  |  assessment/20261112T073151Z-ba1005 (rules branch)")
    print("  Two independent branches over the SAME captured session; novelty/DEC do NOT feed threat scoring.")

    head("SECTION A - COWRIE INTERACTION                              [OBSERVED]")
    c = by("cowrie.session.connect")[0]
    kv("Session ID", SID, "[OBSERVED]")
    kv("Connection (Cowrie view)", f"{c['src_ip']}:{c['src_port']} -> {c['dst_ip']}:{c['dst_port']}  (relay address)", "[OBSERVED]")
    kv("Client version", by("cowrie.client.version")[0].get("version", "-"), "[OBSERVED]")
    lg = by("cowrie.login.success")
    kv("Login result", f"SUCCESS user '{lg[0]['username']}' at {lg[0]['timestamp']}  (failed logins: {len(by('cowrie.login.failed'))})", "[OBSERVED]")
    for i, e in enumerate(by("cowrie.command.input"), 1):
        kv(f"Command {i}", e["input"], "[OBSERVED]")
    for e in by("cowrie.command.failed"):
        kv("Cowrie command.failed event", e["input"].strip(), "[OBSERVED]")
    kv("Session duration", f"{by('cowrie.session.closed')[0]['duration']} s (Cowrie)  /  {d['session_duration']} s (reconstructed)", "[OBSERVED]")
    kv("Events captured after baseline", f"{len(sl)} (Cowrie log baseline 21,888 lines; rotated)", "[OBSERVED]")

    head("SECTION B - BEHAVIOURAL ANALYSIS (ML branch)                [MODEL]")
    f = E["feat"][0]
    kv("Reconstructed session", f"{len(d['commands'])} commands, auth_success={d['auth_success']}", "[MODEL]")
    kv("Feature table", f"{len(f)} columns (behavior_features.csv)", "[MODEL]")
    kv("DEC model input", f"{E['dec_cfg']['input_dim']} features, {E['dec_cfg']['n_clusters']} clusters (saved model, no refit)", "[MODEL]")
    r = E["dec"][0]
    kv("DEC assignment", f"cluster {r['dec_cluster']}  confidence {float(r['dec_confidence']):.3f}", "[MODEL]")
    kv("Cluster probabilities", " / ".join(f"{float(r[f'cluster_{k}_prob']):.3f}" for k in range(3)), "[MODEL]")
    sg = E["sig"]["signatures"][0] if isinstance(E["sig"], dict) else E["sig"][0]
    kv("Baseline signature", f"{sg['signature_id']}  (cluster {sg['cluster_id']}, {sg['session_count']} baseline sessions, "
       f"confidence {sg['confidence']})", "[MODEL]")
    n = E["nov"]["results"][0]
    kv("Novelty classification", f"{n['assessment_category']}  score {float(n['score']):.3f}  (known threshold "
       f"{E['nov_sum']['thresholds']['known_threshold']})", "[MODEL]")
    kv("Closest signature", f"{n['closest_signature_id']}  ({n.get('best_signature_label')})", "[MODEL]")

    head("SECTION C - THREAT SCORING & RULES (rules branch)           [DECISION]")
    ev, a, s = E["evidence"], E["assess"], E["signed"]
    kv("Behavioural evidence level", f"{ev['evidence_level']}  (catalogue {ev['catalogue_version']})", "[DECISION]")
    for i in ev["indicators"]:
        lines = ", ".join(m.get("line") or "-" for m in i["matches"])
        kv(f"Indicator {i['id']} ({i['kind']})", f"{i['evidence_class']}: {lines}", "[OBSERVED]")
    for fd in a["findings"]:
        kv("Finding", f"{fd['interpretation']}: {fd['severity']} / {fd['evidence_level']}, success observed: {fd['success_observed']}", "[DECISION]")
    au = a["authentication_evidence"]
    kv("Successful-login evidence", f"{au['state']} at {au['login_success_utc']} (via signed result)", "[DECISION]")
    sa, m = a["session_attribution"], a["session_attribution"]["mapping"]
    kv("Signed attribution", f"{s['result_id']}  signature {'VERIFIED' if E['sig_ok'] else 'FAILED'} (DEMO key {s['signer']['key_id']})", "[VERIFIED]")
    kv("Verified attribution", f"{sa['state']} -> client {m['client']['ip']}:{m['client']['port']} ({m['client']['role']})", "[DECISION]")
    kv("Relay connection", m["connection_id"], "[OBSERVED]")
    for g, val in a["gates"].items():
        num, name = g.split("_", 1)
        kv(f"Gate {num}", f"{'PASS' if val else 'FAIL'}  {name.replace('_', ' ')}", "[DECISION]")
    kv("THREAT TIER", f"{a['tier'].upper()} - {a['tier_reason']}", "[DECISION]")
    pa = a["proposed_action"]
    kv("Proposal (recorded only)", f"{pa['type']} {pa['subject']}, mode {pa['mode']}, approval {pa['manual_approval']}, {pa['execution']}", "[DECISION]")

    head("SECTION D - DYNAMIC RESPONSE                               [SIMULATED]")
    p, ap, ra = E["proposal"], E["approval"], E["raudit"]
    kv("Proposal", f"{p['proposal_id']}  hash {p['proposal_hash'][:16]}... (recomputed: OK)", "[VERIFIED]")
    kv("Bound to signed result", p["attribution"]["result_id"], "[VERIFIED]")
    kv("Response action / target", f"{p['action']['type']} on {p['action']['target']} (listener {p['action']['listener']}; "
       f"from {p['source_proposal']['type']} {p['source_proposal']['subject']})", "[DECISION]")
    kv("Maximum duration", f"{p['action']['max_ttl_seconds']} s", "[DECISION]")
    for k, val in E["neg"].items():
        kv("Refused approval", f"{k}: {val['result']['reason']}", "[VERIFIED]")
    kv("Approval", f"{ap['decision']} by '{ap['approver']['name']}' key {ap['approver']['key_id']}, rule TTL {ap['rule']['ttl_seconds']} s", "[SIMULATED]")
    kv("Approval verification", "signature verified by the controller at run time (audit: approval_recorded); approval_hash recomputed now: OK", "[VERIFIED]")
    for e in ra:
        if e["event"] != "operation_rejected":
            kv(f"#{e['sequence']:<2} {e['event']}", f"-> {e['to_state']}", "[SIMULATED]")
    sim = next(e for e in ra if e["event"] == "simulated")
    kv("DRY-RUN status", f"enforced={sim['details']['enforced']}: {sim['details']['note']}", "[SIMULATED]")
    vp = next(e for e in ra if e["event"] == "verification_passed")
    kv("Operator verification", vp["details"]["outcome"], "[SIMULATED]")
    kv("Rollback", next(e for e in ra if e["event"] == "rollback_verified")["event"], "[SIMULATED]")
    kv("Refused operations logged", sum(e["event"] == "operation_rejected" for e in ra), "[VERIFIED]")

    head("SECTION E - FEEDBACK                                        [SIMULATED]")
    fb = E["fb"]
    kv("Feedback record", f"feedback_record.json sha256 {E['fb_sha'][:16]}...", "[VERIFIED]")
    kv("Feedback core hash", f"{fb['feedback_core_sha256'][:16]}... (recomputed: OK)", "[VERIFIED]")
    kv("Label", f"{fb['annotation']['label']} by {fb['annotation']['operator']}", "[SIMULATED]")
    kv("Audit verification", f"{len(ra)} entries, chain and transitions intact, last {ra[-1]['record_hash'][:16]}...", "[VERIFIED]")
    kv("Final response state", f"{fb['final_state']} (response_success={fb['response_success']})", "[SIMULATED]")
    kv("Enforcement interface calls", fb["enforcement_calls"], "[VERIFIED]")
    print()
    line("=")
    print("  ACTUAL_BLOCKING: NOT_EXECUTED")
    line("=")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--verify", action="store_true", help="run the integrity verification only")
    a = ap.parse_args(argv)
    try:
        E = load_and_verify()
    except Exception as exc:                                                  # noqa: BLE001
        print(f"VERIFICATION ERROR: {type(exc).__name__}: {exc}")
        print("Recovery: show demo_transcript_29f.txt (see DEMO_GUIDE.md, section 5).")
        return 2
    print("PRE-FLIGHT VERIFICATION (saved evidence)")
    for name, good, detail in CHECKS:
        print(f"  [{'PASS' if good else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))
    failed = [c for c in CHECKS if not c[1]]
    print(f"  {len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("VERIFICATION FAILED - do not present; see DEMO_GUIDE.md section 5.")
        return 1
    if not a.verify:
        show(E)
    return 0


if __name__ == "__main__":
    sys.exit(main())
