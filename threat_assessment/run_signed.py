"""Isolated assessment runner (Task 26C): evidence -> verification of signed attribution results -> assessment.

    python -m threat_assessment.run_signed --attribution-config ... --policy ... --calibration ... \
        --cowrie-events events.jsonl --signed-result result.json [--signed-result ...] --now 2026-...Z --out-dir out/

Intended to run in the `threat-assessment` container (no key mounts, no Docker socket, no network, read-only code).
Before doing anything it checks its own isolation and refuses to run if a private key, a relay secret path or the
Docker socket is reachable. It verifies signatures only; it holds no signing key and cannot produce a valid result.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

FORBIDDEN_PATHS = ("/run/relay", "/run/relay/relay_mapping_ed25519.pem", "/var/relay_records", "/run/secrets", "/var/run/docker.sock",
                   "/run/docker.sock", "/run/attribution", "/var/lib/docker")
SCAN_LIMIT_BYTES = 4 * 1024 * 1024
KEY_PEM = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*" + bytes.fromhex("50524956415445204b4559") + rb"-----")  # PEM private-key header


def in_container() -> bool:
    if os.path.exists("/.dockerenv"):
        return True
    try:
        return any(k in Path("/proc/1/cgroup").read_text() for k in ("docker", "containerd", "kubepods"))
    except OSError:
        return False


def isolation_report(scan_roots) -> dict:
    """What this process can reach. ok=False if any private key or secret/socket path is accessible."""
    reachable = [p for p in FORBIDDEN_PATHS if os.path.exists(p)]
    keys = []
    for root in scan_roots:
        for dirpath, _, files in os.walk(root):
            for f in files:
                p = os.path.join(dirpath, f)
                try:
                    if os.path.getsize(p) <= SCAN_LIMIT_BYTES and KEY_PEM.search(Path(p).read_bytes()):
                        keys.append(p)
                except OSError:
                    continue
    try:
        ifaces = [l.split(":")[0].strip() for l in Path("/proc/net/dev").read_text().splitlines()[2:]]
    except OSError:
        ifaces = None
    try:
        uid = os.getuid()
    except AttributeError:
        uid = None
    rep = {"in_container": in_container(), "uid": uid, "forbidden_paths_reachable": reachable, "private_key_files_readable": keys,
           "network_interfaces": ifaces, "scan_roots": [str(r) for r in scan_roots]}
    rep["ok"] = not reachable and not keys and uid != 0
    return rep


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--attribution-config", required=True)
    ap.add_argument("--policy", required=True)
    ap.add_argument("--result-public-key", help="PEM of the pinned attribution-result key (its sha256 must equal the config pin)")
    ap.add_argument("--calibration", required=True)
    ap.add_argument("--reference-sequences", help="JSON list of command sequences (optional)")
    ap.add_argument("--cowrie-events", required=True)
    ap.add_argument("--signed-result", action="append", default=[])
    ap.add_argument("--now", required=True, help="evaluation time (ISO 8601, UTC)")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--allow-host", action="store_true", help="tests only: run outside a container")
    a = ap.parse_args(argv)
    sys.path.insert(0, a.repo_root)
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    scan = [a.repo_root, str(Path(a.cowrie_events).parent)] + [str(Path(p).parent) for p in a.signed_result]
    iso = isolation_report(sorted(set(scan)))
    (out / "isolation.json").write_text(json.dumps(iso, indent=2) + "\n", encoding="utf-8")
    if not iso["ok"] or (not iso["in_container"] and not a.allow_host):
        print(json.dumps(iso, indent=1))
        raise SystemExit("refusing to run: assessment environment is not isolated from signing keys")

    from behavioural_evidence import EvidenceConfig, EvidenceEngine
    from behavioural_evidence.calibration import load_calibration
    from behavioural_evidence.engine import read_jsonl
    from threat_assessment import AuditLog, ThreatAssessor, load_attribution_config, load_policy, verify_chain
    from threat_assessment.assessment import assess_sessions
    from threat_assessment.audit import read_log

    pem = Path(a.result_public_key).read_bytes() if a.result_public_key else None
    att = load_attribution_config(a.attribution_config, repo_root=a.repo_root, result_public_key_pem=pem)
    pol = load_policy(a.policy)
    ref = frozenset(tuple(s) for s in json.loads(Path(a.reference_sequences).read_text())) if a.reference_sequences else frozenset()
    ecfg = EvidenceConfig(relay_sources=frozenset(att.relay_strings), internal_networks=att.internal_cidr_strings,
                          calibration=load_calibration(a.calibration), reference_sequences=ref)
    evidence = EvidenceEngine(ecfg).evaluate(read_jsonl(a.cowrie_events))["sessions"]
    docs = [json.loads(Path(p).read_text(encoding="utf-8")) for p in a.signed_result]
    now = datetime.fromisoformat(a.now.replace("Z", "+00:00"))
    assessor = ThreatAssessor(att, pol, ecfg)
    assessed = assess_sessions(evidence, assessor, docs if docs else None, now=now)
    with open(out / "evidence.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for r in evidence:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    with open(out / "assessments.jsonl", "w", encoding="utf-8", newline="\n") as f:
        for r in assessed:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    audit = out / "audit.jsonl"
    if audit.exists():
        audit.unlink()
    log = AuditLog("task26c-isolated", path=audit, clock=lambda: a.now)
    for r in assessed:
        log.append(r)
    ck = log.checkpoint()
    summary = {"isolation": iso, "attribution_config": att.digest, "attribution_schema": att.schema, "policy": pol.policy_version,
               "policy_schema": pol.schema_version, "result_key_status": att.result_key_status,
               "audit_chain": verify_chain(read_log(audit), ck),
               "sessions": {r["session_ref"]: {"tier": r["tier"], "attribution": r["session_attribution"]["state"],
                                               "failed_gates": [k for k, v in r["gates"].items() if not v],
                                               "login_basis": r["successful_login_basis"],
                                               "subject": (r["proposed_action"] or {}).get("subject")} for r in assessed},
               "attribution_results": assessed[0]["versions"]["attribution_results"] if assessed else None}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary["sessions"], indent=1))


if __name__ == "__main__":
    main()
