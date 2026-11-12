"""Task 26C real-data validation on the Task 26A captured demo sessions.

Signer role (this host process): an EPHEMERAL attribution-result key generated in memory for validation only. The private
key is never written; only its public key and validation-only configs (copies of the v3 config and policy 2.2.0 with
that key pinned) are saved under evidence/validation_fixtures/. The deployment config keeps the result key pending.
Verifier role: threat_assessment.run_signed inside the isolated `threat-assessment` container (no key, no network).
Reads no Dataset V2 or sealed data. Nothing is enforced.
"""
import copy
import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from behavioural_evidence.engine import read_jsonl  # noqa: E402
from client_attribution import (build_result, config_from_document, correlate, correlate_authentication, make_checkpoint,  # noqa: E402
                                sign_result, verify_checkpoints)
from client_attribution.records import load_public_key, verify_records  # noqa: E402
from threat_assessment.config import canonical_digest  # noqa: E402

A26 = REPO / "reports" / "client_attribution_implementation_20261111"
EV = HERE / "evidence"
FIX = EV / "validation_fixtures"
WORK_IN = REPO / "cowrie" / "assessment_work" / "input"
WORK_OUT = REPO / "cowrie" / "assessment_work" / "output"
NOW = datetime(2026, 11, 11, 17, 30, 0, tzinfo=timezone.utc)
CHECK_AT = "2026-11-11T17:31:00Z"
S1, S2, S3, S4, S5 = "9441bcce555c", "acc2bad4a442", "d588636ce120", "3eede5e19e25", "4542a85f37ec"
LABEL = {S1: "S1 published banner", S2: "S2 test banner", S3: "S3 control banner", S4: "S4 test shell", S5: "S5 control shell"}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def dump(p, obj):
    Path(p).write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


for d in (EV, FIX, WORK_IN, WORK_OUT):
    d.mkdir(parents=True, exist_ok=True)
for p in list(WORK_IN.iterdir()) + list(WORK_OUT.iterdir()):
    shutil.rmtree(p) if p.is_dir() else p.unlink()          # this run's own scratch I/O only

# ------------------------------------------------------------------------------------------- inputs (26A, hash-checked)
m26 = {}
for line in (A26 / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    h, n = line.split(maxsplit=1)
    n = n.lstrip("*")
    if n.startswith("./evidence/") or n.startswith("evidence/"):
        m26[n] = sha(A26 / n) == h
assert all(m26.values()), m26
events = read_jsonl(A26 / "evidence" / "cowrie_events_after_baseline.jsonl")
lines = (A26 / "evidence" / "relay_mapping.jsonl").read_text(encoding="utf-8").splitlines()
relay_pem = (REPO / "cowrie" / "attributing_relay" / "relay_mapping_ed25519.pub.pem").read_bytes()

# ------------------------------------------------------------------------------------------- validation fixtures
eph = Ed25519PrivateKey.generate()                          # validation only; never written
eph_pem = eph.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
eph_sha = hashlib.sha256(eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
v3 = json.loads((REPO / "configs" / "threat_attribution_v3.json").read_text(encoding="utf-8"))
val_cfg = copy.deepcopy(v3)
val_cfg["config_version"] = "3.0.0-validation"
val_cfg["attribution_result"].update(status="provisioned", public_key_sha256=eph_sha, public_key_path=None,
                                     key_validity={"not_before": "2026-11-11T00:00:00Z", "not_after": "2026-11-12T00:00:00Z"},
                                     status_note="VALIDATION FIXTURE ONLY: ephemeral key generated in memory by validate_remediation.py.")
val_pol = json.loads((REPO / "configs" / "defence_policy_v2_2.json").read_text(encoding="utf-8"))
val_pol["policy_version"] = "2.2.0-validation"
val_pol["attribution_config"] = {"path": "validation fixture", "config_version": val_cfg["config_version"], "sha256_digest": canonical_digest(val_cfg)}
for name, obj in (("threat_attribution_v3_validation.json", val_cfg), ("defence_policy_v2_2_validation.json", val_pol)):
    dump(FIX / name, obj)
(FIX / "attribution_result_validation.pub.pem").write_bytes(eph_pem)

# ------------------------------------------------------------------------------------------- signer role
cfg = config_from_document(val_cfg)
pub, pub_sha = load_public_key(relay_pem)
ver = verify_records(lines, pub, pub_sha, cfg.key_not_before, cfg.key_not_after)
checkpoint = make_checkpoint(ver, "cowrie-ssh-relay/relay_mapping.jsonl", "2026-11-11T17:30:00.000000Z", eph, eph_sha)
cps, cp_rej = verify_checkpoints([checkpoint], eph_pem, eph_sha, "cowrie-ssh-relay/relay_mapping.jsonl")
corr = correlate(events, lines, relay_pem, cfg, evaluation_time=NOW, checkpoints=cps)
auth = correlate_authentication(events)
genuine = sign_result(build_result(corr, auth, cfg, events, NOW, 3600, NOW, result_id="task26c-validation-genuine"), eph)
dump(EV / "signed_result_genuine.json", genuine)
dump(EV / "relay_log_checkpoint.json", checkpoint)

# ------------------------------------------------------------------------------------------- attack inputs
attacker = Ed25519PrivateKey.generate()
unsigned = correlate(events, lines, relay_pem, cfg, evaluation_time=NOW)          # exactly the 26B-attacked object
attack_a = copy.deepcopy(unsigned)
attack_a["sessions"][S5].update(client_ip="10.250.25.3", client_role="test_client")
attack_b = copy.deepcopy(unsigned)
attack_b["sessions"][S4].update(client_ip="203.0.113.9", client_role="forged")


def entry(doc, sid):
    return next(e for e in doc["sessions"] if e["cowrie_session_id"] == sid)


def strip(doc):
    return {k: v for k, v in copy.deepcopy(doc).items() if k not in ("signer", "result_hash", "signature")}


signed_a_altered = copy.deepcopy(genuine)
entry(signed_a_altered, S5)["client"] = {"ip": "10.250.25.3", "port": 46198, "role": "test_client"}
signed_b_altered = copy.deepcopy(genuine)
entry(signed_b_altered, S4)["client"]["ip"] = "203.0.113.9"
resigned_a = strip(genuine)
entry(resigned_a, S5)["client"] = {"ip": "10.250.25.3", "port": 46198, "role": "test_client"}
resigned_a = sign_result(resigned_a, attacker)
cases = {
    "genuine": [genuine],
    "attackA_unsigned_S5_to_test_client": [attack_a],
    "attackB_unsigned_S4_to_unregistered": [attack_b],
    "attackA_signed_then_altered": [signed_a_altered],
    "attackB_signed_then_altered": [signed_b_altered],
    "attackA_resigned_with_attacker_key": [resigned_a],
    "genuine_plus_forged": [genuine, attack_a],
}

shutil.copy(A26 / "evidence" / "cowrie_events_after_baseline.jsonl", WORK_IN / "cowrie_events.jsonl")
shutil.copy(REPO / "reports" / "behavioural_evidence_framework_implementation_20261111" / "config" / "sensor_calibration_lab_train.json",
            WORK_IN / "calibration.json")
for name in ("threat_attribution_v3_validation.json", "defence_policy_v2_2_validation.json", "attribution_result_validation.pub.pem"):
    shutil.copy(FIX / name, WORK_IN / name)
for case, docs in cases.items():
    for k, d in enumerate(docs):
        dump(WORK_IN / f"{case}_{k}.json", d)

COMPOSE = ["docker", "compose", "-f", str(REPO / "cowrie" / "docker-compose.yml"), "--profile", "assessment", "run", "--rm", "-T"]


def run_case(case, docs, now=CHECK_AT, cfg_path="/work/input/threat_attribution_v3_validation.json",
             pol_path="/work/input/defence_policy_v2_2_validation.json", pem=True, inputs=None):
    """case: output directory name; inputs: the document set (file prefix) to verify (default: case)."""
    inputs = inputs or case
    args = COMPOSE + ["threat-assessment", "--repo-root", "/opt/project", "--attribution-config", cfg_path,
                      "--policy", pol_path, "--calibration", "/work/input/calibration.json",
                      "--cowrie-events", "/work/input/cowrie_events.jsonl", "--now", now, "--out-dir", f"/work/output/{case}"]
    if pem:
        args += ["--result-public-key", "/work/input/attribution_result_validation.pub.pem"]
    for k in range(len(docs)):
        args += ["--signed-result", f"/work/input/{inputs}_{k}.json"]
    p = subprocess.run(args, capture_output=True, text=True)
    out = WORK_OUT / case
    res = {"exit_code": p.returncode, "stderr_tail": p.stderr.strip().splitlines()[-3:]}
    if (out / "summary.json").exists():
        res["summary"] = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    return res


results = {case: run_case(case, docs) for case, docs in cases.items()}
results["genuine_after_expiry"] = run_case("genuine_after_expiry", cases["genuine"], now="2026-11-11T18:30:01Z", inputs="genuine")
# deployment configs (result key pending): the genuine validation result must be rejected
results["deployment_config_pending_key"] = run_case("deployment_config_pending_key", cases["genuine"], inputs="genuine", pem=False,
                                                    cfg_path="/opt/project/configs/threat_attribution_v3.json",
                                                    pol_path="/opt/project/configs/defence_policy_v2_2.json")

rows = []
for case, r in results.items():
    s = r.get("summary") or {}
    for sid, v in sorted((s.get("sessions") or {}).items()):
        rows.append({"case": case, "session": LABEL.get(sid, sid), "tier": v["tier"], "attribution": v["attribution"],
                     "failed_gates": ",".join(v["failed_gates"]), "login_basis": v["login_basis"], "subject": v["subject"]})
    if not s:
        rows.append({"case": case, "session": "-", "tier": f"exit {r['exit_code']}", "attribution": " | ".join(r["stderr_tail"]),
                     "failed_gates": "", "login_basis": "", "subject": ""})
proposals = [r for r in rows if r["tier"] == "propose"]

# ------------------------------------------------------------------------------------------- container isolation probe
PROBE = r"""
import json, os, re, socket
KEY_PEM = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*" + bytes.fromhex("50524956415445204b4559") + rb"-----")
r = {}
for p in ["/run/relay/relay_mapping_ed25519.pem", "/run/relay", "/var/relay_records/relay_mapping.jsonl", "/var/run/docker.sock",
          "/run/docker.sock", "/opt/relay", "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"]:
    try:
        open(p, "rb").read(1); r[p] = "READABLE"
    except Exception as e:
        r[p] = type(e).__name__
found = []
for root in ["/opt/project", "/work", "/cowrie", "/etc", "/tmp", "/run", "/var"]:
    for d, _, fs in os.walk(root):
        for f in fs:
            try:
                q = os.path.join(d, f)
                if os.path.getsize(q) < 4_000_000 and KEY_PEM.search(open(q, "rb").read()):
                    found.append(q)
            except Exception:
                pass
r["private_key_files_found"] = found
r["mounts"] = [l.split()[4] + " " + l.split()[5].split(",")[0] for l in open("/proc/self/mountinfo") if l.split()[4].startswith(("/opt", "/work", "/run", "/var"))]
r["interfaces"] = [l.split(":")[0].strip() for l in open("/proc/net/dev").read().splitlines()[2:]]
try:
    socket.create_connection(("172.22.0.1", 2222), timeout=2); r["network"] = "CONNECTED"
except Exception as e:
    r["network"] = type(e).__name__
r["uid"] = os.getuid()
try:
    open("/opt/project/threat_assessment/x", "w"); r["code_writable"] = True
except Exception as e:
    r["code_writable"] = type(e).__name__
print(json.dumps(r))
"""
p = subprocess.run(COMPOSE + ["--entrypoint", "/cowrie/cowrie-env/bin/python3", "threat-assessment", "-c", PROBE], capture_output=True, text=True)
probe = json.loads(p.stdout.strip().splitlines()[-1]) if p.returncode == 0 else {"error": p.stderr[-500:]}

summary = {"evaluation_time": NOW.isoformat(), "checked_at": CHECK_AT, "ephemeral_result_key_sha256": eph_sha,
           "validation_config_digest": canonical_digest(val_cfg), "relay_log_verification": ver["reason"], "relay_log_tail": corr["verification"]["tail"],
           "checkpoint": {"seq": checkpoint["seq"], "verified": bool(cps), "rejected": cp_rej},
           "authentication": {LABEL[s]: auth[s]["state"] for s in LABEL}, "inputs_26A_hash_checked": len(m26),
           "container_isolation_probe": probe, "proposals": proposals,
           "cases": {c: {"exit": r["exit_code"], "isolation_ok": ((r.get("summary") or {}).get("isolation") or {}).get("ok"),
                         "rejected": ((r.get("summary") or {}).get("attribution_results") or {}).get("rejected")} for c, r in results.items()}}
dump(EV / "validation_summary.json", summary)
with open(HERE / "real_data_results.csv", "w", encoding="utf-8", newline="") as f:
    import csv
    w = csv.DictWriter(f, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
for case in list(results):
    src = WORK_OUT / case
    if src.exists():
        shutil.copytree(src, EV / "container_runs" / case, dirs_exist_ok=True)
print(json.dumps({"proposals": proposals, "probe": probe, "cases": summary["cases"]}, indent=1))
for r in rows:
    print(r)
