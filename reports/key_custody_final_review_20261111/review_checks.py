"""Task 26D read-only review checks: fail-closed behaviour with missing/invalid/replaced keys and the pinning chain.
In-memory only; reads configs, Task 26A captured evidence and Task 26C validation fixtures. No key is generated
except throwaway in-memory keys that stand in for an attacker's replacement key (never written). No Dataset V2 access."""
import copy
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from behavioural_evidence.engine import read_jsonl  # noqa: E402
from client_attribution import correlate, load_attribution_config as load_corr_cfg  # noqa: E402
from threat_assessment import AssessmentConfigError, load_attribution_config, load_policy  # noqa: E402
from threat_assessment.config import AttributionConfig, canonical_digest  # noqa: E402
from threat_assessment.signed_attribution import SignedResultError, verify_result  # noqa: E402

A26 = REPO / "reports/client_attribution_implementation_20261111/evidence"
C26 = REPO / "reports/attribution_trust_boundary_remediation_20261111/evidence"
NOW = datetime(2026, 11, 11, 17, 31, tzinfo=timezone.utc)
OUT = []


def check(name, fn, expect):
    try:
        got = fn()
    except (AssessmentConfigError, SignedResultError, ValueError) as exc:
        got = f"{type(exc).__name__}: {exc}"
    ok = expect(got)
    OUT.append({"check": name, "result": str(got)[:220], "fail_closed": bool(ok)})


def attacker_pem():
    k = Ed25519PrivateKey.generate()                       # in-memory stand-in for a malicious replacement key
    return k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


events = read_jsonl(A26 / "cowrie_events_after_baseline.jsonl")
lines = (A26 / "relay_mapping.jsonl").read_text(encoding="utf-8").splitlines()
relay_pem = (REPO / "cowrie/attributing_relay/relay_mapping_ed25519.pub.pem").read_bytes()
v3_path = REPO / "configs/threat_attribution_v3.json"
v3 = json.loads(v3_path.read_text(encoding="utf-8"))
addr = json.loads((REPO / "configs/address_safety_v1.json").read_text(encoding="utf-8"))
ccfg = load_corr_cfg(v3_path)
genuine = json.loads((C26 / "signed_result_genuine.json").read_text(encoding="utf-8"))
val_cfg = json.loads((C26 / "validation_fixtures/threat_attribution_v3_validation.json").read_text(encoding="utf-8"))
val_pem = (C26 / "validation_fixtures/attribution_result_validation.pub.pem").read_bytes()
attributed = lambda out: sum(v["state"] == "attributable_via_proxy_mapping" for v in out["sessions"].values())

# --- relay record key (verifier side)
check("relay public key file missing (correlator given no key)", lambda: attributed(correlate(events, lines, b"", ccfg, NOW)), lambda n: n == 0)
check("relay public key replaced by another key", lambda: attributed(correlate(events, lines, attacker_pem(), ccfg, NOW)), lambda n: n == 0)
check("relay log unavailable", lambda: attributed(correlate(events, None, relay_pem, ccfg, NOW)), lambda n: n == 0)
check("genuine relay key (control)", lambda: attributed(correlate(events, lines, relay_pem, ccfg, NOW)), lambda n: n == 4)
# a relay restarted with a replacement key: its records carry another key_id -> rejected line by line
rk = Ed25519PrivateKey.generate()                          # in-memory stand-in for an unapproved replacement relay key
rk_sha = hashlib.sha256(rk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
last = json.loads(lines[-1])
swap = {"schema": "relay-mapping-record-1", "seq": last["seq"] + 1, "prev_hash": last["record_hash"], "record_type": "relay_start",
        "written_utc": "2026-11-11T17:25:00.000000Z", "key_id": rk_sha[:16], "listeners": [], "backend": "cowrie:2222", "public_key_sha256": rk_sha}
swap["record_hash"] = hashlib.sha256(json.dumps(swap, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
swap["signature"] = rk.sign(swap["record_hash"].encode("ascii")).hex()
check("relay restarted with a silently swapped key (correctly signed by the new key)",
      lambda: correlate(events, lines + [json.dumps(swap)], relay_pem, ccfg, NOW)["verification"]["rejected"],
      lambda r: len(r) == 1 and "not the pinned key" in r[0]["reason"])

# --- attribution result key (assessment side)
check("live v3 config: result key pending", lambda: load_attribution_config(v3_path).result_key_status, lambda s: s == "pending_provisioning")
check("live v3 config: any signed result", lambda: verify_result(genuine, load_attribution_config(v3_path), NOW), lambda r: "no attribution result key is pinned" in str(r))
prov = copy.deepcopy(v3)
prov["attribution_result"].update(status="provisioned", public_key_sha256=val_cfg["attribution_result"]["public_key_sha256"],
                                  key_validity=val_cfg["attribution_result"]["key_validity"], public_key_path="does/not/exist.pem")
check("provisioned config, public key file missing", lambda: AttributionConfig.from_document(prov, address_doc=addr, result_public_key_pem=None),
      lambda r: "requires its public key" in str(r))
check("provisioned config, public key replaced", lambda: AttributionConfig.from_document(prov, address_doc=addr, result_public_key_pem=attacker_pem()),
      lambda r: "does not match the pinned" in str(r))
check("provisioned config, corrupt public key", lambda: AttributionConfig.from_document(prov, address_doc=addr, result_public_key_pem=b"junk"),
      lambda r: "Error" in str(r))
bad_pin = copy.deepcopy(prov)
bad_pin["attribution_result"]["public_key_sha256"] = "zz"
check("provisioned config, malformed pin", lambda: AttributionConfig.from_document(bad_pin, address_doc=addr, result_public_key_pem=val_pem),
      lambda r: "64-hex" in str(r))
vcfg = AttributionConfig.from_document(val_cfg, address_doc=addr, result_public_key_pem=val_pem)
check("validation config + genuine result (control)", lambda: verify_result(genuine, vcfg, NOW)["result_id"], lambda r: r == "task26c-validation-genuine")
check("result signed by a different (unpinned) key", lambda: verify_result(dict(genuine, signer={"key_id": "0" * 16, "public_key_sha256": "0" * 64}), vcfg, NOW),
      lambda r: "not pinned" in str(r))

# --- pinning chain against silent replacement
pol = load_policy(REPO / "configs/defence_policy_v2_2.json")
live = load_attribution_config(v3_path)
check("policy 2.2.0 pins the live v3 digest", lambda: pol.attribution_digest == live.digest, lambda r: r is True)
check("re-pinning the result key changes the v3 digest", lambda: canonical_digest(prov) != live.digest, lambda r: r is True)
check("policy 2.2.0 rejects a re-pinned v3 (digest no longer pinned)", lambda: pol.attribution_digest == canonical_digest(prov), lambda r: r is False)

(HERE / "evidence").mkdir(exist_ok=True)
(HERE / "evidence" / "fail_closed_checks.json").write_text(json.dumps(OUT, indent=2) + "\n", encoding="utf-8")
for r in OUT:
    print(("PASS " if r["fail_closed"] else "FAIL ") + r["check"], "->", r["result"][:110])
