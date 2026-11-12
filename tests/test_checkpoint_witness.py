"""Task 28A: checkpoint-witness architecture with placeholders and TEST/LOCAL MOCK infrastructure.

All keys are ephemeral in-memory TEST fixtures (six roles + approval role). No network, no placeholder URL, no
production key, no deployment change. The clock is injected so the 2-s, 60-s and 15-min rules are exercised exactly.
"""
import copy
import hashlib
import json
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "cowrie" / "attributing_relay"))

from client_attribution import config_from_document, correlate, correlate_authentication, sign_result  # noqa: E402
from client_attribution.checkpoints import v1_view, verify_checkpoint_chain  # noqa: E402
from client_attribution.framing import InProcessTransport, StreamTransport, serve_stream  # noqa: E402
from client_attribution.offhost_mock import (MockAdministrator, MockRejected, MockTrustAnchorRepository, MockWitnessLogRepository,  # noqa: E402
                                             signed)
from client_attribution.offhost_monitor import check_repository  # noqa: E402
from client_attribution.placeholders import (MOCK_LABEL, ProductionNotReady, assert_production_ready, load_offhost_config,  # noqa: E402
                                             placeholder_fields)
from client_attribution.records import verify_records  # noqa: E402
from client_attribution.replicator import ProductionRemoteNotConfigured, ReplicationError, Replicator  # noqa: E402
from client_attribution.result import build_result, witness_evidence  # noqa: E402
from client_attribution.trust_root import (MANIFEST_SCHEMA, RECOVERY_SCHEMA, REQUIRED_THRESHOLDS, TrustRootError, anchor_fingerprint,  # noqa: E402
                                           doc_digest, verify_manifest)
from client_attribution.witness import CheckpointStore, WitnessCore  # noqa: E402
from relay_gate import Halted, RecordWriterV2, RelayWitnessGate  # noqa: E402
from threat_assessment import AssessmentConfigError, AttributionConfig, PolicyConfig, ThreatAssessor  # noqa: E402
from trust_fixtures import (ADDR, ATT3, ECFG, RELAY_KEY, RELAY_PEM, RELAY_SHA, RESULT_KEY, RESULT_PEM, T0, TEST_CLIENT, att3_doc,  # noqa: E402
                            policy21, relay_session)
from behavioural_evidence import EvidenceEngine  # noqa: E402

LOG_ID = "relay-mapping-log-mock"


def key():
    k = Ed25519PrivateKey.generate()
    pem = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return k, pem, hashlib.sha256(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()


class Clock:
    def __init__(self, t):
        self.t, self.mono = t, 0.0

    def __call__(self):
        return self.t

    def monotonic(self):
        return self.mono

    def advance(self, s):
        self.t += timedelta(seconds=s)
        self.mono += s

    def iso(self):
        return self.t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class FakeListener:
    def __init__(self, name):
        self.name, self.stopped = name, False

    def stop(self):
        self.stopped = True


class FakeSession:
    def __init__(self):
        self.aborted = False

    def abort(self):
        self.aborted = True


WITNESS_KEY, WITNESS_PEM, WITNESS_SHA = key()
C1_KEY, C1_PEM, C1_SHA = key()
ADMIN_A = MockAdministrator("A", Ed25519PrivateKey.generate())
ADMIN_B = MockAdministrator("B", Ed25519PrivateKey.generate())
APPROVER_KEY, APPROVER_PEM, APPROVER_SHA = key()
RESULT_SHA = hashlib.sha256(RESULT_KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()


def manifest_doc(seq=1, prev=None, roles=None, admins=(ADMIN_A, ADMIN_B), issued="2026-11-01T00:00:00Z", valid="2027-11-01T00:00:00Z",
                 digests=None, approval=None, revoked=()):
    r = {"relay_record": RELAY_SHA, "attribution_result": RESULT_SHA, "checkpoint_witness": WITNESS_SHA, "replicator_push": C1_SHA}
    r.update(roles or {})
    return {"schema": MANIFEST_SCHEMA, "sequence": seq, "previous_manifest_sha256": doc_digest(prev) if prev else None, "issued_utc": issued,
            "valid_until": valid, "administrators": {a.admin_id: a.entry() for a in admins}, "thresholds": dict(REQUIRED_THRESHOLDS),
            "roles": {k: {"sha256": v, "not_before": "2026-11-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z"} for k, v in r.items()},
            "approval_role": approval, "digests": digests or {"attribution_config": "a" * 64, "policy": "b" * 64}, "revoked": list(revoked),
            "mode": "TEST/LOCAL MOCK"}


MANIFEST = signed(manifest_doc(), ADMIN_A, ADMIN_B)
ANCHOR = doc_digest(MANIFEST)
FINGERPRINT = anchor_fingerprint(MANIFEST)
PARAMS = load_offhost_config()["parameters"]


class Harness:
    def __init__(self, tmp, start=T0 - timedelta(seconds=10), manifest=MANIFEST):
        self.clock = Clock(start)
        self.tmp = tmp
        self.store = CheckpointStore(tmp / "checkpoints.jsonl")
        self.writer = RecordWriterV2(RELAY_KEY, RELAY_SHA, self.clock.iso, path=tmp / "relay_records.jsonl")
        self.tamper = None
        self.status = {"v": None}
        self.witness = WitnessCore(LOG_ID, RELAY_PEM, RELAY_SHA, WITNESS_KEY, WITNESS_SHA, ANCHOR, self.store, self.read_log, self.clock,
                                   replication_status=lambda: self.status["v"], manifest=manifest, params=PARAMS,
                                   relay_key_validity=(datetime(2026, 11, 1, tzinfo=timezone.utc), datetime(2026, 12, 1, tzinfo=timezone.utc)))
        self.transport = InProcessTransport(self.witness.handle, clock=self.clock, timeout=2.0)
        self.listeners = [FakeListener("published"), FakeListener("demo")]
        self.gate = RelayWitnessGate(self.writer, self.transport, WITNESS_PEM, WITNESS_SHA, RELAY_SHA, LOG_ID, self.clock, self.listeners,
                                     timeout=2.0, halt_marker=tmp / "relay_halt.json")
        self.repo, self.anchors = MockWitnessLogRepository(), MockTrustAnchorRepository()
        self.anchors.publish(manifest, by=ADMIN_A)
        self.replicator = Replicator(self.store.all, self.repo, self.anchors, ANCHOR, WITNESS_PEM, WITNESS_SHA, LOG_ID, self.clock)

    def read_log(self):
        lines = (self.tmp / "relay_records.jsonl").read_text(encoding="utf-8").splitlines() if (self.tmp / "relay_records.jsonl").exists() else []
        return self.tamper(lines) if self.tamper else lines

    def replicate(self):
        self.status["v"] = self.replicator.run_once()
        return self.status["v"]

    def start(self):
        return self.gate.start(listeners=[{"name": "published"}, {"name": "demo"}], backend="cowrie:2222", public_key_sha256=RELAY_SHA)

    def open_record(self, cid="c1", uport=50001, t=0.0, client=TEST_CLIENT):
        from trust_fixtures import DEMO_LISTENER, iso
        self.clock.t = T0 + timedelta(seconds=t + 0.01)
        return self.gate.append("connection_open", connection_id=cid, listener="demo", listener_mode="demo", ingress_listener=DEMO_LISTENER,
                                client_ip=client, client_port=40000, accepted_local=DEMO_LISTENER, accepted_utc=iso(t), upstream_local_ip="172.22.0.2",
                                upstream_local_port=uport, upstream_peer="172.22.0.1:2222", upstream_connected_utc=iso(t + 0.01))

    def close_record(self, cid="c1", uport=50001, t=5.0, client=TEST_CLIENT):
        from trust_fixtures import iso
        self.clock.t = T0 + timedelta(seconds=t)
        return self.gate.append("connection_close", connection_id=cid, listener="demo", client_ip=client, client_port=40000,
                                upstream_local_ip="172.22.0.2", upstream_local_port=uport, closed_utc=iso(t))

    def recovery(self, *admins, category="ordinary", cause="ack_timeout", halt_ref=None, valid=600):
        doc = {"schema": RECOVERY_SCHEMA, "log_id": LOG_ID, "halt_ref": halt_ref or self.witness.head_ref(), "category": category, "cause": cause,
               "incident_ref": "INC-TEST-1", "issued_utc": self.clock.iso(), "valid_until": (self.clock.t + timedelta(seconds=valid)).strftime(
                   "%Y-%m-%dT%H:%M:%S.%fZ"), "operator": "operator-test"}
        return signed(doc, *admins)


@pytest.fixture
def h(tmp_path):
    return Harness(tmp_path)


# =========================================================================================== happy path
def test_every_record_is_confirmed_and_linked(h):
    assert h.start()
    h.open_record()
    h.close_record()
    chain = h.store.all()
    assert [c["kind"] for c in chain] == ["attest"] * 3 and [c["relay_seq"] for c in chain] == [1, 2, 3]
    assert verify_checkpoint_chain(chain, WITNESS_PEM, WITNESS_SHA, LOG_ID)["ok"]
    recs = [json.loads(l) for l in h.read_log()]
    assert recs[0]["witness_ack"] is None
    assert [r["witness_ack"]["checkpoint_hash"] for r in recs[1:]] == [chain[0]["checkpoint_hash"], chain[1]["checkpoint_hash"]]
    from client_attribution.records import load_public_key
    pub, sha = load_public_key(RELAY_PEM)
    v = verify_records(h.read_log(), pub, sha, checkpoints=v1_view(chain))
    assert v["ok"] and v["tail"]["status"] == "attested"
    assert not any(l.stopped for l in h.listeners) and not h.gate.halted


def test_heartbeat_every_60s_reattests_head(h):
    h.start()
    h.clock.advance(60)
    assert h.gate.heartbeat()
    hb = h.store.all()[-1]
    assert hb["kind"] == "heartbeat" and hb["relay_seq"] == 1 and hb["trust_anchor_digest"] == ANCHOR
    h.open_record()                                                     # next record links to the heartbeat confirmation
    assert json.loads(h.read_log()[-1])["witness_ack"]["checkpoint_hash"] == hb["checkpoint_hash"]


# =========================================================================================== invalid / duplicate / replay
@pytest.mark.parametrize("attack,cause", [
    ("modify_field", "integrity"), ("bad_signature", "invalid_signature"), ("malformed", "conflict"), ("unknown_key", "invalid_signature")])
def test_invalid_record_faults_and_halts(h, attack, cause):
    h.start()

    def tamper(lines):
        out = list(lines)
        r = json.loads(out[-1])
        if r["seq"] == 2:
            if attack == "modify_field":
                r["client_ip"] = "10.250.25.4"
            elif attack == "bad_signature":
                r["signature"] = "00" * 64
            elif attack == "unknown_key":
                r["key_id"] = "0" * 16
            out[-1] = json.dumps(r) if attack != "malformed" else out[-1]
            if attack == "malformed":
                out.append(out[-1])                                     # two records with the same seq
        return out
    h.tamper = tamper
    with pytest.raises(Halted):
        h.open_record()
    assert h.gate.halted and all(l.stopped for l in h.listeners)
    fault = h.store.all()[-1]
    assert fault["kind"] == "fault" and fault["details"]["cause"] in (cause, "integrity", "conflict")


def test_duplicate_and_replayed_attest_requests(h):
    h.start()
    rec = h.open_record()
    n = len(h.store.all())
    r = h.witness.handle({"type": "attest", "log_id": LOG_ID, "seq": rec["seq"], "record_hash": rec["record_hash"]})
    assert r["type"] == "nack" and r["cause"] == "duplicate" and len(h.store.all()) == n and h.witness.fault is None
    r2 = h.witness.handle({"type": "attest", "log_id": LOG_ID, "seq": rec["seq"], "record_hash": "f" * 64})
    assert r2["type"] == "nack" and h.witness.fault["cause"] == "conflict" and h.witness.fault["category"] == "elevated"


def test_gap_and_unknown_requests_fault(h):
    h.start()
    assert h.witness.handle({"type": "attest", "log_id": LOG_ID, "seq": 5, "record_hash": "a" * 64})["cause"] == "gap"
    assert h.witness.handle({"type": "heartbeat", "log_id": LOG_ID})["cause"] == "halted"


def test_expired_relay_key_faults(h):
    h.start()
    h.clock.t = datetime(2026, 12, 2, tzinfo=timezone.utc)
    with pytest.raises(Halted):
        h.gate.append("connection_rejected", connection_id="x", reason="test")
    assert h.store.all()[-1]["details"]["cause"] == "key_expired"


# =========================================================================================== broken chains
def test_broken_relay_chain_faults(h):
    h.start()
    h.writer.prev = "e" * 64                                            # relay record no longer links
    with pytest.raises(Halted):
        h.open_record()
    assert h.store.all()[-1]["details"]["cause"] == "broken_chain"


def test_witness_ack_cross_link_enforced(h):
    h.start()
    h.gate.last_ack = dict(h.gate.last_ack, checkpoint_hash="d" * 64)   # relay references a confirmation that never existed
    with pytest.raises(Halted):
        h.open_record()
    assert h.store.all()[-1]["details"]["cause"] == "broken_chain"


@pytest.mark.parametrize("attack", ["modify", "delete", "reorder", "resign_other_key"])
def test_checkpoint_chain_tampering_detected(h, attack):
    h.start()
    h.open_record()
    h.close_record()
    chain = copy.deepcopy(h.store.all())
    if attack == "modify":
        chain[1]["relay_seq"] = 9
    elif attack == "delete":
        del chain[1]
    elif attack == "reorder":
        chain[0], chain[1] = chain[1], chain[0]
    else:
        other, _, _ = key()
        chain[1]["signature"] = other.sign(chain[1]["checkpoint_hash"].encode()).hex()
    assert not verify_checkpoint_chain(chain, WITNESS_PEM, WITNESS_SHA, LOG_ID)["ok"]


def test_witness_restart_on_tampered_store_refuses(h):
    h.start()
    h.open_record()
    lines = (h.tmp / "checkpoints.jsonl").read_text().splitlines()
    cp = json.loads(lines[0])
    cp["relay_seq"] = 7
    lines[0] = json.dumps(cp)
    (h.tmp / "checkpoints.jsonl").write_text("\n".join(lines) + "\n")
    w = WitnessCore(LOG_ID, RELAY_PEM, RELAY_SHA, WITNESS_KEY, WITNESS_SHA, ANCHOR, CheckpointStore(h.tmp / "checkpoints.jsonl"), h.read_log,
                    h.clock, manifest=MANIFEST, params=PARAMS)
    assert w.fault and w.fault["category"] == "elevated"
    assert w.handle({"type": "heartbeat", "log_id": LOG_ID})["type"] == "nack"


# =========================================================================================== invalid acks / missing confirmation / 2-s timeout
def test_invalid_ack_signature_halts(h):
    h.start()
    real = h.transport.handler

    def forged(frame):
        r = real(frame)
        if r.get("type") == "ack":
            r["checkpoint"]["signature"] = "00" * 64
        return r
    h.transport.handler = forged
    with pytest.raises(Halted):
        h.open_record()
    assert h.gate.halt_cause == "invalid_ack" and all(l.stopped for l in h.listeners)


def test_ack_for_another_record_halts(h):
    h.start()
    real = h.transport.handler
    h.transport.handler = lambda frame: real({"type": "heartbeat", "log_id": LOG_ID}) if frame.get("type") == "attest" else real(frame)
    with pytest.raises(Halted):
        h.open_record()
    assert h.gate.halt_cause == "invalid_ack"


def test_missing_confirmation_halts(h):
    h.start()
    h.transport.down = True
    with pytest.raises(Halted):
        h.open_record()
    assert h.gate.halt_cause == "witness_unavailable"


@pytest.mark.parametrize("delay,halts", [(1.9, False), (2.5, True), (30.0, True)])
def test_two_second_timeout_injected_clock(h, delay, halts):
    h.start()
    h.transport.delay = delay
    if halts:
        with pytest.raises(Halted):
            h.open_record()
        assert h.gate.halt_cause == "ack_timeout"
    else:
        h.open_record()
        assert not h.gate.halted


def test_two_second_timeout_real_stream_transport(tmp_path):
    """Transport independence + real time: the same protocol over a socket pair; a witness that answers after 2.3 s halts the relay."""
    hh = Harness(tmp_path)
    a, b = socket.socketpair()
    slow = {"delay": 0.0}

    def handler(frame):
        time.sleep(slow["delay"])
        return hh.witness.handle(frame)
    threading.Thread(target=serve_stream, args=(b, handler), daemon=True).start()

    class RealClock:
        monotonic = staticmethod(time.monotonic)
    hh.gate.transport, hh.gate.clock = StreamTransport(a, timeout=2.0), RealClock()
    hh.clock.t = T0 - timedelta(seconds=10)
    assert hh.start()
    slow["delay"] = 2.3
    hh.clock.t = T0
    t0 = time.monotonic()
    with pytest.raises(Halted):
        hh.gate.append("connection_rejected", connection_id="x", reason="t")
    assert 1.9 <= time.monotonic() - t0 < 3.0 and hh.gate.halt_cause == "ack_timeout"
    a.close()


# =========================================================================================== replication
def test_replication_failure_beyond_15_minutes_halts(h):
    h.start()
    h.replicate()
    h.repo.offline = True
    h.clock.advance(60)
    h.gate.heartbeat()                                                   # new checkpoint, not replicated
    with pytest.raises(MockRejected):
        h.replicate()                                                   # push fails: status is NOT advanced
    for _ in range(13):
        h.clock.advance(60)
        assert h.gate.heartbeat()                                       # lag < 15 min: still operating
    h.clock.advance(120)                                                # oldest unreplicated checkpoint now > 900 s old
    assert not h.gate.heartbeat()
    assert h.gate.halt_cause == "nack:replication_lag" and all(l.stopped for l in h.listeners)


def test_stale_or_missing_status_counts_as_not_replicated(h):
    h.start()
    h.replicate()
    h.status["v"] = None                                                # status file missing
    h.clock.advance(901)
    assert not h.gate.heartbeat() and h.gate.halt_cause == "nack:replication_lag"


def test_status_claim_cannot_override_lag(h):
    h.start()
    h.replicate()
    h.clock.advance(60)
    h.gate.heartbeat()
    h.status["v"] = dict(h.status["v"], pushed_utc=(h.clock.t - timedelta(seconds=1000)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    h.clock.advance(1)
    assert not h.gate.heartbeat()


def test_replicator_refuses_invalid_local_chain_and_production_remote(h):
    h.start()
    lines = (h.tmp / "checkpoints.jsonl").read_text().splitlines()
    cp = json.loads(lines[0]); cp["kind"] = "heartbeat"; lines[0] = json.dumps(cp)
    (h.tmp / "checkpoints.jsonl").write_text("\n".join(lines) + "\n")
    with pytest.raises(ReplicationError):
        h.replicate()
    cfg = load_offhost_config()
    remote = ProductionRemoteNotConfigured(cfg["witness_log_repository"], cfg["replication_credential"])
    with pytest.raises(ReplicationError, match="placeholder"):
        remote.push([], None)


def test_anchor_mismatch_halts_as_elevated(h):
    h.start()
    other = signed(manifest_doc(digests={"attribution_config": "c" * 64, "policy": "d" * 64}), ADMIN_A, ADMIN_B)
    h.anchors.publish(other, by=ADMIN_B)                                # off-host anchor changed; local anchor did not
    h.replicate()
    assert not h.gate.heartbeat() and h.gate.halt_cause == "nack:anchor_mismatch"
    assert h.witness.fault["category"] == "elevated"


# =========================================================================================== heartbeat / halt / sessions
def test_missing_heartbeat_halts_both_listeners_and_aborts_sessions(h):
    h.start()
    sessions = [FakeSession(), FakeSession(), FakeSession()]
    for s in sessions:
        h.gate.register_session(s)
    h.transport.down = True
    assert not h.gate.heartbeat()
    assert h.gate.halt_cause == "heartbeat_missing"
    assert [l.stopped for l in h.listeners] == [True, True]
    assert all(s.aborted for s in sessions) and not h.gate.sessions
    with pytest.raises(Halted):
        h.gate.register_session(FakeSession())
    with pytest.raises(Halted):
        h.open_record()
    assert json.loads((h.tmp / "relay_halt.json").read_text())["cause"] == "heartbeat_missing"


def test_halt_marker_blocks_restart(h):
    h.start()
    h.transport.down = True
    h.gate.heartbeat()
    h2 = RelayWitnessGate(h.writer, h.transport, WITNESS_PEM, WITNESS_SHA, RELAY_SHA, LOG_ID, h.clock, [FakeListener("x")],
                          halt_marker=h.tmp / "relay_halt.json")
    with pytest.raises(Halted, match="manual recovery"):
        h2.start()


def test_monitor_alerts_on_missing_heartbeats(h):
    h.start()
    h.replicate()
    h.clock.advance(1201)
    res = check_repository(h.repo, WITNESS_PEM, WITNESS_SHA, LOG_ID, ANCHOR, h.clock())
    assert not res["ok"] and any("stale" in a for a in res["alerts"]) and res["notify"] == ["ADMIN_A", "ADMIN_B"]
    assert res["mock"] and res["production_trust"] is False and "MOCK" in res["label"]


# =========================================================================================== recovery (D11)
def test_ordinary_recovery_with_one_signature(h):
    h.start()
    h.transport.delay = 3.0
    with pytest.raises(Halted):
        h.open_record()                                                 # record 2 written but never confirmed
    h.transport.delay = 0.0
    r = h.gate.recover(h.recovery(ADMIN_A))
    assert r["recovered"] and r["category"] == "ordinary"
    rc = h.store.all()[-1]
    assert rc["kind"] == "recovery" and rc["details"]["signers"] == ["A"] and rc["details"]["unattested_relay_seqs"] == [2]
    assert not (h.tmp / "relay_halt.json").exists() and not h.gate.halted
    h.close_record(t=6.0)                                               # operation continues, linked to the recovery confirmation
    assert verify_checkpoint_chain(h.store.all(), WITNESS_PEM, WITNESS_SHA, LOG_ID)["ok"]


def test_elevated_recovery_rejects_one_signature_and_accepts_two(h):
    h.start()
    h.tamper = lambda lines: lines[:-1] + [lines[-1].replace('"connection_open"', '"connection_close"')] if len(lines) > 1 else lines
    with pytest.raises(Halted):
        h.open_record()
    assert h.witness.fault["category"] == "elevated"
    h.tamper = None
    one = h.gate.recover(h.recovery(ADMIN_A, category="ordinary", cause="ack_timeout"))
    assert not one["recovered"] and "elevated" in one["reason"]
    one_elevated = h.gate.recover(h.recovery(ADMIN_B, category="elevated", cause="integrity"))
    assert not one_elevated["recovered"] and "2 administrator signature" in one_elevated["reason"]
    both = h.gate.recover(h.recovery(ADMIN_A, ADMIN_B, category="elevated", cause="integrity"))
    assert both["recovered"] and both["category"] == "elevated" and h.store.all()[-1]["details"]["signers"] == ["A", "B"]


@pytest.mark.parametrize("mutate,why", [
    (lambda d: d.update(halt_ref="0" * 64), "another halt"), (lambda d: d.update(cause="integrity"), "requires elevated"),
    (lambda d: d.update(operator=""), "operator"), (lambda d: d.update(log_id="other"), None)])
def test_recovery_authorisation_validation(h, mutate, why):
    h.start()
    h.transport.down = True
    h.gate.heartbeat()
    h.transport.down = False
    doc = {k: v for k, v in h.recovery(ADMIN_A).items() if k != "signatures"}
    mutate(doc)
    r = h.gate.recover(signed(doc, ADMIN_A))
    if why:
        assert not r["recovered"] and why in r["reason"]


def test_recovery_authorisation_expiry_and_forgery(h):
    h.start()
    h.transport.down = True
    h.gate.heartbeat()
    h.transport.down = False
    auth = h.recovery(ADMIN_A, valid=60)
    h.clock.advance(61)
    assert not h.gate.recover(auth)["recovered"]
    forged = h.recovery(MockAdministrator("A", Ed25519PrivateKey.generate()))
    assert not h.gate.recover(forged)["recovered"]
    assert h.gate.halted


def test_recovery_refused_when_offhost_disagrees(h):
    h.start()
    h.replicate()
    h.status["v"] = dict(h.status["v"], remote_head_checkpoint_hash="9" * 64)
    h.transport.down = True
    h.gate.heartbeat()
    h.transport.down = False
    r = h.gate.recover(h.recovery(ADMIN_A, ADMIN_B, category="elevated", cause="compromise"))
    assert not r["recovered"] and "off-host head disagrees" in r["reason"]


# =========================================================================================== trust root (D10, D16)
def test_trust_root_establishment_needs_both_signatures():
    now = datetime(2026, 11, 12, tzinfo=timezone.utc)
    assert verify_manifest(MANIFEST, now, pinned_anchor_fingerprint=FINGERPRINT)["category"] == "trust_root_change"
    with pytest.raises(TrustRootError, match="requires 2"):
        verify_manifest(signed(manifest_doc(), ADMIN_A), now, pinned_anchor_fingerprint=FINGERPRINT)


def test_trust_root_change_needs_two_routine_rotation_needs_one():
    now = datetime(2026, 11, 12, tzinfo=timezone.utc)
    _, _, new_witness = key()
    routine = manifest_doc(seq=2, prev=MANIFEST, roles={"checkpoint_witness": new_witness})
    assert verify_manifest(signed(routine, ADMIN_B), now, previous=MANIFEST)["category"] == "routine_rotation"
    change = manifest_doc(seq=2, prev=MANIFEST, digests={"attribution_config": "e" * 64, "policy": "f" * 64})
    with pytest.raises(TrustRootError, match="trust_root_change requires 2"):
        verify_manifest(signed(change, ADMIN_A), now, previous=MANIFEST)
    assert verify_manifest(signed(change, ADMIN_A, ADMIN_B), now, previous=MANIFEST)["category"] == "trust_root_change"
    revoke = manifest_doc(seq=2, prev=MANIFEST, revoked=[RELAY_SHA])
    with pytest.raises(TrustRootError):
        verify_manifest(signed(revoke, ADMIN_A), now, previous=MANIFEST)


def test_replacing_an_administrator_needs_current_administrators():
    now = datetime(2026, 11, 12, tzinfo=timezone.utc)
    mallory = MockAdministrator("B", Ed25519PrivateKey.generate())
    takeover = manifest_doc(seq=2, prev=MANIFEST, admins=(ADMIN_A, mallory))
    with pytest.raises(TrustRootError):
        verify_manifest(signed(takeover, ADMIN_A, mallory), now, previous=MANIFEST)       # mallory is not a current administrator
    with pytest.raises(TrustRootError):
        verify_manifest(signed(manifest_doc(admins=(ADMIN_A, mallory)), ADMIN_A, mallory), now, pinned_anchor_fingerprint=FINGERPRINT)


@pytest.mark.parametrize("roles", [{"checkpoint_witness": RELAY_SHA}, {"attribution_result": WITNESS_SHA}, {"replicator_push": RESULT_SHA},
                                   {"relay_record": ADMIN_A.public_key_sha256}])
def test_six_roles_must_be_distinct(roles):
    with pytest.raises(TrustRootError, match="key-role separation"):
        verify_manifest(signed(manifest_doc(roles=roles), ADMIN_A, ADMIN_B), datetime(2026, 11, 12, tzinfo=timezone.utc),
                        pinned_anchor_fingerprint=FINGERPRINT)


def test_approval_role_is_a_distinct_seventh_role():
    now = datetime(2026, 11, 12, tzinfo=timezone.utc)
    ok = manifest_doc(approval={"sha256": APPROVER_SHA})
    assert verify_manifest(signed(ok, ADMIN_A, ADMIN_B), now, pinned_anchor_fingerprint=anchor_fingerprint(ok))
    dup = manifest_doc(approval={"sha256": RELAY_SHA})
    with pytest.raises(TrustRootError, match="key-role separation"):
        verify_manifest(signed(dup, ADMIN_A, ADMIN_B), now, pinned_anchor_fingerprint=anchor_fingerprint(dup))


def test_manifest_expiry_and_thresholds_cannot_be_weakened():
    with pytest.raises(TrustRootError, match="validity"):
        verify_manifest(MANIFEST, datetime(2028, 1, 1, tzinfo=timezone.utc), pinned_anchor_fingerprint=FINGERPRINT)
    weak = manifest_doc()
    weak["thresholds"] = dict(REQUIRED_THRESHOLDS, trust_root_change=1)
    with pytest.raises(TrustRootError, match="thresholds"):
        verify_manifest(signed(weak, ADMIN_A, ADMIN_B), datetime(2026, 11, 12, tzinfo=timezone.utc), pinned_anchor_fingerprint=FINGERPRINT)


# =========================================================================================== placeholders / production mode
def test_repository_offhost_config_is_placeholder_and_blocks_production():
    cfg = load_offhost_config()
    assert set(placeholder_fields(cfg)) == {"trust_anchor_repository", "witness_log_repository", "administrators", "replication_credential",
                                            "trust_anchor_fingerprint"}
    assert cfg["administrators"] == {"A": "ADMIN_A_PENDING", "B": "ADMIN_B_PENDING"} and cfg["replication_credential"] == "NOT_CONFIGURED"
    assert cfg["trust_anchor_fingerprint"] == "PENDING_PROVISIONING" and "PLACEHOLDER" in cfg["trust_anchor_repository"]
    with pytest.raises(ProductionNotReady):
        assert_production_ready(cfg)


@pytest.mark.parametrize("script", ["witness_service.py", "replicator_service.py", "recover.py"])
def test_entry_points_refuse_production(script):
    p = subprocess.run([sys.executable, str(REPO / "cowrie" / "witness" / script), "--mode", "production"], capture_output=True, text=True)
    assert p.returncode != 0 and "production startup refused" in (p.stderr + p.stdout)


def test_production_refused_even_without_placeholders(tmp_path):
    cfg = load_offhost_config()
    good = dict(cfg, trust_anchor_repository="https://example.invalid/a.git", witness_log_repository="https://example.invalid/w.git",
                administrators={"A": "x", "B": "y"}, replication_credential="configured", trust_anchor_fingerprint="0" * 64)
    assert assert_production_ready(good)
    (tmp_path / "c.json").write_text(json.dumps(good))
    p = subprocess.run([sys.executable, str(REPO / "cowrie" / "witness" / "witness_service.py"), "--mode", "production",
                        "--offhost-config", str(tmp_path / "c.json")], capture_output=True, text=True)
    assert p.returncode != 0 and "M7" in (p.stderr + p.stdout)


def test_pending_fingerprint_cannot_establish_trust():
    with pytest.raises(TrustRootError, match="PENDING_PROVISIONING"):
        verify_manifest(MANIFEST, datetime(2026, 11, 12, tzinfo=timezone.utc), pinned_anchor_fingerprint="PENDING_PROVISIONING")
    placeholder_admin = manifest_doc()
    placeholder_admin["administrators"]["A"] = {"name": "A", "public_key_sha256": "ADMIN_A_PENDING", "public_key_pem": "ADMIN_A_PENDING"}
    with pytest.raises(TrustRootError, match="placeholder"):
        verify_manifest(placeholder_admin, datetime(2026, 11, 12, tzinfo=timezone.utc), pinned_anchor_fingerprint=FINGERPRINT)


# =========================================================================================== mock repository tampering
def test_mock_repositories_are_labelled_and_enforce_rulesets(h):
    h.start()
    h.replicate()
    for m in (h.repo, h.anchors, ADMIN_A):
        assert m.is_mock and m.production_trust is False and m.delivered_offhost is False and m.label == MOCK_LABEL
    assert h.status["v"]["mock"] and h.status["v"]["production_trust"] is False and h.status["v"]["authoritative"] is False
    with pytest.raises(MockRejected):
        h.repo.force_push([])
    with pytest.raises(MockRejected):
        h.repo.delete()
    with pytest.raises(MockRejected):
        h.repo.push([], h.clock(), parent="not-the-head")
    with pytest.raises(MockRejected):
        h.anchors.publish(MANIFEST, by="local-operator")


@pytest.mark.parametrize("attack,expect", [("rewrite_history", "fast-forward"), ("edit_checkpoint", "chain invalid"),
                                           ("drop_checkpoint", "chain invalid"), ("foreign_anchor", "trust-anchor digest")])
def test_monitor_detects_mock_repository_tampering(h, attack, expect):
    h.start()
    h.replicate()
    h.open_record()
    h.replicate()
    hist = h.repo.history()
    if attack == "rewrite_history":
        hist[1]["parent"] = "forged"
    elif attack == "edit_checkpoint":
        hist[1]["checkpoints"][0]["relay_record_type"] = "connection_close"
    elif attack == "drop_checkpoint":
        hist[0]["checkpoints"] = []
    h.repo._tamper_rewrite(hist)
    anchor = "1" * 64 if attack == "foreign_anchor" else ANCHOR
    res = check_repository(h.repo, WITNESS_PEM, WITNESS_SHA, LOG_ID, anchor, h.clock())
    assert not res["ok"] and any(expect in a for a in res["alerts"])


# =========================================================================================== assessment: unconfirmed results
def _att_with_witness(status="mock", anchor=ANCHOR, pem=WITNESS_PEM, sha=WITNESS_SHA, allow=True):
    doc = att3_doc()
    doc["checkpoint_witness"] = {"status": status, "public_key_sha256": sha, "max_checkpoint_age_seconds": 120,
                                 "max_replication_lag_seconds": 900, "trust_anchor_digest": anchor}
    return doc, AttributionConfig.from_document(doc, address_doc=ADDR, result_public_key_pem=RESULT_PEM, witness_public_key_pem=pem,
                                                allow_mock_witness=allow)


def _witnessed_result(h, with_witness=True, checkpoints=True, issued_offset=60):
    h.start()
    h.open_record()
    h.close_record()
    h.replicate()
    events = relay_session("d1", 50001)
    doc, _ = _att_with_witness()
    cfg = config_from_document(doc)
    chain = h.store.all()
    now = T0 + timedelta(seconds=issued_offset)
    corr = correlate(events, h.read_log(), RELAY_PEM, cfg, evaluation_time=now, checkpoints=v1_view(chain) if checkpoints else None)
    wit = witness_evidence(chain, h.status["v"], now, mock=True) if with_witness else None
    res = build_result(corr, correlate_authentication(events), cfg, events, now - timedelta(seconds=1), 600, now, witness=wit)
    return doc, sign_result(res, RESULT_KEY), events, now


def _assess(doc, cfg, signed_result, events, now):
    a = ThreatAssessor(cfg, PolicyConfig.from_document(policy21(doc)), ECFG)
    rec = EvidenceEngine(ECFG).evaluate(events)["sessions"][0]
    return a.assess(rec, signed_result, now=now)


def test_confirmed_result_is_accepted_but_marked_mock(h):
    doc, signed_result, events, now = _witnessed_result(h)
    _, cfg = _att_with_witness()
    out = _assess(doc, cfg, signed_result, events, now)
    assert out["tier"] == "propose" and out["session_attribution"]["state"] == "attributable_via_proxy_mapping"
    assert out["versions"]["attribution_results"]["accepted"][0]["witness_status"].startswith("TEST/LOCAL MOCK")
    assert signed_result["relay_log"]["witness"]["mode"].startswith("TEST/LOCAL MOCK")


@pytest.mark.parametrize("variant,why", [("no_witness_block", "no witness checkpoint"), ("tail_unattested", "not attested"),
                                         ("tampered_checkpoint", "modified"), ("stale", "stale"), ("other_anchor", "trust anchor"),
                                         ("no_offhost", "off-host")])
def test_unconfirmed_results_are_rejected(h, variant, why):
    import client_attribution.result as res_mod
    doc, signed_result, events, now = _witnessed_result(h, with_witness=variant != "no_witness_block", checkpoints=variant != "tail_unattested")
    anchor = "2" * 64 if variant == "other_anchor" else ANCHOR
    doc2, cfg = _att_with_witness(anchor=anchor)
    if variant == "other_anchor":                                       # same result, signed under the config that pins another anchor
        from threat_assessment.config import canonical_digest
        body = {k: v for k, v in copy.deepcopy(signed_result).items() if k not in ("signer", "result_hash", "signature")}
        body["attribution_config"]["digest"] = canonical_digest(doc2)
        signed_result = res_mod.sign_result(body, RESULT_KEY)
    if variant in ("tampered_checkpoint", "stale", "no_offhost"):
        body = {k: v for k, v in copy.deepcopy(signed_result).items() if k not in ("signer", "result_hash", "signature")}
        w = body["relay_log"]["witness"]
        if variant == "tampered_checkpoint":
            w["checkpoint"]["relay_seq"] = 99
        elif variant == "stale":
            w["checkpoint"] = h.store.all()[0]
            body["relay_log"]["tail"]["last_seq"] = 1
        else:
            w["offhost_confirmed_utc"] = None
        signed_result = res_mod.sign_result(body, RESULT_KEY)
        if variant == "stale":
            now = T0 + timedelta(seconds=300)
            body["issued_utc"] = (now - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            body["not_after_utc"] = (now + timedelta(seconds=500)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            signed_result = res_mod.sign_result(body, RESULT_KEY)
    out = _assess(doc2, cfg, signed_result, events, now)
    assert out["proposed_action"] is None and out["session_attribution"]["state"] == "unattributed:result_rejected"
    reason = out["versions"]["attribution_results"]["rejected"][0]["reason"]
    assert why in reason or (variant == "stale" and "does not confirm" in reason), reason


def test_signer_refuses_stale_or_unreplicated_evidence(h):
    h.start()
    h.open_record()
    chain = h.store.all()
    with pytest.raises(ValueError, match="off-host"):
        witness_evidence(chain, None, h.clock())
    h.replicate()
    with pytest.raises(ValueError, match="stale"):
        witness_evidence(chain, h.status["v"], h.clock() + timedelta(seconds=121))


def test_mock_witness_config_refused_outside_mock_mode_and_role_separation():
    with pytest.raises(AssessmentConfigError, match="TEST/LOCAL MOCK"):
        _att_with_witness(allow=False)
    with pytest.raises(AssessmentConfigError, match="key-role separation"):
        _att_with_witness(pem=RELAY_PEM, sha=RELAY_SHA)
    with pytest.raises(AssessmentConfigError, match="PENDING_PROVISIONING"):
        _att_with_witness(anchor="PENDING_PROVISIONING")


def test_existing_configs_have_no_witness_requirement():
    from threat_assessment import load_attribution_config
    att = load_attribution_config(REPO / "configs" / "threat_attribution_v3.json")
    assert att.witness_key_sha256 is None and att.witness_status == "none"


# =========================================================================================== key separation (six roles)
def test_six_test_key_roles_are_distinct_and_witness_holds_only_its_key(h):
    ids = {RELAY_SHA, RESULT_SHA, WITNESS_SHA, ADMIN_A.public_key_sha256, ADMIN_B.public_key_sha256, C1_SHA}
    assert len(ids) == 6 and APPROVER_SHA not in ids
    with pytest.raises(ValueError, match="key-role separation"):
        WitnessCore(LOG_ID, RELAY_PEM, RELAY_SHA, RELAY_KEY, RELAY_SHA, ANCHOR, h.store, h.read_log, h.clock)
    with pytest.raises(ValueError, match="key-role separation"):
        RelayWitnessGate(h.writer, h.transport, RELAY_PEM, RELAY_SHA, RELAY_SHA, LOG_ID, h.clock, [])
    for f in ("witness.py", "replicator.py", "offhost_monitor.py", "trust_root.py", "framing.py", "placeholders.py"):
        src = (REPO / "client_attribution" / f).read_text(encoding="utf-8")
        assert "load_pem_private_key" not in src and "PRIVATE KEY" not in src, f
        assert "github.com" not in src and "requests" not in src and "urllib" not in src, f
