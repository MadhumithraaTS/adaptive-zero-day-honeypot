"""Task 28B: non-blocking relay-witness gate. Deterministic event loop (FakeScheduler) and a controlled mock witness
transport; the witness itself is the real WitnessCore. Ephemeral test keys only; no network, no deployment change."""
import heapq
import itertools
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "cowrie" / "attributing_relay"))

from async_gate import AsyncRelayWitnessGate, Halted, Pending  # noqa: E402
from client_attribution.checkpoints import verify_checkpoint_chain  # noqa: E402
from client_attribution.framing import respond  # noqa: E402
from client_attribution.offhost_mock import signed  # noqa: E402
from client_attribution.trust_root import RECOVERY_SCHEMA  # noqa: E402
from client_attribution.witness import CheckpointStore, WitnessCore  # noqa: E402
from relay_gate import RecordWriterV2  # noqa: E402
from test_checkpoint_witness import (ADMIN_A, ADMIN_B, ANCHOR, LOG_ID, MANIFEST, PARAMS, WITNESS_KEY, WITNESS_PEM, WITNESS_SHA, FakeListener,  # noqa: E402
                                     FakeSession)
from trust_fixtures import RELAY_KEY, RELAY_PEM, RELAY_SHA  # noqa: E402

BASE = datetime(2026, 11, 12, 10, 0, 0, tzinfo=timezone.utc)


class FakeScheduler:
    """Deterministic event loop: events run in (time, scheduling order); nothing blocks."""

    class Handle:
        def __init__(self):
            self.cancelled = False

        def cancel(self):
            self.cancelled = True

    def __init__(self):
        self.t, self._q, self._n = 0.0, [], itertools.count()

    def call_later(self, seconds, fn):
        h = self.Handle()
        heapq.heappush(self._q, (self.t + seconds, next(self._n), h, fn))
        return h

    def seconds(self):
        return self.t

    def advance(self, dt):
        target = self.t + dt
        while self._q and self._q[0][0] <= target + 1e-12:
            when, _, h, fn = heapq.heappop(self._q)
            self.t = when
            if not h.cancelled:
                fn()
        self.t = target

    def now(self):
        return BASE + timedelta(seconds=self.t)


class MockWitnessTransport:
    """Controlled async witness: each response is delivered after a scripted delay (None = never)."""

    def __init__(self, sched, witness):
        self.sched, self.witness, self.gate = sched, witness, None
        self.delay = lambda frame: 0.1
        self.mutate = None
        self.duplicate = False
        self.sent, self.responses, self.fail_send, self.lose_requests = [], [], False, False

    def send(self, frame):
        if self.fail_send:
            raise ConnectionError("socket closed")
        self.sent.append((self.sched.seconds(), json.loads(json.dumps(frame))))
        if self.lose_requests:
            return                                                           # the witness never sees the request
        resp = respond(self.witness.handle, frame)
        self.responses.append(resp)
        if self.mutate:
            resp = self.mutate(frame, resp)
        d = self.delay(frame)
        if d is None:
            return
        self.sched.call_later(d, lambda: self.gate.on_response(json.loads(json.dumps(resp))))
        if self.duplicate:
            self.sched.call_later(d + 0.05, lambda: self.gate.on_response(json.loads(json.dumps(resp))))


class Rig:
    def __init__(self, tmp):
        self.sched, self.tmp = FakeScheduler(), tmp
        iso = lambda: self.sched.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")          # noqa: E731
        self.writer = RecordWriterV2(RELAY_KEY, RELAY_SHA, iso, path=tmp / "relay.jsonl")
        self.store = CheckpointStore(tmp / "cp.jsonl")
        status = lambda: {"remote_head_checkpoint_seq": 10 ** 9, "remote_head_checkpoint_hash": None, "pushed_utc": iso(),  # noqa: E731
                          "anchor_match": True, "mock": True}
        self.witness = WitnessCore(LOG_ID, RELAY_PEM, RELAY_SHA, WITNESS_KEY, WITNESS_SHA, ANCHOR, self.store, self.read_log, self.sched.now,
                                   replication_status=status, manifest=MANIFEST, params=PARAMS)
        self.transport = MockWitnessTransport(self.sched, self.witness)
        self.listeners = [FakeListener("published"), FakeListener("demo")]
        self.gate = AsyncRelayWitnessGate(self.writer, self.transport, WITNESS_PEM, WITNESS_SHA, RELAY_SHA, LOG_ID, self.sched, self.listeners,
                                          timeout=2.0, heartbeat_interval=60.0, halt_marker=tmp / "halt.json")
        self.transport.gate = self.gate

    def read_log(self):
        p = self.tmp / "relay.jsonl"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []

    def start(self):
        p = self.gate.start(listeners=[], backend="cowrie:2222", public_key_sha256=RELAY_SHA)
        self.sched.advance(0.2)
        assert p.done and p.ok
        return p

    def rec(self, i):
        return {"connection_id": f"c{i}", "reason": "test"}

    def recovery(self, *admins, category="ordinary", cause="ack_timeout"):
        now = self.sched.now()
        doc = {"schema": RECOVERY_SCHEMA, "log_id": LOG_ID, "halt_ref": self.witness.head_ref(), "category": category, "cause": cause,
               "incident_ref": "INC-28B", "issued_utc": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
               "valid_until": (now + timedelta(seconds=600)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "operator": "operator-test"}
        return signed(doc, *admins)


@pytest.fixture
def r(tmp_path):
    return Rig(tmp_path)


def records(r):
    return [json.loads(l) for l in r.read_log()]


# =========================================================================================== start / basic
def test_start_is_asynchronous_and_listeners_wait_for_confirmation(r):
    opened = []
    p = r.gate.start(listeners=[], backend="cowrie:2222", public_key_sha256=RELAY_SHA).add_callbacks(lambda rec: opened.append(rec["seq"]))
    assert not p.done and opened == [] and r.sched.t == 0.0              # returned immediately; nothing opened yet
    r.sched.advance(0.1)
    assert p.ok and opened == [1] and r.store.all()[0]["relay_record_type"] == "relay_start"


def test_slow_witness_within_two_seconds_is_accepted(r):
    r.start()
    r.transport.delay = lambda f: 1.9
    p = r.gate.append("connection_rejected", **r.rec(1))
    r.sched.advance(1.89)
    assert not p.done and not r.gate.halted
    r.sched.advance(0.02)
    assert p.ok and not r.gate.halted


# =========================================================================================== timeout / late
def test_timeout_is_exactly_two_seconds(r):
    r.start()
    t_sent = r.sched.t
    r.transport.delay = lambda f: 5.0
    p = r.gate.append("connection_rejected", **r.rec(1))
    r.sched.advance(1.999)
    assert not r.gate.halted and not p.done
    r.sched.advance(0.001)
    assert r.gate.halted and r.gate.halt_cause == "ack_timeout" and abs(r.sched.t - t_sent - 2.0) < 1e-9
    assert p.done and not p.ok and isinstance(p.value, Halted)


def test_confirmation_at_exactly_two_seconds_is_late(r):
    r.start()
    r.transport.delay = lambda f: 2.0
    r.gate.append("connection_rejected", **r.rec(1))
    r.sched.advance(2.0)
    assert r.gate.halted and r.gate.halt_cause == "ack_timeout" and r.gate.stats["rejected_after_halt"] == 1


def test_late_confirmation_after_halt_is_ignored(r):
    r.start()
    r.transport.delay = lambda f: 3.0
    p = r.gate.append("connection_rejected", **r.rec(1))
    r.sched.advance(5.0)
    assert r.gate.halted and r.gate.halt_cause == "ack_timeout" and not p.ok
    assert r.gate.stats["rejected_after_halt"] == 1 and r.gate.stats["confirmed"] == 1      # only relay_start was ever confirmed


# =========================================================================================== invalid / out-of-order / duplicate / replay
def test_invalid_signature_halts(r):
    r.start()

    def bad(frame, resp):
        resp = json.loads(json.dumps(resp))
        resp["checkpoint"]["signature"] = "00" * 64
        return resp
    r.transport.mutate = bad
    p = r.gate.append("connection_rejected", **r.rec(1))
    r.sched.advance(1)
    assert r.gate.halt_cause == "invalid_ack" and not p.ok


def test_out_of_order_confirmation_halts(r):
    r.start()
    r.transport.mutate = lambda frame, resp: dict(resp, request_id="r999")
    r.gate.append("connection_rejected", **r.rec(1))
    r.sched.advance(1)
    assert r.gate.halt_cause == "out_of_order_confirmation"


def test_replayed_previous_confirmation_halts(r):
    r.start()
    first = dict(r.transport.responses[0])
    r.transport.mutate = lambda frame, resp: dict(first, request_id=frame["request_id"])   # old ack re-labelled with the current id
    r.gate.append("connection_rejected", **r.rec(1))
    r.sched.advance(1)
    assert r.gate.halt_cause == "invalid_ack"


def test_duplicate_confirmation_is_rejected(r):
    r.start()
    r.transport.duplicate = True
    p = r.gate.append("connection_rejected", **r.rec(1))
    r.sched.advance(1)
    assert p.ok and r.gate.halted and r.gate.halt_cause == "unexpected_confirmation"


def test_conflicting_confirmation_for_another_record_halts(r):
    r.start()
    r.transport.mutate = lambda frame, resp: dict(respond(r.witness.handle, {"type": "heartbeat", "log_id": LOG_ID}),
                                                  request_id=frame["request_id"]) if frame["type"] == "attest" else resp
    r.gate.append("connection_rejected", **r.rec(1))
    r.sched.advance(1)
    assert r.gate.halt_cause == "invalid_ack"


def test_witness_nack_halts(r):
    r.start()
    r.witness.fault = {"cause": "storage", "category": "ordinary", "checkpoint_hash": None}
    r.gate.append("connection_rejected", **r.rec(1))
    r.sched.advance(1)
    assert r.gate.halted and r.gate.halt_cause.startswith("nack:")


# =========================================================================================== concurrency / ordering
def test_concurrent_sessions_are_serialised_one_outstanding(r):
    r.start()
    r.transport.delay = lambda f: 0.3
    pend = [r.gate.append("connection_rejected", **r.rec(i)) for i in range(5)]
    assert all(not p.done for p in pend) and len(r.read_log()) == 2         # only the first queued record is written yet
    r.sched.advance(3.0)
    assert all(p.ok for p in pend) and not r.gate.halted
    sends = [t for t, f in r.transport.sent[1:]]
    assert sends == pytest.approx([0.2 + 0.3 * k for k in range(5)])        # each sent only after the previous confirmation
    assert r.gate.stats["max_outstanding"] == 1


def test_queued_requests_do_not_time_out_behind_others(r):
    r.start()
    r.transport.delay = lambda f: 0.5
    pend = [r.gate.append("connection_rejected", **r.rec(i)) for i in range(8)]
    r.sched.advance(4.5)
    assert all(p.ok for p in pend) and not r.gate.halted                    # total 4 s > 2 s: the timer is per request from send


def test_multiple_simultaneous_writes_keep_order_and_cross_links(r):
    r.start()
    order = []
    for i in range(3):
        r.gate.append("connection_rejected", **r.rec(i)).add_callbacks(lambda rec, i=i: order.append(("rec", i, rec["seq"])))
    r.gate.heartbeat().add_callbacks(lambda cp: order.append(("hb", cp["checkpoint_seq"])))
    for i in range(3, 5):
        r.gate.append("connection_rejected", **r.rec(i)).add_callbacks(lambda rec, i=i: order.append(("rec", i, rec["seq"])))
    r.sched.advance(2.0)
    assert order == [("rec", 0, 2), ("rec", 1, 3), ("rec", 2, 4), ("hb", 5), ("rec", 3, 5), ("rec", 4, 6)]
    recs, cps = records(r), r.store.all()
    assert [x["seq"] for x in recs] == [1, 2, 3, 4, 5, 6]
    by_rec = {c["relay_seq"]: c for c in cps if c["kind"] == "attest"}
    for rec in recs[1:]:
        prev_cp = [c for c in cps if c["checkpoint_seq"] == rec["witness_ack"]["checkpoint_seq"]][0]
        assert rec["witness_ack"]["checkpoint_hash"] == prev_cp["checkpoint_hash"]
        assert by_rec[rec["seq"]]["prev_checkpoint_hash"] == prev_cp["checkpoint_hash"]
    assert verify_checkpoint_chain(cps, WITNESS_PEM, WITNESS_SHA, LOG_ID)["ok"]


# =========================================================================================== heartbeat
def test_heartbeats_run_every_60s_and_expiry_halts(r):
    r.start()
    r.gate.start_heartbeats()
    r.sched.advance(60.5)
    assert r.store.all()[-1]["kind"] == "heartbeat" and not r.gate.halted
    r.transport.delay = lambda f: None if f["type"] == "heartbeat" else 0.1
    r.sched.advance(60.0)
    assert not r.gate.halted                                                 # heartbeat 2 sent at 120.2, still within 2 s
    r.sched.advance(2.0)
    assert r.gate.halted and r.gate.halt_cause == "heartbeat_missing"
    sent_after = len(r.transport.sent)
    r.sched.advance(300)
    assert len(r.transport.sent) == sent_after                               # heartbeat loop cancelled on halt


# =========================================================================================== halt during active sessions
def test_halt_during_active_sessions_stops_everything(r):
    r.start()
    sessions = [FakeSession() for _ in range(4)]
    for s in sessions:
        r.gate.register_session(s)
    r.transport.delay = lambda f: None                                       # witness stops answering
    pend = [r.gate.append("connection_rejected", **r.rec(i)) for i in range(4)]
    r.sched.advance(2.0)
    assert r.gate.halted and [l.stopped for l in r.listeners] == [True, True]
    assert all(s.aborted for s in sessions) and not r.gate.sessions
    assert all(p.done and not p.ok and isinstance(p.value, Halted) for p in pend) and not r.gate.queue
    assert len(r.read_log()) == 2                                            # queued records were never written
    late = r.gate.append("connection_rejected", **r.rec(9))
    assert late.done and not late.ok
    with pytest.raises(Halted):
        r.gate.register_session(FakeSession())
    assert json.loads((r.tmp / "halt.json").read_text())["cause"] == "ack_timeout"


def test_send_failure_and_lost_transport_halt(r, tmp_path):
    r.start()
    r.transport.fail_send = True
    r.gate.append("connection_rejected", **r.rec(1))
    assert r.gate.halted and r.gate.halt_cause == "witness_unavailable"
    (tmp_path / "b").mkdir(exist_ok=True)
    r2 = Rig(tmp_path / "b")
    r2.start()
    r2.gate.transport_lost("socket closed")
    assert r2.gate.halted and r2.gate.halt_cause == "witness_unavailable"


# =========================================================================================== event-loop responsiveness
def test_event_loop_stays_responsive_during_delayed_confirmation(r):
    r.start()
    r.transport.delay = lambda f: 1.9
    t_call = r.sched.t
    p = r.gate.append("connection_rejected", **r.rec(1))
    assert r.sched.t == t_call and not p.done                               # returned at once: no time passed inside the call
    ticks = []

    def tick():
        ticks.append((r.sched.t, p.done))
        if len(ticks) < 18:
            r.sched.call_later(0.1, tick)
    r.sched.call_later(0.1, tick)
    other = []
    r.sched.call_later(0.5, lambda: other.append("other session relayed data"))
    r.sched.advance(1.85)
    assert len(ticks) == 18 and not any(done for _, done in ticks) and other
    r.sched.advance(0.1)
    assert p.ok


# =========================================================================================== restart / recovery
def test_restart_with_halt_marker_refused_and_async_recovery(r):
    r.start()
    r.transport.delay = lambda f: None
    r.gate.append("connection_rejected", **r.rec(1))
    r.sched.advance(2.0)
    assert r.gate.halted
    g2 = AsyncRelayWitnessGate(r.writer, r.transport, WITNESS_PEM, WITNESS_SHA, RELAY_SHA, LOG_ID, r.sched, [FakeListener("x")],
                               halt_marker=r.tmp / "halt.json")
    with pytest.raises(Halted, match="manual recovery"):
        g2.start(listeners=[], backend="x", public_key_sha256=RELAY_SHA)
    r.transport.delay = lambda f: 0.1
    bad = r.gate.recover(r.recovery(ADMIN_A, category="elevated", cause="integrity"))
    r.sched.advance(0.2)
    assert bad.done and not bad.ok and r.gate.halted                       # one signature cannot authorise elevated recovery
    rec = r.gate.recover(r.recovery(ADMIN_A))
    assert not rec.done
    r.sched.advance(0.2)
    assert rec.ok and not r.gate.halted and not (r.tmp / "halt.json").exists()
    # the answer was lost but the witness DID receive and confirm record 2: nothing is unattested
    assert rec.value["details"]["unattested_relay_seqs"] == [] and any(c["kind"] == "attest" and c["relay_seq"] == 2 for c in r.store.all())
    p = r.gate.append("connection_rejected", **r.rec(2))
    r.sched.advance(0.2)
    assert p.ok and records(r)[-1]["witness_ack"]["checkpoint_hash"] == rec.value["checkpoint_hash"]


def test_lost_request_leaves_record_explicitly_unattested(r):
    r.start()
    r.transport.lose_requests = True
    r.gate.append("connection_rejected", **r.rec(1))
    r.sched.advance(2.0)
    assert r.gate.halted and r.gate.halt_cause == "ack_timeout"
    r.transport.lose_requests = False
    rec = r.gate.recover(r.recovery(ADMIN_A))
    r.sched.advance(0.2)
    assert rec.ok and rec.value["details"]["unattested_relay_seqs"] == [2]
    assert not any(c["kind"] == "attest" and c["relay_seq"] == 2 for c in r.store.all())   # never attested after the fact


def test_recovery_refused_unless_halted_and_idle(r):
    r.start()
    p = r.gate.recover(r.recovery(ADMIN_A))
    assert p.done and not p.ok


def test_recovery_needs_two_signatures_for_elevated_faults(r):
    r.start()
    real = r.witness.handle

    def tamper_once(frame):
        if frame.get("type") == "attest":
            r.witness.fault = None
            return r.witness._fault("integrity", "test integrity fault")
        return real(frame)
    r.transport.witness = type("W", (), {"handle": staticmethod(tamper_once)})()
    r.gate.append("connection_rejected", **r.rec(1))
    r.sched.advance(0.2)
    assert r.gate.halted and r.witness.fault["category"] == "elevated"
    r.transport.witness = r.witness
    one = r.gate.recover(r.recovery(ADMIN_B, category="elevated", cause="integrity"))
    r.sched.advance(0.2)
    assert not one.ok
    both = r.gate.recover(r.recovery(ADMIN_A, ADMIN_B, category="elevated", cause="integrity"))
    r.sched.advance(0.2)
    assert both.ok and both.value["details"]["signers"] == ["A", "B"]


def test_pending_callbacks_after_resolution():
    p = Pending()
    got = []
    p.resolve(5)
    p.add_callbacks(got.append)
    p.fail(RuntimeError("ignored"))
    assert got == [5] and p.ok
