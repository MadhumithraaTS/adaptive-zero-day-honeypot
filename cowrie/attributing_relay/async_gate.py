"""Non-blocking relay-witness gate (Task 28B). Reactor-agnostic; holds ONLY the relay record key.

Concurrency model - strict serialisation without blocking:
  * every append/heartbeat returns a `Pending` IMMEDIATELY; nothing ever waits on the event loop;
  * at most ONE witness request is outstanding; further requests wait in a FIFO queue. A record is written to disk
    only when it is dequeued, so its `witness_ack` always names the confirmation of the record before it and the
    on-disk order equals the confirmation order;
  * each request carries a unique `request_id`; its 2.0-s timer starts when the frame is sent. A confirmation must
    arrive strictly before the timer fires (equal-time events run in scheduling order, and the timer is scheduled
    first). Late, unexpected, duplicate, replayed, out-of-order, invalid or conflicting confirmations HALT;
  * HALT stops BOTH listeners, aborts ALL in-progress sessions, fails every pending/queued request, cancels timers
    and the heartbeat loop, and writes the halt marker. A restart with the marker present is refused.

Interfaces: `scheduler.call_later(seconds, fn) -> handle(.cancel())`, `scheduler.seconds() -> float`;
`transport.send(frame)` (non-blocking); the transport calls `gate.on_response(frame)` / `gate.transport_lost(reason)`.
"""
import json
from collections import deque
from pathlib import Path

from relay_gate import Halted                                      # sets sys.path; the synchronous gate is unchanged
from client_attribution.checkpoints import GENESIS_V2, verify_checkpoint_v2  # noqa: E402
from client_attribution.records import load_public_key  # noqa: E402


class Pending:
    """Minimal one-shot result holder (Twisted-independent); callbacks run synchronously on resolution."""

    def __init__(self):
        self.done, self.ok, self.value, self._cbs = False, None, None, []

    def add_callbacks(self, on_ok, on_err=None):
        if self.done:
            (on_ok if self.ok else (on_err or (lambda e: None)))(self.value)
        else:
            self._cbs.append((on_ok, on_err))
        return self

    def _finish(self, ok, value):
        if self.done:
            return
        self.done, self.ok, self.value = True, ok, value
        for on_ok, on_err in self._cbs:
            (on_ok if ok else (on_err or (lambda e: None)))(value)
        self._cbs = []

    def resolve(self, value):
        self._finish(True, value)

    def fail(self, exc):
        self._finish(False, exc)


class AsyncRelayWitnessGate:
    def __init__(self, writer, transport, witness_public_pem, witness_pin, relay_pin, log_id, scheduler, listeners=(), timeout=2.0,
                 heartbeat_interval=60.0, halt_marker=None, on_halt=None):
        if witness_pin == relay_pin:
            raise ValueError("key-role separation: witness key equals relay key")
        self.witness_pub, sha = load_public_key(witness_public_pem)
        if sha != witness_pin:
            raise ValueError("witness public key does not match its pin")
        self.writer, self.transport, self.pin, self.log_id, self.sched = writer, transport, witness_pin, log_id, scheduler
        self.listeners, self.timeout, self.hb_interval = list(listeners), float(timeout), float(heartbeat_interval)
        self.halt_marker, self.on_halt = Path(halt_marker) if halt_marker else None, on_halt
        self.sessions, self.queue, self.outstanding = set(), deque(), None
        self.halted, self.halt_cause, self.last_ack = False, None, None
        self._next_id, self._hb_handle = 0, None
        self.stats = {"sent": 0, "confirmed": 0, "max_outstanding": 0, "rejected_after_halt": 0}

    # ------------------------------------------------------------------------------------------------ sessions
    def register_session(self, s):
        if self.halted:
            raise Halted(f"relay halted ({self.halt_cause})")
        self.sessions.add(s)

    def unregister_session(self, s):
        self.sessions.discard(s)

    # ------------------------------------------------------------------------------------------------ public API
    def start(self, **relay_start_fields):
        """Queue relay_start. The caller opens listeners only in the success callback. Refused if a halt marker exists."""
        if self.halt_marker and self.halt_marker.exists():
            self.halted = True
            self.halt_cause = json.loads(self.halt_marker.read_text(encoding="utf-8")).get("cause")
            raise Halted(f"halt marker present ({self.halt_cause}): manual recovery required")
        return self.append("relay_start", **relay_start_fields)

    def append(self, rtype, **fields):
        p = Pending()
        if self.halted:
            p.fail(Halted(f"relay halted ({self.halt_cause})"))
            return p
        self.queue.append(("attest", rtype, fields, p))
        self._pump()
        return p

    def heartbeat(self):
        p = Pending()
        if self.halted:
            p.fail(Halted(f"relay halted ({self.halt_cause})"))
            return p
        self.queue.append(("heartbeat", None, None, p))
        self._pump()
        return p

    def start_heartbeats(self):
        def tick():
            self._hb_handle = None
            if not self.halted:
                self.heartbeat()
                self._hb_handle = self.sched.call_later(self.hb_interval, tick)
        self._hb_handle = self.sched.call_later(self.hb_interval, tick)

    # ------------------------------------------------------------------------------------------------ engine
    def _pump(self):
        if self.halted or self.outstanding is not None or not self.queue:
            return
        kind, rtype, fields, p = self.queue.popleft()
        self._next_id += 1
        rid = f"r{self._next_id}"
        if kind == "attest":
            ack_ref = None if self.last_ack is None else {"checkpoint_seq": self.last_ack["checkpoint_seq"],
                                                           "checkpoint_hash": self.last_ack["checkpoint_hash"]}
            rec = self.writer.write(rtype, ack_ref, **fields)          # written only now: witness_ack is exact
            frame = {"type": "attest", "log_id": self.log_id, "seq": rec["seq"], "record_hash": rec["record_hash"], "request_id": rid}
        else:
            rec, frame = None, {"type": "heartbeat", "log_id": self.log_id, "request_id": rid}
        cause = "heartbeat_missing" if kind == "heartbeat" else "ack_timeout"
        self.outstanding = {"id": rid, "kind": kind, "record": rec, "pending": p, "sent_at": self.sched.seconds(),
                            "timer": self.sched.call_later(self.timeout, lambda: self._expired(rid, cause))}
        self.stats["sent"] += 1
        self.stats["max_outstanding"] = max(self.stats["max_outstanding"], 1)
        try:
            self.transport.send(frame)
        except Exception as exc:                                       # noqa: BLE001 - any send failure is fail-closed
            self.halt("witness_unavailable", detail=str(exc))

    def _expired(self, rid, cause):
        if self.outstanding is not None and self.outstanding["id"] == rid and not self.halted:
            self.outstanding["timer"] = None
            self.halt(cause)

    def on_response(self, resp):
        if self._recovery is not None and isinstance(resp, dict) and resp.get("request_id") == self._recovery["id"]:
            return self.on_recovery_response(resp)                   # the only answer accepted while halted
        if self.halted:
            self.stats["rejected_after_halt"] += 1                  # late/duplicate after halt: ignored, never un-halts
            return
        o = self.outstanding
        if o is None:
            self.halt("unexpected_confirmation")                     # duplicate or replayed confirmation while idle
            return
        if not isinstance(resp, dict) or resp.get("request_id") != o["id"]:
            self.halt("out_of_order_confirmation")
            return
        if self.sched.seconds() - o["sent_at"] >= self.timeout:
            self.halt("late_confirmation")
            return
        if resp.get("type") != "ack":
            self.halt(f"nack:{resp.get('cause')}")
            return
        cp = resp.get("checkpoint")
        try:
            verify_checkpoint_v2(cp, self.witness_pub, self.pin)
        except ValueError:
            self.halt("invalid_ack")
            return
        prev = self.last_ack["checkpoint_hash"] if self.last_ack else GENESIS_V2
        ok = cp["kind"] == o["kind"] and cp["log_id"] == self.log_id and cp["prev_checkpoint_hash"] == prev
        if o["kind"] == "attest":
            ok = ok and cp["relay_seq"] == o["record"]["seq"] and cp["relay_record_hash"] == o["record"]["record_hash"]
        if not ok:
            self.halt("invalid_ack")                                 # conflicting / replayed / out-of-order content
            return
        if o["timer"] is not None:
            o["timer"].cancel()
        self.last_ack, self.outstanding = cp, None
        self.stats["confirmed"] += 1
        o["pending"].resolve(o["record"] if o["kind"] == "attest" else cp)
        self._pump()

    def transport_lost(self, reason="connection lost"):
        if not self.halted:
            self.halt("witness_unavailable", detail=str(reason))

    def halt(self, cause, detail=None):
        """D12: stop BOTH listeners, abort ALL sessions, fail every pending request, write the marker."""
        if self.halted:
            return
        self.halted, self.halt_cause = True, cause
        if self._hb_handle is not None:
            self._hb_handle.cancel()
            self._hb_handle = None
        o, self.outstanding = self.outstanding, None
        if o is not None and o["timer"] is not None:
            o["timer"].cancel()
        for l in self.listeners:
            try:
                l.stop()
            except Exception:                                          # noqa: BLE001
                pass
        for s in list(self.sessions):
            try:
                s.abort()
            except Exception:                                          # noqa: BLE001
                pass
        self.sessions.clear()
        if self.halt_marker:
            self.halt_marker.write_text(json.dumps({"cause": cause, "detail": detail,
                                                    "last_ack": self.last_ack["checkpoint_hash"] if self.last_ack else None,
                                                    "relay_seq": self.writer.seq}), encoding="utf-8")
        err = Halted(f"relay halted ({cause})")
        if o is not None:
            o["pending"].fail(err)
        while self.queue:
            self.queue.popleft()[3].fail(err)
        if self.on_halt:
            self.on_halt(cause)

    # ------------------------------------------------------------------------------------------------ recovery
    def recover(self, authorisation):
        """Send an administrator-signed recovery authorisation (async). Clears HALTED only on a verified recovery checkpoint."""
        p = Pending()
        if not self.halted or self.outstanding is not None:
            p.fail(RuntimeError("recovery only while halted and idle"))
            return p
        self._next_id += 1
        rid = f"r{self._next_id}"

        def expired():
            if self._recovery and self._recovery["id"] == rid:
                self._recovery = None
                p.fail(RuntimeError("recovery: no witness answer within the timeout"))
        self._recovery = {"id": rid, "pending": p, "sent_at": self.sched.seconds(), "timer": self.sched.call_later(self.timeout, expired)}
        try:
            self.transport.send({"type": "recovery", "authorisation": authorisation, "request_id": rid})
        except Exception as exc:                                       # noqa: BLE001
            self._recovery = None
            p.fail(RuntimeError(f"recovery: witness unreachable: {exc}"))
        return p

    _recovery = None

    def on_recovery_response(self, resp):
        r, self._recovery = self._recovery, None
        if r is None or not isinstance(resp, dict) or resp.get("request_id") != r["id"]:
            return
        r["timer"].cancel()
        if resp.get("type") != "ack":
            r["pending"].fail(RuntimeError(resp.get("reason", "recovery rejected")))
            return
        cp = resp.get("checkpoint")
        try:
            verify_checkpoint_v2(cp, self.witness_pub, self.pin)
        except ValueError as exc:
            r["pending"].fail(RuntimeError(f"invalid recovery ack: {exc}"))
            return
        if cp["kind"] != "recovery" or cp["log_id"] != self.log_id:
            r["pending"].fail(RuntimeError("ack is not a recovery checkpoint"))
            return
        self.last_ack, self.halted, self.halt_cause = cp, False, None
        self.writer.seq = max(self.writer.seq, cp["relay_seq"])
        if self.halt_marker and self.halt_marker.exists():
            self.halt_marker.unlink()
        r["pending"].resolve(cp)
