"""Relay-side witness gate (component 1), reactor-agnostic. Holds ONLY the relay record key.

Not used by the running relay (`attributing_relay.py` is unchanged). The witnessed relay adapter
(`witnessed_relay.py`) uses this gate after the coordinated migration (M7), which has NOT been run.

Rules (approved design, D12):
  * every record (including relay_start) is confirmed by the witness before the relay proceeds; no listener opens
    before relay_start is confirmed; no client resumes before its open record is confirmed;
  * each record carries `witness_ack` = the previous confirmation (cross-link);
  * the ack must be a checkpoint signed by the pinned witness key that names exactly this record and links to the
    previous confirmation;
  * no confirmation within 2 s, a nack, an invalid ack or a missed heartbeat => HALTED: stop BOTH listeners, abort ALL
    in-progress sessions, write a halt marker, accept no further records. Recovery is manual (administrator-signed).
"""
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))            # repository root (or /opt/project in the container)
from client_attribution.checkpoints import GENESIS_V2, verify_checkpoint_v2  # noqa: E402
from client_attribution.framing import WitnessTimeout, WitnessUnavailable  # noqa: E402
from client_attribution.records import GENESIS, canonical, load_public_key  # noqa: E402

RECORD_SCHEMA = "relay-mapping-record-1"


class Halted(RuntimeError):
    pass


class RecordWriterV2:
    """Signed, hash-chained relay records with the `witness_ack` cross-link. Durable (fsync) when given a path."""

    def __init__(self, key, key_sha256, clock_iso, path=None):
        self.key, self.key_id, self.clock_iso, self.path = key, key_sha256[:16], clock_iso, Path(path) if path else None
        self.seq, self.prev, self.lines = 0, GENESIS, []

    def write(self, rtype, witness_ack, **fields):
        self.seq += 1
        rec = {"schema": RECORD_SCHEMA, "seq": self.seq, "prev_hash": self.prev, "record_type": rtype, "written_utc": self.clock_iso(),
               "key_id": self.key_id, "witness_ack": witness_ack, **fields}
        h = hashlib.sha256(canonical(rec).encode("utf-8")).hexdigest()
        rec["record_hash"], rec["signature"] = h, self.key.sign(h.encode("ascii")).hex()
        line = canonical(rec)
        if self.path:
            with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
        self.lines.append(line)
        self.prev = h
        return rec


class RelayWitnessGate:
    def __init__(self, writer, transport, witness_public_pem, witness_pin, relay_pin, log_id, clock, listeners, timeout=2.0,
                 halt_marker=None, on_halt=None):
        if witness_pin == relay_pin:
            raise ValueError("key-role separation: witness key equals relay key")
        self.writer, self.transport, self.pin, self.log_id, self.clock = writer, transport, witness_pin, log_id, clock
        self.witness_pub, sha = load_public_key(witness_public_pem)
        if sha != witness_pin:
            raise ValueError("witness public key does not match its pin")
        self.listeners, self.timeout = list(listeners), timeout
        self.halt_marker = Path(halt_marker) if halt_marker else None
        self.sessions, self.halted, self.halt_cause, self.last_ack, self.on_halt = set(), False, None, None, on_halt

    # ------------------------------------------------------------------------------------------------ sessions
    def register_session(self, s):
        if self.halted:
            raise Halted("relay halted")
        self.sessions.add(s)

    def unregister_session(self, s):
        self.sessions.discard(s)

    # ------------------------------------------------------------------------------------------------ lifecycle
    def start(self, **relay_start_fields):
        """Confirm relay_start BEFORE any listener opens. Returns True only if the relay may open its listeners."""
        if self.halt_marker and self.halt_marker.exists():
            self.halted, self.halt_cause = True, json.loads(self.halt_marker.read_text(encoding="utf-8")).get("cause")
            raise Halted(f"halt marker present ({self.halt_cause}): manual recovery required")
        self.append("relay_start", **relay_start_fields)
        return not self.halted

    def append(self, rtype, **fields):
        if self.halted:
            raise Halted(f"relay halted ({self.halt_cause})")
        ack_ref = None if self.last_ack is None else {"checkpoint_seq": self.last_ack["checkpoint_seq"], "checkpoint_hash": self.last_ack["checkpoint_hash"]}
        rec = self.writer.write(rtype, ack_ref, **fields)
        cp = self._request({"type": "attest", "log_id": self.log_id, "seq": rec["seq"], "record_hash": rec["record_hash"]}, "attest", rec)
        if cp is None:
            raise Halted(f"relay halted ({self.halt_cause})")
        return rec

    def heartbeat(self):
        if self.halted:
            return False
        return self._request({"type": "heartbeat", "log_id": self.log_id}, "heartbeat", None, cause_on_timeout="heartbeat_missing") is not None

    def _request(self, frame, kind, rec, cause_on_timeout="ack_timeout"):
        t0 = self.clock.monotonic()
        try:
            resp = self.transport.request(frame)
        except WitnessTimeout:
            self.halt(cause_on_timeout)
            return None
        except WitnessUnavailable:
            self.halt("witness_unavailable" if kind == "attest" else cause_on_timeout)
            return None
        if self.clock.monotonic() - t0 > self.timeout:
            self.halt(cause_on_timeout)
            return None
        if not isinstance(resp, dict) or resp.get("type") != "ack":
            self.halt(f"nack:{(resp or {}).get('cause')}")
            return None
        cp = resp.get("checkpoint")
        try:
            verify_checkpoint_v2(cp, self.witness_pub, self.pin)
        except ValueError:
            self.halt("invalid_ack")
            return None
        prev = self.last_ack["checkpoint_hash"] if self.last_ack else GENESIS_V2
        ok = cp["kind"] == kind and cp["log_id"] == self.log_id and cp["prev_checkpoint_hash"] == prev
        if kind == "attest":
            ok = ok and cp["relay_seq"] == rec["seq"] and cp["relay_record_hash"] == rec["record_hash"]
        if not ok:
            self.halt("invalid_ack")
            return None
        self.last_ack = cp
        return cp

    def halt(self, cause):
        """D12: stop BOTH listeners, abort ALL in-progress sessions, write the halt marker, accept nothing further."""
        if self.halted:
            return
        self.halted, self.halt_cause = True, cause
        for l in self.listeners:
            try:
                l.stop()
            except Exception:                                    # noqa: BLE001 - keep stopping the others
                pass
        for s in list(self.sessions):
            try:
                s.abort()
            except Exception:                                    # noqa: BLE001
                pass
        self.sessions.clear()
        if self.halt_marker:
            self.halt_marker.write_text(json.dumps({"cause": cause, "last_ack": self.last_ack["checkpoint_hash"] if self.last_ack else None,
                                                    "relay_seq": self.writer.seq}), encoding="utf-8")
        if self.on_halt:
            self.on_halt(cause)

    def recover(self, authorisation):
        """Submit an administrator-signed recovery authorisation. Clears HALTED only after a verified `recovery` ack."""
        try:
            resp = self.transport.request({"type": "recovery", "authorisation": authorisation})
        except (WitnessTimeout, WitnessUnavailable) as exc:
            return {"recovered": False, "reason": f"witness unreachable: {exc}"}
        if not isinstance(resp, dict) or resp.get("type") != "ack":
            return {"recovered": False, "reason": (resp or {}).get("reason", "rejected")}
        cp = resp["checkpoint"]
        try:
            verify_checkpoint_v2(cp, self.witness_pub, self.pin)
        except ValueError as exc:
            return {"recovered": False, "reason": f"invalid recovery ack: {exc}"}
        if cp["kind"] != "recovery" or cp["log_id"] != self.log_id:
            return {"recovered": False, "reason": "ack is not a recovery checkpoint"}
        self.last_ack, self.halted, self.halt_cause = cp, False, None
        self.writer.seq = max(self.writer.seq, cp["relay_seq"])
        if self.halt_marker and self.halt_marker.exists():
            self.halt_marker.unlink()
        return {"recovered": True, "checkpoint": cp, "category": cp["details"]["category"]}
