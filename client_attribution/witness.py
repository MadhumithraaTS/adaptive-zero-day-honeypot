"""Checkpoint witness (component 2). Holds ONLY the witness key (P3).

For every attest request it re-reads the record from the relay log itself (never trusting the request), verifies it
independently (schema, record hash, pinned relay signature, key validity, sequence, prev_hash link, witness_ack
cross-link, clock skew), checks off-host replication lag, appends a signed hash-linked checkpoint DURABLY (fsync), and
only then acknowledges. Any failure writes a `fault` checkpoint where possible and refuses all further work until a
manual, administrator-authorised recovery (D11). There is never automatic recovery.
"""
import json
import os
from pathlib import Path

from .checkpoints import GENESIS_V2, make_checkpoint_v2, verify_checkpoint_chain
from .records import GENESIS, _check_one, load_public_key, verify_records
from .trust_root import TrustRootError, recovery_category, verify_recovery_authorisation


class StoreError(RuntimeError):
    pass


class CheckpointStore:
    """Append-only JSONL checkpoint store with durable appends (fsync of file and, where supported, directory)."""

    def __init__(self, path):
        self.path = Path(path)
        self.fail_next = False                                    # failure injection for tests

    def append(self, cp):
        if self.fail_next:
            raise StoreError("simulated storage failure")
        try:
            with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(cp, sort_keys=True, separators=(",", ":")) + "\n")
                f.flush()
                os.fsync(f.fileno())
            try:
                fd = os.open(str(self.path.parent), os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError:
                pass                                              # directory fsync unsupported on this platform
        except OSError as exc:
            raise StoreError(str(exc)) from exc

    def all(self):
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]


def replication_lag_seconds(checkpoints, status, now, stale_after_s):
    """Age of the oldest checkpoint not confirmed off-host. A missing or stale status (unsigned, NOT authoritative,
    D15) can only make the lag larger: it never shortens it."""
    remote_seq = status.get("remote_head_checkpoint_seq", 0) if isinstance(status, dict) else 0
    unrep = [c for c in checkpoints if c["checkpoint_seq"] > remote_seq]
    lag = (now - _t(unrep[0]["attested_utc"])).total_seconds() if unrep else 0.0
    pushed = _t(status["pushed_utc"]) if isinstance(status, dict) and status.get("pushed_utc") else None
    if unrep and (pushed is None or (now - pushed).total_seconds() > stale_after_s):
        lag = max(lag, (now - pushed).total_seconds() if pushed else lag)
    return lag


def _t(s):
    from .records import ts
    return ts(s)


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class WitnessCore:
    def __init__(self, log_id, relay_public_pem, relay_pin, witness_key, witness_pin, trust_anchor_digest, store, read_relay_log, clock,
                 replication_status=lambda: None, manifest=None, params=None, relay_key_validity=(None, None), mode="mock"):
        p = params or {}
        self.log_id, self.relay_pin, self.key, self.pin = log_id, relay_pin, witness_key, witness_pin
        self.relay_pub, sha = load_public_key(relay_public_pem)
        if sha != relay_pin:
            raise ValueError("relay public key does not match its pin")
        if relay_pin == witness_pin:
            raise ValueError("key-role separation: witness key equals relay key")
        self.anchor, self.store, self.read_relay_log, self.clock = trust_anchor_digest, store, read_relay_log, clock
        self.replication_status, self.manifest, self.mode = replication_status, manifest, mode
        self.max_lag = p.get("max_replication_lag_seconds", 900)
        self.stale_after = p.get("replication_status_stale_seconds", 120)
        self.skew = p.get("clock_skew_seconds", 5)
        self.relay_nb, self.relay_na = relay_key_validity
        self.last_relay_seq, self.last_relay_hash, self.fault = 0, GENESIS, None
        existing = store.all()
        self.head = existing[-1] if existing else None
        if existing:                                              # restart: rebuild state and refuse unless the chain verifies
            v = verify_checkpoint_chain(existing, self._witness_pem(), self.pin, log_id)
            if not v["ok"]:
                self.fault = {"cause": "broken_chain", "category": "elevated", "checkpoint_hash": None}
            for cp in existing:
                if cp["kind"] in ("attest", "recovery") and cp["relay_seq"]:
                    self.last_relay_seq, self.last_relay_hash = cp["relay_seq"], cp["relay_record_hash"] or self.last_relay_hash
                if cp["kind"] in ("fault", "halt"):
                    self.fault = {"cause": cp["details"].get("cause"), "category": cp["details"].get("category"), "checkpoint_hash": cp["checkpoint_hash"]}
                elif cp["kind"] == "recovery":
                    self.fault = None

    def _witness_pem(self):
        from cryptography.hazmat.primitives import serialization
        return self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    # ------------------------------------------------------------------------------------------------ helpers
    def _now(self):
        return self.clock()

    def _write(self, kind, relay=None, details=None):
        cp = make_checkpoint_v2(self.head, kind, self.log_id, relay, _iso(self._now()), self.anchor, self.key, self.pin, details)
        self.store.append(cp)                                     # durable before anything is acknowledged
        self.head = cp
        return cp

    def _fault(self, cause, reason):
        cat = recovery_category(cause)
        try:
            cp = self._write("fault", {"seq": self.last_relay_seq, "record_hash": self.last_relay_hash if self.last_relay_seq else None},
                             {"cause": cause, "category": cat, "reason": reason})
            ref = cp["checkpoint_hash"]
        except StoreError:
            ref = None
        self.fault = {"cause": cause, "category": cat, "checkpoint_hash": ref}
        return {"type": "nack", "cause": cause, "category": cat, "reason": reason}

    def _lag_ok(self):
        lag = replication_lag_seconds(self.store.all(), self.replication_status(), self._now(), self.stale_after)
        status = self.replication_status() or {}
        if status.get("anchor_match") is False:
            return "anchor_mismatch", "replicator reports the local trust anchor differs from the off-host anchor"
        if lag > self.max_lag:
            return "replication_lag", f"off-host replication lag {lag:.0f} s exceeds {self.max_lag} s"
        return None, None

    def head_ref(self):
        return self.head["checkpoint_hash"] if self.head else GENESIS_V2

    # ------------------------------------------------------------------------------------------------ protocol
    def handle(self, frame):
        t = frame.get("type") if isinstance(frame, dict) else None
        if t == "recovery":
            return self._recover(frame)
        if self.fault:
            return {"type": "nack", "cause": "halted", "category": self.fault["category"], "reason": f"witness halted ({self.fault['cause']})"}
        if not isinstance(frame, dict) or frame.get("log_id") != self.log_id:
            return self._fault("integrity", "request for another log or malformed request")
        if t == "attest":
            return self._attest(frame)
        if t == "heartbeat":
            return self._heartbeat()
        return self._fault("integrity", f"unknown request type {t!r}")

    def _attest(self, frame):
        seq = frame.get("seq")
        if not isinstance(seq, int) or seq < 1:
            return self._fault("integrity", "malformed sequence number")
        lines = [l for l in self.read_relay_log() if l.strip()]
        cands = [l for l in lines if _seq_of(l) == seq]
        if seq <= self.last_relay_seq:
            if any(_hash_of(l) == frame.get("record_hash") for l in cands):
                return {"type": "nack", "cause": "duplicate", "category": None, "reason": f"seq {seq} already attested (replay rejected)"}
            return self._fault("conflict", f"seq {seq} differs from the record already attested")
        if seq > self.last_relay_seq + 1:
            return self._fault("gap", f"seq {seq} skips {self.last_relay_seq + 1}")
        if len(cands) != 1:
            return self._fault("integrity" if not cands else "conflict", f"{len(cands)} relay records with seq {seq}")
        rec, why = _check_one(cands[0], self.relay_pub, self.relay_pin[:16], self.relay_nb, self.relay_na)
        if why:
            cause = "key_expired" if "validity" in why else "invalid_signature" if ("signature" in why or "key_id" in why) else "integrity"
            return self._fault(cause, f"record seq {seq}: {why}")
        if rec["record_hash"] != frame.get("record_hash"):
            return self._fault("integrity", "request does not match the record on disk")
        if rec["prev_hash"] != self.last_relay_hash:
            return self._fault("broken_chain", f"record seq {seq} does not link to seq {self.last_relay_seq}")
        expected_ack = None if self.head is None else {"checkpoint_seq": self.head["checkpoint_seq"], "checkpoint_hash": self.head["checkpoint_hash"]}
        if rec.get("witness_ack") != expected_ack:
            return self._fault("broken_chain", "record does not reference the previous witness confirmation")
        if abs((self._now() - _t(rec["written_utc"])).total_seconds()) > self.skew:
            return self._fault("clock", "record time outside the clock-skew budget")
        cause, reason = self._lag_ok()
        if cause:
            return self._fault(cause, reason)
        try:
            cp = self._write("attest", {"seq": seq, "record_hash": rec["record_hash"], "record_type": rec["record_type"], "written_utc": rec["written_utc"]})
        except StoreError as exc:
            return self._fault("storage", str(exc))
        self.last_relay_seq, self.last_relay_hash = seq, rec["record_hash"]
        return {"type": "ack", "checkpoint": cp}

    def _heartbeat(self):
        cause, reason = self._lag_ok()
        if cause:
            return self._fault(cause, reason)
        try:
            cp = self._write("heartbeat", {"seq": self.last_relay_seq, "record_hash": self.last_relay_hash if self.last_relay_seq else None})
        except StoreError as exc:
            return self._fault("storage", str(exc))
        return {"type": "ack", "checkpoint": cp}

    # ------------------------------------------------------------------------------------------------ recovery (D11)
    def _recover(self, frame):
        if self.manifest is None:
            return {"type": "nack", "cause": "no_manifest", "category": None, "reason": "no verified trust-root manifest: recovery impossible"}
        minimum = "elevated" if (self.fault and self.fault["category"] == "elevated") else "ordinary"
        try:
            ok = verify_recovery_authorisation(frame.get("authorisation"), self.manifest, self._now(), self.head_ref(), minimum)
        except TrustRootError as exc:
            return {"type": "nack", "cause": "recovery_rejected", "category": minimum, "reason": str(exc)}
        chain = verify_checkpoint_chain(self.store.all(), self._witness_pem(), self.pin, self.log_id)
        if not chain["ok"]:
            return {"type": "nack", "cause": "recovery_rejected", "category": "elevated", "reason": f"checkpoint chain broken: {chain['reason']}"}
        lines = [l for l in self.read_relay_log() if l.strip()]
        rv = verify_records(lines, self.relay_pub, self.relay_pin, self.relay_nb, self.relay_na)
        if not rv["ok"]:
            return {"type": "nack", "cause": "recovery_rejected", "category": "elevated", "reason": f"relay chain broken: {rv['reason']}"}
        recs = rv["records"]
        attested = [r for r in recs if r["seq"] <= self.last_relay_seq]
        if attested and attested[-1]["record_hash"] != self.last_relay_hash:
            return {"type": "nack", "cause": "recovery_rejected", "category": "elevated", "reason": "relay log differs from attested history"}
        status = self.replication_status() or {}
        remote_seq, remote_hash = status.get("remote_head_checkpoint_seq", 0), status.get("remote_head_checkpoint_hash")
        local = {c["checkpoint_seq"]: c["checkpoint_hash"] for c in self.store.all()}
        if remote_seq and local.get(remote_seq) != remote_hash:
            return {"type": "nack", "cause": "recovery_rejected", "category": "elevated", "reason": "off-host head disagrees with the local chain"}
        pending = [r["seq"] for r in recs if r["seq"] > self.last_relay_seq]
        last = recs[-1] if recs else None
        try:
            cp = self._write("recovery", {"seq": last["seq"] if last else 0, "record_hash": last["record_hash"] if last else None},
                             {"authorisation_hash": ok["authorisation_hash"], "category": ok["category"], "signers": ok["signers"],
                              "unattested_relay_seqs": pending, "cleared_cause": (self.fault or {}).get("cause", "relay_side_halt")})
        except StoreError as exc:
            return {"type": "nack", "cause": "storage", "category": "ordinary", "reason": str(exc)}
        if last:
            self.last_relay_seq, self.last_relay_hash = last["seq"], last["record_hash"]
        self.fault = None
        return {"type": "ack", "checkpoint": cp}


def _seq_of(line):
    try:
        return json.loads(line).get("seq")
    except (json.JSONDecodeError, AttributeError):
        return None


def _hash_of(line):
    try:
        return json.loads(line).get("record_hash")
    except (json.JSONDecodeError, AttributeError):
        return None
