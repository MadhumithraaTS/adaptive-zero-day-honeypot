"""Independent verification of signed attribution results (F-1). Public-key operations only; this module never signs
and is independent of the signer package (no imports from it). A result is accepted only when ALL checks pass; otherwise it is rejected as a
whole and none of its claims are used.

Checks: exact top-level field set and schema; signer key pinned by the v3 attribution config; result_hash recomputed
over the complete document; Ed25519 signature; issue time inside the key validity; issued <= now <= not_after and
validity <= the configured maximum; attribution config digest equal to the loaded config; unique session IDs; every
entry internally consistent with the pinned registry, demo listeners, relay addresses, timing skew and decision rules.
"""
import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .config import ed25519_public_key_identity
from .errors import AssessmentConfigError

RESULT_SCHEMA = "signed-attribution-result-1"
TOP_FIELDS = {"schema", "result_id", "issued_utc", "not_after_utc", "evaluation_time_utc", "attribution_config", "relay_log",
              "cowrie_input", "sessions", "signer", "result_hash", "signature"}
ENTRY_FIELDS = {"cowrie_session_id", "decision", "reason", "client", "relay_listener", "relay_to_cowrie", "timestamps", "relay_records",
                "close_check", "authentication"}
DECISIONS = {"attributable_via_proxy_mapping", "unattributed:mapping_missing", "unattributed:mapping_ambiguous",
             "unattributed:mapping_duplicate", "unattributed:mapping_untrusted", "unattributed:mapping_unavailable",
             "unattributed:mapping_expired", "unattributed:unregistered_peer", "unattributed:published_listener",
             "unattributed:close_inconsistent", "unattributed:not_via_relay", "unattributed:log_gap", "excluded_diagnostic"}
AUTH_STATES = {"login_success_observed", "indeterminate:no_login_success_event", "indeterminate:ambiguous"}


class SignedResultError(ValueError):
    pass


def _canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _t(s, what):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (AttributeError, ValueError, TypeError) as exc:
        raise SignedResultError(f"invalid timestamp {what}") from exc


def _check_entry(e, cfg):
    sid = e.get("cowrie_session_id") if isinstance(e, dict) else None
    if not isinstance(e, dict) or set(e) != ENTRY_FIELDS:
        raise SignedResultError(f"session entry {sid!r}: unexpected field set")
    if not isinstance(sid, str) or not sid:
        raise SignedResultError("session entry without cowrie_session_id")
    d = e["decision"]
    if d not in DECISIONS:
        raise SignedResultError(f"{sid}: unknown decision {d!r}")
    a = e["authentication"]
    if not isinstance(a, dict) or a.get("state") not in AUTH_STATES:
        raise SignedResultError(f"{sid}: invalid authentication block")
    ts_ = e["timestamps"] if isinstance(e["timestamps"], dict) else {}
    if a["state"] == "login_success_observed":
        t_login = _t(a.get("login_success_utc"), f"{sid} login")
        if ts_.get("cowrie_connect_utc") and t_login < _t(ts_["cowrie_connect_utc"], f"{sid} connect"):
            raise SignedResultError(f"{sid}: login before connect")
        if ts_.get("cowrie_closed_utc") and t_login > _t(ts_["cowrie_closed_utc"], f"{sid} close"):
            raise SignedResultError(f"{sid}: login after close")
    if d != "attributable_via_proxy_mapping":
        if e["client"] is not None:
            raise SignedResultError(f"{sid}: unattributed entry names a client")
        return
    if sid in cfg.excluded_sessions:
        raise SignedResultError(f"{sid}: excluded diagnostic session marked attributable")
    c, lst, up, rr = e["client"], e["relay_listener"], e["relay_to_cowrie"], e["relay_records"]
    if not all(isinstance(x, dict) for x in (c, lst, up, rr)):
        raise SignedResultError(f"{sid}: attributable entry is incomplete")
    try:
        ipaddress.ip_address(c.get("ip"))
    except ValueError as exc:
        raise SignedResultError(f"{sid}: invalid client ip") from exc
    reg = cfg.registry.get(c["ip"])
    if not reg or reg.get("role") != c.get("role") or not isinstance(c.get("port"), int):
        raise SignedResultError(f"{sid}: client {c.get('ip')} not in the pinned registry with that role")
    if f"{lst.get('ip')}:{lst.get('port')}" not in cfg.demo_listeners or lst.get("mode") != "demo" \
            or str(lst.get("accepted_local", "")).split(":")[0] != lst.get("ip"):
        raise SignedResultError(f"{sid}: relay listener is not a configured demo listener")
    if up.get("src_ip") not in cfg.mapping_relays or not isinstance(up.get("src_port"), int):
        raise SignedResultError(f"{sid}: relay-to-Cowrie tuple does not start at a configured relay address")
    if not isinstance(rr.get("connection_id"), str) or not isinstance((rr.get("open") or {}).get("seq"), int) \
            or len(str((rr.get("open") or {}).get("record_hash", ""))) != 64:
        raise SignedResultError(f"{sid}: relay record identity incomplete")
    acc, upc, con = (_t(ts_.get("relay_accepted_utc"), f"{sid} accept"), _t(ts_.get("relay_upstream_connected_utc"), f"{sid} upstream"),
                     _t(ts_.get("cowrie_connect_utc"), f"{sid} connect"))
    if acc > upc or abs((con - upc).total_seconds()) > cfg.skew_s or (acc - con).total_seconds() > cfg.skew_s:
        raise SignedResultError(f"{sid}: connection timestamps inconsistent")
    rc, cc = ts_.get("relay_closed_utc"), ts_.get("cowrie_closed_utc")
    if cc and not rc:
        raise SignedResultError(f"{sid}: Cowrie closed but no relay close")
    if cc and rc:
        if abs((_t(cc, "close") - _t(rc, "relay close")).total_seconds()) > cfg.skew_s or e["close_check"] != "consistent" \
                or not rr.get("close"):
            raise SignedResultError(f"{sid}: close inconsistent")
    elif e["close_check"] != "session_open":
        raise SignedResultError(f"{sid}: close_check does not match the timestamps")


WITNESS_FIELDS = ("schema", "log_id", "checkpoint_seq", "prev_checkpoint_hash", "kind", "relay_seq", "relay_record_hash", "relay_record_type",
                  "relay_record_written_utc", "attested_utc", "trust_anchor_digest", "witness_key_id", "details", "checkpoint_hash", "signature")


def _check_witness(doc, cfg, issued):
    """Task 28A: when the config pins a checkpoint witness, a result must cover a relay log whose head is CONFIRMED by a
    witness checkpoint (verified here independently with the pinned witness key), fresh, under the pinned trust anchor
    and replicated off-host within the lag bound. Otherwise the result is unconfirmed and rejected."""
    rl = doc["relay_log"] if isinstance(doc["relay_log"], dict) else {}
    tail = rl.get("tail") if isinstance(rl.get("tail"), dict) else {}
    if tail.get("status") != "attested":
        raise SignedResultError("unconfirmed relay log: the witness has not attested its head")
    w = rl.get("witness") if isinstance(rl.get("witness"), dict) else {}
    cp = w.get("checkpoint")
    if not isinstance(cp, dict) or set(cp) != set(WITNESS_FIELDS) or cp.get("schema") != "relay-log-checkpoint-2":
        raise SignedResultError("unconfirmed relay log: no witness checkpoint")
    body = {k: v for k, v in cp.items() if k not in ("checkpoint_hash", "signature")}
    if hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest() != cp["checkpoint_hash"] or cp["witness_key_id"] != cfg.witness_key_sha256[:16]:
        raise SignedResultError("witness checkpoint modified or signed by an unpinned key")
    try:
        serialization.load_pem_public_key(cfg.witness_public_key_pem).verify(bytes.fromhex(cp["signature"]), cp["checkpoint_hash"].encode("ascii"))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise SignedResultError("witness checkpoint signature invalid") from exc
    if cp["kind"] not in ("attest", "heartbeat", "recovery") or cp["relay_seq"] != tail.get("last_seq"):
        raise SignedResultError("witness checkpoint does not confirm the relay log head")
    if cp["trust_anchor_digest"] != cfg.trust_anchor_digest:
        raise SignedResultError("witness checkpoint was made under a different trust anchor")
    attested = _t(cp["attested_utc"], "checkpoint")
    if (issued - attested).total_seconds() > cfg.witness_max_age_s or (attested - issued).total_seconds() > 5:
        raise SignedResultError("witness checkpoint is stale")
    off = w.get("offhost_confirmed_utc")
    if not off or (issued - _t(off, "off-host confirmation")).total_seconds() > cfg.witness_max_lag_s:
        raise SignedResultError("off-host replication not confirmed within the lag bound")


@dataclass
class VerifiedAttribution:
    """Outcome of verifying all supplied results. Only `sessions` from accepted results are ever used."""
    accepted: List[dict] = field(default_factory=list)        # {result_id, result_hash, issued_utc}
    rejected: List[dict] = field(default_factory=list)        # {result_id, reason}
    sessions: Dict[str, dict] = field(default_factory=dict)   # session id -> {entry, result_id, result_hash}
    conflicts: set = field(default_factory=set)

    @property
    def all_verified(self):
        return not self.rejected

    def lookup(self, sid) -> Optional[dict]:
        if sid in self.conflicts:
            return {"status": "conflict", "reason": "session covered by conflicting attribution results"}
        if sid in self.sessions:
            return {"status": "verified", **self.sessions[sid]}
        if self.rejected:
            return {"status": "rejected", "reason": "; ".join(f"{r['result_id']}: {r['reason']}" for r in self.rejected)}
        return None


def verify_result(doc, cfg, now: datetime) -> dict:
    """Verify one result document against the v3 attribution config. Returns the document; raises SignedResultError."""
    if not isinstance(doc, dict):
        raise SignedResultError("attribution result is not a JSON object")
    if "signature" not in doc or "result_hash" not in doc or "signer" not in doc:
        raise SignedResultError("unsigned attribution result")
    if set(doc) != TOP_FIELDS or doc.get("schema") != RESULT_SCHEMA:
        raise SignedResultError("unexpected field set or schema")
    if cfg.result_key_sha256 is None or cfg.result_public_key_pem is None:
        raise SignedResultError(f"no attribution result key is pinned (config schema {cfg.schema}, status {cfg.result_key_status})")
    if cfg.relay_key_sha256 is None or cfg.result_key_sha256 == cfg.relay_key_sha256:
        raise SignedResultError("key-role separation: the attribution result key is not distinct from the relay record key")
    signer = doc["signer"] if isinstance(doc["signer"], dict) else {}
    if signer.get("public_key_sha256") == cfg.relay_key_sha256:
        raise SignedResultError("key-role separation: result claims to be signed by the relay record key")
    if signer.get("public_key_sha256") != cfg.result_key_sha256 or signer.get("key_id") != cfg.result_key_sha256[:16]:
        raise SignedResultError("signed by a key that is not pinned")
    body = {k: v for k, v in doc.items() if k not in ("result_hash", "signature")}
    if hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest() != doc["result_hash"]:
        raise SignedResultError("result_hash mismatch (result modified)")
    try:
        ident = ed25519_public_key_identity(cfg.result_public_key_pem, "attribution_result")
    except AssessmentConfigError as exc:
        raise SignedResultError(f"configured result public key unusable: {exc}") from exc
    if ident == cfg.relay_key_sha256:
        raise SignedResultError("key-role separation: the configured result public key is the relay record key")
    if ident != cfg.result_key_sha256:
        raise SignedResultError("configured public key does not match the pin")
    pub = serialization.load_pem_public_key(cfg.result_public_key_pem)
    try:
        pub.verify(bytes.fromhex(doc["signature"]), doc["result_hash"].encode("ascii"))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise SignedResultError("signature invalid") from exc
    issued, not_after = _t(doc["issued_utc"], "issued"), _t(doc["not_after_utc"], "not_after")
    if (cfg.result_key_not_before and issued < cfg.result_key_not_before) or (cfg.result_key_not_after and issued > cfg.result_key_not_after):
        raise SignedResultError("issued outside the result key validity")
    if (not_after - issued).total_seconds() > cfg.result_max_validity_s or not_after < issued:
        raise SignedResultError("validity period longer than allowed")
    if now < issued:
        raise SignedResultError("result not yet valid (issued in the future)")
    if now > not_after:
        raise SignedResultError("result expired")
    ac = doc["attribution_config"] if isinstance(doc["attribution_config"], dict) else {}
    if ac.get("digest") != cfg.digest:
        raise SignedResultError("result was produced under a different attribution config (digest mismatch)")
    if cfg.witness_key_sha256:
        _check_witness(doc, cfg, issued)
    if not isinstance(doc["sessions"], list):
        raise SignedResultError("sessions must be a list")
    ids = [e.get("cowrie_session_id") if isinstance(e, dict) else None for e in doc["sessions"]]
    if len(ids) != len(set(ids)):
        raise SignedResultError("duplicated session entries")
    for e in doc["sessions"]:
        _check_entry(e, cfg)
    return doc


def verify_results(docs, cfg, now: datetime) -> VerifiedAttribution:
    out = VerifiedAttribution()
    seen = {}
    for doc in docs:
        rid = doc.get("result_id") if isinstance(doc, dict) else None
        try:
            verify_result(doc, cfg, now)
        except SignedResultError as exc:
            out.rejected.append({"result_id": rid, "reason": str(exc)})
            continue
        if rid in seen:
            if seen[rid] != doc["result_hash"]:
                out.rejected.append({"result_id": rid, "reason": "result_id reused for a different result"})
            continue                                         # exact duplicate: counted once
        seen[rid] = doc["result_hash"]
        out.accepted.append({"result_id": rid, "result_hash": doc["result_hash"], "issued_utc": doc["issued_utc"],
                             **({"witness_status": "TEST/LOCAL MOCK (not production trust)" if cfg.witness_status == "mock" else cfg.witness_status}
                                if cfg.witness_key_sha256 else {})})
        for e in doc["sessions"]:
            sid = e["cowrie_session_id"]
            prev = out.sessions.get(sid)
            if prev is not None and _canonical(prev["entry"]) != _canonical(e):
                out.conflicts.add(sid)
            out.sessions.setdefault(sid, {"entry": e, "result_id": rid, "result_hash": doc["result_hash"]})
    return out
