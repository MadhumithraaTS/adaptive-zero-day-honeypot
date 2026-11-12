"""External relay-log checkpoints (F-4): a witness key that the relay does not hold attests {seq, record_hash} of the
relay log head. Checkpoints must be stored where the relay cannot write. A log that is shorter than, or diverges from,
a verified checkpoint is reported by verify_records(); records written after the newest checkpoint stay unattested.
"""
import hashlib
import uuid

from cryptography.exceptions import InvalidSignature

from .records import canonical, load_public_key, ts

CHECKPOINT_SCHEMA = "relay-log-checkpoint-1"
FIELDS = ("schema", "checkpoint_id", "log_id", "seq", "record_hash", "record_written_utc", "attested_utc", "witness_key_id",
          "checkpoint_hash", "signature")


def make_checkpoint(verification: dict, log_id: str, attested_utc: str, witness_private_key, witness_public_key_sha256: str) -> dict:
    """Witness side: attest the head of a verified, fully linked log. Refuses logs with gaps or rejections."""
    if not verification.get("ok"):
        raise ValueError(f"refusing to checkpoint a log that is not intact: {verification.get('reason')}")
    head = verification["records"][-1]
    doc = {"schema": CHECKPOINT_SCHEMA, "checkpoint_id": str(uuid.uuid4()), "log_id": log_id, "seq": head["seq"],
           "record_hash": head["record_hash"], "record_written_utc": head["written_utc"], "attested_utc": attested_utc,
           "witness_key_id": witness_public_key_sha256[:16]}
    doc["checkpoint_hash"] = hashlib.sha256(canonical(doc).encode("utf-8")).hexdigest()
    doc["signature"] = witness_private_key.sign(doc["checkpoint_hash"].encode("ascii")).hex()
    return doc


def verify_checkpoints(docs, witness_public_key_pem: bytes, pinned_sha256: str, log_id: str):
    """Return (verified, rejected). Only verified checkpoints may be passed to verify_records()."""
    verified, rejected = [], []
    try:
        pub, sha = load_public_key(witness_public_key_pem)
    except Exception as exc:                                   # noqa: BLE001 - unusable key: nothing verifies
        return [], [{"checkpoint": None, "reason": f"witness key unusable: {exc}"}]
    if sha != pinned_sha256:
        return [], [{"checkpoint": None, "reason": "witness public key does not match the pinned sha256"}]
    for d in docs:
        cid = d.get("checkpoint_id") if isinstance(d, dict) else None
        if not isinstance(d, dict) or set(d) != set(FIELDS) or d["schema"] != CHECKPOINT_SCHEMA:
            rejected.append({"checkpoint": cid, "reason": "malformed checkpoint"})
            continue
        body = {k: v for k, v in d.items() if k not in ("checkpoint_hash", "signature")}
        if hashlib.sha256(canonical(body).encode("utf-8")).hexdigest() != d["checkpoint_hash"]:
            rejected.append({"checkpoint": cid, "reason": "checkpoint_hash mismatch"})
            continue
        if d["witness_key_id"] != sha[:16]:
            rejected.append({"checkpoint": cid, "reason": "checkpoint signed by an unpinned witness key"})
            continue
        try:
            pub.verify(bytes.fromhex(d["signature"]), d["checkpoint_hash"].encode("ascii"))
        except (InvalidSignature, ValueError):
            rejected.append({"checkpoint": cid, "reason": "checkpoint signature invalid"})
            continue
        if d["log_id"] != log_id:
            rejected.append({"checkpoint": cid, "reason": "checkpoint is for another log"})
            continue
        ts(d["record_written_utc"]), ts(d["attested_utc"])
        verified.append({k: d[k] for k in ("checkpoint_id", "seq", "record_hash", "record_written_utc", "attested_utc")})
    return verified, rejected


# ================================================================================================ checkpoint v2 (Task 28A)
# Per-record witness confirmation: a hash-linked chain of signed checkpoints (attest / heartbeat / fault / halt /
# recovery / key_rollover). Each checkpoint names the relay record it attests and the active trust-anchor digest.
CHECKPOINT_V2 = "relay-log-checkpoint-2"
KINDS_V2 = ("attest", "heartbeat", "fault", "halt", "recovery", "key_rollover")
FIELDS_V2 = ("schema", "log_id", "checkpoint_seq", "prev_checkpoint_hash", "kind", "relay_seq", "relay_record_hash", "relay_record_type",
             "relay_record_written_utc", "attested_utc", "trust_anchor_digest", "witness_key_id", "details", "checkpoint_hash", "signature")
GENESIS_V2 = "0" * 64


def make_checkpoint_v2(prev, kind, log_id, relay, attested_utc, trust_anchor_digest, private_key, key_sha256, details=None) -> dict:
    """Witness side only. `prev` is the previous v2 checkpoint (or None); `relay` = {seq, record_hash, record_type, written_utc}."""
    if kind not in KINDS_V2:
        raise ValueError(f"unknown checkpoint kind {kind!r}")
    relay = relay or {}
    doc = {"schema": CHECKPOINT_V2, "log_id": log_id, "checkpoint_seq": (prev["checkpoint_seq"] + 1) if prev else 1,
           "prev_checkpoint_hash": prev["checkpoint_hash"] if prev else GENESIS_V2, "kind": kind, "relay_seq": relay.get("seq", 0),
           "relay_record_hash": relay.get("record_hash"), "relay_record_type": relay.get("record_type"),
           "relay_record_written_utc": relay.get("written_utc"), "attested_utc": attested_utc, "trust_anchor_digest": trust_anchor_digest,
           "witness_key_id": key_sha256[:16], "details": details or {}}
    doc["checkpoint_hash"] = hashlib.sha256(canonical(doc).encode("utf-8")).hexdigest()
    doc["signature"] = private_key.sign(doc["checkpoint_hash"].encode("ascii")).hex()
    return doc


def verify_checkpoint_v2(cp, public_key, pinned_sha256):
    """Raise ValueError unless `cp` is a well-formed v2 checkpoint signed by the pinned witness key."""
    if not isinstance(cp, dict) or set(cp) != set(FIELDS_V2) or cp["schema"] != CHECKPOINT_V2 or cp["kind"] not in KINDS_V2:
        raise ValueError("malformed v2 checkpoint")
    body = {k: v for k, v in cp.items() if k not in ("checkpoint_hash", "signature")}
    if hashlib.sha256(canonical(body).encode("utf-8")).hexdigest() != cp["checkpoint_hash"]:
        raise ValueError("checkpoint_hash mismatch")
    if cp["witness_key_id"] != pinned_sha256[:16]:
        raise ValueError("checkpoint signed by an unpinned witness key")
    try:
        public_key.verify(bytes.fromhex(cp["signature"]), cp["checkpoint_hash"].encode("ascii"))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("checkpoint signature invalid") from exc


def verify_checkpoint_chain(checkpoints, witness_public_key_pem, pinned_sha256, log_id) -> dict:
    """Verify a complete v2 chain: signatures, hash links, sequence, log_id and relay-sequence monotonicity."""
    try:
        pub, sha = load_public_key(witness_public_key_pem)
    except Exception as exc:                                    # noqa: BLE001
        return {"ok": False, "reason": f"witness key unusable: {exc}", "head": None, "count": 0}
    if sha != pinned_sha256:
        return {"ok": False, "reason": "witness public key does not match the pin", "head": None, "count": 0}
    prev, relay_seq = None, 0
    for k, cp in enumerate(checkpoints):
        try:
            verify_checkpoint_v2(cp, pub, pinned_sha256)
        except ValueError as exc:
            return {"ok": False, "reason": f"checkpoint {k + 1}: {exc}", "head": prev, "count": k}
        if cp["log_id"] != log_id:
            return {"ok": False, "reason": f"checkpoint {k + 1}: other log", "head": prev, "count": k}
        if cp["checkpoint_seq"] != k + 1 or cp["prev_checkpoint_hash"] != (prev["checkpoint_hash"] if prev else GENESIS_V2):
            return {"ok": False, "reason": f"checkpoint {k + 1}: broken checkpoint chain", "head": prev, "count": k}
        if cp["kind"] == "attest":
            if cp["relay_seq"] != relay_seq + 1:
                return {"ok": False, "reason": f"checkpoint {k + 1}: relay sequence not contiguous", "head": prev, "count": k}
            relay_seq = cp["relay_seq"]
        elif cp["kind"] == "recovery":
            relay_seq = max(relay_seq, cp["relay_seq"])           # unattested records are listed explicitly in details
        elif cp["relay_seq"] != relay_seq:
            return {"ok": False, "reason": f"checkpoint {k + 1}: {cp['kind']} does not re-attest the head", "head": prev, "count": k}
        prev = cp
    return {"ok": True, "reason": "checkpoint chain verifies", "head": prev, "count": len(checkpoints)}


def v1_view(checkpoints) -> list:
    """Attest checkpoints in the {seq, record_hash, record_written_utc, attested_utc} form used by verify_records()."""
    return [{"checkpoint_id": cp["checkpoint_hash"], "seq": cp["relay_seq"], "record_hash": cp["relay_record_hash"],
             "record_written_utc": cp["relay_record_written_utc"], "attested_utc": cp["attested_utc"]}
            for cp in checkpoints if cp["kind"] == "attest"]
