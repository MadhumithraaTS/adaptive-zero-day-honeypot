"""Relay mapping record verification: schema, hash chain, Ed25519 signature, key validity, gaps and checkpoints.

Each line is verified on its own (F-6): a malformed, unsigned or wrongly signed line is rejected individually and the
rest of the log stays usable. The hash chain stays strict: consecutive verified records must link (`seq` + 1 and
`prev_hash`); a missing `seq` range is reported as a gap with its time interval, and anything correlated across a gap
is withheld by the caller. A signed record that does not link to its predecessor (fork), a record that disagrees with
a verified checkpoint (divergence) or a `relay_start` announcing another key makes the whole log untrusted.
Without an independently stored checkpoint, deletion of the newest records cannot be detected.
"""
import hashlib
import json
from datetime import datetime
from typing import Dict, List

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

RECORD_SCHEMA = "relay-mapping-record-1"
GENESIS = "0" * 64
REQUIRED = {
    "relay_start": ("listeners", "backend", "public_key_sha256"),
    "connection_open": ("connection_id", "listener", "listener_mode", "ingress_listener", "client_ip", "client_port", "accepted_local",
                        "accepted_utc", "upstream_local_ip", "upstream_local_port", "upstream_connected_utc"),
    "connection_close": ("connection_id", "upstream_local_ip", "upstream_local_port", "closed_utc"),
    "connection_rejected": ("connection_id", "reason"),
}


class RecordVerificationError(ValueError):
    pass


def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def load_public_key(pem_bytes):
    key = serialization.load_pem_public_key(pem_bytes)
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, hashlib.sha256(raw).hexdigest()


def _check_one(line, public_key, key_id, key_not_before, key_not_after):
    """Return (record, None) when the line is an authentic record, else (partial_or_None, reason)."""
    try:
        r = json.loads(line)
    except json.JSONDecodeError:
        return None, "malformed JSON"
    if not isinstance(r, dict):
        return None, "not a JSON object"
    if r.get("schema") != RECORD_SCHEMA:
        return r, f"unsupported schema {r.get('schema')!r}"
    rt = r.get("record_type")
    miss = [k for k in ("seq", "prev_hash", "record_type", "written_utc", "key_id", "record_hash", "signature") + REQUIRED.get(rt, ("_unknown_type",))
            if k not in r]
    if miss:
        return r, f"missing fields {miss}"
    if not isinstance(r["seq"], int) or r["seq"] < 1:
        return r, "invalid seq"
    body = {k: v for k, v in r.items() if k not in ("record_hash", "signature")}
    if hashlib.sha256(canonical(body).encode("utf-8")).hexdigest() != r["record_hash"]:
        return r, "record_hash mismatch (record modified)"
    if r["key_id"] != key_id:
        return r, f"key_id {r['key_id']} is not the pinned key {key_id}"
    try:
        public_key.verify(bytes.fromhex(r["signature"]), r["record_hash"].encode("ascii"))
    except (InvalidSignature, ValueError, TypeError):
        return r, "signature invalid"
    try:
        w = ts(r["written_utc"])
    except (ValueError, AttributeError):
        return r, "invalid written_utc"
    if (key_not_before and w < key_not_before) or (key_not_after and w > key_not_after):
        return r, "record written outside the key validity period (expired/not yet valid)"
    return r, None


def verify_records(lines: List[str], public_key, public_key_sha256: str, key_not_before=None, key_not_after=None,
                   checkpoints=None) -> Dict:
    """Verify a relay log line by line. Never raises on bad data.

    checkpoints: already-verified checkpoint dicts {seq, record_hash, record_written_utc, attested_utc} (see checkpoints.py).
    Returns ok (fully intact and complete as far as checkpoints show), usable (records may be used, subject to gaps),
    records, rejected, gaps, segments, tail, checkpoint results, reason, chain_head, count, first_bad.
    """
    key_id = public_key_sha256[:16]
    good, rejected, gaps, segments = [], [], [], []
    fatal, last = None, None
    for n, line in enumerate(l for l in lines if l.strip()):
        r, why = _check_one(line, public_key, key_id, key_not_before, key_not_after)
        if why:
            rejected.append({"line": n, "seq": r.get("seq") if isinstance(r, dict) else None, "reason": why})
            continue
        if r["record_type"] == "relay_start" and r["public_key_sha256"] != public_key_sha256:
            fatal = f"line {n}: relay_start announces a different public key"
            break
        seq = r["seq"]
        if last is None:
            if seq != 1 or r["prev_hash"] != GENESIS:
                gaps.append({"after_seq": 0, "before_seq": seq, "missing": seq - 1, "start_utc": None, "end_utc": r["written_utc"],
                             "kind": "head_missing"})
            segments.append([seq, seq])
        elif seq <= last["seq"]:
            rejected.append({"line": n, "seq": seq, "reason": f"duplicate or out-of-order seq {seq} (after {last['seq']})"})
            continue
        elif seq == last["seq"] + 1:
            if r["prev_hash"] != last["record_hash"]:
                fatal = f"line {n}: signed record seq {seq} does not link to seq {last['seq']} (fork)"
                break
            segments[-1][1] = seq
        else:
            gaps.append({"after_seq": last["seq"], "before_seq": seq, "missing": seq - last["seq"] - 1,
                         "start_utc": last["written_utc"], "end_utc": r["written_utc"], "kind": "missing_records"})
            segments.append([seq, seq])
        good.append(r)
        last = r

    cp_results, tail = [], {"last_seq": last["seq"] if last else None, "status": "unattested"}
    by_seq = {r["seq"]: r for r in good}
    if not fatal and checkpoints:
        for cp in sorted(checkpoints, key=lambda c: c["seq"]):
            have = by_seq.get(cp["seq"])
            if have is not None:
                if have["record_hash"] != cp["record_hash"]:
                    fatal = f"record seq {cp['seq']} diverges from a verified checkpoint (history rewritten)"
                    break
                cp_results.append({"seq": cp["seq"], "status": "consistent"})
            elif last is not None and cp["seq"] > last["seq"]:
                gaps.append({"after_seq": last["seq"], "before_seq": cp["seq"] + 1, "missing": cp["seq"] - last["seq"],
                             "start_utc": last["written_utc"], "end_utc": cp.get("record_written_utc"), "kind": "tail_incomplete"})
                cp_results.append({"seq": cp["seq"], "status": "beyond_log_end"})
            else:
                cp_results.append({"seq": cp["seq"], "status": "within_gap"})
        if not fatal:
            top = max(c["seq"] for c in checkpoints)
            if last is not None and top > last["seq"]:
                tail = {"last_seq": last["seq"], "status": "incomplete", "checkpoint_seq": top}
            elif last is not None and top == last["seq"]:
                tail = {"last_seq": last["seq"], "status": "attested", "checkpoint_seq": top}
            else:
                tail = {"last_seq": last["seq"] if last else None, "status": "unattested_after_checkpoint", "checkpoint_seq": top}

    usable = fatal is None and bool(good)
    ok = usable and not rejected and not gaps
    if fatal:
        reason = fatal
    elif not good:
        reason = rejected[0]["reason"] if rejected else "empty log"
    elif ok:
        reason = "chain and signatures verify"
    else:
        reason = f"{len(rejected)} rejected line(s), {len(gaps)} gap(s); remaining records verify"
    return {"ok": ok, "usable": usable, "records": good if usable else [], "rejected": rejected, "gaps": gaps,
            "segments": segments, "tail": tail, "checkpoints": cp_results, "reason": reason,
            "chain_head": last["record_hash"] if last and usable else None, "count": len(good) if usable else 0,
            "first_bad": rejected[0]["line"] if rejected else None}
