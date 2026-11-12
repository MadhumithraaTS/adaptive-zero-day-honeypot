"""Signed attribution results (F-1). The attribution component signs the COMPLETE result document; threat_assessment
verifies it independently with a pinned public key and never holds the private key.

Format `signed-attribution-result-1` (canonical JSON; result_hash = SHA-256 of the document without result_hash and
signature; signature = Ed25519 over the ASCII result_hash). See reports/attribution_trust_boundary_remediation_20261111/
signed_attribution_design.md.
"""
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization

from .records import canonical

RESULT_SCHEMA = "signed-attribution-result-1"


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _hp(s):
    if not s or ":" not in s:
        return {"ip": None, "port": None}
    h, p = s.rsplit(":", 1)
    return {"ip": h, "port": int(p) if p.isdigit() else None}


def session_entry(sid, m, auth):
    """One per Cowrie session: identity, tuples, timestamps, relay record identity, decision and authentication."""
    attributable = m.get("state") == "attributable_via_proxy_mapping"
    up = {"ip": m.get("upstream_local_ip"), "port": m.get("upstream_local_port")} if m.get("upstream_local_ip") else _hp(m.get("cowrie_src"))
    return {
        "cowrie_session_id": sid,
        "decision": m.get("state"),
        "reason": m.get("reason"),
        "client": {"ip": m.get("client_ip"), "port": m.get("client_port"), "role": m.get("client_role")} if attributable else None,
        "relay_listener": ({**_hp(m.get("ingress_listener")), "name": m.get("listener"), "mode": m.get("listener_mode"),
                            "accepted_local": m.get("accepted_local")} if m.get("ingress_listener") else None),
        "relay_to_cowrie": {"src_ip": up["ip"], "src_port": up["port"], **{f"dst_{k}": v for k, v in _hp(m.get("cowrie_dst")).items()}},
        "timestamps": {"relay_accepted_utc": m.get("relay_accepted_utc"), "relay_upstream_connected_utc": m.get("relay_upstream_connected_utc"),
                       "cowrie_connect_utc": m.get("cowrie_connect_utc"), "relay_closed_utc": m.get("relay_closed_utc"),
                       "cowrie_closed_utc": m.get("cowrie_closed_utc")},
        "relay_records": ({"connection_id": m.get("connection_id"),
                           "open": {"seq": m.get("relay_open_seq"), "record_hash": m.get("relay_record_hash")},
                           "close": ({"seq": m["relay_close_seq"], "record_hash": m["relay_close_record_hash"]} if m.get("relay_close_seq") else None)}
                          if m.get("connection_id") else None),
        "close_check": m.get("close_check"),
        "authentication": {k: auth.get(k) for k in ("state", "reason", "login_success_utc", "username", "sensor", "n_login_success",
                                                     "n_login_failed")} if auth else
                          {"state": "indeterminate:no_login_success_event", "reason": "no events for this session", "login_success_utc": None,
                           "username": None, "sensor": None, "n_login_success": 0, "n_login_failed": 0},
    }


def witness_evidence(chain, replication_status, now, max_age_seconds=120, max_lag_seconds=900, mock=False):
    """Signer-side freshness rule (Task 28A): refuse to sign unless the newest checkpoint is fresh and the off-host
    head covers it within the lag bound. Returns the `relay_log.witness` block."""
    from .records import ts
    if not chain:
        raise ValueError("no witness checkpoints: refusing to sign")
    head = chain[-1]
    if (now - ts(head["attested_utc"])).total_seconds() > max_age_seconds:
        raise ValueError("newest witness checkpoint is stale: refusing to sign")
    st = replication_status or {}
    covered = [c for c in chain if c["checkpoint_seq"] <= st.get("remote_head_checkpoint_seq", 0)]
    if not covered or not st.get("pushed_utc") or (now - ts(st["pushed_utc"])).total_seconds() > max_lag_seconds:
        raise ValueError("off-host replication not confirmed within the lag bound: refusing to sign")
    return {"checkpoint": head, "offhost_confirmed_utc": st["pushed_utc"], "offhost_head_checkpoint_seq": st["remote_head_checkpoint_seq"],
            "mode": "TEST/LOCAL MOCK (not production trust)" if mock else "production"}


def build_result(correlation: dict, authentication: dict, cfg, cowrie_events, issued: datetime, validity_seconds: int,
                 evaluation_time: datetime, result_id: str = None, witness: dict = None) -> dict:
    events = list(cowrie_events)
    stamps = sorted(e["timestamp"] for e in events if e.get("timestamp"))
    ver = correlation["verification"]
    return {
        "schema": RESULT_SCHEMA,
        "result_id": result_id or str(uuid.uuid4()),
        "issued_utc": _iso(issued),
        "not_after_utc": _iso(issued + timedelta(seconds=validity_seconds)),
        "evaluation_time_utc": _iso(evaluation_time),
        "attribution_config": {"schema": cfg.doc.get("schema"), "config_version": cfg.doc.get("config_version"), "digest": cfg.digest},
        "relay_log": {"public_key_sha256": cfg.public_key_sha256, "verification": ver.get("reason"), "intact": ver.get("ok"),
                      "record_count": ver.get("count"), "chain_head": ver.get("chain_head"), "gaps": ver.get("gaps", []),
                      "rejected_lines": len(ver.get("rejected", [])), "tail": ver.get("tail"), "checkpoints": ver.get("checkpoints", []),
                      **({"witness": witness} if witness else {})},
        "cowrie_input": {"n_events": len(events), "first_utc": stamps[0] if stamps else None, "last_utc": stamps[-1] if stamps else None,
                         "sha256": hashlib.sha256("\n".join(canonical(e) for e in events).encode("utf-8")).hexdigest()},
        "sessions": [session_entry(sid, m, authentication.get(sid)) for sid, m in sorted(correlation["sessions"].items())],
    }


def sign_result(doc: dict, private_key) -> dict:
    """Signer side only. Adds signer identity, result_hash and signature over the complete document."""
    raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sha = hashlib.sha256(raw).hexdigest()
    body = {k: v for k, v in doc.items() if k not in ("signer", "result_hash", "signature")}
    body["signer"] = {"key_id": sha[:16], "public_key_sha256": sha}
    body["result_hash"] = hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()
    body["signature"] = private_key.sign(body["result_hash"].encode("ascii")).hex()
    return body
