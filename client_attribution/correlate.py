"""Correlate verified relay records with Cowrie sessions. Exact tuple + time constraints; abstain on anything else."""
import hashlib
import ipaddress
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

from .records import load_public_key, ts, verify_records

SCHEMA_V2 = "threat-attribution-config-2"
SCHEMA_V3 = "threat-attribution-config-3"
STATES = ("attributable_via_proxy_mapping", "unattributed:mapping_missing", "unattributed:mapping_ambiguous",
          "unattributed:mapping_duplicate", "unattributed:mapping_untrusted", "unattributed:mapping_unavailable",
          "unattributed:mapping_expired", "unattributed:unregistered_peer", "unattributed:published_listener",
          "unattributed:close_inconsistent", "unattributed:not_via_relay", "unattributed:log_gap", "excluded_diagnostic")


def canonical_digest(doc):
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AttributionConfigV2:
    doc: dict
    digest: str
    relay_upstream: Tuple[str, ...]
    demo_listeners: Tuple[str, ...]
    registry: Dict[str, dict]
    excluded_sessions: frozenset
    skew_s: float
    max_record_age_s: float
    public_key_sha256: str
    key_not_before: Optional[datetime]
    key_not_after: Optional[datetime]


def config_from_document(doc) -> AttributionConfigV2:
    if doc.get("schema") not in (SCHEMA_V2, SCHEMA_V3):
        raise ValueError(f"attribution config schema {doc.get('schema')!r} is not {SCHEMA_V2!r} or {SCHEMA_V3!r}")
    m = doc.get("proxy_client_mapping")
    if not isinstance(m, dict):
        raise ValueError("proxy_client_mapping must be an object")
    for k in ("verifier", "public_key_sha256", "relay_upstream_addresses", "demo_listeners", "client_registry",
              "correlation_skew_seconds", "max_record_age_seconds", "key_validity"):
        if k not in m:
            raise ValueError(f"proxy_client_mapping missing {k!r}")
    if m["verifier"] != "client_attribution":
        raise ValueError("unsupported mapping verifier")
    kv = m["key_validity"]
    return AttributionConfigV2(
        doc=doc, digest=canonical_digest(doc), relay_upstream=tuple(m["relay_upstream_addresses"]), demo_listeners=tuple(m["demo_listeners"]),
        registry=dict(m["client_registry"]), excluded_sessions=frozenset(doc.get("excluded_diagnostic_sessions", [])),
        skew_s=float(m["correlation_skew_seconds"]), max_record_age_s=float(m["max_record_age_seconds"]),
        public_key_sha256=m["public_key_sha256"],
        key_not_before=ts(kv["not_before"]) if kv.get("not_before") else None, key_not_after=ts(kv["not_after"]) if kv.get("not_after") else None)


def load_attribution_v2(path) -> AttributionConfigV2:
    """Load a v2 or v3 attribution config (the mapping block is the same in both)."""
    return config_from_document(json.loads(Path(path).read_text(encoding="utf-8")))


load_attribution_config = load_attribution_v2


def _cowrie_sessions(events: Iterable[dict]):
    conn, closed = {}, {}
    for e in events:
        sid = e.get("session")
        if e.get("eventid") == "cowrie.session.connect":
            conn.setdefault(sid, []).append(e)
        elif e.get("eventid") == "cowrie.session.closed":
            closed.setdefault(sid, []).append(e)
    return conn, closed


def _gap_intervals(gaps):
    lo, hi = datetime.min.replace(tzinfo=timezone.utc), datetime.max.replace(tzinfo=timezone.utc)
    return [(ts(g["start_utc"]) if g.get("start_utc") else lo, ts(g["end_utc"]) if g.get("end_utc") else hi, g) for g in gaps]


def correlate(cowrie_events: Iterable[dict], record_lines, public_key_pem: bytes, cfg: AttributionConfigV2,
              evaluation_time: Optional[datetime] = None, checkpoints=None) -> Dict:
    """Return {"config_digest", "verification", "sessions": {session_ref: result}}. Pure function of its inputs.

    checkpoints: verified checkpoint dicts (checkpoints.verify_checkpoints). Sessions whose relay records could lie in a
    gap (missing seq range, missing head, or a tail shorter than a checkpoint) are `unattributed:log_gap`."""
    events = list(cowrie_events)
    conn, closed = _cowrie_sessions(events)
    out = {"config_digest": cfg.digest, "sessions": {}}
    if record_lines is None:
        ver = {"ok": False, "usable": False, "reason": "mapping log unavailable", "records": [], "gaps": [], "rejected": []}
    else:
        try:
            pub, pub_sha = load_public_key(public_key_pem)
        except Exception as exc:                                   # unusable key -> nothing can be trusted
            pub, pub_sha = None, None
            ver = {"ok": False, "usable": False, "reason": f"public key unusable: {exc}", "records": [], "gaps": [], "rejected": []}
        if pub is not None:
            if pub_sha != cfg.public_key_sha256:
                ver = {"ok": False, "usable": False, "reason": "public key does not match the pinned sha256", "records": [], "gaps": [],
                       "rejected": []}
            else:
                ver = verify_records(record_lines, pub, pub_sha, cfg.key_not_before, cfg.key_not_after, checkpoints=checkpoints)
    out["verification"] = {k: v for k, v in ver.items() if k != "records"}
    usable = ver["usable"]
    recs = ver.get("records", []) if usable else []
    gaps = _gap_intervals(ver.get("gaps", [])) if usable else []
    opens, by_cid, closes = defaultdict(list), defaultdict(list), defaultdict(list)
    for r in recs:
        if r["record_type"] == "connection_open":
            opens[(r["upstream_local_ip"], int(r["upstream_local_port"]))].append(r)
            by_cid[r["connection_id"]].append(r)
        elif r["record_type"] == "connection_close":
            closes[r["connection_id"]].append(r)
    eval_t = evaluation_time or datetime.now(timezone.utc)
    skew = timedelta(seconds=cfg.skew_s)
    for sid, cevs in sorted(conn.items()):
        res = {"session_ref": sid}
        c = cevs[0]

        def put(state, reason, **extra):
            out["sessions"][sid] = {**res, **extra, "state": state, "reason": reason}

        if sid in cfg.excluded_sessions:
            put("excluded_diagnostic", "registered diagnostic session; never evaluated")
            continue
        if len(cevs) != 1:
            put("unattributed:close_inconsistent", "multiple session.connect events for one session")
            continue
        src, sport, t = c.get("src_ip"), c.get("src_port"), ts(c["timestamp"])
        cc = closed.get(sid, [])
        res.update({"cowrie_src": f"{src}:{sport}", "cowrie_connect_utc": c["timestamp"], "cowrie_dst": f"{c.get('dst_ip')}:{c.get('dst_port')}",
                    "cowrie_closed_utc": cc[0]["timestamp"] if len(cc) == 1 else None})
        if src not in cfg.relay_upstream:
            put("unattributed:not_via_relay", "session did not arrive from a configured relay address")
            continue
        if sport is None:
            put("unattributed:mapping_missing", "Cowrie connect event has no src_port")
            continue
        if not usable:
            put("unattributed:mapping_unavailable" if record_lines is None else "unattributed:mapping_untrusted", ver["reason"])
            continue
        # A session's open record is written within the skew of its connect; a gap (records strictly between two verified
        # records, or before the first / after the last one) overlapping that window could hide a competing record.
        hit = [g for lo, hi, g in gaps if lo < t + skew and hi > t - skew]
        if hit:
            put("unattributed:log_gap", f"relay log {hit[0]['kind']} (seq {hit[0]['after_seq']}..{hit[0]['before_seq']}) overlaps the open window")
            continue
        cands = [r for r in opens.get((src, int(sport)), [])
                 if ts(r["accepted_utc"]) <= t + skew and abs((t - ts(r["upstream_connected_utc"])).total_seconds()) <= cfg.skew_s]
        if not cands:
            put("unattributed:mapping_missing", "no relay record with this upstream tuple in the time window")
            continue
        if len(cands) > 1:
            put("unattributed:mapping_ambiguous", f"{len(cands)} relay records match", connection_ids=[r["connection_id"] for r in cands])
            continue
        r = cands[0]
        res.update({"connection_id": r["connection_id"], "relay_record_hash": r["record_hash"], "relay_open_seq": r["seq"],
                    "listener": r["listener"], "listener_mode": r["listener_mode"], "ingress_listener": r["ingress_listener"],
                    "accepted_local": r["accepted_local"], "client_ip": r["client_ip"], "client_port": r["client_port"],
                    "upstream_local_ip": r["upstream_local_ip"], "upstream_local_port": r["upstream_local_port"],
                    "upstream_peer": r.get("upstream_peer"), "relay_accepted_utc": r["accepted_utc"],
                    "relay_upstream_connected_utc": r["upstream_connected_utc"]})
        if len(by_cid[r["connection_id"]]) != 1 or len(closes.get(r["connection_id"], [])) > 1:
            put("unattributed:mapping_duplicate", "connection_id appears in more than one open/close record")
            continue
        if (eval_t - ts(r["written_utc"])).total_seconds() > cfg.max_record_age_s:
            put("unattributed:mapping_expired", f"relay record older than {cfg.max_record_age_s:.0f} s")
            continue
        if r["listener_mode"] != "demo" or r["ingress_listener"] not in cfg.demo_listeners:
            put("unattributed:published_listener", "accepted on a non-demo listener (proxy peer)")
            continue
        if r["accepted_local"].split(":")[0] != r["ingress_listener"].split(":")[0]:
            put("unattributed:close_inconsistent", "accepted local address differs from the listener")
            continue
        reg = cfg.registry.get(r["client_ip"])
        if not reg:
            put("unattributed:unregistered_peer", "client IP not in the demo client registry")
            continue
        # close consistency via Cowrie session ID (Cowrie's close event has no src_port)
        rc = closes.get(r["connection_id"], [])
        if rc:
            res.update({"relay_close_seq": rc[0]["seq"], "relay_close_record_hash": rc[0]["record_hash"], "relay_closed_utc": rc[0]["closed_utc"]})
        if len(cc) > 1:
            put("unattributed:close_inconsistent", "multiple session.closed events")
            continue
        if cc and rc:
            ct, rt_ = ts(cc[0]["timestamp"]), ts(rc[0]["closed_utc"])
            if ct < ts(r["accepted_utc"]) or abs((ct - rt_).total_seconds()) > cfg.skew_s or \
                    (rc[0]["upstream_local_ip"], int(rc[0]["upstream_local_port"])) != (src, int(sport)):
                put("unattributed:close_inconsistent", "Cowrie and relay close records disagree")
                continue
            res["close_check"] = "consistent"
        elif cc and not rc:
            ct = ts(cc[0]["timestamp"])
            if any(lo < ct + skew and hi > ct - skew for lo, hi, _ in gaps):
                put("unattributed:log_gap", "the relay close record may lie in a relay-log gap")
            else:
                put("unattributed:close_inconsistent", "Cowrie closed the session but the relay has no close record")
            continue
        else:
            res["close_check"] = "session_open"
        try:
            ipaddress.ip_address(r["client_ip"])
        except ValueError:
            put("unattributed:unregistered_peer", "invalid client IP")
            continue
        put("attributable_via_proxy_mapping", "exactly one verified demo-listener relay record matches tuple, time and close",
            client_role=reg.get("role"))
    return out
