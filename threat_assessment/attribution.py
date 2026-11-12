"""Source attribution from the Cowrie-observed src_ip only. Forwarded-for style fields are ignored and reported.

Relay sessions (attribution config v2/v3) may be attributed only from a session entry of a signed attribution result
that threat_assessment.signed_attribution has verified; plain dictionaries are never accepted (Task 26C, F-1).
"""
import ipaddress
import re

from .config import AttributionConfig

FORWARDED_FIELD = re.compile(r"(forwarded|x[-_]?real[-_]?ip|client[-_]?ip|true[-_]?client|proxy)", re.I)
STATES = ("attributable", "attributable_via_proxy_mapping", "unattributed:no_source", "unattributed:invalid_source",
          "unattributed:trusted_proxy", "unattributed:mapping_unavailable", "unattributed:result_rejected", "unattributed:result_conflict",
          "unattributed:result_inconsistent", "protected", "shared_source", "enforcement_excluded")
ATTRIBUTABLE_STATES = ("attributable", "attributable_via_proxy_mapping")


def _classify(ip, cfg: AttributionConfig):
    if any(ip in n for n in cfg.protected):
        return "protected", "source inside a protected network"
    if any(ip in n for n in cfg.shared_sources):
        return "shared_source", "configured NAT/shared source"
    if any(ip in n for n in cfg.enforcement_excluded):
        return "enforcement_excluded", "source permanently excluded from enforcement (e.g. demo control client)"
    return None, None


def attribute(record: dict, cfg: AttributionConfig, mapping: dict = None) -> dict:
    """mapping: VerifiedAttribution.lookup(session_ref) - {"status": verified|rejected|conflict, ...} - or None."""
    ignored = sorted(k for k in record if k != "src_ip" and FORWARDED_FIELD.search(k))
    ip_s = record.get("src_ip")
    out = {"source": ip_s, "source_field": "src_ip", "ignored_untrusted_fields": ignored, "subject": None}
    if not ip_s:
        return {**out, "state": "unattributed:no_source", "reason": "no Cowrie-observed src_ip"}
    try:
        ip = ipaddress.ip_address(ip_s)
    except ValueError:
        return {**out, "state": "unattributed:invalid_source", "reason": f"src_ip {ip_s!r} is not an IP address"}
    if ip in cfg.relay_addresses or any(ip in n for n in cfg.trusted_proxies):
        if not cfg.mapping_enabled:
            return {**out, "state": "unattributed:trusted_proxy", "reason": "relay/trusted proxy; no client mapping configured"}
        if not mapping:
            return {**out, "state": "unattributed:mapping_unavailable", "reason": "no verified signed attribution result covers this session"}
        if mapping["status"] == "rejected":
            return {**out, "state": "unattributed:result_rejected", "reason": mapping["reason"]}
        if mapping["status"] == "conflict":
            return {**out, "state": "unattributed:result_conflict", "reason": mapping["reason"]}
        e = mapping["entry"]
        m = {"result_id": mapping["result_id"], "result_hash": mapping["result_hash"], "decision": e["decision"], "reason": e["reason"],
             "client": e["client"], "relay_listener": e["relay_listener"], "relay_to_cowrie": e["relay_to_cowrie"],
             "connection_id": (e["relay_records"] or {}).get("connection_id"), "close_check": e["close_check"]}
        if (e["relay_to_cowrie"] or {}).get("src_ip") != ip_s:
            return {**out, "state": "unattributed:result_inconsistent", "reason": "signed result's relay tuple does not match the Cowrie-observed source",
                    "mapping": m}
        if e["decision"] != "attributable_via_proxy_mapping":
            return {**out, "state": e["decision"], "reason": e["reason"], "mapping": m}
        client = ipaddress.ip_address(e["client"]["ip"])
        if cfg.registry.get(str(client), {}).get("role") != e["client"].get("role"):
            return {**out, "state": "unattributed:result_inconsistent", "reason": "client not in the pinned registry", "mapping": m}
        st, why = _classify(client, cfg)
        if st:
            return {**out, "state": st, "reason": f"mapped client {client}: {why}", "mapping": m}
        return {**out, "state": "attributable_via_proxy_mapping", "subject": str(client),
                "reason": "verified signed attribution result maps this session to a registered demo client", "mapping": m}
    st, why = _classify(ip, cfg)
    if st:
        return {**out, "state": st, "reason": why}
    return {**out, "state": "attributable", "subject": ip_s, "reason": "Cowrie-observed src_ip, not proxy/protected/shared"}
