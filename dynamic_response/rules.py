"""Target and time-window validation. Targets come only from the authoritative address-safety configuration
(`configs/address_safety_v1.json`, loaded through the v3 attribution config); the allowlist is never expanded here."""
import ipaddress
from datetime import timedelta

from .common import ResponseError, ts


class TargetRejected(ResponseError):
    pass


class WindowRejected(ResponseError):
    pass


def validate_target(target, att) -> str:
    """Return the canonical single-address target `a.b.c.d/32`, or raise TargetRejected.

    `att` is a threat_assessment AttributionConfig (v3): protected, shared_sources, enforcement_excluded and
    enforcement_allowlist all come from the pinned address-safety document."""
    if not isinstance(target, str):
        raise TargetRejected(f"target must be one address string, got {type(target).__name__}")
    t = target.strip()
    if t != target or any(c in t for c in ", ;\t\n") or t.count("/") > 1:
        raise TargetRejected("multiple or malformed addresses are not allowed")
    try:
        net = ipaddress.ip_network(t, strict=True)
    except ValueError as exc:
        raise TargetRejected(f"invalid target {target!r}") from exc
    if net.version != 4:
        raise TargetRejected("only IPv4 targets are supported")
    if net.prefixlen != 32:
        raise TargetRejected("exactly one address (/32) is allowed")
    ip = net.network_address
    for nets, why in ((att.protected, "protected network"), (att.shared_sources, "shared source"),
                      (att.enforcement_excluded, "enforcement-excluded address (e.g. control client)")):
        if any(ip in n for n in nets):
            raise TargetRejected(f"target {ip} is a {why}")
    if not any(ip in n for n in att.enforcement_allowlist):
        raise TargetRejected(f"target {ip} is not in the enforcement allowlist")
    return f"{ip}/32"


def validate_window(created_utc, expires_utc, ttl_seconds, max_ttl_seconds, skew_seconds, now):
    """Duration bounded by the policy maximum (R2), consistent with its timestamps, and currently valid."""
    c, e = ts(created_utc), ts(expires_utc)
    if not isinstance(ttl_seconds, int) or not 0 < ttl_seconds <= max_ttl_seconds:
        raise WindowRejected(f"duration must be 1..{max_ttl_seconds} s")
    if (e - c).total_seconds() != ttl_seconds:
        raise WindowRejected("expiry does not equal creation + duration")
    if c > now + timedelta(seconds=skew_seconds):
        raise WindowRejected("rule created in the future")
    if now >= e:
        raise WindowRejected("rule expired")
    return c, e
