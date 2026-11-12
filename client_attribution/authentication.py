"""Session-level authentication correlation from Cowrie events (F-2). Independent of behavioural_evidence.

A session has `login_success_observed` only when, under its own Cowrie session ID, there is exactly one
`cowrie.session.connect` and exactly one `cowrie.login.success` whose src_ip (and sensor, when present) equal the
connect's, timestamped at/after the connect and at/before the (single) close. Command input is never considered.
Anything else is indeterminate with a reason. Passwords are never copied.
"""
from collections import defaultdict
from typing import Dict, Iterable

from .records import ts

STATES = ("login_success_observed", "indeterminate:no_login_success_event", "indeterminate:ambiguous")


def correlate_authentication(events: Iterable[dict]) -> Dict[str, dict]:
    per = defaultdict(lambda: defaultdict(list))
    for e in events:
        per[e.get("session")][e.get("eventid")].append(e)
    out = {}
    for sid, ev in sorted(per.items(), key=lambda kv: str(kv[0])):
        if not sid:
            continue
        conns, succ, fail, closed = (ev["cowrie.session.connect"], ev["cowrie.login.success"], ev["cowrie.login.failed"],
                                     ev["cowrie.session.closed"])
        res = {"n_login_success": len(succ), "n_login_failed": len(fail), "login_success_utc": None, "username": None, "sensor": None}

        def done(state, reason):
            out[sid] = {**res, "state": state, "reason": reason}

        if len(conns) != 1:
            done("indeterminate:ambiguous", f"{len(conns)} session.connect events")
            continue
        if not succ:
            done("indeterminate:no_login_success_event", "no cowrie.login.success under this session ID")
            continue
        if len(succ) > 1:
            done("indeterminate:ambiguous", f"{len(succ)} cowrie.login.success events in one session")
            continue
        if len(closed) > 1:
            done("indeterminate:ambiguous", f"{len(closed)} session.closed events")
            continue
        c, s = conns[0], succ[0]
        res.update({"login_success_utc": s.get("timestamp"), "username": s.get("username"), "sensor": s.get("sensor")})
        if s.get("src_ip") != c.get("src_ip"):
            done("indeterminate:ambiguous", "login.success src_ip differs from the session's connect")
            continue
        if s.get("sensor") and c.get("sensor") and s["sensor"] != c["sensor"]:
            done("indeterminate:ambiguous", "login.success sensor differs from the session's connect")
            continue
        try:
            t_s, t_c = ts(s["timestamp"]), ts(c["timestamp"])
            t_x = ts(closed[0]["timestamp"]) if closed else None
        except (KeyError, ValueError, AttributeError):
            done("indeterminate:ambiguous", "unparseable timestamp")
            continue
        if t_s < t_c or (t_x is not None and t_s > t_x):
            done("indeterminate:ambiguous", "login.success outside the session's connect..close interval")
            continue
        done("login_success_observed", "exactly one cowrie.login.success correlated by session ID, source, sensor and time")
    return out
