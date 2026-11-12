"""Feedback and outcome review (R6: stays inside the response layer).

Reads the response audit log only. It produces outcome records, a review queue and metrics, and records operator
annotations as audit events. It never changes threat severity, assessment thresholds, proposal gates, behavioural
evidence, clustering/novelty models or any configuration; it imports nothing from those packages. Any policy change
suggested by these results needs a separate human-approved policy version.
"""
from collections import Counter

from .states import FAILURE_STATES

LABELS = ("true_positive", "false_positive", "inconclusive")


def outcomes(entries):
    out = {}
    for e in entries:
        pid = e.get("proposal_id")
        if pid is None:
            continue
        o = out.setdefault(pid, {"proposal_id": pid, "final_state": None, "events": [], "verification": None, "rollback": None,
                                 "labels": [], "rejected_operations": 0})
        if e["event"] == "annotation_recorded":
            o["labels"].append({k: e["details"].get(k) for k in ("label", "operator", "note")})
        elif e["event"] == "operation_rejected":
            o["rejected_operations"] += 1
        else:
            o["events"].append(e["event"])
            o["final_state"] = e["to_state"]
            if e["event"] in ("verification_passed", "verification_failed"):
                o["verification"] = e["details"].get("outcome")
            if e["event"] in ("rollback_verified", "rollback_failed"):
                o["rollback"] = e["event"]
    for o in out.values():
        ev = set(o["events"])
        o["response_success"] = "verification_passed" in ev and "verification_failed" not in ev and "rollback_failed" not in ev
        o["failure"] = bool(ev & {"verification_failed", "rollback_failed"}) or o["final_state"] in FAILURE_STATES
    return out


def annotate(audit, proposal_id, operator, label, note=""):
    if label not in LABELS:
        raise ValueError(f"label must be one of {LABELS}")
    if not operator:
        raise ValueError("operator identity is required")
    return audit.append("annotation_recorded", proposal_id, {"operator": operator, "label": label, "note": note})


def review_queue(entries):
    q = []
    for pid, o in outcomes(entries).items():
        reasons = []
        if "verification_failed" in o["events"]:
            reasons.append("verification failed")
        if o["rollback"] == "rollback_failed":
            reasons.append("rollback failed")
        if any(l["label"] == "false_positive" for l in o["labels"]):
            reasons.append("labelled false positive")
        if o["rejected_operations"]:
            reasons.append(f"{o['rejected_operations']} rejected operation(s)")
        if reasons:
            q.append({"proposal_id": pid, "final_state": o["final_state"], "reasons": reasons})
    unattached = sum(1 for e in entries if e["event"] == "operation_rejected" and e.get("proposal_id") is None)
    if unattached:
        q.append({"proposal_id": None, "final_state": None, "reasons": [f"{unattached} rejected operation(s) without a known proposal"]})
    return q


def metrics(entries):
    outs = outcomes(entries)
    c = Counter(o["final_state"] for o in outs.values())
    labels = Counter(l["label"] for o in outs.values() for l in o["labels"])
    return {"proposals": len(outs), "final_states": dict(c), "response_success": sum(o["response_success"] for o in outs.values()),
            "response_failure": sum(o["failure"] for o in outs.values()), "labels": dict(labels),
            "rejected_operations": sum(1 for e in entries if e["event"] == "operation_rejected"),
            "note": "dry-run metrics; no real response was executed"}
