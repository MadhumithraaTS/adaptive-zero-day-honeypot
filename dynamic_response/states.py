"""Response lifecycle state machine (dry-run). Every state change is an audit event; the verifier re-runs this table.

`verified_effective` (enforcement confirmed) is deliberately absent: it can only exist when real enforcement is
implemented and activated. A failed rollback can never become a successful one (it can only close at TTL lapse).
"""
TRANSITIONS = {
    # event:                (allowed from states,                                 to state)
    "proposal_created":     ({None},                                               "proposed"),
    "approval_recorded":    ({"proposed"},                                         "approved"),
    "rejection_recorded":   ({"proposed"},                                         "rejected"),
    "proposal_expired":     ({"proposed"},                                         "proposal_expired"),
    "simulated":            ({"approved"},                                         "simulated"),
    "approval_expired":     ({"approved"},                                         "expired_unexecuted"),
    "verification_passed":  ({"simulated"},                                        "verified_dry_run"),
    "verification_failed":  ({"simulated"},                                        "verification_failed"),
    "rule_expired":         ({"simulated", "verified_dry_run"},                    "expired"),
    "revoked":              ({"simulated", "verified_dry_run"},                    "revoked"),
    "rollback_started":     ({"verification_failed", "expired", "revoked"},        "rollback_pending"),
    "rollback_verified":    ({"rollback_pending"},                                 "rolled_back"),
    "rollback_failed":      ({"rollback_pending"},                                 "rollback_failed"),
    "closed_after_ttl":     ({"rollback_failed"},                                  "rollback_failed_closed"),
}
NON_STATE_EVENTS = {"operation_rejected", "annotation_recorded"}
TERMINAL = {"rejected", "proposal_expired", "expired_unexecuted", "rolled_back", "rollback_failed_closed"}
FAILURE_STATES = {"verification_failed", "rollback_failed", "rollback_failed_closed"}


class TransitionError(ValueError):
    pass


def next_state(current, event):
    if event in NON_STATE_EVENTS:
        if event == "annotation_recorded" and current is None:
            raise TransitionError("annotation for an unknown proposal")
        return current
    if event not in TRANSITIONS:
        raise TransitionError(f"unknown or not-permitted event {event!r}")
    allowed, to = TRANSITIONS[event]
    if current not in allowed:
        raise TransitionError(f"invalid transition {current!r} --{event}-->")
    return to
