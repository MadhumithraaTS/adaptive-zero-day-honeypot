"""Relay-side enforcement boundary: EXPLICITLY DISABLED in this version.

Real enforcement (staging approver-signed rules for the relay's demo-listener accept handler) is not implemented. It
depends on D0 -> M0-M8 -> A1, provisioning of the human-approval role P5 and a separate enforcement-activation approval.
Every call raises; nothing is written, sent or executed. The dry-run controller never calls this interface.
"""


class EnforcementDisabledError(RuntimeError):
    pass


class DisabledRelayEnforcement:
    enabled = False

    def stage_rule(self, rule):
        raise EnforcementDisabledError("relay enforcement is disabled: dry-run only (no rule staged)")

    def remove_rule(self, rule_id):
        raise EnforcementDisabledError("relay enforcement is disabled: dry-run only (nothing to remove)")

    def active_rules(self):
        raise EnforcementDisabledError("relay enforcement is disabled: no relay state is read")
