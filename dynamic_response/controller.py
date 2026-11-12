"""Dry-run response controller.

Proposal intake -> approval verification -> target and expiry validation -> dry-run processing -> operator verification
-> simulated rollback. The controller VERIFIES approvals and never creates them. It holds no private key, has no Docker,
process or network access, cannot modify trust anchors, and in dry-run never calls the relay enforcement boundary
(which is itself disabled). Every refused operation is recorded as `operation_rejected`; nothing is silently ignored.
"""
from .approval import ApprovalRejected, verify_approval
from .common import ResponseError, iso, sha256_hex, ts
from .proposals import ProposalRejected, build_proposal, fingerprints
from .relay_interface import DisabledRelayEnforcement
from .rules import TargetRejected, validate_target

VERIFICATION_FIELDS = {"verification_id", "proposal_id", "kind", "restriction_observed", "control_unaffected", "verified_utc", "operator",
                       "evidence_ref", "result"}


class ResponseController:
    def __init__(self, policy, att, defence_policy, audit, relay=None):
        if att.address_safety_digest != policy.address_safety_digest:
            raise ResponseError("response policy and attribution config pin different address-safety configs")
        self.policy, self.att, self.defence_policy, self.audit = policy, att, defence_policy, audit
        self.relay = relay or DisabledRelayEnforcement()           # never called in dry-run
        self.proposals, self.rules = {}, {}
        self._approvals_seen, self._verifications_seen = set(), set()
        self._other_role_keys = tuple(k for k in (att.relay_key_sha256, att.result_key_sha256) if k)

    # ---------------------------------------------------------------------------------------------------- helpers
    def state(self, proposal_id):
        return self.audit.state.get(proposal_id)

    def _reject(self, proposal_id, operation, reason):
        known = proposal_id if proposal_id in self.audit.state else None
        self.audit.append("operation_rejected", known, {"operation": operation, "reason": reason, "proposal_ref": proposal_id})
        return {"accepted": False, "state": self.state(proposal_id), "reason": reason}

    def _ok(self, proposal_id, reason=""):
        return {"accepted": True, "state": self.state(proposal_id), "reason": reason}

    def _fingerprints(self):
        return fingerprints(self.policy, self.att, self.defence_policy)

    # ---------------------------------------------------------------------------------------------------- intake
    def intake(self, assessment, assessment_audit_entries, now):
        try:
            p = build_proposal(assessment, assessment_audit_entries, self.policy, self.att, self.defence_policy, now)
        except (ProposalRejected, TargetRejected) as exc:
            return self._reject(None, "intake", str(exc))
        if p["proposal_id"] in self.proposals:
            return self._reject(p["proposal_id"], "intake", "duplicate proposal (already taken in)")
        self.proposals[p["proposal_id"]] = p
        self.audit.append("proposal_created", p["proposal_id"], {"target": p["action"]["target"], "expires_utc": p["expires_utc"]},
                          {"proposal_hash": p["proposal_hash"], "assessment_record_hash": p["assessment_audit"]["record_hash"],
                           "attribution_result_id": p["attribution"]["result_id"]})
        return {**self._ok(p["proposal_id"]), "proposal": p}

    # ---------------------------------------------------------------------------------------------------- approval
    def submit_decision(self, approval, now):
        pid = approval.get("proposal_id") if isinstance(approval, dict) else None
        if pid not in self.proposals:
            return self._reject(pid, "approval", "unknown proposal")
        key = (approval.get("approval_id"), approval.get("approval_hash"))
        if approval.get("approval_id") in {k[0] for k in self._approvals_seen} or key in self._approvals_seen:
            return self._reject(pid, "approval", "replayed approval document")
        if self.state(pid) != "proposed":
            return self._reject(pid, "approval", f"a decision already exists or the proposal is closed (state {self.state(pid)})")
        try:
            rule = verify_approval(approval, self.proposals[pid], self.policy, self._fingerprints(), now, self._other_role_keys)
            if rule is not None:
                validate_target(rule["target"], self.att)            # re-validated against the pinned address safety
        except (ApprovalRejected, TargetRejected, ResponseError) as exc:
            return self._reject(pid, "approval", str(exc))
        self._approvals_seen.add(key)
        refs = {"approval_id": approval["approval_id"], "approval_hash": approval["approval_hash"], "approver_key_id": approval["approver"]["key_id"]}
        if rule is None:
            self.audit.append("rejection_recorded", pid, {"reason": approval["reason"]}, refs)
            return self._ok(pid, "rejected by approver")
        self.rules[pid] = rule
        self.audit.append("approval_recorded", pid, {"rule_id": rule["rule_id"], "target": rule["target"], "ttl_seconds": rule["ttl_seconds"],
                                                     "expires_utc": rule["expires_utc"]}, {**refs, "rule_hash": sha256_hex(rule)})
        return self._ok(pid)

    # ---------------------------------------------------------------------------------------------------- execution
    def execute(self, proposal_id, now, mode="dry_run"):
        if mode != "dry_run" or self.policy.mode != "dry_run":
            return self._reject(proposal_id, "execute", "enforcement_not_activated: only dry-run is supported")
        if self.state(proposal_id) != "approved":
            return self._reject(proposal_id, "execute", f"duplicate or invalid execution (state {self.state(proposal_id)})")
        rule = self.rules[proposal_id]
        if now >= ts(rule["expires_utc"]):
            return self._reject(proposal_id, "execute", "approval expired before execution")
        if now < ts(rule["created_utc"]):
            return self._reject(proposal_id, "execute", "rule not yet valid")
        try:
            validate_target(rule["target"], self.att)
        except TargetRejected as exc:
            return self._reject(proposal_id, "execute", str(exc))
        if rule["fingerprints"] != self._fingerprints():
            return self._reject(proposal_id, "execute", "configuration/policy fingerprints changed since approval")
        self.audit.append("simulated", proposal_id, {"rule_id": rule["rule_id"], "target": rule["target"], "expires_utc": rule["expires_utc"],
                                                     "enforced": False, "note": "dry-run: no rule staged, relay not contacted"},
                          {"rule_hash": sha256_hex(rule)})
        return self._ok(proposal_id, "simulated (not enforced)")

    # ---------------------------------------------------------------------------------------------------- verification
    def _check_verification(self, v, proposal_id, kind, now):
        if not isinstance(v, dict) or set(v) != VERIFICATION_FIELDS:
            return "incomplete", "verification record has missing or unexpected fields"
        if v["proposal_id"] != proposal_id or v["kind"] != kind:
            return "invalid", "verification refers to another proposal or kind"
        missing = [k for k in ("operator", "evidence_ref") if not isinstance(v[k], str) or not v[k].strip()]
        if missing or not isinstance(v["restriction_observed"], bool) or not isinstance(v["control_unaffected"], bool) \
                or v["result"] not in ("pass", "fail"):
            return "incomplete", f"verification incomplete ({missing or 'observations/result missing'})"
        try:
            if ts(v["verified_utc"]) > now:
                return "invalid", "verification dated in the future"
        except ResponseError as exc:
            return "invalid", str(exc)
        return "complete", ""

    def record_verification(self, v, now):
        pid = v.get("proposal_id") if isinstance(v, dict) else None
        if pid not in self.proposals:
            return self._reject(pid, "verification", "unknown proposal")
        if isinstance(v, dict) and v.get("verification_id") in self._verifications_seen:
            return self._reject(pid, "verification", "replayed verification record")
        if self.state(pid) != "simulated":
            return self._reject(pid, "verification", f"no response awaiting verification (state {self.state(pid)})")
        status, why = self._check_verification(v, pid, "response", now)
        if status == "invalid":
            return self._reject(pid, "verification", why)
        self._verifications_seen.add(v.get("verification_id"))
        details = {k: v.get(k) for k in VERIFICATION_FIELDS if k != "proposal_id"}
        details["expected"] = {"restriction_observed": False, "control_unaffected": True}   # dry-run: no real effect expected
        if status == "incomplete":
            details["outcome"] = "incomplete"
            return self._fail_and_rollback(pid, details, why)
        rest_ok, ctrl_ok = v["restriction_observed"] is False, v["control_unaffected"] is True
        if rest_ok and ctrl_ok and v["result"] == "pass":
            details["outcome"] = "dry_run_confirmed_no_effect"
            self.audit.append("verification_passed", pid, details, {"evidence_ref": v["evidence_ref"]})
            return self._ok(pid, "dry-run verified: no real effect, control unaffected")
        details["outcome"] = "partial" if rest_ok != ctrl_ok else ("operator_reported_fail" if rest_ok else "unexpected_effect")
        return self._fail_and_rollback(pid, details, details["outcome"])

    def _fail_and_rollback(self, pid, details, why):
        self.audit.append("verification_failed", pid, details, {"evidence_ref": details.get("evidence_ref")})
        self._start_rollback(pid, f"verification failed: {why}")
        return {"accepted": True, "state": self.state(pid), "reason": f"verification failed ({why}); rollback started"}

    # ---------------------------------------------------------------------------------------------------- rollback / expiry
    def _start_rollback(self, pid, reason):
        rule = self.rules.get(pid, {})
        self.audit.append("rollback_started", pid, {"reason": reason, "inverse": {"type": "remove_restriction", "rule_id": rule.get("rule_id")},
                                                    "simulated": True, "relay_contacted": False})

    def revoke(self, proposal_id, operator, reason, now):
        if self.state(proposal_id) not in ("simulated", "verified_dry_run"):
            return self._reject(proposal_id, "revoke", f"nothing active to revoke (state {self.state(proposal_id)})")
        self.audit.append("revoked", proposal_id, {"operator": operator, "reason": reason, "at": iso(now)})
        self._start_rollback(proposal_id, f"revoked: {reason}")
        return self._ok(proposal_id, "revoked; rollback started")

    def record_rollback_verification(self, v, now):
        pid = v.get("proposal_id") if isinstance(v, dict) else None
        if pid not in self.proposals:
            return self._reject(pid, "rollback_verification", "unknown proposal")
        if isinstance(v, dict) and v.get("verification_id") in self._verifications_seen:
            return self._reject(pid, "rollback_verification", "replayed verification record")
        if self.state(pid) != "rollback_pending":
            return self._reject(pid, "rollback_verification", f"duplicate or invalid rollback attempt (state {self.state(pid)})")
        status, why = self._check_verification(v, pid, "rollback", now)
        if status == "invalid":
            return self._reject(pid, "rollback_verification", why)
        self._verifications_seen.add(v.get("verification_id"))
        details = {k: v.get(k) for k in VERIFICATION_FIELDS if k != "proposal_id"} if isinstance(v, dict) else {}
        if status == "complete" and v["restriction_observed"] is False and v["control_unaffected"] is True and v["result"] == "pass":
            self.audit.append("rollback_verified", pid, details, {"evidence_ref": v["evidence_ref"]})
            return self._ok(pid, "rollback verified")
        details["reason"] = why or "rollback verification did not pass"
        self.audit.append("rollback_failed", pid, details, {"evidence_ref": details.get("evidence_ref")})
        return {"accepted": True, "state": self.state(pid), "reason": "rollback FAILED (recorded); rule lapses only at TTL"}

    def tick(self, now):
        """Expiry processing. Never renews anything."""
        for pid, p in self.proposals.items():
            st, rule = self.state(pid), self.rules.get(pid)
            if st == "proposed" and now > ts(p["expires_utc"]):
                self.audit.append("proposal_expired", pid, {"at": iso(now)})
            elif rule and now >= ts(rule["expires_utc"]):
                if st == "approved":
                    self.audit.append("approval_expired", pid, {"at": iso(now)})
                elif st in ("simulated", "verified_dry_run"):
                    self.audit.append("rule_expired", pid, {"at": iso(now), "renewed": False})
                    self._start_rollback(pid, "expiry")
                elif st == "rollback_failed":
                    self.audit.append("closed_after_ttl", pid, {"at": iso(now), "note": "rule window lapsed; rollback remains FAILED"})
