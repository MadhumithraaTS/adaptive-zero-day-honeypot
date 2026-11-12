"""Verification of human approval decisions (`response-approval-1`). The controller only VERIFIES approvals; signing
happens on the approver's own device (dynamic_response/approve_cli.py). The approval covers the exact rule: proposal,
target, action, duration, creation and expiry timestamps, and configuration/policy fingerprints. Any change to any
field invalidates the signature (R1: approver-signed rules; the controller holds no signing key)."""
from datetime import timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .common import ResponseError, sha256_hex, ts
from .rules import validate_window

APPROVAL_SCHEMA = "response-approval-1"
TOP = {"schema", "approval_id", "proposal_id", "proposal_hash", "decision", "reason", "approver", "decided_utc", "rule",
       "approval_hash", "signature"}
RULE = {"rule_id", "action", "target", "listener", "ttl_seconds", "created_utc", "expires_utc", "fingerprints"}


class ApprovalRejected(ResponseError):
    pass


def approval_hash(doc) -> str:
    return sha256_hex({k: v for k, v in doc.items() if k not in ("approval_hash", "signature")})


def verify_approval(doc, proposal, policy, current_fingerprints, now, other_role_key_sha256s=()):
    """Return the approved rule (decision 'approve') or None (decision 'reject'); raise ApprovalRejected otherwise."""
    if not isinstance(doc, dict) or set(doc) != TOP or doc.get("schema") != APPROVAL_SCHEMA:
        raise ApprovalRejected("unexpected approval format")
    if doc["approval_hash"] != approval_hash(doc):
        raise ApprovalRejected("approval_hash mismatch (approval modified)")
    approver = doc["approver"] if isinstance(doc["approver"], dict) else {}
    reg = policy.approver(approver.get("key_id"))
    if reg is None:
        raise ApprovalRejected("approver key is not in the approver registry")
    if reg.public_key_sha256 in set(other_role_key_sha256s):
        raise ApprovalRejected("approver key is also used by another key role (key-role separation)")
    if approver.get("name") != reg.name:
        raise ApprovalRejected("approver name does not match the registry")
    try:
        key = serialization.load_pem_public_key(reg.public_key_pem)
        key.verify(bytes.fromhex(doc["signature"]), doc["approval_hash"].encode("ascii"))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ApprovalRejected("approval signature invalid") from exc
    decided = ts(doc["decided_utc"])
    if not reg.not_before <= decided <= reg.not_after:
        raise ApprovalRejected("approver key not valid at the decision time")
    if decided > now + timedelta(seconds=policy.skew_seconds):
        raise ApprovalRejected("decision dated in the future")
    if doc["proposal_id"] != proposal["proposal_id"] or doc["proposal_hash"] != proposal["proposal_hash"]:
        raise ApprovalRejected("approval does not refer to this exact proposal")
    if not ts(proposal["created_utc"]) <= decided <= ts(proposal["expires_utc"]):
        raise ApprovalRejected("approval decided outside the proposal validity (expired proposal)")
    if doc["decision"] == "reject":
        if not isinstance(doc["reason"], str) or not doc["reason"].strip():
            raise ApprovalRejected("a rejection needs a reason")
        return None
    if doc["decision"] != "approve":
        raise ApprovalRejected("decision must be 'approve' or 'reject'")
    rule = doc["rule"]
    if not isinstance(rule, dict) or set(rule) != RULE:
        raise ApprovalRejected("unexpected rule format")
    a = proposal["action"]
    if rule["action"] != a["type"] or rule["listener"] != a["listener"]:
        raise ApprovalRejected("approved action or listener differs from the proposal")
    if rule["target"] != a["target"]:                       # re-validated against address safety by the controller
        raise ApprovalRejected("approved target differs from the proposal")
    if rule["fingerprints"] != proposal["fingerprints"] or rule["fingerprints"] != current_fingerprints:
        raise ApprovalRejected("configuration/policy fingerprints changed since the proposal")
    if not isinstance(rule["ttl_seconds"], int) or rule["ttl_seconds"] > a["max_ttl_seconds"]:
        raise ApprovalRejected("approved duration exceeds the proposal maximum")
    if ts(rule["created_utc"]) < decided - timedelta(seconds=policy.skew_seconds):
        raise ApprovalRejected("rule created before the approval decision")
    try:
        validate_window(rule["created_utc"], rule["expires_utc"], rule["ttl_seconds"], policy.max_ttl_seconds, policy.skew_seconds, now)
    except ResponseError as exc:
        raise ApprovalRejected(str(exc)) from exc
    return dict(rule)

