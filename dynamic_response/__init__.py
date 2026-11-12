"""Dynamic Response & Feedback — DRY-RUN ONLY (Task 27B).

Workflow: threat-assessment `propose` output (verified signed relay attribution) -> response proposal -> human approval
signed on the approver's device (R1) -> controller verification (target allowlist, <= 15 min duration, fingerprints,
single decision) -> dry-run processing (nothing is enforced) -> operator verification (R5) -> simulated rollback ->
hash-chained response audit -> feedback (R6: response layer only).

Real enforcement is NOT implemented: `relay_interface.DisabledRelayEnforcement` raises on every call and the response
policy loader refuses any document that enables enforcement. Design: reports/dynamic_response_feedback_design_20261112/.
"""
from .audit import ResponseAuditLog, verify_response_log
from .config import ResponseConfigError, ResponsePolicy, from_document as response_policy_from_document, load_response_policy
from .controller import ResponseController
from .feedback import annotate, metrics, outcomes, review_queue
from .relay_interface import DisabledRelayEnforcement, EnforcementDisabledError

VERSION = "dynamic-response-1.0.0-dry-run"
__all__ = ["VERSION", "ResponseAuditLog", "verify_response_log", "ResponseConfigError", "ResponsePolicy", "response_policy_from_document",
           "load_response_policy", "ResponseController", "annotate", "metrics", "outcomes", "review_queue", "DisabledRelayEnforcement",
           "EnforcementDisabledError"]
