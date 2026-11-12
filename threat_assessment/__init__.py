"""Threat assessment and policy-eligibility engine (Task 24).

Consumes session records produced by the unchanged `behavioural_evidence` package and produces, per session:
findings (one per interpretation) with interpretation-specific evidence level and an independent S0-S3 severity,
per-finding source attribution, a policy tier (abstain / record / review / propose) with every gate's result, and a
hash-chained audit entry. Proposed actions are recorded with their inverse and are never executed.
Design: reports/threat_assessment_design_20261111/.
1.1.0 (Task 26A): relay sessions attributed via an (unsigned) client_attribution result (attribution config v2).
1.2.0 (Task 26C): only SIGNED attribution results, verified here with a pinned public key, are used (config v3);
address lists come from one address-safety config; policy 2.1 requires an authentication event for successful login.
"""
from .assessment import ThreatAssessor, assess_sessions
from .audit import AuditLog, verify_chain
from .config import AttributionConfig, PolicyConfig, load_attribution_config, load_policy
from .signed_attribution import SignedResultError, VerifiedAttribution, verify_result, verify_results
from .errors import AssessmentConfigError, AssessmentInputError

ASSESSMENT_VERSION = "threat-assessment-1.2.0"

__all__ = ["ASSESSMENT_VERSION", "ThreatAssessor", "assess_sessions", "AuditLog", "verify_chain", "AttributionConfig",
           "PolicyConfig", "load_attribution_config", "load_policy", "AssessmentConfigError", "AssessmentInputError",
           "SignedResultError", "VerifiedAttribution", "verify_result", "verify_results"]
