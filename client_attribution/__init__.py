"""Verified client attribution: verify signed relay mapping records, correlate them with Cowrie sessions, correlate
session authentication, and sign the complete result for threat_assessment (Task 26A; trust boundary Task 26C).

A Cowrie session is attributed to a client ONLY when exactly one verified relay `connection_open` record on a demo
listener matches the session's `cowrie.session.connect` (src_ip, src_port) within the time constraints, the client is
in the registry, the close is consistent and no relay-log gap overlaps the session. Everything else stays
unattributed with an explicit reason. This package is the signer; threat_assessment only verifies.
"""
from .authentication import correlate_authentication
from .checkpoints import make_checkpoint, verify_checkpoints
from .correlate import AttributionConfigV2, config_from_document, correlate, load_attribution_config, load_attribution_v2
from .records import RecordVerificationError, verify_records
from .result import RESULT_SCHEMA, build_result, sign_result

VERSION = "client-attribution-1.1.0"
__all__ = ["VERSION", "AttributionConfigV2", "config_from_document", "correlate", "load_attribution_config", "load_attribution_v2",
           "verify_records", "RecordVerificationError", "correlate_authentication", "make_checkpoint", "verify_checkpoints",
           "RESULT_SCHEMA", "build_result", "sign_result"]
