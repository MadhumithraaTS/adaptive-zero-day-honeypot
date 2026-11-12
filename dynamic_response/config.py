"""Response policy (`response-policy-1`). This version supports dry-run only: any document that requests enforcement is
refused at load. The approver registry holds public keys only; production approver keys are not provisioned."""
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

from .common import ResponseError, sha256_hex, ts

SCHEMA = "response-policy-1"
MAX_TTL_SECONDS = 900                    # R2: 15 minutes, never more
SUPPORTED_ACTION = "restrict_new_connections"
SUPPORTED_LISTENER = "demo"
REQUIRED_ATTRIBUTION = "attributable_via_proxy_mapping"   # R4: only relay-attributed sources


class ResponseConfigError(ResponseError):
    pass


@dataclass(frozen=True)
class Approver:
    name: str
    key_id: str
    public_key_sha256: str
    public_key_pem: bytes
    not_before: datetime
    not_after: datetime


@dataclass(frozen=True)
class ResponsePolicy:
    version: str
    digest: str
    mode: str
    max_ttl_seconds: int
    proposal_validity_seconds: int
    skew_seconds: int
    action: str
    listener: str
    required_attribution: str
    address_safety_digest: str
    registry_status: str
    approvers: Tuple[Approver, ...]

    def approver(self, key_id: str) -> Optional[Approver]:
        return next((a for a in self.approvers if a.key_id == key_id), None)


def _approver(entry) -> Approver:
    from threat_assessment.config import ed25519_public_key_identity
    from threat_assessment.errors import AssessmentConfigError
    for k in ("name", "key_id", "public_key_sha256", "public_key_pem", "not_before", "not_after"):
        if k not in entry:
            raise ResponseConfigError(f"approver entry missing {k!r}")
    pem = entry["public_key_pem"].encode("ascii") if isinstance(entry["public_key_pem"], str) else entry["public_key_pem"]
    try:
        ident = ed25519_public_key_identity(pem, f"approver {entry['name']}")
    except AssessmentConfigError as exc:
        raise ResponseConfigError(str(exc)) from exc
    if ident != entry["public_key_sha256"] or entry["key_id"] != ident[:16]:
        raise ResponseConfigError(f"approver {entry['name']}: key_id/public_key_sha256 do not match the public key")
    return Approver(name=entry["name"], key_id=entry["key_id"], public_key_sha256=ident, public_key_pem=pem,
                    not_before=ts(entry["not_before"]), not_after=ts(entry["not_after"]))


def from_document(doc) -> ResponsePolicy:
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise ResponseConfigError(f"response policy must have schema {SCHEMA!r}")
    if doc.get("enforcement_activated") is not False or doc.get("mode") != "dry_run":
        raise ResponseConfigError("this version supports dry-run only: mode must be 'dry_run' and enforcement_activated false")
    ttl = doc.get("max_ttl_seconds")
    if not isinstance(ttl, int) or not 0 < ttl <= MAX_TTL_SECONDS:
        raise ResponseConfigError(f"max_ttl_seconds must be 1..{MAX_TTL_SECONDS}")
    pv, skew = doc.get("proposal_validity_seconds"), doc.get("clock_skew_seconds")
    if not isinstance(pv, int) or not 0 < pv <= 3600 or not isinstance(skew, int) or not 0 <= skew <= 30:
        raise ResponseConfigError("proposal_validity_seconds (1..3600) and clock_skew_seconds (0..30) are required")
    if doc.get("action") != SUPPORTED_ACTION or doc.get("listener") != SUPPORTED_LISTENER:
        raise ResponseConfigError(f"only action {SUPPORTED_ACTION!r} on listener {SUPPORTED_LISTENER!r} is supported")
    if doc.get("required_attribution") != REQUIRED_ATTRIBUTION:
        raise ResponseConfigError(f"required_attribution must be {REQUIRED_ATTRIBUTION!r} (R4)")
    ref = doc.get("address_safety") or {}
    if not isinstance(ref.get("sha256_digest"), str) or len(ref["sha256_digest"]) != 64:
        raise ResponseConfigError("address_safety.sha256_digest must be pinned")
    reg = doc.get("approver_registry") or {}
    status, entries = reg.get("status"), reg.get("approvers")
    if status not in ("pending_provisioning", "provisioned") or not isinstance(entries, list):
        raise ResponseConfigError("approver_registry needs status pending_provisioning|provisioned and an approvers list")
    if status == "pending_provisioning" and entries:
        raise ResponseConfigError("a pending approver registry must be empty")
    approvers = tuple(_approver(e) for e in entries)
    if len({a.key_id for a in approvers}) != len(approvers):
        raise ResponseConfigError("duplicate approver keys")
    return ResponsePolicy(version=str(doc.get("config_version")), digest=sha256_hex(doc), mode="dry_run", max_ttl_seconds=ttl,
                          proposal_validity_seconds=pv, skew_seconds=skew, action=SUPPORTED_ACTION, listener=SUPPORTED_LISTENER,
                          required_attribution=REQUIRED_ATTRIBUTION, address_safety_digest=ref["sha256_digest"],
                          registry_status=status, approvers=approvers)


def load_response_policy(path) -> ResponsePolicy:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ResponseConfigError(f"cannot read response policy {path}: {exc}") from exc
    return from_document(doc)
