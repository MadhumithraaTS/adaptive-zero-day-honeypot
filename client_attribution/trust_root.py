"""Trust-root manifest and recovery-authorisation verification (D10, D11, D16).

A `trust-root-manifest-1` pins the six current key roles - relay_record, attribution_result, checkpoint_witness,
replicator_push and administrators A and B - plus approval thresholds and configuration digests. All identities must
be pairwise distinct; the human-approval role (seventh) is optional and must also be distinct.

Signatures: `ed25519-canonical-v1` (Ed25519 over the SHA-256 of the canonical document without signatures). The
administrators' production signing tool (planned: `ssh-keygen -Y sign`) is not yet agreed; until D0 is resolved only
TEST/LOCAL MOCK administrators sign. Thresholds:
  trust_root_change 2 (both), routine_rotation 1 (either), ordinary_recovery 1 (either), elevated_recovery 2 (both).
"""
import hashlib
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .placeholders import PLACEHOLDER_MARKERS
from .records import canonical, ts

MANIFEST_SCHEMA = "trust-root-manifest-1"
RECOVERY_SCHEMA = "recovery-authorisation-1"
SIG_SCHEME = "ed25519-canonical-v1"
ROLES = ("relay_record", "attribution_result", "checkpoint_witness", "replicator_push")
ADMINS = ("A", "B")
REQUIRED_THRESHOLDS = {"trust_root_change": 2, "routine_rotation": 1, "ordinary_recovery": 1, "elevated_recovery": 2}
MANIFEST_FIELDS = {"schema", "sequence", "previous_manifest_sha256", "issued_utc", "valid_until", "administrators", "thresholds", "roles",
                   "approval_role", "digests", "revoked", "mode"}
ORDINARY_CAUSES = {"ack_timeout", "witness_unavailable", "storage", "replication_lag", "heartbeat_missing", "key_expired", "clock"}
ELEVATED_CAUSES = {"integrity", "invalid_ack", "conflict", "gap", "broken_chain", "invalid_signature", "anchor_mismatch", "compromise"}


class TrustRootError(ValueError):
    pass


def doc_digest(doc) -> str:
    return hashlib.sha256(canonical({k: v for k, v in doc.items() if k != "signatures"}).encode("utf-8")).hexdigest()


def anchor_fingerprint(manifest) -> str:
    """Fingerprint of the administrator key set (what is pinned out of band as the trust-anchor fingerprint)."""
    return hashlib.sha256(canonical({a: manifest["administrators"][a]["public_key_sha256"] for a in ADMINS}).encode()).hexdigest()


def _is_placeholder(v):
    return isinstance(v, str) and any(m in v.upper() for m in PLACEHOLDER_MARKERS)


def _pub_sha(pem):
    k = serialization.load_pem_public_key(pem.encode("ascii") if isinstance(pem, str) else pem)
    return k, hashlib.sha256(k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()


def _check_manifest_shape(m, now):
    if not isinstance(m, dict) or set(m) - {"signatures"} != MANIFEST_FIELDS or m.get("schema") != MANIFEST_SCHEMA:
        raise TrustRootError("malformed trust-root manifest")
    if m["thresholds"] != REQUIRED_THRESHOLDS:
        raise TrustRootError("thresholds differ from the approved D10/D11 values")
    ids = []
    for a in ADMINS:
        adm = m["administrators"].get(a) or {}
        if _is_placeholder(adm.get("public_key_sha256")) or _is_placeholder(adm.get("public_key_pem")) or not adm.get("public_key_pem"):
            raise TrustRootError(f"administrator {a} is a placeholder (D0 not resolved)")
        _, sha = _pub_sha(adm["public_key_pem"])
        if sha != adm.get("public_key_sha256"):
            raise TrustRootError(f"administrator {a} public key does not match its pin")
        ids.append(sha)
    for r in ROLES:
        role = m["roles"].get(r) or {}
        if _is_placeholder(role.get("sha256")) or not isinstance(role.get("sha256"), str) or len(role["sha256"]) != 64:
            raise TrustRootError(f"role {r} is a placeholder or malformed")
        ids.append(role["sha256"])
    if m["approval_role"] is not None:
        ids.append(m["approval_role"]["sha256"])
    if len(ids) != len(set(ids)):
        raise TrustRootError("key-role separation: two roles share a key (all six roles, and the approval role, must be distinct)")
    if not ts(m["issued_utc"]) <= now <= ts(m["valid_until"]):
        raise TrustRootError("manifest outside its validity period")
    for r in ROLES:
        role = m["roles"][r]
        if not ts(role["not_before"]) <= now <= ts(role["not_after"]):
            raise TrustRootError(f"role {r} key outside its validity period")


def classify_change(previous, new) -> str:
    """routine_rotation only if nothing but role keys (and their validity) changed; anything else is a trust-root change."""
    if previous is None:
        return "trust_root_change"
    same = lambda k: canonical(previous[k]) == canonical(new[k])
    if not all(same(k) for k in ("administrators", "thresholds", "digests", "approval_role", "mode", "revoked")):
        return "trust_root_change"
    return "routine_rotation"


def _count_signatures(doc, signatures, admins):
    digest, signers = doc_digest(doc), set()
    for s in signatures or []:
        if not isinstance(s, dict) or s.get("scheme") != SIG_SCHEME or s.get("admin") not in admins:
            continue
        adm = admins[s["admin"]]
        if s.get("key_sha256") != adm["public_key_sha256"]:
            continue
        key, _ = _pub_sha(adm["public_key_pem"])
        try:
            key.verify(bytes.fromhex(s["signature"]), digest.encode("ascii"))
        except (InvalidSignature, ValueError, TypeError):
            continue
        signers.add(s["admin"])
    return signers


def verify_manifest(manifest, now: datetime, previous=None, pinned_anchor_fingerprint=None) -> dict:
    """Verify a manifest (and its change category against `previous`). Raises TrustRootError."""
    _check_manifest_shape(manifest, now)
    if previous is None:
        if pinned_anchor_fingerprint is None or _is_placeholder(pinned_anchor_fingerprint):
            raise TrustRootError("no trust-anchor fingerprint pinned (PENDING_PROVISIONING): the first manifest cannot be trusted")
        if anchor_fingerprint(manifest) != pinned_anchor_fingerprint:
            raise TrustRootError("administrator keys do not match the pinned trust-anchor fingerprint")
        if manifest["sequence"] != 1 or manifest["previous_manifest_sha256"] is not None:
            raise TrustRootError("first manifest must have sequence 1 and no predecessor")
        signing_admins = manifest["administrators"]
    else:
        if manifest["sequence"] != previous["sequence"] + 1 or manifest["previous_manifest_sha256"] != doc_digest(previous):
            raise TrustRootError("manifest does not extend the previous manifest")
        signing_admins = previous["administrators"]                 # changes are authorised by the CURRENT administrators
    category = classify_change(previous, manifest)
    signers = _count_signatures(manifest, manifest.get("signatures"), signing_admins)
    required = (previous or manifest)["thresholds"][category]
    if len(signers) < required:
        raise TrustRootError(f"{category} requires {required} administrator signature(s); got {len(signers)}")
    return {"ok": True, "category": category, "signers": sorted(signers), "digest": doc_digest(manifest)}


def recovery_category(cause) -> str:
    if cause in ELEVATED_CAUSES:
        return "elevated"
    if cause in ORDINARY_CAUSES:
        return "ordinary"
    raise TrustRootError(f"unknown halt cause {cause!r}")


def verify_recovery_authorisation(auth, manifest, now, halt_ref, minimum_category) -> dict:
    """D11: ordinary recovery needs either administrator; elevated recovery needs both."""
    fields = {"schema", "log_id", "halt_ref", "category", "cause", "incident_ref", "issued_utc", "valid_until", "operator", "signatures"}
    if not isinstance(auth, dict) or set(auth) != fields or auth["schema"] != RECOVERY_SCHEMA:
        raise TrustRootError("malformed recovery authorisation")
    if auth["category"] not in ("ordinary", "elevated"):
        raise TrustRootError("category must be ordinary or elevated")
    if recovery_category(auth["cause"]) == "elevated" and auth["category"] != "elevated":
        raise TrustRootError("the declared cause requires elevated recovery")
    if minimum_category == "elevated" and auth["category"] != "elevated":
        raise TrustRootError("this halt requires elevated (two-administrator) recovery")
    if auth["halt_ref"] != halt_ref:
        raise TrustRootError("authorisation refers to another halt")
    if not ts(auth["issued_utc"]) <= now <= ts(auth["valid_until"]) or (ts(auth["valid_until"]) - ts(auth["issued_utc"])).total_seconds() > 3600:
        raise TrustRootError("authorisation expired, not yet valid, or valid for more than 1 hour")
    if not auth["operator"] or not auth["incident_ref"]:
        raise TrustRootError("operator and incident reference are required")
    signers = _count_signatures(auth, auth["signatures"], manifest["administrators"])
    required = manifest["thresholds"]["elevated_recovery" if auth["category"] == "elevated" else "ordinary_recovery"]
    if len(signers) < required:
        raise TrustRootError(f"{auth['category']} recovery requires {required} administrator signature(s); got {len(signers)}")
    return {"category": auth["category"], "signers": sorted(signers), "authorisation_hash": doc_digest(auth)}
