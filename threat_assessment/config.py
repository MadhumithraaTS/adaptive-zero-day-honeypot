"""Versioned attribution and policy configuration. Every list is explicit; there are no implicit defaults.

Attribution config schemas:
  v1  no proxy mapping (relay sessions unattributable).
  v2  unsigned proxy mapping (Task 26A). Withdrawn by Task 26C (F-1): v2 pins no result-signing key, so no
      attribution result can be verified and relay sessions stay unattributed.
  v3  signed attribution results verified here with a pinned public key; protected/shared/excluded addresses come only
      from the referenced address-safety config (pinned by digest); inline address lists are rejected (F-8).
Policy schemas: 2.0 (legacy, historical reproduction) and 2.1 (pins the address-safety digest; successful login
requires an authentication event, never command input alone - F-2).
"""
import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

from .errors import AssessmentConfigError

ATTRIBUTION_SCHEMA = "threat-attribution-config-1"
ATTRIBUTION_SCHEMA_V2 = "threat-attribution-config-2"     # unsigned proxy mapping (withdrawn: F-1)
ATTRIBUTION_SCHEMA_V3 = "threat-attribution-config-3"     # signed attribution results (Task 26C)
ADDRESS_SAFETY_SCHEMA = "address-safety-config-1"
RESULT_SCHEMA = "signed-attribution-result-1"
POLICY_SCHEMA_VERSION = "2.0"
POLICY_SCHEMA_V21 = "2.1"
POLICY_SCHEMAS = (POLICY_SCHEMA_VERSION, POLICY_SCHEMA_V21)
REPO_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_ATTR_KEYS = ("schema", "config_version", "source_field", "trusted_proxy_cidrs", "relay_addresses", "proxy_client_mapping",
                      "shared_source_cidrs", "protected_cidrs", "internal_cidrs")
REQUIRED_ATTR_KEYS_V3 = ("schema", "config_version", "source_field", "trusted_proxy_cidrs", "relay_addresses", "internal_cidrs",
                         "address_safety", "proxy_client_mapping", "attribution_result", "excluded_diagnostic_sessions")
ADDRESS_LIST_KEYS = ("protected_cidrs", "shared_source_cidrs", "enforcement_excluded_sources", "enforcement_allowlist")
INLINE_ADDRESS_KEYS = ("protected_cidrs", "shared_source_cidrs", "enforcement_excluded_sources", "protected_networks",
                       "enforcement_allowlist")
MAPPING_KEYS = ("public_key_sha256", "relay_upstream_addresses", "demo_listeners", "client_registry", "correlation_skew_seconds",
                "max_record_age_seconds", "key_validity")
CONDITION_KEYS = ("min_finding_severity", "min_interpretation_evidence_level", "min_distinct_action_indicators", "require_successful_login",
                  "require_attributable_source", "exclude_protected_and_shared_sources", "require_verified_configuration_digests",
                  "require_no_processing_errors")
CONDITION_KEYS_V21 = CONDITION_KEYS + ("require_authentication_event",)
MAX_RESULT_VALIDITY_S = 86400


def canonical_digest(doc) -> str:
    """SHA-256 of canonical JSON (sorted keys, no whitespace): independent of file formatting."""
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _nets(values, key):
    if not isinstance(values, list):
        raise AssessmentConfigError(f"{key} must be an explicit list")
    out = []
    for v in values:
        try:
            out.append(ipaddress.ip_network(v, strict=True))
        except ValueError as exc:
            raise AssessmentConfigError(f"{key}: invalid CIDR {v!r} ({exc})") from exc
    return tuple(out)


def _ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _hex64(v):
    return isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)


def _pin(value, role) -> str:
    """A key pin is the SHA-256 of the raw Ed25519 public key as exactly 64 lowercase hex characters. Any other spelling
    (case, whitespace, prefix) is rejected, so equal keys always have byte-equal pins and role comparison cannot be evaded."""
    if not _hex64(value):
        raise AssessmentConfigError(f"{role} pin must be 64 lowercase hex characters (SHA-256 of the raw Ed25519 public key)")
    return value


def ed25519_public_key_identity(pem, role) -> str:
    """SHA-256 of the raw Ed25519 public key in `pem`. Every failure (missing, malformed, private key, other algorithm)
    raises AssessmentConfigError. The identity depends on the key, not on its PEM encoding."""
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    if not isinstance(pem, (bytes, bytearray)) or not pem:
        raise AssessmentConfigError(f"{role} public key is missing")
    try:
        key = serialization.load_pem_public_key(bytes(pem))
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise AssessmentConfigError(f"{role} public key is malformed or not a PEM public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise AssessmentConfigError(f"{role} public key must be Ed25519 (got {type(key).__name__})")
    return hashlib.sha256(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()


def validate_address_safety(doc) -> str:
    """Validate the single authoritative address-safety document; return its canonical digest."""
    if not isinstance(doc, dict) or doc.get("schema") != ADDRESS_SAFETY_SCHEMA:
        raise AssessmentConfigError(f"address-safety config must have schema {ADDRESS_SAFETY_SCHEMA!r}")
    for k in ("config_version",) + ADDRESS_LIST_KEYS:
        if k not in doc:
            raise AssessmentConfigError(f"address-safety config missing {k!r}")
    nets = {k: _nets(doc[k], k) for k in ADDRESS_LIST_KEYS}
    for a in nets["enforcement_allowlist"]:
        for k in ("protected_cidrs", "shared_source_cidrs", "enforcement_excluded_sources"):
            if any(a.overlaps(n) for n in nets[k]):
                raise AssessmentConfigError(f"enforcement_allowlist {a} overlaps {k}")
    return canonical_digest(doc)


@dataclass(frozen=True)
class AttributionConfig:
    config_version: str
    digest: str
    trusted_proxies: Tuple
    relay_addresses: Tuple
    shared_sources: Tuple
    protected: Tuple
    internal: Tuple
    internal_cidr_strings: Tuple[str, ...]
    relay_strings: Tuple[str, ...]
    mapping_enabled: bool = False                 # v2/v3: relay sessions may be attributed via a client mapping
    enforcement_excluded: Tuple = ()              # v2/v3: sources that may never be an action subject (control client)
    schema: str = ATTRIBUTION_SCHEMA
    registry: Dict[str, dict] = field(default_factory=dict)
    demo_listeners: Tuple[str, ...] = ()
    mapping_relays: Tuple[str, ...] = ()
    skew_s: float = 0.0
    excluded_sessions: frozenset = frozenset()
    address_safety_digest: Optional[str] = None
    address_safety_version: Optional[str] = None
    enforcement_allowlist: Tuple = ()
    result_key_sha256: Optional[str] = None       # v3 only; None = no verifiable results (v2, or v3 pending)
    relay_key_sha256: Optional[str] = None        # v3 only; the relay record key pin (never valid as a result key)
    witness_key_sha256: Optional[str] = None      # v3 optional `checkpoint_witness` block (Task 28A); None = no witness requirement
    witness_public_key_pem: Optional[bytes] = None
    witness_status: str = "none"                  # none | mock (TEST/LOCAL MOCK, never production trust) | provisioned
    witness_max_age_s: int = 0
    witness_max_lag_s: int = 0
    trust_anchor_digest: Optional[str] = None
    result_key_status: str = "none"
    result_public_key_pem: Optional[bytes] = None
    result_max_validity_s: int = 0
    result_key_not_before: Optional[datetime] = None
    result_key_not_after: Optional[datetime] = None

    @classmethod
    def from_document(cls, doc, address_doc=None, result_public_key_pem: Optional[bytes] = None, witness_public_key_pem: Optional[bytes] = None,
                      allow_mock_witness: bool = False):
        schema = doc.get("schema")
        if schema == ATTRIBUTION_SCHEMA_V3:
            return cls._from_v3(doc, address_doc, result_public_key_pem, witness_public_key_pem, allow_mock_witness)
        missing = [k for k in REQUIRED_ATTR_KEYS if k not in doc]
        if missing:
            raise AssessmentConfigError(f"attribution config missing {missing}")
        if schema not in (ATTRIBUTION_SCHEMA, ATTRIBUTION_SCHEMA_V2):
            raise AssessmentConfigError(f"attribution config schema {schema!r} unsupported")
        if doc["source_field"] != "src_ip":
            raise AssessmentConfigError("only the Cowrie-observed src_ip may be used as source identity")
        mapping = doc["proxy_client_mapping"]
        if schema == ATTRIBUTION_SCHEMA and mapping is not None:
            raise AssessmentConfigError("proxy client mapping requires attribution config schema v2/v3; v1 must be null")
        if schema == ATTRIBUTION_SCHEMA_V2:
            cls._check_mapping(doc, mapping)
            if "enforcement_excluded_sources" not in doc:
                raise AssessmentConfigError("v2 requires an explicit enforcement_excluded_sources list")
        base = cls._base(doc)
        extra = {}
        if schema == ATTRIBUTION_SCHEMA_V2:
            extra = cls._mapping_fields(doc, mapping)
        return cls(**base, shared_sources=_nets(doc["shared_source_cidrs"], "shared_source_cidrs"),
                   protected=_nets(doc["protected_cidrs"], "protected_cidrs"), mapping_enabled=schema == ATTRIBUTION_SCHEMA_V2,
                   enforcement_excluded=_nets(doc.get("enforcement_excluded_sources", []), "enforcement_excluded_sources"),
                   schema=schema, **extra)

    # ---------------------------------------------------------------------------------------------- helpers
    @staticmethod
    def _check_mapping(doc, mapping):
        if not isinstance(mapping, dict) or mapping.get("verifier") != "client_attribution":
            raise AssessmentConfigError("proxy_client_mapping with verifier 'client_attribution' is required")
        for k in MAPPING_KEYS:
            if k not in mapping:
                raise AssessmentConfigError(f"proxy_client_mapping missing {k!r}")
        if not set(mapping["relay_upstream_addresses"]) <= set(doc["relay_addresses"]):
            raise AssessmentConfigError("mapping relay_upstream_addresses must be configured relay addresses")

    @staticmethod
    def _mapping_fields(doc, m):
        return {"registry": dict(m["client_registry"]), "demo_listeners": tuple(m["demo_listeners"]),
                "mapping_relays": tuple(m["relay_upstream_addresses"]), "skew_s": float(m["correlation_skew_seconds"]),
                "excluded_sessions": frozenset(doc.get("excluded_diagnostic_sessions", []))}

    @staticmethod
    def _base(doc):
        if not doc["internal_cidrs"]:
            raise AssessmentConfigError("internal_cidrs must be explicitly configured (non-empty); implicit defaults are not allowed")
        relays = []
        for a in doc["relay_addresses"]:
            try:
                relays.append(ipaddress.ip_address(a))
            except ValueError as exc:
                raise AssessmentConfigError(f"relay_addresses: invalid address {a!r}") from exc
        return {"config_version": str(doc["config_version"]), "digest": canonical_digest(doc),
                "trusted_proxies": _nets(doc["trusted_proxy_cidrs"], "trusted_proxy_cidrs"), "relay_addresses": tuple(relays),
                "internal": _nets(doc["internal_cidrs"], "internal_cidrs"), "internal_cidr_strings": tuple(doc["internal_cidrs"]),
                "relay_strings": tuple(doc["relay_addresses"])}

    @classmethod
    def _from_v3(cls, doc, address_doc, pem, witness_pem=None, allow_mock_witness=False):
        missing = [k for k in REQUIRED_ATTR_KEYS_V3 if k not in doc]
        if missing:
            raise AssessmentConfigError(f"attribution config v3 missing {missing}")
        inline = [k for k in INLINE_ADDRESS_KEYS if k in doc]
        if inline:
            raise AssessmentConfigError(f"attribution config v3 must not carry inline address lists {inline}; use the address-safety config")
        if doc["source_field"] != "src_ip":
            raise AssessmentConfigError("only the Cowrie-observed src_ip may be used as source identity")
        cls._check_mapping(doc, doc["proxy_client_mapping"])
        ref = doc["address_safety"]
        if not isinstance(ref, dict) or not _hex64(ref.get("sha256_digest")) or not ref.get("path"):
            raise AssessmentConfigError("address_safety must give a path and a sha256_digest")
        if address_doc is None:
            raise AssessmentConfigError("attribution config v3 requires its address-safety document")
        a_digest = validate_address_safety(address_doc)
        if a_digest != ref["sha256_digest"]:
            raise AssessmentConfigError(f"address-safety digest {a_digest[:16]} does not match the pinned {ref['sha256_digest'][:16]} (drift)")
        if ref.get("config_version") != address_doc["config_version"]:
            raise AssessmentConfigError("address-safety config_version does not match the reference")
        r = doc["attribution_result"]
        if not isinstance(r, dict) or r.get("verifier") != "threat_assessment.signed_attribution" or r.get("schema") != RESULT_SCHEMA:
            raise AssessmentConfigError(f"attribution_result must use verifier 'threat_assessment.signed_attribution' and schema {RESULT_SCHEMA!r}")
        mv = r.get("max_validity_seconds")
        if not isinstance(mv, int) or not 0 < mv <= MAX_RESULT_VALIDITY_S:
            raise AssessmentConfigError(f"attribution_result.max_validity_seconds must be 1..{MAX_RESULT_VALIDITY_S}")
        relay_pin = _pin(doc["proxy_client_mapping"]["public_key_sha256"], "relay record key")
        status, key_sha, nb, na = r.get("status"), r.get("public_key_sha256"), None, None
        if status == "provisioned":
            key_sha = _pin(key_sha, "attribution_result")
            # K-1 key-role separation: the relay signs relay records only; it must never be able to sign attribution
            # results. Pins are canonical (raw-key SHA-256, lowercase hex), so equal keys always compare equal here.
            if key_sha == relay_pin:
                raise AssessmentConfigError("key-role separation: the attribution_result key must not be the relay record key")
            kv = r.get("key_validity") or {}
            if not kv.get("not_before") or not kv.get("not_after"):
                raise AssessmentConfigError("provisioned attribution_result needs key_validity not_before/not_after")
            nb, na = _ts(kv["not_before"]), _ts(kv["not_after"])
            if pem is None:
                raise AssessmentConfigError("provisioned attribution_result requires its public key")
            ident = ed25519_public_key_identity(pem, "attribution_result")
            if ident == relay_pin:
                raise AssessmentConfigError("key-role separation: the attribution_result public key is the relay record key")
            if ident != key_sha:
                raise AssessmentConfigError("attribution_result public key does not match the pinned sha256")
        elif status == "pending_provisioning":
            if key_sha is not None:
                raise AssessmentConfigError("pending attribution_result must not pin a key")
            pem = None
        else:
            raise AssessmentConfigError("attribution_result.status must be 'provisioned' or 'pending_provisioning'")
        witness = _witness_block(doc.get("checkpoint_witness"), relay_pin, key_sha if status == "provisioned" else None, witness_pem,
                                 allow_mock_witness)
        return cls(**cls._base(doc), **witness, shared_sources=_nets(address_doc["shared_source_cidrs"], "shared_source_cidrs"),
                   protected=_nets(address_doc["protected_cidrs"], "protected_cidrs"), mapping_enabled=True,
                   enforcement_excluded=_nets(address_doc["enforcement_excluded_sources"], "enforcement_excluded_sources"),
                   schema=ATTRIBUTION_SCHEMA_V3, **cls._mapping_fields(doc, doc["proxy_client_mapping"]),
                   address_safety_digest=a_digest, address_safety_version=str(address_doc["config_version"]),
                   enforcement_allowlist=_nets(address_doc["enforcement_allowlist"], "enforcement_allowlist"),
                   result_key_sha256=key_sha if status == "provisioned" else None, result_key_status=status, relay_key_sha256=relay_pin,
                   result_public_key_pem=pem, result_max_validity_s=mv, result_key_not_before=nb, result_key_not_after=na)


def _witness_block(w, relay_pin, result_pin, witness_pem, allow_mock):
    """Optional `checkpoint_witness` block (Task 28A). Absent => no witness requirement (existing behaviour)."""
    if w is None:
        return {}
    if not isinstance(w, dict) or w.get("status") not in ("mock", "provisioned"):
        raise AssessmentConfigError("checkpoint_witness.status must be 'mock' or 'provisioned'")
    if w["status"] == "mock" and not allow_mock:
        raise AssessmentConfigError("TEST/LOCAL MOCK checkpoint witness refused: not production trust (allowed only in tests/local mock mode)")
    pin = _pin(w.get("public_key_sha256"), "checkpoint_witness")
    if pin in {relay_pin, result_pin}:
        raise AssessmentConfigError("key-role separation: the checkpoint witness key must differ from the relay and result keys")
    if witness_pem is None:
        raise AssessmentConfigError("checkpoint_witness requires its public key")
    if ed25519_public_key_identity(witness_pem, "checkpoint_witness") != pin:
        raise AssessmentConfigError("checkpoint_witness public key does not match its pin")
    age, lag, anchor = w.get("max_checkpoint_age_seconds"), w.get("max_replication_lag_seconds"), w.get("trust_anchor_digest")
    if not isinstance(age, int) or not 0 < age <= 600 or not isinstance(lag, int) or not 0 < lag <= 900:
        raise AssessmentConfigError("checkpoint_witness needs max_checkpoint_age_seconds (1..600) and max_replication_lag_seconds (1..900)")
    if not _hex64(anchor):
        raise AssessmentConfigError("checkpoint_witness.trust_anchor_digest must be pinned (PENDING_PROVISIONING is refused)")
    return {"witness_key_sha256": pin, "witness_public_key_pem": bytes(witness_pem), "witness_status": w["status"], "witness_max_age_s": age,
            "witness_max_lag_s": lag, "trust_anchor_digest": anchor}


def load_attribution_config(path, repo_root=None, result_public_key_pem: Optional[bytes] = None) -> AttributionConfig:
    """Load an attribution config. v3 also loads its address-safety document and (if provisioned) the result public key;
    paths inside v3 are relative to repo_root (default: the repository containing this package)."""
    root = Path(repo_root) if repo_root else REPO_ROOT
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssessmentConfigError(f"cannot read attribution config {path}: {exc}") from exc
    address_doc = None
    if doc.get("schema") == ATTRIBUTION_SCHEMA_V3:
        try:
            address_doc = json.loads((root / doc["address_safety"]["path"]).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AssessmentConfigError(f"cannot read address-safety config: {exc}") from exc
        r = doc.get("attribution_result") or {}
        if result_public_key_pem is None and r.get("status") == "provisioned" and r.get("public_key_path"):
            try:
                result_public_key_pem = (root / r["public_key_path"]).read_bytes()
            except OSError as exc:
                raise AssessmentConfigError(f"cannot read attribution result public key: {exc}") from exc
    return AttributionConfig.from_document(doc, address_doc=address_doc, result_public_key_pem=result_public_key_pem)


@dataclass(frozen=True)
class PolicyConfig:
    policy_version: str
    digest: str
    attribution_digest: str
    catalogue: str
    conditions: dict
    action: dict
    manual_approval_required: bool
    enforcement: str
    schema_version: str = POLICY_SCHEMA_VERSION
    address_safety_digest: Optional[str] = None
    require_authentication_event: bool = False

    @classmethod
    def from_document(cls, doc):
        sv = doc.get("schema_version")
        if sv not in POLICY_SCHEMAS:
            raise AssessmentConfigError(f"policy schema {sv!r} unsupported (need one of {POLICY_SCHEMAS}); v1 is not consumed")
        if doc.get("manual_approval_required") is not True:
            raise AssessmentConfigError("manual_approval_required must be true")
        if doc.get("enforcement") != "disabled":
            raise AssessmentConfigError("enforcement must be 'disabled' in this version")
        cond = doc.get("proposal_conditions", {})
        keys = CONDITION_KEYS_V21 if sv == POLICY_SCHEMA_V21 else CONDITION_KEYS
        missing = [k for k in keys if k not in cond]
        if missing:
            raise AssessmentConfigError(f"policy proposal_conditions missing {missing}")
        for k in keys:
            if k.startswith(("require_", "exclude_")) and cond[k] is not True:
                raise AssessmentConfigError(f"policy condition {k} cannot be relaxed")
        if cond["min_distinct_action_indicators"] < 2 or cond["min_finding_severity"] not in ("S2", "S3") \
                or cond["min_interpretation_evidence_level"] not in ("E2", "E3"):
            raise AssessmentConfigError("policy thresholds below the approved minimum (S2, E2, 2 action indicators)")
        att = doc.get("attribution_config", {}).get("sha256_digest")
        if not att or len(att) != 64:
            raise AssessmentConfigError("policy must pin the attribution config digest")
        addr = None
        if sv == POLICY_SCHEMA_V21:
            inline = [k for k in INLINE_ADDRESS_KEYS if k in doc]
            if inline:
                raise AssessmentConfigError(f"policy 2.1 must not carry inline address lists {inline}; pin the address-safety config")
            addr = doc.get("address_safety_config", {}).get("sha256_digest")
            if not _hex64(addr):
                raise AssessmentConfigError("policy 2.1 must pin the address-safety config digest")
        act = doc.get("proposed_action", {})
        if act.get("mode") != "dry_run" or not act.get("inverse") or not act.get("ttl_seconds"):
            raise AssessmentConfigError("proposed_action must be dry_run with a TTL and an inverse operation")
        return cls(policy_version=str(doc.get("policy_version")), digest=canonical_digest(doc), attribution_digest=att,
                   catalogue=doc.get("required_behavioural_evidence_catalogue"), conditions=dict(cond), action=dict(act),
                   manual_approval_required=True, enforcement="disabled", schema_version=sv, address_safety_digest=addr,
                   require_authentication_event=sv == POLICY_SCHEMA_V21)


def load_policy(path) -> PolicyConfig:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssessmentConfigError(f"cannot read policy {path}: {exc}") from exc
    return PolicyConfig.from_document(doc)
