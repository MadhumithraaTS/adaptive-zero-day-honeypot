"""Task 26D-1: key-role separation (K-1) and configuration error handling for attribution-result keys (K-2).

Uses only the ephemeral in-memory keys of tests/trust_fixtures.py. The non-Ed25519 key is the X25519 base point,
a fixed public value (no key generation). No key is written or modified."""
import copy
import dataclasses
import hashlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from threat_assessment import AssessmentConfigError, AttributionConfig, SignedResultError, verify_result
from threat_assessment.config import ed25519_public_key_identity
from trust_fixtures import (ADDR, ATT3, NOW, RELAY_KEY, RELAY_PEM, RELAY_SHA, RESULT_KEY, RESULT_PEM, RESULT_SHA, att3_doc, assessor3, demo,
                            resign)


def load(doc, pem):
    return AttributionConfig.from_document(doc, address_doc=ADDR, result_public_key_pem=pem)


def with_result_pin(pin, relay_pin=RELAY_SHA):
    doc = copy.deepcopy(att3_doc(result_sha=pin))
    doc["proxy_client_mapping"]["public_key_sha256"] = relay_pin
    return doc


def reencode(pem, *, crlf=False, strip_newline=False, extra_blank=False):
    """Same key, different PEM spelling."""
    s = pem.decode("ascii")
    if strip_newline:
        s = s.rstrip("\n")
    if extra_blank:
        s = "\n" + s + "\n\n"
    if crlf:
        s = s.replace("\n", "\r\n")
    return s.encode("ascii")


X25519_PEM = X25519PublicKey.from_public_bytes(bytes([9]) + bytes(31)).public_bytes(serialization.Encoding.PEM,
                                                                                    serialization.PublicFormat.SubjectPublicKeyInfo)


# ------------------------------------------------------------------------------------------------ K-1 role separation
def test_relay_key_as_result_key_is_rejected():
    with pytest.raises(AssessmentConfigError, match="key-role separation"):
        load(with_result_pin(RELAY_SHA), RELAY_PEM)


def test_distinct_correct_keys_are_accepted():
    cfg = load(with_result_pin(RESULT_SHA), RESULT_PEM)
    assert cfg.result_key_sha256 == RESULT_SHA and cfg.relay_key_sha256 == RELAY_SHA and cfg.result_key_sha256 != cfg.relay_key_sha256


@pytest.mark.parametrize("variant", [dict(crlf=True), dict(strip_newline=True), dict(extra_blank=True), dict(crlf=True, extra_blank=True)])
def test_reencoded_relay_pem_cannot_bypass(variant):
    """The identity is the raw key, so a re-encoded relay PEM is still recognised as the relay key."""
    pem = reencode(RELAY_PEM, **variant)
    assert ed25519_public_key_identity(pem, "x") == RELAY_SHA
    with pytest.raises(AssessmentConfigError, match="key-role separation"):
        load(with_result_pin(RELAY_SHA), pem)
    with pytest.raises(AssessmentConfigError, match="key-role separation"):       # pinned as a third key, PEM is the relay key
        load(with_result_pin(RESULT_SHA), pem)


@pytest.mark.parametrize("spelling", [lambda h: h.upper(), lambda h: " " + h, lambda h: h + "\n", lambda h: "sha256:" + h,
                                      lambda h: h[:63], lambda h: h + "0"])
def test_alternative_pin_spellings_are_rejected(spelling):
    """Pins must be canonical; a differently spelled relay pin cannot make the same key look like two keys."""
    with pytest.raises(AssessmentConfigError, match="64 lowercase hex"):
        load(with_result_pin(spelling(RELAY_SHA)), RELAY_PEM)                    # result pin spelled differently
    with pytest.raises(AssessmentConfigError, match="64 lowercase hex"):
        load(with_result_pin(RELAY_SHA, relay_pin=spelling(RELAY_SHA)), RELAY_PEM)   # relay pin spelled differently


def test_relay_pin_is_validated_even_while_result_key_is_pending():
    doc = copy.deepcopy(ATT3)
    doc["attribution_result"].update(status="pending_provisioning", public_key_sha256=None, key_validity=None)
    doc["proxy_client_mapping"]["public_key_sha256"] = RELAY_SHA.upper()
    with pytest.raises(AssessmentConfigError, match="relay record key pin"):
        load(doc, None)


def test_verifier_enforces_separation_even_if_config_validation_is_bypassed():
    """Defence in depth: a config object built around the loader cannot make the verifier accept the relay key."""
    rec, signed, _, _ = demo()
    good = load(ATT3, RESULT_PEM)
    forged_cfg = dataclasses.replace(good, result_key_sha256=RELAY_SHA, result_public_key_pem=RELAY_PEM)
    relay_signed = resign(signed, RELAY_KEY)                                       # relay key signs an attribution result
    with pytest.raises(SignedResultError, match="key-role separation"):
        verify_result(relay_signed, forged_cfg, NOW)
    with pytest.raises(SignedResultError, match="key-role separation"):
        verify_result(relay_signed, good, NOW)                                     # signer claims the relay key
    no_relay = dataclasses.replace(good, relay_key_sha256=None)
    with pytest.raises(SignedResultError, match="key-role separation"):
        verify_result(signed, no_relay, NOW)


def test_relay_signed_result_never_proposes():
    rec, signed, _, _ = demo()
    out = assessor3().assess(rec, resign(signed, RELAY_KEY), now=NOW)
    assert out["proposed_action"] is None and out["session_attribution"]["state"] == "unattributed:result_rejected"
    assert "key-role separation" in out["versions"]["attribution_results"]["rejected"][0]["reason"]


# ------------------------------------------------------------------------------------------------ K-2 error handling
PRIVATE_PEM = RESULT_KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


@pytest.mark.parametrize("pem,why", [
    (None, "requires its public key"), (b"", "missing"), (b"not a key", "malformed"),
    (RESULT_PEM[:40], "malformed"), (RESULT_PEM.replace(b"PUBLIC", b"PUBLIK"), "malformed"),
    (RESULT_PEM.replace(RESULT_PEM.splitlines()[1], b"!!!!" + RESULT_PEM.splitlines()[1][4:]), "malformed"),
    (PRIVATE_PEM, "malformed"), ("text, not bytes", "missing")])
def test_missing_or_malformed_result_key_raises_config_error(pem, why):
    with pytest.raises(AssessmentConfigError, match=why):
        load(ATT3, pem)


def test_non_ed25519_key_is_rejected_even_when_pinned():
    """Previously an X25519 key whose hash matched the pin was accepted and crashed later at verification."""
    raw = X25519PublicKey.from_public_bytes(bytes([9]) + bytes(31)).public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    doc = with_result_pin(hashlib.sha256(raw).hexdigest())
    with pytest.raises(AssessmentConfigError, match="must be Ed25519"):
        load(doc, X25519_PEM)


def test_malformed_keys_never_raise_raw_value_error():
    for pem in (b"junk", RESULT_PEM[:40], PRIVATE_PEM, X25519_PEM, b"-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"):
        try:
            load(ATT3, pem)
        except AssessmentConfigError:
            continue
        except Exception as exc:                                                    # pragma: no cover - the defect being fixed
            pytest.fail(f"{type(exc).__name__} escaped for {pem[:30]!r}")
        pytest.fail("malformed key accepted")


def test_verifier_converts_unusable_configured_key_into_rejection():
    good = load(ATT3, RESULT_PEM)
    rec, signed, _, _ = demo()
    broken = dataclasses.replace(good, result_public_key_pem=b"junk")
    with pytest.raises(SignedResultError, match="unusable"):
        verify_result(signed, broken, NOW)


def test_wrong_but_valid_key_is_rejected_by_pin():
    from trust_fixtures import ATTACKER_KEY
    other = ATTACKER_KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(AssessmentConfigError, match="does not match the pinned"):
        load(with_result_pin(RESULT_SHA), other)


# ------------------------------------------------------------------------------------------------ unchanged behaviour
def test_existing_valid_signature_verification_still_works():
    rec, signed, _, _ = demo()
    assert verify_result(signed, load(ATT3, RESULT_PEM), NOW)["result_id"] == signed["result_id"]
    out = assessor3().assess(rec, signed, now=NOW)
    assert out["tier"] == "propose" and out["proposed_action"]["subject"] == "10.250.25.3" and all(out["gates"].values())


def test_reencoded_genuine_result_key_is_accepted():
    cfg = load(ATT3, reencode(RESULT_PEM, crlf=True))
    rec, signed, _, _ = demo()
    assert verify_result(signed, cfg, NOW)["result_id"] == signed["result_id"]


def test_assessment_code_still_holds_no_private_key_capability():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "threat_assessment"
    for f in root.rglob("*.py"):
        src = f.read_text(encoding="utf-8")
        assert "load_pem_private_key" not in src and ".sign(" not in src and "Ed25519PrivateKey" not in src, f
        assert "from client_attribution" not in src and "import client_attribution" not in src, f
