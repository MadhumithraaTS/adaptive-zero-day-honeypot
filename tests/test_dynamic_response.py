"""Task 27B: Dynamic Response & Feedback, dry-run. Safety tests T1-T20 from
reports/dynamic_response_feedback_design_20261112/report.md §10, adapted to dry-run.

Uses the existing signed-attribution fixtures (tests/trust_fixtures.py) to produce real `propose` assessments and the
real assessment audit log. Approver keys are ephemeral in-memory TEST fixtures; no production key exists or is created.
Nothing is enforced: the relay boundary is disabled and is never called.
"""
import copy
import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dynamic_response import (DisabledRelayEnforcement, EnforcementDisabledError, ResponseAuditLog, ResponseConfigError, ResponseController,
                              annotate, load_response_policy, metrics, outcomes, response_policy_from_document, review_queue,
                              verify_response_log)
from dynamic_response.approve_cli import build_approval, sign_approval
from dynamic_response.common import iso
from dynamic_response.rules import TargetRejected, validate_target
from dynamic_response.states import TransitionError
from threat_assessment import AuditLog
from threat_assessment.config import canonical_digest
from trust_fixtures import (ADDR, CONTROL_CLIENT, NOW, RELAY_KEY, RELAY_PEM, RELAY_SHA, REPO, TEST_CLIENT, assessor3, demo, relay_session)

APPROVER_KEY = Ed25519PrivateKey.generate()                  # test fixture only
OTHER_KEY = Ed25519PrivateKey.generate()


def _pub(k):
    pem = k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    sha = hashlib.sha256(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()
    return pem, sha


APPROVER_PEM, APPROVER_SHA = _pub(APPROVER_KEY)


def registry_entry(pem, sha, name="Approver One", nb="2026-11-11T00:00:00Z", na="2026-12-11T00:00:00Z"):
    return {"name": name, "key_id": sha[:16], "public_key_sha256": sha, "public_key_pem": pem.decode("ascii"), "not_before": nb, "not_after": na}


def policy_doc(approvers=None, **over):
    doc = {"schema": "response-policy-1", "config_version": "test", "mode": "dry_run", "enforcement_activated": False,
           "action": "restrict_new_connections", "listener": "demo", "max_ttl_seconds": 900, "proposal_validity_seconds": 1800,
           "clock_skew_seconds": 5, "required_attribution": "attributable_via_proxy_mapping",
           "address_safety": {"path": "x", "config_version": ADDR["config_version"], "sha256_digest": canonical_digest(ADDR)},
           "approver_registry": {"status": "provisioned", "approvers": approvers if approvers is not None else [registry_entry(APPROVER_PEM, APPROVER_SHA)]}}
    doc.update(over)
    return doc


def assessed(client=TEST_CLIENT):
    rec, signed, _, _ = demo(client=client)
    a = assessor3()
    out = a.assess(rec, signed, now=NOW)
    log = AuditLog("t27b", clock=lambda: "2026-11-11T18:01:00Z")
    log.append(out)
    return out, log.entries, a


class SpyRelay(DisabledRelayEnforcement):
    def __init__(self):
        self.calls = []

    def stage_rule(self, rule):
        self.calls.append(("stage", rule))
        return super().stage_rule(rule)

    def remove_rule(self, rule_id):
        self.calls.append(("remove", rule_id))
        return super().remove_rule(rule_id)


def setup(approvers=None, relay=None, client=TEST_CLIENT):
    out, entries, a = assessed(client)
    pol = response_policy_from_document(policy_doc(approvers))
    ctl = ResponseController(pol, a.att, a.policy, ResponseAuditLog(), relay=relay or SpyRelay())
    return ctl, out, entries


def take(ctl, out, entries, now=NOW):
    r = ctl.intake(out, entries, now)
    assert r["accepted"], r
    return r["proposal"]


def approve(proposal, key=APPROVER_KEY, key_id=APPROVER_SHA[:16], name="Approver One", decided=None, ttl=600, decision="approve", **kw):
    decided = decided or NOW + timedelta(seconds=10)
    return sign_approval(build_approval(proposal, decision, name, key_id, decided, ttl, kw.pop("reason", ""), **kw), key)


def verification(pid, kind="response", restriction=False, control=True, result="pass", operator="op1", evidence="ev-1", vid=None, at=None):
    return {"verification_id": vid or f"v-{kind}-{pid}-{restriction}-{control}-{result}-{operator}", "proposal_id": pid, "kind": kind,
            "restriction_observed": restriction, "control_unaffected": control, "verified_utc": iso(at or NOW + timedelta(seconds=40)),
            "operator": operator, "evidence_ref": evidence, "result": result}


def run_to_simulated(ctl, out, entries):
    p = take(ctl, out, entries)
    assert ctl.submit_decision(approve(p), NOW + timedelta(seconds=11))["accepted"]
    assert ctl.execute(p["proposal_id"], NOW + timedelta(seconds=20))["accepted"]
    return p


def last_reason(ctl):
    return [e for e in ctl.audit.entries if e["event"] == "operation_rejected"][-1]["details"]["reason"]


# ===================================================================================== happy path (dry-run)
def test_full_dry_run_workflow_records_no_enforcement():
    spy = SpyRelay()
    ctl, out, entries = setup(relay=spy)
    p = run_to_simulated(ctl, out, entries)
    assert p["action"] == {"type": "restrict_new_connections", "target": "10.250.25.3/32", "listener": "demo", "max_ttl_seconds": 900}
    assert ctl.record_verification(verification(p["proposal_id"]), NOW + timedelta(seconds=45))["state"] == "verified_dry_run"
    ctl.tick(NOW + timedelta(seconds=10 + 600))
    assert ctl.state(p["proposal_id"]) == "rollback_pending"
    ctl.record_rollback_verification(verification(p["proposal_id"], "rollback", at=NOW + timedelta(seconds=650)), NOW + timedelta(seconds=660))
    assert ctl.state(p["proposal_id"]) == "rolled_back"
    sim = next(e for e in ctl.audit.entries if e["event"] == "simulated")
    assert sim["details"]["enforced"] is False and all(e["mode"] == "dry_run" for e in ctl.audit.entries)
    assert spy.calls == [] and verify_response_log(ctl.audit.entries, ctl.audit.checkpoint())["ok"]


# ===================================================================================== T1 approval required
def test_T1_no_execution_without_approval_and_proposal_expires():
    ctl, out, entries = setup()
    p = take(ctl, out, entries)
    assert not ctl.execute(p["proposal_id"], NOW + timedelta(seconds=5))["accepted"]
    ctl.tick(NOW + timedelta(seconds=1801))
    assert ctl.state(p["proposal_id"]) == "proposal_expired"


# ===================================================================================== T2 invalid approval
@pytest.mark.parametrize("case", ["unregistered_key", "wrong_signature", "other_role_key", "unknown_name", "empty_registry"])
def test_T2_invalid_approval_is_rejected(case):
    if case == "other_role_key":                        # the relay key registered as an approver: key-role separation
        approvers = [registry_entry(RELAY_PEM, RELAY_SHA, name="Relay")]
        ctl, out, entries = setup(approvers)
        p = take(ctl, out, entries)
        doc = approve(p, key=RELAY_KEY, key_id=RELAY_SHA[:16], name="Relay")
    elif case == "empty_registry":
        ctl, out, entries = setup(approvers=[])
        p = take(ctl, out, entries)
        doc = approve(p)
    else:
        ctl, out, entries = setup()
        p = take(ctl, out, entries)
        doc = {"unregistered_key": lambda: approve(p, key=OTHER_KEY, key_id=_pub(OTHER_KEY)[1][:16]),
               "wrong_signature": lambda: approve(p, key=OTHER_KEY),
               "unknown_name": lambda: approve(p, name="Somebody Else")}[case]()
    r = ctl.submit_decision(doc, NOW + timedelta(seconds=11))
    assert not r["accepted"] and ctl.state(p["proposal_id"]) == "proposed"
    assert not ctl.execute(p["proposal_id"], NOW + timedelta(seconds=20))["accepted"]


def test_repository_policy_is_dry_run_with_no_approvers():
    pol = load_response_policy(REPO / "configs" / "response_policy_v1.json")
    assert pol.mode == "dry_run" and pol.registry_status == "pending_provisioning" and pol.approvers == () and pol.max_ttl_seconds == 900
    addr = json.loads((REPO / "configs" / "address_safety_v1.json").read_text(encoding="utf-8"))
    assert pol.address_safety_digest == canonical_digest(addr)


# ===================================================================================== T3 duplicate / conflicting / replay
def test_T3_single_decision_rejection_final_and_replay_rejected():
    ctl, out, entries = setup()
    p = take(ctl, out, entries)
    first = approve(p)
    assert ctl.submit_decision(first, NOW + timedelta(seconds=11))["accepted"]
    assert not ctl.submit_decision(first, NOW + timedelta(seconds=12))["accepted"]                      # replay
    assert "replayed" in last_reason(ctl)
    assert not ctl.submit_decision(approve(p, decision="reject", reason="no"), NOW + timedelta(seconds=13))["accepted"]   # conflicting
    ctl2, out2, e2 = setup()
    p2 = take(ctl2, out2, e2)
    assert ctl2.submit_decision(approve(p2, decision="reject", reason="false positive"), NOW + timedelta(seconds=11))["state"] == "rejected"
    assert not ctl2.submit_decision(approve(p2), NOW + timedelta(seconds=12))["accepted"]                # rejection is final
    assert not ctl2.execute(p2["proposal_id"], NOW + timedelta(seconds=20))["accepted"]


# ===================================================================================== T4 target safety
@pytest.mark.parametrize("target,why", [
    ("10.250.25.4/32", "enforcement-excluded"), ("10.250.25.4", "enforcement-excluded"), ("10.250.25.2/32", "protected"),
    ("172.22.0.2/32", "protected"), ("127.0.0.1/32", "protected"), ("198.51.100.7/32", "shared"),
    ("10.250.25.5/32", "allowlist"), ("203.0.113.9/32", "allowlist"),
    ("10.250.25.2/31", "exactly one"), ("10.250.25.3/31", "invalid"), ("10.250.25.0/28", "exactly one"), ("10.250.25.3,10.250.25.4", "multiple"),
    ("10.250.25.3 10.250.25.4", "multiple"), (" 10.250.25.3", "multiple"), ("fe80::1/128", "IPv4"), ("::ffff:10.250.25.3", "IPv4"),
    ("not-an-ip", "invalid"), (["10.250.25.3"], "one address string"), (None, "one address string")])
def test_T4_target_validation(target, why):
    _, _, a = assessed()
    with pytest.raises(TargetRejected, match=why):
        validate_target(target, a.att)


def test_T4_only_the_demo_test_client_qualifies():
    _, _, a = assessed()
    assert validate_target("10.250.25.3/32", a.att) == validate_target("10.250.25.3", a.att) == "10.250.25.3/32"


def test_T4_control_client_session_cannot_become_a_proposal():
    ctl, out, entries = setup(client=CONTROL_CLIENT)
    assert out["tier"] == "review"                                                      # assessment unchanged: no proposal
    r = ctl.intake(out, entries, NOW)
    assert not r["accepted"] and ctl.proposals == {}


# ===================================================================================== T5 modified / broader approval
@pytest.mark.parametrize("mutate", [
    lambda d: d["rule"].update(target="10.250.25.4/32"), lambda d: d["rule"].update(ttl_seconds=300),
    lambda d: d["rule"].update(expires_utc="2026-11-11T19:00:00.000000Z"), lambda d: d["rule"]["fingerprints"].update(address_safety="0" * 64),
    lambda d: d.update(proposal_id="prop-other"), lambda d: d.update(decision="reject"), lambda d: d["rule"].update(action="block_everything"),
    lambda d: d["approver"].update(name="Approver Two")])
def test_T5_modified_approval_is_invalid(mutate):
    ctl, out, entries = setup()
    p = take(ctl, out, entries)
    doc = approve(p)
    mutate(doc)
    assert not ctl.submit_decision(doc, NOW + timedelta(seconds=11))["accepted"]
    assert last_reason(ctl) in ("approval_hash mismatch (approval modified)", "unknown proposal") and ctl.state(p["proposal_id"]) == "proposed"


def test_T5_rehashed_without_key_and_broader_resigned_approvals_rejected():
    from dynamic_response.approval import approval_hash
    ctl, out, entries = setup()
    p = take(ctl, out, entries)
    doc = approve(p)
    doc["rule"]["target"] = "10.250.25.4/32"
    doc["approval_hash"] = approval_hash(doc)
    assert not ctl.submit_decision(doc, NOW + timedelta(seconds=11))["accepted"] and "signature invalid" in last_reason(ctl)
    wrong_target = build_approval(p, "approve", "Approver One", APPROVER_SHA[:16], NOW + timedelta(seconds=10), 600)
    wrong_target["rule"]["target"] = "10.250.25.4/32"
    assert not ctl.submit_decision(sign_approval(wrong_target, APPROVER_KEY), NOW + timedelta(seconds=11))["accepted"]
    assert "target differs" in last_reason(ctl)
    stale_fp = build_approval(p, "approve", "Approver One", APPROVER_SHA[:16], NOW + timedelta(seconds=10), 600)
    stale_fp["rule"]["fingerprints"]["defence_policy"] = "1" * 64
    assert not ctl.submit_decision(sign_approval(stale_fp, APPROVER_KEY), NOW + timedelta(seconds=11))["accepted"]
    assert "fingerprints" in last_reason(ctl)


# ===================================================================================== T6 duration
@pytest.mark.parametrize("ttl", [901, 3600, 86400, 0, -5])
def test_T6_excessive_or_invalid_duration_rejected(ttl):
    ctl, out, entries = setup()
    p = take(ctl, out, entries)
    doc = build_approval(p, "approve", "Approver One", APPROVER_SHA[:16], NOW + timedelta(seconds=10), 600)
    doc["rule"]["ttl_seconds"] = ttl
    doc["rule"]["expires_utc"] = iso(NOW + timedelta(seconds=10 + ttl))
    assert not ctl.submit_decision(sign_approval(doc, APPROVER_KEY), NOW + timedelta(seconds=11))["accepted"]


@pytest.mark.parametrize("over", [{"max_ttl_seconds": 901}, {"max_ttl_seconds": 86400}, {"enforcement_activated": True},
                                  {"mode": "enforce"}, {"required_attribution": "attributable"}, {"action": "block_source_ip"}])
def test_T6_policy_cannot_raise_limits_or_enable_enforcement(over):
    with pytest.raises(ResponseConfigError):
        response_policy_from_document(policy_doc(**over))


def test_T6_expiry_mismatch_rejected():
    ctl, out, entries = setup()
    p = take(ctl, out, entries)
    doc = build_approval(p, "approve", "Approver One", APPROVER_SHA[:16], NOW + timedelta(seconds=10), 600)
    doc["rule"]["expires_utc"] = iso(NOW + timedelta(seconds=10 + 900))           # longer than the signed duration
    assert not ctl.submit_decision(sign_approval(doc, APPROVER_KEY), NOW + timedelta(seconds=11))["accepted"]
    assert "expiry does not equal" in last_reason(ctl)


# ===================================================================================== T7 attribution (R4)
def test_T7_unattributed_relay_session_never_becomes_a_proposal():
    rec, signed, _, _ = demo()
    a = assessor3()
    out = a.assess(rec, None, now=NOW)                                                  # no verified signed result
    log = AuditLog("t", clock=lambda: "2026-11-11T18:01:00Z")
    log.append(out)
    ctl = ResponseController(response_policy_from_document(policy_doc()), a.att, a.policy, ResponseAuditLog())
    assert out["tier"] == "review" and not ctl.intake(out, log.entries, NOW)["accepted"]


def test_T7_direct_source_cannot_be_restricted():
    from behavioural_evidence import EvidenceEngine
    from trust_fixtures import ECFG
    a = assessor3()
    rec = EvidenceEngine(ECFG).evaluate([dict(e, src_ip="203.0.113.50") for e in relay_session("x", 50001)])["sessions"][0]
    out = a.assess(rec, now=NOW)
    log = AuditLog("t", clock=lambda: "2026-11-11T18:01:00Z")
    log.append(out)
    ctl = ResponseController(response_policy_from_document(policy_doc()), a.att, a.policy, ResponseAuditLog())
    assert out["tier"] == "propose" and out["session_attribution"]["state"] == "attributable"
    r = ctl.intake(out, log.entries, NOW)
    assert not r["accepted"] and "R4" in r["reason"]


@pytest.mark.parametrize("mutate", [
    lambda o: o["versions"]["attribution_results"].update(accepted=[]),
    lambda o: o["versions"]["attribution_results"].update(rejected=[{"result_id": "x", "reason": "forged"}]),
    lambda o: o["session_attribution"].update(state="unattributed:mapping_unavailable"),
    lambda o: o["session_attribution"]["mapping"]["client"].update(ip="10.250.25.9"),
    lambda o: o["proposed_action"].update(relay_connection_id="other"),
    lambda o: o["gates"].update({"7_verified_configuration_digests": False}),
    lambda o: o["proposed_action"].update(execution="executed")])
def test_T7_forged_or_inconsistent_assessment_rejected(mutate):
    ctl, out, entries = setup()
    bad = copy.deepcopy(out)
    mutate(bad)
    assert not ctl.intake(bad, entries, NOW)["accepted"] and ctl.proposals == {}


def test_T7_assessment_audit_chain_must_verify():
    ctl, out, entries = setup()
    tampered = copy.deepcopy(entries)
    tampered[0]["tier"] = "record"
    assert not ctl.intake(out, tampered, NOW)["accepted"]


# ===================================================================================== T8 controller access restrictions
CONTROLLER_SIDE = ["controller.py", "proposals.py", "approval.py", "rules.py", "audit.py", "states.py", "relay_interface.py", "feedback.py",
                   "config.py", "common.py"]


@pytest.mark.parametrize("name", CONTROLLER_SIDE)
def test_T8_controller_side_has_no_keys_docker_processes_or_network(name):
    src = (REPO / "dynamic_response" / name).read_text(encoding="utf-8")
    for bad in ("docker", "subprocess", "import socket", "os.system", "Popen", "load_pem_private_key", "private_bytes", ".sign(",
                "Ed25519PrivateKey", "import approve_cli", "from .approve_cli", "iptables", "nft ", "urllib", "import requests",
                "from requests", "http.client"):
        assert bad not in src, (name, bad)


def test_T8_controller_holds_no_key_material_and_cannot_write_trust_anchors():
    ctl, out, entries = setup()
    run_to_simulated(ctl, out, entries)
    for v in vars(ctl).values():
        assert not isinstance(v, Ed25519PrivateKey)
    for name in CONTROLLER_SIDE:
        src = (REPO / "dynamic_response" / name).read_text(encoding="utf-8")
        assert "trust_root" not in src and "allowed_signers" not in src and ".write_text(" not in src and "write_bytes(" not in src, name
        assert "open(" not in src.replace("self.path.open(", ""), name                  # only the response audit file is ever written


# ===================================================================================== T9 / T10 failed or partial verification
@pytest.mark.parametrize("restriction,control,result,outcome", [
    (False, True, "fail", "operator_reported_fail"), (True, True, "pass", "partial"), (False, False, "pass", "partial"),
    (True, False, "fail", "unexpected_effect")])
def test_T9_T10_failed_or_partial_verification_never_succeeds(restriction, control, result, outcome):
    ctl, out, entries = setup()
    p = run_to_simulated(ctl, out, entries)
    r = ctl.record_verification(verification(p["proposal_id"], restriction=restriction, control=control, result=result), NOW + timedelta(seconds=45))
    assert ctl.state(p["proposal_id"]) == "rollback_pending" and "failed" in r["reason"]
    failed = next(e for e in ctl.audit.entries if e["event"] == "verification_failed")
    assert failed["details"]["outcome"] == outcome
    assert not any(e["event"] == "verification_passed" for e in ctl.audit.entries)
    assert outcomes(ctl.audit.entries)[p["proposal_id"]]["response_success"] is False


# ===================================================================================== T11 failed rollback
def test_T11_failed_rollback_stays_failed_and_duplicates_rejected():
    ctl, out, entries = setup()
    p = run_to_simulated(ctl, out, entries)
    ctl.record_verification(verification(p["proposal_id"], result="fail"), NOW + timedelta(seconds=45))
    r = ctl.record_rollback_verification(verification(p["proposal_id"], "rollback", restriction=True, control=True, result="fail"),
                                         NOW + timedelta(seconds=50))
    assert "FAILED" in r["reason"] and ctl.state(p["proposal_id"]) == "rollback_failed"
    good = verification(p["proposal_id"], "rollback", vid="v-second", at=NOW + timedelta(seconds=55))
    assert not ctl.record_rollback_verification(good, NOW + timedelta(seconds=56))["accepted"]               # duplicate rollback
    ctl.tick(NOW + timedelta(seconds=10 + 600))
    assert ctl.state(p["proposal_id"]) == "rollback_failed_closed"
    o = outcomes(ctl.audit.entries)[p["proposal_id"]]
    assert o["failure"] and o["rollback"] == "rollback_failed" and "rollback_verified" not in o["events"]


# ===================================================================================== T12 expiry
def test_T12_expiry_triggers_rollback_and_never_renews():
    ctl, out, entries = setup()
    p = run_to_simulated(ctl, out, entries)
    ctl.record_verification(verification(p["proposal_id"]), NOW + timedelta(seconds=45))
    ctl.tick(NOW + timedelta(seconds=10 + 600))
    expired = next(e for e in ctl.audit.entries if e["event"] == "rule_expired")
    assert expired["details"]["renewed"] is False and ctl.state(p["proposal_id"]) == "rollback_pending"
    started = [e for e in ctl.audit.entries if e["event"] == "rollback_started"][-1]
    assert started["details"]["reason"] == "expiry" and started["details"]["simulated"] is True
    assert not ctl.execute(p["proposal_id"], NOW + timedelta(seconds=700))["accepted"]
    assert not ctl.submit_decision(approve(p, decided=NOW + timedelta(seconds=700)), NOW + timedelta(seconds=700))["accepted"]


def test_T12_approved_but_unexecuted_rule_expires():
    ctl, out, entries = setup()
    p = take(ctl, out, entries)
    ctl.submit_decision(approve(p), NOW + timedelta(seconds=11))
    ctl.tick(NOW + timedelta(seconds=10 + 600))
    assert ctl.state(p["proposal_id"]) == "expired_unexecuted"


# ===================================================================================== T13 successful rollback
def test_T13_revocation_and_successful_rollback():
    ctl, out, entries = setup()
    p = run_to_simulated(ctl, out, entries)
    ctl.record_verification(verification(p["proposal_id"]), NOW + timedelta(seconds=45))
    assert ctl.revoke(p["proposal_id"], "op1", "operator decision", NOW + timedelta(seconds=60))["accepted"]
    assert not ctl.revoke(p["proposal_id"], "op1", "again", NOW + timedelta(seconds=61))["accepted"]
    r = ctl.record_rollback_verification(verification(p["proposal_id"], "rollback", at=NOW + timedelta(seconds=70)), NOW + timedelta(seconds=71))
    assert r["state"] == "rolled_back"
    assert not ctl.record_rollback_verification(verification(p["proposal_id"], "rollback", vid="v-dup", at=NOW + timedelta(seconds=72)),
                                                NOW + timedelta(seconds=73))["accepted"]


# ===================================================================================== T14 / T15 audit tamper and replay
def _full_log():
    ctl, out, entries = setup()
    p = run_to_simulated(ctl, out, entries)
    ctl.record_verification(verification(p["proposal_id"]), NOW + timedelta(seconds=45))
    return ctl.audit


def _rechain(entries):
    from dynamic_response.audit import GENESIS, entry_hash
    prev = GENESIS
    for k, e in enumerate(entries):
        e["sequence"], e["previous_hash"] = k + 1, prev
        e["record_hash"] = entry_hash(e)
        prev = e["record_hash"]
    return entries


@pytest.mark.parametrize("attack,why", [
    ("modify", "record_hash mismatch"), ("delete", "previous_hash"), ("reorder", "previous_hash"), ("truncate", "checkpoint mismatch"),
    ("forge_state", "does not match the state machine"), ("enforce_entry", "non-dry-run"), ("skip_approval", "invalid state transition"),
    ("inject_verified_effective", "invalid state transition")])
def test_T14_response_log_tampering_detected(attack, why):
    log = _full_log()
    ents, ck = copy.deepcopy(log.entries), log.checkpoint()
    if attack == "modify":
        ents[2]["details"]["target"] = "10.250.25.4/32"
    elif attack == "delete":
        del ents[1]
    elif attack == "reorder":
        ents[1], ents[2] = ents[2], ents[1]
    elif attack == "truncate":
        ents = ents[:-1]
    elif attack == "forge_state":
        ents[-1]["to_state"] = "rolled_back"
        _rechain(ents)
    elif attack == "enforce_entry":
        ents[-1]["mode"] = "enforce"
        _rechain(ents)
    elif attack == "skip_approval":
        del ents[1]
        _rechain(ents)
    elif attack == "inject_verified_effective":
        e = copy.deepcopy(ents[-1])
        e.update(event="verified_effective", event_id="new", from_state="verified_dry_run", to_state="verified_effective")
        ents.append(e)
        _rechain(ents)
    v = verify_response_log(ents, ck if attack in ("truncate", "modify", "delete", "reorder") else None)
    assert not v["ok"] and why in v["reason"]
    assert verify_response_log(log.entries, log.checkpoint())["ok"]


@pytest.mark.parametrize("attack,why", [("duplicate_entry", "duplicate event_id"), ("replayed_state_event", "invalid state transition")])
def test_T15_replayed_log_records_detected(attack, why):
    log = _full_log()
    ents = copy.deepcopy(log.entries)
    replay = copy.deepcopy(next(e for e in ents if e["event"] == "approval_recorded"))
    if attack == "replayed_state_event":
        replay["event_id"] = "fresh-id"
    ents.append(replay)
    _rechain(ents)
    v = verify_response_log(ents)
    assert not v["ok"] and why in v["reason"]


def test_T15_replayed_verification_record_rejected_by_controller():
    ctl, out, entries = setup()
    p = run_to_simulated(ctl, out, entries)
    v = verification(p["proposal_id"], result="fail")
    ctl.record_verification(v, NOW + timedelta(seconds=45))
    assert not ctl.record_verification(v, NOW + timedelta(seconds=46))["accepted"]
    rb = dict(v, kind="rollback")
    assert not ctl.record_rollback_verification(rb, NOW + timedelta(seconds=47))["accepted"] and "replayed" in last_reason(ctl)


def test_T15_invalid_transitions_cannot_be_written():
    log = ResponseAuditLog()
    for event in ("approval_recorded", "simulated", "verification_passed", "rollback_verified", "verified_effective", "made_up"):
        with pytest.raises(TransitionError):
            log.append(event, "prop-x")
    assert log.entries == []


# ===================================================================================== T16 dry-run isolation from the relay
def test_T16_relay_boundary_is_disabled_and_never_called():
    with pytest.raises(EnforcementDisabledError):
        DisabledRelayEnforcement().stage_rule({})
    with pytest.raises(EnforcementDisabledError):
        DisabledRelayEnforcement().remove_rule("r")
    spy = SpyRelay()
    ctl, out, entries = setup(relay=spy)
    p = run_to_simulated(ctl, out, entries)
    ctl.record_verification(verification(p["proposal_id"], result="fail"), NOW + timedelta(seconds=45))
    ctl.record_rollback_verification(verification(p["proposal_id"], "rollback", at=NOW + timedelta(seconds=50)), NOW + timedelta(seconds=51))
    assert spy.calls == []


def test_T16_enforce_mode_refused():
    ctl, out, entries = setup()
    p = take(ctl, out, entries)
    ctl.submit_decision(approve(p), NOW + timedelta(seconds=11))
    r = ctl.execute(p["proposal_id"], NOW + timedelta(seconds=20), mode="enforce")
    assert not r["accepted"] and "enforcement_not_activated" in r["reason"] and ctl.state(p["proposal_id"]) == "approved"


# ===================================================================================== T17 duplicate execution
def test_T17_duplicate_execution_rejected():
    ctl, out, entries = setup()
    p = run_to_simulated(ctl, out, entries)
    assert not ctl.execute(p["proposal_id"], NOW + timedelta(seconds=21))["accepted"]
    assert sum(1 for e in ctl.audit.entries if e["event"] == "simulated") == 1
    out2, entries2, _ = assessed()
    assert not ctl.intake(out2, entries2, NOW)["accepted"] and "duplicate proposal" in last_reason(ctl)   # same audit record twice


# ===================================================================================== T18 missing verification evidence
@pytest.mark.parametrize("mutate", [lambda v: v.update(evidence_ref=""), lambda v: v.update(operator=" "), lambda v: v.update(control_unaffected=None),
                                    lambda v: v.update(restriction_observed="no"), lambda v: v.update(result="ok"), lambda v: v.pop("evidence_ref")])
def test_T18_incomplete_verification_never_succeeds(mutate):
    ctl, out, entries = setup()
    p = run_to_simulated(ctl, out, entries)
    v = verification(p["proposal_id"])
    mutate(v)
    ctl.record_verification(v, NOW + timedelta(seconds=45))
    assert ctl.state(p["proposal_id"]) == "rollback_pending"
    assert next(e for e in ctl.audit.entries if e["event"] == "verification_failed")["details"]["outcome"] == "incomplete"


def test_T18_future_dated_or_foreign_verification_rejected():
    ctl, out, entries = setup()
    p = run_to_simulated(ctl, out, entries)
    assert not ctl.record_verification(verification(p["proposal_id"], at=NOW + timedelta(hours=1)), NOW + timedelta(seconds=45))["accepted"]
    assert not ctl.record_verification(dict(verification(p["proposal_id"]), kind="rollback"), NOW + timedelta(seconds=45))["accepted"]
    assert ctl.state(p["proposal_id"]) == "simulated"


# ===================================================================================== T19 feedback isolation
def test_T19_feedback_outcomes_queue_metrics_and_annotations():
    ctl, out, entries = setup()
    p = run_to_simulated(ctl, out, entries)
    ctl.record_verification(verification(p["proposal_id"], result="fail"), NOW + timedelta(seconds=45))
    ctl.record_rollback_verification(verification(p["proposal_id"], "rollback", at=NOW + timedelta(seconds=50)), NOW + timedelta(seconds=51))
    annotate(ctl.audit, p["proposal_id"], "reviewer1", "false_positive", "benign admin activity")
    with pytest.raises(ValueError):
        annotate(ctl.audit, p["proposal_id"], "reviewer1", "lower_severity")
    o = outcomes(ctl.audit.entries)[p["proposal_id"]]
    assert o["final_state"] == "rolled_back" and o["response_success"] is False and o["labels"][0]["label"] == "false_positive"
    q = review_queue(ctl.audit.entries)
    assert q and "verification failed" in q[0]["reasons"] and "labelled false positive" in q[0]["reasons"]
    m = metrics(ctl.audit.entries)
    assert m["response_failure"] == 1 and m["labels"] == {"false_positive": 1} and "no real response" in m["note"]
    assert verify_response_log(ctl.audit.entries)["ok"]


def test_T19_feedback_cannot_change_assessment_models_or_policy():
    watched = ["configs/defence_policy_v2_2.json", "configs/threat_attribution_v3.json", "configs/address_safety_v1.json",
               "configs/response_policy_v1.json", "threat_assessment/severity.py", "threat_assessment/assessment.py"]
    before = {p: hashlib.sha256((REPO / p).read_bytes()).hexdigest() for p in watched}
    out1, _, a = assessed()
    ctl, out, entries = setup()
    p = run_to_simulated(ctl, out, entries)
    ctl.record_verification(verification(p["proposal_id"], result="fail"), NOW + timedelta(seconds=45))
    annotate(ctl.audit, p["proposal_id"], "r", "false_positive")
    review_queue(ctl.audit.entries), metrics(ctl.audit.entries), outcomes(ctl.audit.entries)
    out2, _, _ = assessed()
    fnd = lambda o: [{k: v for k, v in f.items() if k != "attribution"} for f in o["findings"]]   # result ids differ per signing
    assert fnd(out1) == fnd(out2) and out1["gates"] == out2["gates"] and out1["tier"] == out2["tier"]
    assert out1["session_attribution"]["state"] == out2["session_attribution"]["state"] == "attributable_via_proxy_mapping"
    assert {p: hashlib.sha256((REPO / p).read_bytes()).hexdigest() for p in watched} == before
    src = (REPO / "dynamic_response" / "feedback.py").read_text(encoding="utf-8")
    for forbidden in ("threat_assessment", "behavioural_evidence", "ml_pipeline", "sklearn", "keras", "tensorflow", "configs", "open("):
        assert forbidden not in src, forbidden
    for pkg in ("threat_assessment", "behavioural_evidence", "client_attribution"):
        for f in (REPO / pkg).rglob("*.py"):
            assert "dynamic_response" not in f.read_text(encoding="utf-8"), f


# ===================================================================================== T20 expired approval
def test_T20_expired_approvals_rejected():
    ctl, out, entries = setup()
    p = take(ctl, out, entries)
    late = approve(p, decided=NOW + timedelta(seconds=1801))
    assert not ctl.submit_decision(late, NOW + timedelta(seconds=1802))["accepted"] and "proposal validity" in last_reason(ctl)
    ctl2, out2, e2 = setup()
    p2 = take(ctl2, out2, e2)
    ctl2.submit_decision(approve(p2, ttl=60), NOW + timedelta(seconds=11))
    assert not ctl2.execute(p2["proposal_id"], NOW + timedelta(seconds=10 + 61))["accepted"] and "expired" in last_reason(ctl2)
    ctl3, out3, e3 = setup([registry_entry(APPROVER_PEM, APPROVER_SHA, na="2026-11-11T12:00:00Z")])
    p3 = take(ctl3, out3, e3)
    assert not ctl3.submit_decision(approve(p3), NOW + timedelta(seconds=11))["accepted"] and "not valid at the decision time" in last_reason(ctl3)
    ctl4, out4, e4 = setup()
    p4 = take(ctl4, out4, e4)
    stale = approve(p4, decided=NOW + timedelta(seconds=10), ttl=60)
    assert not ctl4.submit_decision(stale, NOW + timedelta(seconds=80))["accepted"] and "expired" in last_reason(ctl4)
