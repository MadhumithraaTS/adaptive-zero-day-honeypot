"""Task 26C trust-boundary tests: signed attribution results (F-1), authentication events (F-2), record integrity and
checkpoints (F-4/F-6), session exclusions (F-7) and configuration drift (F-8). Ephemeral keys only; synthetic data."""
import copy
import json
from datetime import timedelta

import pytest

from behavioural_evidence import EvidenceEngine
from client_attribution import config_from_document, correlate, correlate_authentication, make_checkpoint, verify_checkpoints
from client_attribution.records import canonical, load_public_key, verify_records
from session_exclusions import ExclusionConfigError, from_document as exclusions_from, load_exclusions
from threat_assessment import AssessmentConfigError, AttributionConfig, PolicyConfig, ThreatAssessor, load_attribution_config, load_policy
from threat_assessment.config import canonical_digest
from threat_assessment.run_signed import isolation_report
from trust_fixtures import (ADDR, ATT3, ATTACKER_KEY, CONTROL_CLIENT, DIAG, ECFG, NOW, PROPOSE_LINES, RELAY, RELAY_KEY, RELAY_PEM,
                            RELAY_SHA, REPO, RESULT_KEY, RESULT_PEM, RESULT_SHA, TEST_CLIENT, Writer, att3, att3_doc, assessor3, cev, demo,
                            iso, policy21, relay_session, resign, sign)

SEVEN = ("99732d516898", "b806554e19b9", "9441bcce555c", "acc2bad4a442", "d588636ce120", "3eede5e19e25", "4542a85f37ec")


def entry(doc, sid="d1"):
    return next(e for e in doc["sessions"] if e["cowrie_session_id"] == sid)


def rejected_reason(out):
    return out["versions"]["attribution_results"]["rejected"][0]["reason"]


# ============================================================================================ F-1 signed results
def test_valid_signed_result_proposes_for_test_client_with_event_login():
    rec, signed, _, _ = demo()
    out = assessor3().assess(rec, signed, now=NOW)
    assert out["tier"] == "propose" and all(out["gates"].values())
    p = out["proposed_action"]
    assert p["subject"] == TEST_CLIENT and p["mode"] == "dry_run" and p["manual_approval"] == "pending" and p["execution"] == "not_executed"
    assert out["successful_login_basis"].startswith("cowrie.login.success") and out["authentication_evidence"]["event_observed"]
    assert out["session_attribution"]["mapping"]["result_id"] == signed["result_id"]
    assert out["versions"]["assessment"] == "threat-assessment-1.2.0"


def test_control_client_signed_result_is_enforcement_excluded():
    rec, signed, _, _ = demo(client=CONTROL_CLIENT)
    out = assessor3().assess(rec, signed, now=NOW)
    assert out["tier"] == "review" and out["proposed_action"] is None and out["session_attribution"]["state"] == "enforcement_excluded"


def test_attack_A_forged_unsigned_result_maps_control_session_to_test_client():
    """Task 26B attack 1: an unsigned correlation result that re-labels the control client's session as 10.250.25.3."""
    rec, _, events, w = demo(client=CONTROL_CLIENT)
    forged = correlate(events, w.lines, RELAY_PEM, config_from_document(ATT3), evaluation_time=NOW)
    forged["sessions"]["d1"].update(client_ip=TEST_CLIENT, client_role="test_client")
    out = assessor3().assess(rec, forged, now=NOW)
    assert out["tier"] != "propose" and out["proposed_action"] is None
    assert out["session_attribution"]["state"] == "unattributed:result_rejected" and "unsigned" in rejected_reason(out)


def test_attack_B_forged_unsigned_result_names_unregistered_subject():
    """Task 26B attack 2: an unsigned result that names an unregistered address (203.0.113.9) as the client."""
    rec, _, events, w = demo()
    forged = correlate(events, w.lines, RELAY_PEM, config_from_document(ATT3), evaluation_time=NOW)
    forged["sessions"]["d1"].update(client_ip="203.0.113.9", client_role="forged")
    out = assessor3().assess(rec, forged, now=NOW)
    assert out["proposed_action"] is None and out["session_attribution"]["state"] == "unattributed:result_rejected"


@pytest.mark.parametrize("path,value", [
    (("client", "ip"), CONTROL_CLIENT), (("client", "ip"), "203.0.113.9"), (("client", "port"), 1), (("decision",), "unattributed:log_gap"),
    (("relay_listener", "ip"), "172.21.0.2"), (("relay_to_cowrie", "src_port"), 1), (("timestamps", "cowrie_connect_utc"), "2026-11-11T18:00:09Z"),
    (("relay_records", "connection_id"), "other"), (("authentication", "state"), "indeterminate:ambiguous"), (("cowrie_session_id",), "zz")])
def test_any_altered_signed_field_is_rejected(path, value):
    rec, signed, _, _ = demo()
    bad = copy.deepcopy(signed)
    tgt = entry(bad)
    for k in path[:-1]:
        tgt = tgt[k]
    tgt[path[-1]] = value
    out = assessor3().assess(rec, bad, now=NOW)
    assert out["proposed_action"] is None and "result_hash mismatch" in rejected_reason(out)


@pytest.mark.parametrize("field,value", [("attribution_config", {"digest": "0" * 64}), ("not_after_utc", "2027-01-01T00:00:00.000000Z"),
                                          ("relay_log", {}), ("cowrie_input", {})])
def test_altered_top_level_fields_are_rejected(field, value):
    rec, signed, _, _ = demo()
    bad = dict(signed, **{field: value})
    assert "result_hash mismatch" in rejected_reason(assessor3().assess(rec, bad, now=NOW))


def test_altered_with_recomputed_hash_fails_signature():
    import hashlib
    rec, signed, _, _ = demo(client=CONTROL_CLIENT)
    bad = copy.deepcopy(signed)
    entry(bad)["client"] = {"ip": TEST_CLIENT, "port": 40000, "role": "test_client"}
    body = {k: v for k, v in bad.items() if k not in ("result_hash", "signature")}
    bad["result_hash"] = hashlib.sha256(canonical(body).encode()).hexdigest()
    out = assessor3().assess(rec, bad, now=NOW)
    assert out["proposed_action"] is None and rejected_reason(out) == "signature invalid"


def test_resigned_with_attacker_key_is_rejected():
    rec, signed, _, _ = demo(client=CONTROL_CLIENT)
    bad = copy.deepcopy(signed)
    entry(bad)["client"] = {"ip": TEST_CLIENT, "port": 40000, "role": "test_client"}
    out = assessor3().assess(rec, resign(bad, ATTACKER_KEY), now=NOW)
    assert out["proposed_action"] is None and "not pinned" in rejected_reason(out)


def test_attacker_signature_with_spoofed_signer_identity_is_rejected():
    rec, signed, _, _ = demo(client=CONTROL_CLIENT)
    bad = resign(signed, ATTACKER_KEY)
    bad["signer"] = dict(signed["signer"])
    out = assessor3().assess(rec, bad, now=NOW)
    assert out["proposed_action"] is None and "result_hash mismatch" in rejected_reason(out)


@pytest.mark.parametrize("now_offset,issued_offset,validity,why", [
    (timedelta(hours=1), None, 600, "expired"), (timedelta(seconds=-600), None, 600, "not yet valid"),
    (timedelta(0), None, 7200, "longer than allowed")])
def test_time_window_enforced(now_offset, issued_offset, validity, why):
    events = relay_session("d1", 50001)
    w = Writer(); w.start(); w.open("c1", 50001, 0); w.close("c1", 50001, 1 + len(PROPOSE_LINES))
    signed, _ = sign(events, w.lines, validity=validity)
    rec = EvidenceEngine(ECFG).evaluate(events)["sessions"][0]
    out = assessor3().assess(rec, signed, now=NOW + now_offset)
    assert out["proposed_action"] is None and why in rejected_reason(out)


def test_result_from_other_config_digest_is_rejected():
    other = att3_doc(config_version="other")
    rec, signed, _, _ = demo(doc=other)
    out = assessor3().assess(rec, signed, now=NOW)
    assert out["proposed_action"] is None and "different attribution config" in rejected_reason(out)


def test_duplicated_session_entries_are_rejected():
    rec, signed, _, _ = demo()
    bad = copy.deepcopy(signed)
    bad["sessions"].append(copy.deepcopy(bad["sessions"][0]))
    assert "duplicated session entries" in rejected_reason(assessor3().assess(rec, resign(bad), now=NOW))


@pytest.mark.parametrize("mutate,why", [
    (lambda e: e["client"].update(ip="10.250.25.9"), "not in the pinned registry"),
    (lambda e: e["client"].update(role="control_client"), "not in the pinned registry"),
    (lambda e: e["relay_listener"].update(ip="172.21.0.2", accepted_local="172.21.0.2:2222"), "not a configured demo listener"),
    (lambda e: e["relay_listener"].update(mode="published"), "not a configured demo listener"),
    (lambda e: e["relay_to_cowrie"].update(src_ip="172.22.0.9"), "configured relay address"),
    (lambda e: e["timestamps"].update(relay_accepted_utc="2026-11-11T17:59:50.000000Z", relay_upstream_connected_utc="2026-11-11T17:59:50.010000Z"),
     "timestamps inconsistent"),
    (lambda e: e["timestamps"].update(relay_closed_utc=None), "no relay close"),
    (lambda e: e["timestamps"].update(relay_closed_utc="2026-11-11T18:00:30.000000Z"), "close inconsistent"),
    (lambda e: e.update(close_check="session_open"), "close inconsistent"),
    (lambda e: e["relay_records"].update(open={"seq": 3, "record_hash": "x"}), "identity incomplete"),
    (lambda e: e["authentication"].update(login_success_utc="2026-11-11T17:00:00.000000Z"), "login before connect"),
    (lambda e: e.update(extra=1), "unexpected field set")])
def test_correctly_signed_but_inconsistent_entries_are_rejected(mutate, why):
    """Defence in depth: even content signed with the pinned key is rejected when internally inconsistent."""
    rec, signed, _, _ = demo()
    bad = copy.deepcopy(signed)
    mutate(entry(bad))
    out = assessor3().assess(rec, resign(bad), now=NOW)
    assert out["proposed_action"] is None and why in rejected_reason(out)


def test_unattributed_entry_naming_a_client_is_rejected():
    rec, signed, events, w = demo()
    bad = copy.deepcopy(signed)
    e = entry(bad)
    e["decision"], e["client"]["ip"] = "unattributed:mapping_missing", TEST_CLIENT
    assert "unattributed entry names a client" in rejected_reason(assessor3().assess(rec, resign(bad), now=NOW))


def test_diagnostic_session_marked_attributable_is_rejected():
    rec, signed, _, _ = demo(sid=DIAG[0])
    bad = copy.deepcopy(signed)
    good = demo()[1]
    e = copy.deepcopy(entry(good))
    e["cowrie_session_id"] = DIAG[0]
    bad["sessions"] = [e]
    assert "excluded diagnostic" in rejected_reason(assessor3().assess(rec, resign(bad), now=NOW))


def test_conflicting_results_for_one_session_are_not_used():
    rec, signed, events, w = demo()
    other = copy.deepcopy(signed)
    other["result_id"] = "second"
    entry(other)["client"]["port"] = 40001
    out = assessor3().assess(rec, [signed, resign(other)], now=NOW)
    assert out["session_attribution"]["state"] == "unattributed:result_conflict" and out["proposed_action"] is None


def test_identical_duplicate_result_counted_once_and_reused_id_rejected():
    rec, signed, _, _ = demo()
    out = assessor3().assess(rec, [signed, copy.deepcopy(signed)], now=NOW)
    assert out["tier"] == "propose" and len(out["versions"]["attribution_results"]["accepted"]) == 1
    other = copy.deepcopy(signed)
    entry(other)["client"]["port"] = 40001
    out2 = assessor3().assess(rec, [signed, resign(other)], now=NOW)
    assert out2["proposed_action"] is None and "reused" in rejected_reason(out2)


def test_relay_tuple_must_match_cowrie_observed_source():
    rec, signed, _, _ = demo()
    out = assessor3().assess(dict(rec, src_ip="172.22.0.2"), signed, now=NOW)
    assert out["tier"] == "propose"
    other = dict(rec, src_ip="172.22.0.3")              # inside trusted range? no -> direct source path, never mapped
    out2 = assessor3().assess(other, signed, now=NOW)
    assert out2["session_attribution"].get("mapping") is None


def test_pending_result_key_rejects_everything():
    doc = copy.deepcopy(ATT3)
    doc["attribution_result"].update(status="pending_provisioning", public_key_sha256=None, key_validity=None)
    a = ThreatAssessor(AttributionConfig.from_document(doc, address_doc=ADDR), PolicyConfig.from_document(policy21(doc)), ECFG)
    rec, signed, _, _ = demo()
    out = a.assess(rec, signed, now=NOW)
    assert out["proposed_action"] is None and "pending_provisioning" in rejected_reason(out)


def test_verified_store_object_cannot_be_injected():
    a = assessor3()
    rec, signed, _, _ = demo()
    store = a.verify_attribution(signed, NOW)
    out = a.assess(rec, store, now=NOW)                 # a pre-built store is not a signed document
    assert out["proposed_action"] is None and out["session_attribution"]["state"] == "unattributed:result_rejected"


def test_threat_assessment_is_independent_of_the_signer():
    for f in (REPO / "threat_assessment").rglob("*.py"):
        src = f.read_text(encoding="utf-8")
        assert "from client_attribution" not in src and "import client_attribution" not in src, f
        assert ".sign(" not in src and "load_pem_private_key" not in src and "Ed25519PrivateKey" not in src, f


# ============================================================================================ F-2 authentication
def _auth(events):
    return correlate_authentication(events)["d1"]


def test_login_success_correlated_by_session_id():
    a = _auth(relay_session("d1", 50001))
    assert a["state"] == "login_success_observed" and a["username"] == "demo" and "password" not in a


@pytest.mark.parametrize("mutate,state", [
    (lambda ev: [e for e in ev if e["eventid"] != "cowrie.login.success"], "indeterminate:no_login_success_event"),
    (lambda ev: ev + [dict(next(e for e in ev if e["eventid"] == "cowrie.login.success"), timestamp=iso(0.7))], "indeterminate:ambiguous"),
    (lambda ev: [dict(e, timestamp=iso(-5)) if e["eventid"] == "cowrie.login.success" else e for e in ev], "indeterminate:ambiguous"),
    (lambda ev: [dict(e, timestamp=iso(60)) if e["eventid"] == "cowrie.login.success" else e for e in ev], "indeterminate:ambiguous"),
    (lambda ev: [dict(e, src_ip="10.9.9.9") if e["eventid"] == "cowrie.login.success" else e for e in ev], "indeterminate:ambiguous"),
    (lambda ev: [dict(e, sensor="other") if e["eventid"] == "cowrie.login.success" else e for e in ev], "indeterminate:ambiguous"),
    (lambda ev: ev + [ev[0]], "indeterminate:ambiguous")])
def test_missing_or_ambiguous_login_stays_indeterminate(mutate, state):
    assert _auth(mutate(relay_session("d1", 50001)))["state"] == state


def test_typed_commands_without_login_event_never_satisfy_gate4():
    rec, signed, _, _ = demo(login=False)
    out = assessor3().assess(rec, signed, now=NOW)
    assert rec["n_input_lines"] == 4 and not out["gates"]["4_successful_login"] and out["tier"] == "review"
    assert out["authentication_evidence"]["state"] == "indeterminate:no_login_success_event"
    assert out["authentication_status"] == rec["authentication_status"] == "no_authentication_events"   # evidence unchanged


def test_login_event_from_rejected_result_is_not_used():
    rec, signed, _, _ = demo()
    bad = dict(signed, result_id="tampered")
    out = assessor3().assess(rec, bad, now=NOW)
    assert not out["gates"]["4_successful_login"] and out["authentication_evidence"]["state"] == "indeterminate:no_verified_result"


def test_direct_sources_need_an_authentication_status_event():
    a = assessor3()
    direct = [dict(e, src_ip="203.0.113.50") for e in relay_session("x", 50001)]
    rec = EvidenceEngine(ECFG).evaluate(direct)["sessions"][0]
    assert rec["authentication_status"] == "success_without_repeated_failures" and a.assess(rec)["gates"]["4_successful_login"]
    no_login = [e for e in direct if e["eventid"] != "cowrie.login.success"]
    rec2 = EvidenceEngine(ECFG).evaluate(no_login)["sessions"][0]
    out = a.assess(rec2)
    assert rec2["n_input_lines"] == 4 and not out["gates"]["4_successful_login"]


def test_legacy_policy_2_0_keeps_input_basis():
    """Historical reproduction: policy 2.0 keeps the Task 24 rule (command input counts); only policy 2.1 requires an event."""
    v1 = {"schema": "threat-attribution-config-1", "config_version": "x", "source_field": "src_ip", "trusted_proxy_cidrs": ["172.22.0.2/32"],
          "relay_addresses": [RELAY], "proxy_client_mapping": None, "shared_source_cidrs": [], "protected_cidrs": [], "internal_cidrs": ["10.0.0.0/8"]}
    pol = json.loads((REPO / "configs" / "defence_policy_v2.json").read_text(encoding="utf-8"))
    pol["attribution_config"]["sha256_digest"] = canonical_digest(v1)
    a = ThreatAssessor(AttributionConfig.from_document(v1), PolicyConfig.from_document(pol), ECFG)
    rec = EvidenceEngine(ECFG).evaluate([e for e in relay_session("d1", 50001) if e["eventid"] != "cowrie.login.success"])["sessions"][0]
    out = a.assess(rec)
    assert out["successful_login_basis"].startswith("command input recorded") and out["authentication_evidence"] is None


# ============================================================================================ F-4/F-6 records
def _log(n_sessions=3):
    w = Writer(); w.start()
    for k in range(n_sessions):
        w.open(f"c{k}", 50001 + k, 10 * k); w.close(f"c{k}", 50001 + k, 10 * k + 5)
    events = []
    for k in range(n_sessions):
        events += [cev(f"s{k}", "cowrie.session.connect", 10 * k + 0.02, src_port=50001 + k, dst_ip="172.22.0.1", dst_port=2222),
                   cev(f"s{k}", "cowrie.session.closed", 10 * k + 5.01)]
    return w, events


def _states(events, lines, checkpoints=None, at=None):
    out = correlate(events, lines, RELAY_PEM, config_from_document(ATT3), evaluation_time=at or NOW, checkpoints=checkpoints)
    return out, {k: v["state"] for k, v in out["sessions"].items()}


def test_malformed_line_is_handled_independently():
    w, events = _log()
    lines = list(w.lines)
    lines[3] = lines[3][:30]                                  # s1's open record damaged
    out, st = _states(events, lines)
    assert not out["verification"]["ok"] and out["verification"]["usable"]
    assert st == {"s0": "attributable_via_proxy_mapping", "s1": "unattributed:log_gap", "s2": "attributable_via_proxy_mapping"}
    assert out["verification"]["gaps"][0]["missing"] == 1 and out["verification"]["rejected"][0]["reason"] == "malformed JSON"


def test_missing_records_are_detected_as_gap():
    w, events = _log()
    lines = w.lines[:3] + w.lines[5:]                          # s1 open+close deleted from the middle
    out, st = _states(events, lines)
    g = out["verification"]["gaps"][0]
    assert g["kind"] == "missing_records" and g["missing"] == 2 and st["s1"] == "unattributed:log_gap"
    # s2's open window touches the gap (seq 4-5 could hold a competing record), so it is withheld too; s0 is untouched
    assert st["s0"] == "attributable_via_proxy_mapping" and st["s2"] == "unattributed:log_gap"


def test_strict_chain_fork_untrusts_everything():
    w, events = _log()
    f = Writer(); f.seq, f.prev = 2, "f" * 64                  # pinned key, but does not link (fork)
    f.open("x", 50009, 30)
    lines = w.lines[:2] + f.lines + w.lines[2:]
    out, st = _states(events, lines)
    assert not out["verification"]["usable"] and "fork" in out["verification"]["reason"]
    assert set(st.values()) == {"unattributed:mapping_untrusted"}


def _checkpoint(lines, upto):
    pub, sha = load_public_key(RELAY_PEM)
    v = verify_records(lines[:upto], pub, sha)
    return make_checkpoint(v, "relay-demo", iso(100), RESULT_KEY, RESULT_SHA)


def test_tail_truncation_detected_only_with_checkpoint():
    w, events = _log()
    cp_doc = _checkpoint(w.lines, len(w.lines))
    verified, rej = verify_checkpoints([cp_doc], RESULT_PEM, RESULT_SHA, "relay-demo")
    assert not rej
    truncated = w.lines[:-2]                                   # s2's open+close removed from the tail
    out_no, st_no = _states(events, truncated)
    assert out_no["verification"]["ok"] and out_no["verification"]["tail"]["status"] == "unattested"   # undetectable without checkpoint
    assert st_no["s2"] == "unattributed:mapping_missing"
    out_cp, st_cp = _states(events, truncated, checkpoints=verified)
    assert out_cp["verification"]["tail"]["status"] == "incomplete" and not out_cp["verification"]["ok"]
    assert out_cp["verification"]["gaps"][-1]["kind"] == "tail_incomplete" and st_cp["s2"] == "unattributed:log_gap"
    assert st_cp["s0"] == "attributable_via_proxy_mapping"


def test_checkpoint_divergence_untrusts_log():
    w, events = _log()
    verified, _ = verify_checkpoints([_checkpoint(w.lines, 2)], RESULT_PEM, RESULT_SHA, "relay-demo")
    alt = Writer(); alt.start(); alt.open("zz", 50077, 0)        # a different history with the same seq numbers
    out, st = _states(events, alt.lines + w.lines[3:], checkpoints=verified)
    assert not out["verification"]["usable"]


def test_attested_tail_and_unattested_records_after_checkpoint():
    w, events = _log()
    verified, _ = verify_checkpoints([_checkpoint(w.lines, 5)], RESULT_PEM, RESULT_SHA, "relay-demo")
    out, _ = _states(events, w.lines, checkpoints=verified)
    assert out["verification"]["tail"]["status"] == "unattested_after_checkpoint" and out["verification"]["checkpoints"][0]["status"] == "consistent"
    verified_all, _ = verify_checkpoints([_checkpoint(w.lines, len(w.lines))], RESULT_PEM, RESULT_SHA, "relay-demo")
    assert _states(events, w.lines, checkpoints=verified_all)[0]["verification"]["tail"]["status"] == "attested"


@pytest.mark.parametrize("mutate,why", [
    (lambda d: d.update(seq=99), "checkpoint_hash mismatch"), (lambda d: d.update(log_id="other"), "checkpoint_hash mismatch"),
    (lambda d: d.update(signature="00" * 64), "signature invalid"), (lambda d: d.pop("signature"), "malformed")])
def test_forged_checkpoints_are_rejected(mutate, why):
    w, _ = _log()
    d = _checkpoint(w.lines, len(w.lines))
    mutate(d)
    verified, rej = verify_checkpoints([d], RESULT_PEM, RESULT_SHA, "relay-demo")
    assert not verified and why in rej[0]["reason"]


def test_checkpoint_with_unpinned_witness_and_refusal_on_damaged_log():
    w, _ = _log()
    v0, rej0 = verify_checkpoints([_checkpoint(w.lines, 3)], RELAY_PEM, RELAY_SHA, "relay-demo")   # pinned witness is another key
    assert not v0 and "unpinned witness" in rej0[0]["reason"]
    v, rej = verify_checkpoints([_checkpoint(w.lines, 3)], RESULT_PEM, "0" * 64, "relay-demo")
    assert not v and "pinned" in rej[0]["reason"]
    pub, sha = load_public_key(RELAY_PEM)
    with pytest.raises(ValueError):
        make_checkpoint(verify_records(w.lines + ["junk"], pub, sha), "relay-demo", iso(1), RESULT_KEY, RESULT_SHA)


def test_signed_result_reports_log_integrity():
    w, events = _log()
    lines = list(w.lines)
    lines[3] = "junk"
    cfg = config_from_document(ATT3)
    from client_attribution import build_result, sign_result
    corr = correlate(events, lines, RELAY_PEM, cfg, evaluation_time=NOW)
    doc = sign_result(build_result(corr, correlate_authentication(events), cfg, events, NOW, 600, NOW), RESULT_KEY)
    assert doc["relay_log"]["intact"] is False and doc["relay_log"]["rejected_lines"] == 1 and doc["relay_log"]["gaps"]


# ============================================================================================ F-7 exclusions
LIVE_DEMO_29C = "42ee73a7cbbd"


def test_repository_exclusions_cover_all_seven():
    v1 = load_exclusions(REPO / "configs" / "session_exclusions_v1.json")
    assert v1.ids == frozenset(SEVEN) and {v1.categories[s] for s in DIAG} == {"diagnostic"}
    ex = load_exclusions()
    assert ex.version == "2.0.0" and ex.ids == frozenset(SEVEN) | {LIVE_DEMO_29C} and ex.categories[LIVE_DEMO_29C] == "demo"


@pytest.mark.parametrize("sid", SEVEN + (LIVE_DEMO_29C,))
def test_each_excluded_session_is_filtered(sid):
    ex = load_exclusions()
    events = [{"session": sid, "eventid": "cowrie.session.connect"}, {"session": "aaaaaaaaaaaa", "eventid": "cowrie.session.connect"}]
    kept, dropped = ex.filter_events(events)
    assert [e["session"] for e in kept] == ["aaaaaaaaaaaa"] and dropped == {sid: 1}
    sessions, dropped_ids = ex.filter_sessions({sid: [], "aaaaaaaaaaaa": []})
    assert list(sessions) == ["aaaaaaaaaaaa"] and dropped_ids == [sid]
    with pytest.raises(ExclusionConfigError):
        ex.assert_none(["aaaaaaaaaaaa", sid], "evaluation input")


@pytest.mark.parametrize("bad", [{"schema": "x"}, {"schema": "session-exclusions-1", "sessions": []},
                                 {"schema": "session-exclusions-1", "sessions": [{"session_id": "XYZ", "category": "demo"}]},
                                 {"schema": "session-exclusions-1", "sessions": [{"session_id": "aaaaaaaaaaaa", "category": "other"}]},
                                 {"schema": "session-exclusions-1", "sessions": [{"session_id": "aaaaaaaaaaaa", "category": "demo"}] * 2}])
def test_exclusion_config_validation(bad):
    with pytest.raises(ExclusionConfigError):
        exclusions_from(bad)


def test_feature_extractor_excludes_registered_sessions(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("efv2", REPO / "scripts" / "extract_features_v2.py")
    efv2 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(efv2)
    log = tmp_path / "cowrie.json"
    rows = []
    for sid in ("3eede5e19e25", "aaaaaaaaaaaa"):
        rows += [{"eventid": "cowrie.session.connect", "session": sid, "timestamp": "2026-11-11T18:00:00.000000Z", "src_ip": "1.2.3.4"},
                 {"eventid": "cowrie.session.closed", "session": sid, "timestamp": "2026-11-11T18:00:01.000000Z", "duration": "1.0"}]
    log.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    summary = efv2.extract([str(log)], str(tmp_path / "out"))
    meta = (tmp_path / "out" / "session_metadata.csv").read_text(encoding="utf-8")
    assert summary["sessions"] == 1 and "aaaaaaaaaaaa" in meta and "3eede5e19e25" not in meta
    assert summary["session_exclusions"]["sessions_excluded"] == ["3eede5e19e25"]


def test_exclusions_are_separate_from_scoring():
    for pkg in ("threat_assessment", "behavioural_evidence", "client_attribution"):
        for f in (REPO / pkg).rglob("*.py"):
            assert "session_exclusions" not in f.read_text(encoding="utf-8"), f


# ============================================================================================ F-8 configuration
def test_repository_v3_configs_cross_verify():
    att = load_attribution_config(REPO / "configs" / "threat_attribution_v3.json")
    pol = load_policy(REPO / "configs" / "defence_policy_v2_2.json")
    assert att.schema == "threat-attribution-config-3" and pol.schema_version == "2.1" and pol.require_authentication_event
    assert pol.attribution_digest == att.digest and pol.address_safety_digest == att.address_safety_digest
    assert att.result_key_status == "pending_provisioning" and att.result_key_sha256 is None
    assert [str(n) for n in att.enforcement_excluded] == ["10.250.25.4/32"] and [str(n) for n in att.enforcement_allowlist] == ["10.250.25.3/32"]
    old = json.loads((REPO / "configs" / "defence_policy_v2.json").read_text(encoding="utf-8"))
    assert {k: v for k, v in pol.conditions.items() if k != "require_authentication_event"} == old["proposal_conditions"]
    assert pol.action == old["proposed_action"]


def test_address_safety_drift_is_rejected():
    drifted = dict(ADDR, enforcement_excluded_sources=[])
    with pytest.raises(AssessmentConfigError, match="drift"):
        att3(ATT3, drifted)


@pytest.mark.parametrize("key", ["protected_cidrs", "shared_source_cidrs", "enforcement_excluded_sources"])
def test_v3_rejects_inline_address_lists(key):
    with pytest.raises(AssessmentConfigError, match="inline"):
        att3(dict(ATT3, **{key: []}))


@pytest.mark.parametrize("key", ["protected_networks", "enforcement_excluded_sources"])
def test_policy_2_1_rejects_inline_address_lists(key):
    with pytest.raises(AssessmentConfigError, match="inline"):
        PolicyConfig.from_document(policy21(**{key: []}))


def test_policy_pinning_other_address_safety_fails_gate7():
    pol = policy21()
    pol["address_safety_config"]["sha256_digest"] = "1" * 64
    a = ThreatAssessor(att3(), PolicyConfig.from_document(pol), ECFG)
    rec, signed, _, _ = demo()
    out = a.assess(rec, signed, now=NOW)
    assert not a.config_checks["policy_and_attribution_pin_same_address_safety"] and not out["gates"]["7_verified_configuration_digests"]


def test_version_pairing_enforced():
    v2pol = json.loads((REPO / "configs" / "defence_policy_v2.json").read_text(encoding="utf-8"))
    v2pol["attribution_config"]["sha256_digest"] = canonical_digest(ATT3)
    with pytest.raises(AssessmentConfigError, match="incompatible"):
        ThreatAssessor(att3(), PolicyConfig.from_document(v2pol), ECFG)
    v1 = {"schema": "threat-attribution-config-1", "config_version": "x", "source_field": "src_ip", "trusted_proxy_cidrs": [],
          "relay_addresses": [RELAY], "proxy_client_mapping": None, "shared_source_cidrs": [], "protected_cidrs": [], "internal_cidrs": ["10.0.0.0/8"]}
    with pytest.raises(AssessmentConfigError, match="incompatible"):
        ThreatAssessor(AttributionConfig.from_document(v1), PolicyConfig.from_document(policy21(v1)), ECFG)


def test_authentication_event_condition_cannot_be_relaxed():
    pol = policy21()
    pol["proposal_conditions"]["require_authentication_event"] = False
    with pytest.raises(AssessmentConfigError, match="cannot be relaxed"):
        PolicyConfig.from_document(pol)


def test_allowlist_overlapping_excluded_is_rejected():
    bad = dict(ADDR, enforcement_allowlist=["10.250.25.0/29"])
    with pytest.raises(AssessmentConfigError, match="overlaps"):
        att3(att3_doc(addr=bad), bad)


def test_result_public_key_must_match_pin():
    # the relay key supplied as the result key is caught by the key-role check first (Task 26D-1)
    with pytest.raises(AssessmentConfigError, match="does not match|key-role separation"):
        att3(ATT3, ADDR, pem=RELAY_PEM)


# ============================================================================================ isolation
def test_isolation_report_detects_private_keys_and_secret_paths(tmp_path):
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "pub.pem").write_bytes(RESULT_PEM)
    assert not isolation_report([str(clean)])["private_key_files_readable"]          # public keys are fine
    dirty = tmp_path / "dirty"
    dirty.mkdir()
    from cryptography.hazmat.primitives import serialization
    (dirty / "k.pem").write_bytes(ATTACKER_KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                            serialization.NoEncryption()))
    rep = isolation_report([str(dirty)])
    assert not rep["ok"] and rep["private_key_files_readable"]
