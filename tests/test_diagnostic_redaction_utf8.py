"""Evidence-based redaction and chunk-safe UTF-8 decoding of the generator's diagnostic terminal output.

Regression for reports/cowrie_compatibility_confirmation/report.md section 3: a password that was never
typed (admin/admin, user) was replaced wherever its text appeared, corrupting prompts and help text.
"""
import json
import sys
from pathlib import Path

from dataset_builder import generate_labelled_traffic as glt
from generator_fakes import FakeShell, install

REPO = Path(__file__).resolve().parents[1]
FAST = glt.ReadinessPolicy(prompt_timeout_s=0.3, exit_timeout_s=0.2, poll_interval_s=0.001)
ADMIN_PROMPT = b"\x1b[4hadmin@svr04:~$ "
SUDO_USAGE = (b"usage: sudo -e [-AknS] [-r role] [-t type] [-C fd] [-D level] [-g groupname|#gid] [-p prompt] "
              b"[-u user name|#uid] file ...\r\n")


def _session(monkeypatch, attempts, commands, **shell):
    fake = install(monkeypatch, glt, shell_factory=lambda: FakeShell(**shell))
    record = glt.run_session("h", 1, [list(a) for a in attempts], commands, glt.PacingPolicy(),
                             glt.session_pacing_rng(1, 1), FAST)
    return record, record["terminal_output"], fake


def _prompt_evidence_consistent(terminal):
    return all(t["output"].endswith(t["prompt_match"]) for t in terminal if t["readiness_reason"] == "prompt")


# --- redaction -------------------------------------------------------------------------------------

def test_admin_admin_overlap_leaves_every_prompt_intact(monkeypatch):
    record, terminal, _ = _session(monkeypatch, [("admin", "admin")], ["shell", "cd /tmp", "id"], prompt=ADMIN_PROMPT)
    assert record["termination"] == "clean_exit"
    assert all("[REDACTED]" not in t["output"] for t in terminal)
    assert all(t["output"].endswith("admin@svr04:~$ ") for t in terminal)
    assert all(t["redaction"] == {"applied": False, "reason": "no_secret_typed", "occurrences": 0} for t in terminal)
    assert _prompt_evidence_consistent(terminal)
    # the manifest's prompt record is exactly the saved evidence
    assert [c["prompt_match"] for c in record["command_log"]] == [t["prompt_match"] for t in terminal[1:]]


def test_password_word_in_ordinary_help_text_is_not_redacted(monkeypatch):
    _, terminal, _ = _session(monkeypatch, [("guest", "user")], ["sudo -l"], responses={"sudo -l": SUDO_USAGE})
    assert "[-u user name|#uid]" in terminal[1]["output"]
    assert terminal[1]["redaction"]["reason"] == "no_secret_typed"


def test_username_in_prompt_is_kept_when_the_password_differs(monkeypatch):
    _, terminal, _ = _session(monkeypatch, [("www-data", "Summer2026!")], ["whoami"],
                              prompt=b"\x1b[4hwww-data@svr04:/$ ", responses={"whoami": b"www-data\r\n"})
    assert terminal[1]["output"] == "whoami\nwww-data\nwww-data@svr04:/$ "
    assert _prompt_evidence_consistent(terminal)


def test_a_genuinely_typed_and_echoed_password_is_redacted_but_the_prompt_is_not(monkeypatch):
    record, terminal, _ = _session(monkeypatch, [("admin", "admin")], ["echo admin", "id"], prompt=ADMIN_PROMPT,
                                   responses={"echo admin": b"admin\r\n"})
    typed = terminal[1]
    assert typed["output"] == "echo [REDACTED]\n[REDACTED]\nadmin@svr04:~$ "
    assert typed["redaction"] == {"applied": True, "reason": "typed_secret_echoed_and_redacted", "occurrences": 2}
    assert typed["prompt_match"] == "admin@svr04:~$ " and _prompt_evidence_consistent(terminal)
    # the next step did not type the secret: nothing is redacted there
    assert terminal[2]["redaction"]["reason"] == "no_secret_typed" and "[REDACTED]" not in terminal[2]["output"]
    assert record["commands_sent"] == ["echo admin", "id"]  # manifest semantics unchanged


def test_a_password_that_is_never_echoed_is_never_replaced(monkeypatch):
    _, terminal, _ = _session(monkeypatch, [("root", "hunter22")], ["cat notes"],
                              responses={"cat notes": b"hunter22 is a common example password\r\n"})
    # the text appears in output, but the client never typed it: no evidence of an echoed secret
    assert "hunter22 is a common example password" in terminal[1]["output"]
    assert terminal[1]["redaction"]["applied"] is False


def test_typed_secret_in_the_command_echo_is_redacted(monkeypatch):
    _, terminal, _ = _session(monkeypatch, [("root", "hunter22")], ["passwd -x hunter22"],
                              responses={"passwd -x hunter22": b"done\r\n"})
    t = terminal[1]
    assert t["output"] == "passwd -x [REDACTED]\ndone\nroot@svr04:~# "   # only the echo of the typed command
    assert t["redaction"] == {"applied": True, "reason": "typed_secret_echoed_and_redacted", "occurrences": 1}


def test_typed_secret_absent_from_output_is_recorded_without_replacement():
    cap = glt._OutputCapture()
    cap.add_text("no echo here\nroot@svr04:~# ")
    res = cap.result(prompt_match="root@svr04:~# ", typed_secrets=("hunter22",))
    assert res["output"] == "no echo here\nroot@svr04:~# "
    assert res["redaction"] == {"applied": False, "reason": "typed_secret_not_found_in_output", "occurrences": 0}


def test_secret_substrings_inside_other_words_are_not_redacted():
    cap = glt._OutputCapture()
    cap.add_text("echo admin\nadministrator admin_x xadmin admin\nadmin@svr04:~$ ")
    res = cap.result(prompt_match="admin@svr04:~$ ", typed_secrets=("admin",))
    assert res["output"] == "echo [REDACTED]\nadministrator admin_x xadmin [REDACTED]\nadmin@svr04:~$ "
    assert res["redaction"]["occurrences"] == 2


def test_short_typed_password_is_not_redacted_and_the_reason_is_recorded(monkeypatch):
    _, terminal, _ = _session(monkeypatch, [("root", "abc")], ["echo abc"], responses={"echo abc": b"abc\r\n"})
    assert terminal[1]["output"].startswith("echo abc\nabc\n")
    assert terminal[1]["redaction"] == {"applied": False, "reason": "typed_secret_too_short_not_redacted",
                                        "occurrences": 0}


def test_redaction_with_truncation_keeps_the_bound_the_prompt_and_no_secret(monkeypatch):
    big = b"s3cretPW " + b"y" * 6000 + b" s3cretPW\r\n"
    _, terminal, _ = _session(monkeypatch, [("root", "s3cretPW")], ["printf s3cretPW"],
                              responses={"printf s3cretPW": big})
    t = terminal[1]
    assert t["output_truncated"] is True
    assert len(t["output"]) <= glt.OUTPUT_CAPTURE_CHARS + len(glt.TRUNCATION_MARKER)
    assert "s3cretPW" not in t["output"] and t["output"].endswith("root@svr04:~# ")
    assert _prompt_evidence_consistent(terminal)


def test_a_secret_straddling_the_truncation_cut_is_not_partly_leaked():
    secret = "Zq9SECRETkey"
    cap = glt._OutputCapture(limit=40, margin=len(secret))
    cap.add_text("a" * 14 + " " + secret + " " + "b" * 200)   # the token straddles the 20-character head cut
    res = cap.result(typed_secrets=(secret,))
    assert "Zq9" not in res["output"] and "key" not in res["output"].replace("[REDACTED]", "")
    assert len(res["output"]) <= 40 + len(glt.TRUNCATION_MARKER)


# --- UTF-8 decoding ---------------------------------------------------------------------------------

def test_unicode_split_across_two_or_more_chunks_is_preserved(monkeypatch):
    message = "wget: unable to resolve host address ‘mirror.example’ — \U0001F600\r\n".encode("utf-8")
    _, terminal, _ = _session(monkeypatch, [("root", "toor1")], ["wget http://mirror.example/x"],
                              responses={"wget http://mirror.example/x": message}, chunk_size=1)
    t = terminal[1]
    assert "‘mirror.example’ — \U0001F600" in t["output"]
    assert "�" not in t["output"] and t["invalid_utf8_bytes"] == 0
    assert t["output_bytes"] == len(b"wget http://mirror.example/x\r\n" + message + b"\x1b[4hroot@svr04:~# ")


def test_invalid_utf8_is_rendered_explicitly_and_counted(monkeypatch):
    _, terminal, _ = _session(monkeypatch, [("root", "toor1")], ["cat bin"],
                              responses={"cat bin": b"A\x90B\xffC\xc3\r\n"}, chunk_size=3)
    t = terminal[1]
    assert "A\\x90B\\xffC\\xc3" in t["output"] and "�" not in t["output"]
    assert t["invalid_utf8_bytes"] == 3 and t["readiness_reason"] == "prompt"


def test_incomplete_sequence_at_the_end_of_a_wait_is_flushed_explicitly():
    stream = glt._Utf8Stream()
    assert stream.decode(b"ok \xe2\x80") == "ok "          # held back: could be the start of a character
    assert stream.flush() == "\\xe2\\x80" and stream.invalid_bytes == 2


def test_prompt_detection_is_unchanged_for_split_prompts(monkeypatch):
    record, terminal, fake = _session(monkeypatch, [("admin", "admin")], ["id"], prompt=ADMIN_PROMPT, chunk_size=2)
    assert record["termination"] == "clean_exit" and all(ready for _, ready in fake.instances[0].shell.received)
    assert _prompt_evidence_consistent(terminal)


# --- diagnostic output stays out of the manifest and model inputs -----------------------------------

def test_redaction_and_decoding_metadata_never_enter_the_manifest(tmp_path, monkeypatch):
    install(monkeypatch, glt, shell_factory=lambda: FakeShell(prompt=ADMIN_PROMPT))
    config = {"version": "t", "placeholders": {}, "profiles": [
        {"name": "p", "attack_cat": "botnet", "label": 1, "delay_range": [0, 0],
         "credentials": {"usernames": ["admin"], "passwords": ["admin"], "failed_attempts": [0, 0]},
         "steps": [["id"]]}]}
    cfg = tmp_path / "profiles.json"
    cfg.write_text(json.dumps(config), encoding="utf-8")
    out = tmp_path / "runs" / "r"
    monkeypatch.setattr(sys, "argv", ["g", "--config", str(cfg), "--sessions", "2", "--seed", "1", "--pacing-seed", "31",
                                      "--no-baseline", "--output-dir", str(out), "--prompt-timeout", "0.3"])
    glt.main()
    manifest = (out / "manifest.jsonl").read_text(encoding="utf-8")
    assert "redaction" not in manifest and "invalid_utf8_bytes" not in manifest and "[REDACTED]" not in manifest
    terminal = [json.loads(line) for line in (out / "terminal_output.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all("redaction" in t and "invalid_utf8_bytes" in t for t in terminal)
    assert all(t["output"].endswith(t["prompt_match"]) for t in terminal)
    meta = json.loads((out / "run_meta.json").read_text(encoding="utf-8"))
    assert "only in a step whose sent command contains them" in meta["output_redaction_policy"]
    spec = json.loads((REPO / "configs" / "feature_spec_v2.json").read_text(encoding="utf-8"))
    assert "generator diagnostic terminal output (terminal_output.jsonl)" in spec["forbidden_inputs"]
