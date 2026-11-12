"""UTF-8 handling of raw Cowrie logs in parse_logs.py, extract_features.py and the dataset builder.

Regression for reports/cowrie_payload_observability_pilot/report.md section 7: logs were read with the
platform default encoding (cp1252 on Windows) and the builder silently replaced invalid bytes.
The CLI tests run without PYTHONUTF8 so the platform default applies.
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.extract_features import extract_features
from scripts.parse_logs import LogParseError, parse_logs


REPO_ROOT = Path(__file__).resolve().parents[1]
PARSE = REPO_ROOT / "scripts" / "parse_logs.py"
BUILD = REPO_ROOT / "dataset_builder" / "build_labelled_dataset.py"
BASE = {"session": "s1", "src_ip": "172.22.0.3", "src_port": 40000, "dst_ip": "172.22.0.2", "dst_port": 2222,
        "protocol": "ssh"}
NON_ASCII_INPUT = "PILOT \u0090é END"  # U+0090 and e-acute


def _event(eventid, ts, **extra):
    return dict(BASE, eventid=eventid, timestamp=f"2026-11-10T08:00:{ts:02d}.000000Z", **extra)


def _session_lines(command_input, ensure_ascii=True):
    events = [_event("cowrie.session.connect", 0), _event("cowrie.login.success", 1, username="root", password="x"),
              _event("cowrie.command.input", 2, input=command_input), _event("cowrie.session.closed", 3, duration=3.0)]
    return [json.dumps(e, ensure_ascii=ensure_ascii).encode("utf-8") for e in events]


def _write(path, lines, newline=b"\n"):
    path.write_bytes(b"".join(line + newline for line in lines))
    return path


def _cli(script, *args):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONUTF8"}
    return subprocess.run([sys.executable, str(script), *map(str, args)], cwd=REPO_ROOT, env=env,
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, check=False)


def _parsed_input(path):
    sessions = json.loads(Path(path).read_text(encoding="utf-8"))
    return [e["input"] for e in sessions["s1"] if e["eventid"] == "cowrie.command.input"][0]


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --- parse_logs ----------------------------------------------------------------------------------

@pytest.mark.parametrize("command_input, ensure_ascii", [
    ("uname -a", True),               # ASCII JSONL
    (NON_ASCII_INPUT, False),         # valid raw UTF-8 bytes in the log
    (NON_ASCII_INPUT, True),          # JSON \u escapes
], ids=["ascii", "raw-utf8", "json-escapes"])
def test_parse_preserves_input_under_the_platform_default_encoding(tmp_path, command_input, ensure_ascii):
    raw = _write(tmp_path / "cowrie.json", _session_lines(command_input, ensure_ascii))
    result = _cli(PARSE, "--input", raw, "--output", tmp_path / "sessions.json")
    assert result.returncode == 0, result.stderr
    assert _parsed_input(tmp_path / "sessions.json") == command_input


def test_parse_accepts_crlf_line_endings(tmp_path):
    raw = _write(tmp_path / "cowrie.json", _session_lines(NON_ASCII_INPUT, False), newline=b"\r\n")
    assert parse_logs(str(raw), str(tmp_path / "sessions.json")) == 1
    assert _parsed_input(tmp_path / "sessions.json") == NON_ASCII_INPUT


def test_parse_output_is_valid_utf8_with_escaped_non_ascii(tmp_path):
    raw = _write(tmp_path / "cowrie.json", _session_lines(NON_ASCII_INPUT, False))
    parse_logs(str(raw), str(tmp_path / "sessions.json"))
    written = (tmp_path / "sessions.json").read_bytes()
    written.decode("utf-8")  # raises if not UTF-8
    assert "\\u0090" in written.decode("ascii") and "\\u00e9" in written.decode("ascii")


def test_parse_invalid_utf8_raises_with_line_and_byte_and_writes_nothing(tmp_path):
    lines = _session_lines("PILOT X END")
    lines[2] = lines[2].replace(b"PILOT X", b"PILOT \x90")
    raw = _write(tmp_path / "cowrie.json", lines)
    before = _sha256(raw)
    with pytest.raises(LogParseError) as caught:
        parse_logs(str(raw), str(tmp_path / "sessions.json"))
    message = str(caught.value)
    assert "Line 3 of" in message and "not valid UTF-8" in message and "byte 0x90" in message
    assert not (tmp_path / "sessions.json").exists()
    assert _sha256(raw) == before  # the raw log is never modified


def test_parse_cli_invalid_utf8_exits_1_and_keeps_stale_output(tmp_path):
    lines = _session_lines("PILOT X END")
    lines[2] = lines[2].replace(b"PILOT X", b"PILOT \xff")
    raw = _write(tmp_path / "cowrie.json", lines)
    stale = tmp_path / "sessions.json"
    stale.write_text('{"old": []}', encoding="utf-8")
    result = _cli(PARSE, "--input", raw, "--output", stale)
    assert result.returncode == 1
    assert "not valid UTF-8" in result.stderr and "byte 0xff" in result.stderr
    assert "was not updated" in result.stderr
    assert stale.read_text(encoding="utf-8") == '{"old": []}'


# --- extract_features ----------------------------------------------------------------------------

def test_extract_writes_utf8_outputs_and_keeps_non_ascii_commands(tmp_path):
    raw = _write(tmp_path / "cowrie.json", _session_lines(NON_ASCII_INPUT, False))
    parse_logs(str(raw), str(tmp_path / "sessions.json"))
    extract_features(str(tmp_path / "sessions.json"), str(tmp_path / "features.csv"), str(tmp_path / "details.json"))
    details = json.loads((tmp_path / "details.json").read_bytes().decode("utf-8"))
    assert details["s1"]["commands"] == [NON_ASCII_INPUT]
    (tmp_path / "features.csv").read_bytes().decode("utf-8")
    # sbytes counts the UTF-8 bytes of what Cowrie logged, not bytes Cowrie may have dropped earlier.
    assert details["s1"]["features"]["sbytes"] == len(NON_ASCII_INPUT.encode("utf-8"))


# --- dataset builder -----------------------------------------------------------------------------

def _builder_run(tmp_path, raw_lines, baseline=None):
    run = tmp_path / "run"
    run.mkdir()
    entry = {"index": 1, "profile": "p", "attack_cat": "reconnaissance", "label": 1, "held_out": False,
             "username": "root", "start_utc": "2026-11-10T08:00:00Z", "end_utc": "2026-11-10T08:00:05Z",
             "auth_attempts": [["root", "x"]], "auth_success": True, "commands_sent": [], "status": "ok", "error": None}
    (run / "manifest.jsonl").write_text(json.dumps(entry) + "\n", encoding="utf-8")
    if baseline is not None:
        (run / "run_meta.json").write_text(json.dumps({"log_baseline_lines": baseline}), encoding="utf-8")
    source = _write(tmp_path / "source_cowrie.json", raw_lines, newline=b"\r\n")
    return run, source, _cli(BUILD, "--output-dir", run, "--raw-input", source)


def test_builder_copies_raw_log_byte_for_byte_and_trims_baseline_in_bytes(tmp_path):
    earlier = json.dumps(_event("cowrie.session.connect", 0, session="older")).encode("utf-8")
    lines = [earlier] + _session_lines(NON_ASCII_INPUT, False)
    run, source, result = _builder_run(tmp_path, lines, baseline=1)
    assert result.returncode == 0, result.stderr[-2000:]
    assert (run / "raw" / "cowrie.json").read_bytes() == source.read_bytes()
    assert (run / "raw" / "cowrie_thisrun.json").read_bytes() == source.read_bytes().split(b"\r\n", 1)[1]
    assert _parsed_input(run / "parsed" / "sessions.json") == NON_ASCII_INPUT


def test_builder_stops_on_invalid_utf8_without_replacing_bytes(tmp_path):
    lines = _session_lines("PILOT X END")
    lines[2] = lines[2].replace(b"PILOT X", b"PILOT \x90")
    run, source, result = _builder_run(tmp_path, lines)
    assert result.returncode != 0
    assert "not valid UTF-8" in result.stderr and "byte 0x90" in result.stderr
    copied = (run / "raw" / "cowrie.json").read_bytes()
    assert copied == source.read_bytes() and b"\xef\xbf\xbd" not in copied  # no U+FFFD substitution
    assert not (run / "parsed" / "sessions.json").exists()
    assert not (run / "labelled" / "behavior_features.csv").exists()
