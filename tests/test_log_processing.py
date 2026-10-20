import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.extract_features import OUTPUT_COLUMNS, FeatureExtractionError, extract_features
from scripts.parse_logs import LogParseError, parse_logs


REPO_ROOT = Path(__file__).resolve().parents[1]
PARSE = REPO_ROOT / "scripts" / "parse_logs.py"
EXTRACT = REPO_ROOT / "scripts" / "extract_features.py"
DEMO = REPO_ROOT / "data" / "demo_20261019_213439"
needs_demo = pytest.mark.skipif(not (DEMO / "raw" / "cowrie.json").is_file(), reason="demo outputs not present")

EVENT = {"session": "abc123", "eventid": "cowrie.session.connect", "timestamp": "2026-10-19T16:00:00.000000Z",
         "src_ip": "172.19.0.1", "src_port": 40000, "dst_ip": "172.19.0.2", "dst_port": 2222, "protocol": "ssh"}


def _cli(script, *args):
    return subprocess.run([sys.executable, str(script), *map(str, args)], cwd=REPO_ROOT,
                          capture_output=True, text=True, timeout=120, check=False)


def _write_lines(path, lines):
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return path


# --- parse_logs ----------------------------------------------------------------------------------

def test_parse_missing_input_exits_1_and_leaves_stale_output_untouched(tmp_path):
    stale = tmp_path / "sessions.json"
    stale.write_text('{"old": []}', encoding="utf-8")
    result = _cli(PARSE, "--input", tmp_path / "missing.json", "--output", stale)
    assert result.returncode == 1
    assert "does not exist" in result.stderr
    assert "was not updated" in result.stderr
    assert stale.read_text(encoding="utf-8") == '{"old": []}'


def test_parse_empty_input_exits_1_without_creating_output(tmp_path):
    raw = tmp_path / "cowrie.json"
    raw.write_text("", encoding="utf-8")
    result = _cli(PARSE, "--input", raw, "--output", tmp_path / "sessions.json")
    assert result.returncode == 1
    assert "No session events" in result.stderr
    assert not (tmp_path / "sessions.json").exists()


@pytest.mark.parametrize("bad_line, message", [
    ("{not json", "Malformed JSON on line 2"),
    ("[1, 2, 3]", "Line 2 of"),
    ('{"session": 42, "eventid": "x"}', "non-string session ID"),
])
def test_parse_malformed_or_invalid_lines_raise(tmp_path, bad_line, message):
    raw = _write_lines(tmp_path / "cowrie.json", [json.dumps(EVENT), bad_line])
    with pytest.raises(LogParseError, match=message):
        parse_logs(str(raw), str(tmp_path / "sessions.json"))
    assert not (tmp_path / "sessions.json").exists()


def test_parse_input_without_session_events_raises(tmp_path):
    raw = _write_lines(tmp_path / "cowrie.json", [json.dumps({"eventid": "cowrie.log.open"})])
    with pytest.raises(LogParseError, match="No session events"):
        parse_logs(str(raw), str(tmp_path / "sessions.json"))


def test_parse_failed_output_write_raises_and_leaves_no_output(tmp_path):
    raw = _write_lines(tmp_path / "cowrie.json", [json.dumps(EVENT)])
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("file", encoding="utf-8")
    with pytest.raises(LogParseError, match="Could not write"):
        parse_logs(str(raw), str(blocker / "sessions.json"))
    assert blocker.read_text(encoding="utf-8") == "file"


def test_parse_success_writes_validated_sessions(tmp_path):
    raw = _write_lines(tmp_path / "cowrie.json", [json.dumps(EVENT), json.dumps(dict(EVENT, session="def456"))])
    assert parse_logs(str(raw), str(tmp_path / "sessions.json")) == 2
    assert sorted(json.loads((tmp_path / "sessions.json").read_text())) == ["abc123", "def456"]
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


@needs_demo
def test_parse_output_is_byte_identical_to_existing_demo_output(tmp_path):
    result = _cli(PARSE, "--input", DEMO / "raw" / "cowrie.json", "--output", tmp_path / "sessions.json")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "sessions.json").read_bytes() == (DEMO / "parsed" / "sessions.json").read_bytes()


# --- extract_features ----------------------------------------------------------------------------

def _extract_args(tmp_path, sessions_path):
    return ["--input", sessions_path, "--output", tmp_path / "out" / "features.csv", "--details", tmp_path / "out" / "details.json"]


def test_extract_missing_input_exits_1(tmp_path):
    result = _cli(EXTRACT, *_extract_args(tmp_path, tmp_path / "missing.json"))
    assert result.returncode == 1
    assert "does not exist" in result.stderr
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("content, message", [
    ("{not json", "Could not read sessions"),
    ("[]", "object keyed by session ID"),
    ("{}", "contains no sessions"),
    ('{"abc": []}', "has no event list"),
    ('{"abc": "not-a-list"}', "has no event list"),
    ('{"abc": [1]}', "non-object event"),
])
def test_extract_invalid_session_data_exits_1_without_outputs(tmp_path, content, message):
    sessions = tmp_path / "sessions.json"
    sessions.write_text(content, encoding="utf-8")
    result = _cli(EXTRACT, *_extract_args(tmp_path, sessions))
    assert result.returncode == 1, result.stdout
    assert message in result.stderr
    assert not (tmp_path / "out" / "features.csv").exists()
    assert not (tmp_path / "out" / "details.json").exists()


def test_extract_failed_details_write_leaves_neither_output(tmp_path):
    sessions = tmp_path / "sessions.json"
    sessions.write_text(json.dumps({"abc123": [EVENT]}), encoding="utf-8")
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("file", encoding="utf-8")
    with pytest.raises(FeatureExtractionError, match="Could not write"):
        extract_features(str(sessions), str(tmp_path / "features.csv"), str(blocker / "details.json"))
    assert not (tmp_path / "features.csv").exists()
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


def test_extract_failure_leaves_existing_outputs_unchanged(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "features.csv").write_text("stale", encoding="utf-8")
    (out / "details.json").write_text("stale", encoding="utf-8")
    sessions = tmp_path / "sessions.json"
    sessions.write_text("{}", encoding="utf-8")
    result = _cli(EXTRACT, *_extract_args(tmp_path, sessions))
    assert result.returncode == 1
    assert result.stderr.count("was not updated") == 2
    assert (out / "features.csv").read_text(encoding="utf-8") == "stale"
    assert (out / "details.json").read_text(encoding="utf-8") == "stale"


def test_extract_success_has_expected_schema_and_counts(tmp_path):
    sessions = tmp_path / "sessions.json"
    sessions.write_text(json.dumps({"abc123": [EVENT], "0042": [dict(EVENT, session="0042")]}), encoding="utf-8")
    assert extract_features(str(sessions), str(tmp_path / "features.csv"), str(tmp_path / "details.json")) == 2
    with open(tmp_path / "features.csv", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
    assert reader.fieldnames == OUTPUT_COLUMNS
    assert [row["session_id"] for row in rows] == ["abc123", "0042"]
    assert sorted(json.loads((tmp_path / "details.json").read_text())) == ["0042", "abc123"]


@needs_demo
def test_extract_outputs_are_byte_identical_to_existing_demo_outputs(tmp_path):
    result = _cli(EXTRACT, "--input", DEMO / "parsed" / "sessions.json",
                  "--output", tmp_path / "behavior_features.csv", "--details", tmp_path / "session_details.json")
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "behavior_features.csv").read_bytes() == (DEMO / "parsed" / "behavior_features.csv").read_bytes()
    assert (tmp_path / "session_details.json").read_bytes() == (DEMO / "parsed" / "session_details.json").read_bytes()
