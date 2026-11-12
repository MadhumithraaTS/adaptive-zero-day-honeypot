"""scripts/extract_features_v2.py against configs/feature_spec_v2.json (draft.3).

Every test writes Cowrie-style JSONL to a temporary file, runs the extractor, and reads the CSV outputs back,
so serialization (including 'NaN') is covered too.
"""
import ast
import builtins
import csv
import json
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scripts import extract_features_v2 as x2

REPO = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc)


def ev(sid, eventid, t, **fields):
    stamp = (T0 + timedelta(seconds=t)).isoformat().replace("+00:00", "Z")
    return {"eventid": eventid, "session": sid, "timestamp": stamp, "src_ip": "172.22.0.2", "sensor": "s",
            "uuid": "bafc61de", "protocol": "ssh", **fields}


def logged_in(sid="s1", commands=(), closed_at=None, duration=None, size=500, login_t=1.0, failed_before=0):
    """connect, version, kex, [failed logins], success, size, params, commands (t, text), log.closed, closed."""
    events = [ev(sid, "cowrie.session.connect", 0.0), ev(sid, "cowrie.client.version", 0.01),
              ev(sid, "cowrie.client.kex", 0.02)]
    events += [ev(sid, "cowrie.login.failed", 0.5 + i * 0.01, username="scan", password="x") for i in range(failed_before)]
    events += [ev(sid, "cowrie.login.success", login_t, username="root", password="pw"),
               ev(sid, "cowrie.client.size", login_t + 0.01), ev(sid, "cowrie.session.params", login_t + 0.02)]
    events += [ev(sid, "cowrie.command.input", t, input=text) for t, text in commands]
    end = closed_at if closed_at is not None else (max([t for t, _ in commands], default=login_t) + 1.0)
    if size is not None:
        events.append(ev(sid, "cowrie.log.closed", end - 0.01, size=size, duration="1.0"))
    events.append(ev(sid, "cowrie.session.closed", end, duration=duration if duration is not None else end))
    return events


def failed_only(sid="f1", attempts=1, end=1.1):
    events = [ev(sid, "cowrie.session.connect", 0.0), ev(sid, "cowrie.client.version", 0.01),
              ev(sid, "cowrie.client.kex", 0.02)]
    events += [ev(sid, "cowrie.login.failed", 0.05 + i * 0.01, username="scan", password="123456") for i in range(attempts)]
    events.append(ev(sid, "cowrie.session.closed", end, duration=end))
    return events


def run(tmp_path, records, name="cowrie.json", **kw):
    path = tmp_path / name
    path.write_text("".join((r if isinstance(r, str) else json.dumps(r)) + "\n" for r in records), encoding="utf-8")
    out = tmp_path / "out"
    summary = x2.extract([str(path)], str(out), **kw)
    feats = list(csv.DictReader(open(out / "model_features.csv", encoding="utf-8")))
    meta = list(csv.DictReader(open(out / "session_metadata.csv", encoding="utf-8")))
    rows = {}
    for f, m in zip(feats, meta):
        row = {k: (float(v) if k in ("session_duration_s", "input_line_max_bytes", "time_to_first_input_s",
                                     "inter_input_mean_s", "inter_input_std_s", "tty_output_bytes") else int(v))
               for k, v in f.items()}
        row.update({k: int(m[k]) for k in x2.DESCRIPTIVE_FIELDS})
        row["warnings"] = [w for w in m["warnings"].split(";") if w]
        row["status"] = m["extraction_status"]
        rows[m["session_ref"]] = row
    return rows, summary, out


def nan(value):
    return isinstance(value, float) and math.isnan(value)


# --- specification binding -------------------------------------------------------------------------

def test_extractor_matches_the_specification_exactly():
    spec = json.loads((REPO / "configs" / "feature_spec_v2.json").read_text(encoding="utf-8"))
    assert spec["spec_version"] == x2.IMPLEMENTED_SPEC_VERSION
    assert [f["name"] for f in spec["features"]] == x2.MODEL_FEATURES and len(x2.MODEL_FEATURES) == 13
    assert [d["name"] for d in spec["descriptive_fields"]] == x2.DESCRIPTIVE_FIELDS
    sh = next(f for f in spec["features"] if f["name"] == "shell_operator_lines")["formula"]
    dl = next(f for f in spec["features"] if f["name"] == "download_command_lines")["formula"]
    assert all(repr(op) in sh for op in x2.SHELL_OPERATORS)
    assert all(f"'{c}'" in dl for c in x2.DOWNLOAD_COMMANDS)
    assert "'exit' or 'logout'" in spec["conventions"]["input_lines"]


def test_a_mismatched_specification_is_refused(tmp_path):
    spec = json.loads((REPO / "configs" / "feature_spec_v2.json").read_text(encoding="utf-8"))
    spec["spec_version"] = "9.9.9"
    bad = tmp_path / "spec.json"
    bad.write_text(json.dumps(spec), encoding="utf-8")
    with pytest.raises(x2.ExtractionError, match="does not match"):
        x2.load_spec(str(bad))


def test_model_matrix_has_exactly_the_13_features_and_no_identifier(tmp_path):
    _, _, out = run(tmp_path, logged_in(commands=[(2.0, "id")]))
    header = (out / "model_features.csv").read_text(encoding="utf-8").splitlines()[0].split(",")
    assert header == x2.MODEL_FEATURES
    meta_header = (out / "session_metadata.csv").read_text(encoding="utf-8").splitlines()[0].split(",")
    assert "session_ref" in meta_header and not set(meta_header) & set(x2.MODEL_FEATURES)


# --- authentication ----------------------------------------------------------------------------------

def test_successful_login(tmp_path):
    r = run(tmp_path, logged_in())[0]["s1"]
    assert r["login_success"] == 1 and r["login_failed_count"] == 0


def test_failed_login_session(tmp_path):
    r = run(tmp_path, failed_only())[0]["f1"]
    assert r["login_success"] == 0 and r["login_failed_count"] == 1
    assert r["tty_output_bytes"] == 0.0                      # structural zero: no terminal without login
    assert nan(r["time_to_first_input_s"]) and nan(r["inter_input_mean_s"]) and nan(r["inter_input_std_s"])
    assert r["input_line_count"] == 0 and nan(r["input_line_max_bytes"])


def test_multiple_failed_attempts_in_one_session(tmp_path):
    assert run(tmp_path, failed_only(attempts=3))[0]["f1"]["login_failed_count"] == 3


def test_failed_then_successful_login_in_one_session(tmp_path):
    r = run(tmp_path, logged_in(failed_before=2, commands=[(3.0, "id")]))[0]["s1"]
    assert r["login_success"] == 1 and r["login_failed_count"] == 2
    assert r["time_to_first_input_s"] == pytest.approx(2.0)  # from the first login.success


def test_no_authentication_event_is_warned(tmp_path):
    rows = run(tmp_path, [ev("n1", "cowrie.session.connect", 0), ev("n1", "cowrie.session.closed", 0.5, duration=0.5)])[0]
    assert "no_authentication_event" in rows["n1"]["warnings"] and rows["n1"]["status"] == "ok_with_warnings"


# --- session -------------------------------------------------------------------------------------------

def test_session_duration_comes_from_session_closed(tmp_path):
    r = run(tmp_path, logged_in(commands=[(2.0, "id")], closed_at=3.0, duration=3.0))[0]["s1"]
    assert r["session_duration_s"] == 3.0 and r["session_closed_observed"] == 1


def test_missing_closing_event_gives_nan_duration_and_warning(tmp_path):
    events = [e for e in logged_in(commands=[(2.0, "id")]) if e["eventid"] != "cowrie.session.closed"]
    r = run(tmp_path, events)[0]["s1"]
    assert nan(r["session_duration_s"]) and r["session_closed_observed"] == 0 and "no_session_closed" in r["warnings"]


def test_zero_duration_session_is_permitted(tmp_path):
    events = [ev("z1", "cowrie.session.connect", 0.0), ev("z1", "cowrie.login.failed", 0.0),
              ev("z1", "cowrie.session.closed", 0.0, duration=0.0)]
    r = run(tmp_path, events)[0]["z1"]
    assert r["session_duration_s"] == 0.0 and "negative_session_duration" not in r["warnings"]


def test_duration_inconsistent_with_event_span_is_warned(tmp_path):
    r = run(tmp_path, logged_in(commands=[(2.0, "id")], closed_at=3.0, duration=60.0))[0]["s1"]
    assert r["session_duration_s"] == 60.0 and "session_duration_differs_from_event_span" in r["warnings"]


def test_out_of_order_records_are_sorted_by_timestamp_and_flagged(tmp_path):
    events = logged_in(commands=[(2.0, "uname -a"), (3.0, "id"), (5.0, "w")])
    i = next(k for k, e in enumerate(events) if e.get("input") == "w")
    events.insert(next(k for k, e in enumerate(events) if e.get("input") == "uname -a"), events.pop(i))  # w logged first
    r = run(tmp_path, events)[0]["s1"]
    assert r["timestamp_order_mismatch"] == 1
    assert r["inter_input_mean_s"] == pytest.approx(1.5)            # computed in timestamp order: 1.0, 2.0
    assert r["time_to_first_input_s"] == pytest.approx(1.0)


def test_invalid_timestamp_is_warned_and_timing_becomes_undefined(tmp_path):
    events = logged_in(commands=[(2.0, "id"), (3.0, "w")])
    next(e for e in events if e.get("input") == "w")["timestamp"] = "not-a-time"
    r = run(tmp_path, events)[0]["s1"]
    assert any(w.startswith("missing_or_invalid_timestamp@") for w in r["warnings"])
    assert "recorded_input_without_timestamp_timing_undefined" in r["warnings"]
    assert nan(r["time_to_first_input_s"]) and nan(r["inter_input_mean_s"])
    assert r["input_line_count"] == 2                                # the line still counts


# --- recorded input ------------------------------------------------------------------------------------

def test_no_input_events(tmp_path):
    r = run(tmp_path, logged_in())[0]["s1"]
    assert (r["input_line_count"], r["input_bytes_total"], r["unique_command_names"], r["shell_operator_lines"],
            r["download_command_lines"]) == (0, 0, 0, 0, 0)
    assert nan(r["input_line_max_bytes"]) and nan(r["time_to_first_input_s"])


def test_one_input_event(tmp_path):
    r = run(tmp_path, logged_in(commands=[(2.5, "uname -a")]))[0]["s1"]
    assert r["input_line_count"] == 1 and r["input_bytes_total"] == 8 and r["input_line_max_bytes"] == 8.0
    assert r["time_to_first_input_s"] == pytest.approx(1.5) and nan(r["inter_input_mean_s"]) and nan(r["inter_input_std_s"])


def test_multiple_input_events_and_exit_is_excluded(tmp_path):
    cmds = [(2.0, "uname -a"), (3.0, "id"), (5.0, "cat /etc/passwd"), (6.0, "exit"), (6.5, " logout ")]
    r = run(tmp_path, logged_in(commands=cmds))[0]["s1"]
    assert r["input_line_count"] == 3 and r["input_bytes_total"] == 8 + 2 + 15
    assert r["input_line_max_bytes"] == 15.0 and r["unique_command_names"] == 3


def test_empty_command_counts_as_a_recorded_line_but_has_no_name(tmp_path):
    r = run(tmp_path, logged_in(commands=[(2.0, ""), (3.0, "   "), (4.0, "id")]))[0]["s1"]
    assert r["input_line_count"] == 3 and r["unique_command_names"] == 1 and r["input_bytes_total"] == 0 + 3 + 2


def test_unicode_command_bytes_are_utf8(tmp_path):
    r = run(tmp_path, logged_in(commands=[(2.0, "echo caf\u00e9 \U0001F600")]))[0]["s1"]
    assert r["input_bytes_total"] == len("echo caf\u00e9 \U0001F600".encode("utf-8")) == 15
    assert "non_ascii_recorded_input" in r["warnings"]


def test_shell_operator_lines(tmp_path):
    cmds = [(2.0, "cat a | grep b"), (3.0, "a; b"), (4.0, "a && b"), (5.0, "echo x > f"), (6.0, "wc < f"),
            (7.0, "echo `id`"), (8.0, "echo $(id)"), (9.0, "ls -la"), (10.0, "echo $HOME")]
    r = run(tmp_path, logged_in(commands=cmds))[0]["s1"]
    assert r["shell_operator_lines"] == 7


def test_download_command_lines_count_attempts_by_command_name(tmp_path):
    cmds = [(2.0, "wget http://files.example/a"), (3.0, "curl -O http://files.example/b"), (4.0, "tftp 192.0.2.1"),
            (5.0, "ftp 192.0.2.1"), (6.0, "ftpget x"), (7.0, "scp a root@192.0.2.5:/tmp/"), (8.0, "echo wget"),
            (9.0, "/usr/bin/wget x")]
    r = run(tmp_path, logged_in(commands=cmds))[0]["s1"]
    assert r["download_command_lines"] == 6                     # first token only: 'echo wget' and a path do not count
    assert r["url_download_events"] == 0                         # a recorded command is not a download


def test_repeated_commands_and_arguments(tmp_path):
    cmds = [(2.0, "ls"), (3.0, "ls -la"), (4.0, "ls /tmp"), (5.0, "id"), (6.0, "id")]
    r = run(tmp_path, logged_in(commands=cmds))[0]["s1"]
    assert r["input_line_count"] == 5 and r["unique_command_names"] == 2


# --- timing --------------------------------------------------------------------------------------------

def test_one_interval(tmp_path):
    r = run(tmp_path, logged_in(commands=[(2.0, "id"), (4.5, "w")]))[0]["s1"]
    assert r["inter_input_mean_s"] == pytest.approx(2.5) and nan(r["inter_input_std_s"])


def test_multiple_intervals(tmp_path):
    r = run(tmp_path, logged_in(commands=[(2.0, "a"), (3.0, "b"), (6.0, "c")]))[0]["s1"]
    assert r["inter_input_mean_s"] == pytest.approx(2.0) and r["inter_input_std_s"] == pytest.approx(1.0)


def test_missing_timestamp_on_login_leaves_time_to_first_undefined(tmp_path):
    events = logged_in(commands=[(2.0, "id"), (3.0, "w")])
    del next(e for e in events if e["eventid"] == "cowrie.login.success")["timestamp"]
    r = run(tmp_path, events)[0]["s1"]
    assert nan(r["time_to_first_input_s"]) and r["inter_input_mean_s"] == pytest.approx(1.0)


def test_negative_time_to_first_input_is_kept_and_warned(tmp_path):
    events = logged_in(commands=[(2.0, "id")])
    next(e for e in events if e["eventid"] == "cowrie.login.success")["timestamp"] = \
        (T0 + timedelta(seconds=2.5)).isoformat().replace("+00:00", "Z")
    r = run(tmp_path, events)[0]["s1"]
    assert r["time_to_first_input_s"] == pytest.approx(-0.5) and "negative_time_to_first_input" in r["warnings"]


# --- server output ---------------------------------------------------------------------------------------

def test_non_zero_terminal_output(tmp_path):
    assert run(tmp_path, logged_in(commands=[(2.0, "id")], size=654))[0]["s1"]["tty_output_bytes"] == 654.0


def test_zero_terminal_output_when_logged_in(tmp_path):
    r = run(tmp_path, logged_in(commands=[(2.0, "id")], size=0))[0]["s1"]
    assert r["tty_output_bytes"] == 0.0 and "tty_output_below_recorded_input_bytes" in r["warnings"]


def test_logged_in_without_log_closed_gives_nan_output(tmp_path):
    r = run(tmp_path, logged_in(commands=[(2.0, "id")], size=None))[0]["s1"]
    assert nan(r["tty_output_bytes"]) and "logged_in_without_log_closed" in r["warnings"]


# --- file events ------------------------------------------------------------------------------------------

def test_download_event_variants_are_counted_separately(tmp_path):
    events = logged_in(commands=[(2.0, "wget http://files.example/a"), (4.0, "echo x > /tmp/f"), (6.0, "scp a h:/t")])
    events[-2:-2] = [
        ev("s1", "cowrie.session.file_download", 2.5, url="http://files.example/a", outfile="o", shasum="h"),
        ev("s1", "cowrie.session.file_download.failed", 2.6, url="http://192.0.2.40/b"),
        ev("s1", "cowrie.session.file_download", 4.5, destfile="/tmp/f", outfile="o2", shasum="h2"),
        ev("s1", "cowrie.session.file_download", 6.5, realm="scp", input="exit"),
        ev("s1", "cowrie.session.file_download", 6.6, message="no url, no destfile, no realm"),
    ]
    r = run(tmp_path, events)[0]["s1"]
    assert (r["url_download_events"], r["download_failed_events"], r["redirect_write_events"], r["scp_stdin_events"]) == (1, 1, 1, 1)
    assert r["download_command_lines"] == 2 and r["input_line_count"] == 3   # file events never count as input


def test_failed_command_events_are_descriptive_only(tmp_path):
    events = logged_in(commands=[(2.0, "shell"), (3.0, "a; b")])
    events[-2:-2] = [ev("s1", "cowrie.command.failed", 2.01, input="shell"), ev("s1", "cowrie.command.failed", 3.01, input="a"),
                     ev("s1", "cowrie.command.failed", 3.02, input="b")]
    r = run(tmp_path, events)[0]["s1"]
    assert r["unknown_command_events"] == 3 and r["input_line_count"] == 2


# --- data integrity ------------------------------------------------------------------------------------------

def test_exact_duplicate_records_are_removed_and_reported(tmp_path):
    events = logged_in(commands=[(2.0, "id")])
    events.insert(5, dict(events[4]))  # duplicate login.success record
    events.append(dict(next(e for e in events if e["eventid"] == "cowrie.command.input")))
    rows, summary, _ = run(tmp_path, events)
    r = rows["s1"]
    assert r["input_line_count"] == 1 and r["event_count"] == len(events) - 2
    assert "duplicate_records_removed=2" in r["warnings"] and summary["duplicate_records_removed"] == 2


def test_malformed_json_stops_by_default_with_line_number(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(ev("s1", "cowrie.session.connect", 0)) + "\n{not json\n", encoding="utf-8")
    with pytest.raises(x2.ExtractionError, match=r"c\.json:2: malformed JSON"):
        x2.extract([str(path)], str(tmp_path / "out"))


def test_malformed_json_is_reported_not_silently_dropped_when_allowed(tmp_path):
    records = logged_in(commands=[(2.0, "id")])
    rows, summary, _ = run(tmp_path, records[:3] + ["{not json", "[1, 2]"] + records[3:], allow_malformed=True)
    assert rows["s1"]["input_line_count"] == 1
    skipped = [w for w in summary["file_level_warnings"] if w["warning"] == "malformed_json_skipped"]
    assert [w["where"].rsplit(":", 1)[1] for w in skipped] == ["4", "5"]


def test_invalid_utf8_always_stops(tmp_path):
    path = tmp_path / "c.json"
    path.write_bytes(json.dumps(ev("s1", "cowrie.session.connect", 0)).encode() + b"\n" + b'{"session": "s1", "x": "\x90"}\n')
    with pytest.raises(x2.ExtractionError, match="not valid UTF-8"):
        x2.extract([str(path)], str(tmp_path / "out"))


def test_missing_fields_are_warned(tmp_path):
    events = logged_in(commands=[(2.0, "id")])
    del next(e for e in events if e["eventid"] == "cowrie.command.input")["input"]
    events.append({"eventid": "cowrie.client.size", "timestamp": "2026-11-10T10:00:00Z"})   # no session id
    events.append({"session": "s1", "timestamp": "2026-11-10T10:00:00Z"})                 # no eventid
    rows, summary, _ = run(tmp_path, events)
    r = rows["s1"]
    assert any(w.startswith("command_input_without_text@") for w in r["warnings"])
    assert any(w.startswith("missing_eventid@") for w in r["warnings"])
    assert [w["warning"] for w in summary["file_level_warnings"]] == ["event_without_session_id"]


def test_unknown_event_types_are_counted_and_reported(tmp_path):
    events = logged_in(commands=[(2.0, "id")])
    events.insert(4, ev("s1", "cowrie.direct-tcpip.request", 0.9, dst_ip="192.0.2.1"))
    r = run(tmp_path, events)[0]["s1"]
    assert "unknown_event_type:cowrie.direct-tcpip.request" in r["warnings"] and r["event_count"] == len(events)


def test_unicode_and_escaped_json_content(tmp_path):
    events = logged_in(commands=[(2.0, "echo \u2018quoted\u2019")])
    lines = [json.dumps(e, ensure_ascii=True) for e in events[:6]] + [json.dumps(e, ensure_ascii=False) for e in events[6:]]
    r = run(tmp_path, lines)[0]["s1"]
    assert r["input_bytes_total"] == len("echo \u2018quoted\u2019".encode("utf-8"))


def test_every_session_appears_once_and_output_is_deterministic(tmp_path):
    records = logged_in("b", commands=[(2.0, "id")]) + failed_only("a") + logged_in("c", commands=[(3.0, "w"), (4.0, "id")])
    _, s1, out = run(tmp_path, records, name="one.json")
    first = [(out / n).read_bytes() for n in ("model_features.csv", "session_metadata.csv")]
    _, s2, out2 = run(tmp_path, records, name="one.json")
    assert [(out2 / n).read_bytes() for n in ("model_features.csv", "session_metadata.csv")] == first
    assert s1["sessions"] == 3 and [r.split(",")[1] for r in first[1].decode().splitlines()[1:]] == ["a", "b", "c"]


def test_reserved_test_marker_is_flagged_not_altered(tmp_path):
    r = run(tmp_path, logged_in(commands=[(2.0, "PILOT_A_1234 x")]))[0]["s1"]
    assert "reserved_test_marker_present" in r["warnings"] and r["input_line_count"] == 1


# --- isolation from prohibited inputs ------------------------------------------------------------------------

def test_only_the_given_log_and_the_specification_are_opened(tmp_path, monkeypatch):
    (tmp_path / "manifest.jsonl").write_text('{"attack_cat": "botnet"}\n', encoding="utf-8")
    (tmp_path / "terminal_output.jsonl").write_text('{"output": "x"}\n', encoding="utf-8")
    opened = []
    real_open = builtins.open

    def spy(file, *args, **kwargs):
        opened.append(Path(file).name)
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", spy)
    run(tmp_path, logged_in(commands=[(2.0, "id")]))
    assert "manifest.jsonl" not in opened and "terminal_output.jsonl" not in opened
    assert set(opened) <= {"cowrie.json", "feature_spec_v2.json", "model_features.csv", "session_metadata.csv",
                           "extraction_summary.json"}


def test_labels_profiles_credentials_and_identifiers_do_not_change_features(tmp_path):
    base = logged_in(commands=[(2.0, "id"), (3.0, "w")])
    tagged = [dict(e, attack_cat="botnet", label=1, profile="botnet", src_ip="198.51.100.9", src_port=4444,
                   username="other", password="other-pw", hassh="zzz") for e in base]
    renamed = [dict(e, session="zz-other-id") for e in base]
    for sub in ("a", "b", "c"):
        (tmp_path / sub).mkdir()
    a = run(tmp_path / "a", base)[0]["s1"]
    b = run(tmp_path / "b", tagged)[0]["s1"]
    c = run(tmp_path / "c", renamed)[0]["zz-other-id"]
    pick = lambda r: [r[k] if not nan(r[k]) else "nan" for k in x2.MODEL_FEATURES]  # noqa: E731
    assert pick(a) == pick(b) == pick(c)


def test_v1_extractor_is_not_imported():
    tree = ast.parse((REPO / "scripts" / "extract_features_v2.py").read_text(encoding="utf-8"))
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not any("extract_features" in m and "v2" not in m for m in imported)
    assert not any(m.startswith(("dataset_builder", "scripts")) for m in imported)
