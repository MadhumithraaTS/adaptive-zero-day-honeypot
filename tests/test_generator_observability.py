"""Bounded terminal-output capture and the explicit pacing-seed policy of generator 2.1.

Terminal output is diagnostic evidence for readiness decisions. It is written to terminal_output.jsonl,
never to the manifest, and nothing in the dataset builder, labelling or extractors reads it.
"""
import json
import sys
from pathlib import Path

import pytest

from dataset_builder import generate_labelled_traffic as glt
from generator_fakes import PROMPT, FakeShell, install

REPO = Path(__file__).resolve().parents[1]
FAST = glt.ReadinessPolicy(prompt_timeout_s=0.2, exit_timeout_s=0.2, poll_interval_s=0.001)


def _run(commands, behaviours=None, password="x"):
    return glt.run_session("h", 1, [["root", password]], commands, glt.PacingPolicy(),
                           glt.session_pacing_rng(1, 1), FAST)


# --- output capture ------------------------------------------------------------------------------

def test_readiness_decision_is_traceable_to_the_observed_prompt(monkeypatch):
    install(monkeypatch, glt)
    record = _run(["id"])
    initial, first = record["terminal_output"][0], record["terminal_output"][1]
    assert initial["step"] == "initial" and initial["readiness_reason"] == "prompt"
    assert first["step"] == 1 and first["prompt_match"] == "root@svr04:~# "
    assert first["prompt_match"] in first["output"]          # the matched prompt is in the recorded output
    assert first["output"].startswith("id\nok\n")           # echo and output, control sequences stripped
    entry = record["command_log"][0]
    assert entry["readiness_reason"] == "prompt" and entry["prompt_match"] == "root@svr04:~# "
    assert entry["output_chars"] == first["output_chars"] and entry["output_truncated"] is False


def test_timeout_records_the_output_that_was_seen_and_no_prompt(monkeypatch):
    install(monkeypatch, glt, shell_factory=lambda: FakeShell(behaviours={"scp": "hang"}))
    record = _run(["scp d.tar root@192.0.2.5:/tmp/"])
    out = record["terminal_output"][1]
    assert out["readiness_reason"] == "timeout" and out["prompt_match"] is None
    assert out["output"] == "scp d.tar root@192.0.2.5:/tmp/\n"
    assert record["command_log"][0]["readiness_reason"] == "timeout"


def test_large_output_is_truncated_to_the_capture_limit(monkeypatch):
    install(monkeypatch, glt, shell_factory=lambda: FakeShell(behaviours={"cat": "big"}))
    record = _run(["cat /var/log/huge"])
    out = record["terminal_output"][1]
    limit = glt.OUTPUT_CAPTURE_CHARS
    assert out["output_truncated"] is True
    assert out["output_chars"] > 10000
    assert len(out["output"]) <= limit + len("\n[...truncated...]\n")
    assert "[...truncated...]" in out["output"] and out["output"].endswith("root@svr04:~# ")
    assert record["command_log"][0]["output_truncated"] is True


def test_capture_redacts_the_session_passwords(monkeypatch):
    install(monkeypatch, glt)
    record = glt.run_session("h", 1, [["scan", "guess123"], ["root", "s3cretPW"]], ["echo s3cretPW", "echo guess123"],
                             glt.PacingPolicy(), glt.session_pacing_rng(1, 1), FAST)
    text = " ".join(t["output"] for t in record["terminal_output"])
    assert "s3cretPW" not in text and "guess123" not in text and "[REDACTED]" in text


def test_short_typed_passwords_are_not_redacted_and_redaction_never_exceeds_the_bound():
    cap = glt._OutputCapture(limit=40)
    cap.add_text("echo x x x")
    res = cap.result(typed_secrets=("x",))                           # 1-char secret: left alone, reason recorded
    assert res["output"] == "echo x x x"
    assert res["redaction"] == {"applied": False, "reason": "typed_secret_too_short_not_redacted", "occurrences": 0}
    cap2 = glt._OutputCapture(limit=40, margin=4)
    cap2.add_text(" ".join(["abcd"] * 6))                            # 6 x [REDACTED] grows past the 40-char bound
    res = cap2.result(typed_secrets=("abcd",))
    assert "abcd" not in res["output"] and res["output_truncated"] is True
    assert len(res["output"]) <= 40 + len(glt.TRUNCATION_MARKER)


def test_output_capture_class_bounds_and_counts():
    cap = glt._OutputCapture(limit=10)
    cap.add_bytes(15)
    cap.add_text("abcdefghij")
    cap.add_text("KLMNO")
    res = cap.result()
    assert res["output_chars"] == 15 and res["output_bytes"] == 15 and res["output_truncated"] is True
    assert res["output"] == "abcde\n[...truncated...]\nKLMNO"
    assert res["redaction"] == {"applied": False, "reason": "no_secret_typed", "occurrences": 0}


# --- end to end: separate diagnostic file, manifest stays clean ------------------------------------

def _run_main(tmp_path, monkeypatch, extra=(), out_name="run"):
    install(monkeypatch, glt)
    config = {"version": "test", "placeholders": {}, "profiles": [
        {"name": "p", "attack_cat": "botnet", "label": 1, "delay_range": [0, 0],
         "credentials": {"usernames": ["root"], "passwords": ["pw-secret"], "failed_attempts": [1, 1]},
         "steps": [["uname -a"], ["id"]]}]}
    cfg = tmp_path / "profiles.json"
    cfg.write_text(json.dumps(config), encoding="utf-8")
    out = tmp_path / "runs" / out_name
    argv = ["generate_labelled_traffic.py", "--config", str(cfg), "--sessions", "3", "--seed", "1",
            "--no-baseline", "--output-dir", str(out), "--prompt-timeout", "0.2", *extra]
    monkeypatch.setattr(sys, "argv", argv)
    glt.main()
    return out


def test_terminal_output_goes_to_its_own_file_and_never_into_the_manifest(tmp_path, monkeypatch):
    out = _run_main(tmp_path, monkeypatch, ["--pacing-seed", "11"])
    manifest_text = (out / "manifest.jsonl").read_text(encoding="utf-8")
    entries = [json.loads(line) for line in manifest_text.splitlines()]
    assert all("terminal_output" not in e for e in entries)
    assert "root@svr04" not in manifest_text.replace('"prompt_match": "root@svr04:~# "', "")  # only the prompt match
    assert "pw-secret" in manifest_text  # credentials stay in auth_attempts, as before (label source)
    terminal = [json.loads(line) for line in (out / "terminal_output.jsonl").read_text(encoding="utf-8").splitlines()]
    # one initial record plus one per sent command, per session
    assert len(terminal) == sum(1 + len(e["commands_sent"]) for e in entries)
    assert {t["index"] for t in terminal} == {e["index"] for e in entries}
    assert all("pw-secret" not in t["output"] for t in terminal)
    meta = json.loads((out / "run_meta.json").read_text(encoding="utf-8"))
    assert meta["terminal_output_file"].startswith("terminal_output.jsonl")
    assert meta["output_capture_chars"] == glt.OUTPUT_CAPTURE_CHARS


def test_no_feature_or_label_code_reads_the_terminal_output():
    for rel in ("dataset_builder/build_labelled_dataset.py", "dataset_builder/labelling.py",
                "dataset_builder/relabel_run.py", "scripts/extract_features.py", "scripts/parse_logs.py"):
        source = (REPO / rel).read_text(encoding="utf-8")
        assert "terminal_output" not in source and "command_log" not in source, rel
    spec = json.loads((REPO / "configs" / "feature_spec_v2.json").read_text(encoding="utf-8"))
    forbidden = " ".join(spec["forbidden_inputs"])
    assert "terminal_output.jsonl" in forbidden and "command_log" in forbidden
    assert spec["feature_counts"]["model_features"] == 13


# --- pacing seed policy ----------------------------------------------------------------------------

def test_pacing_seed_is_required(tmp_path, monkeypatch):
    with pytest.raises(SystemExit) as caught:
        _run_main(tmp_path, monkeypatch)
    assert caught.value.code == 2  # argparse: missing required --pacing-seed


def test_pacing_seed_is_recorded_and_independent_of_the_planning_seed(tmp_path, monkeypatch):
    out = _run_main(tmp_path, monkeypatch, ["--pacing-seed", "999"])
    meta = json.loads((out / "run_meta.json").read_text(encoding="utf-8"))
    assert meta["seed"] == 1 and meta["pacing_seed"] == 999
    assert meta["pacing_seed_source"] == "explicit --pacing-seed"
    entries = [json.loads(line) for line in (out / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [e["pacing_stream"] for e in entries] == ["pacing:999:1", "pacing:999:2", "pacing:999:3"]


def test_reusing_a_pacing_seed_under_the_runs_root_is_refused(tmp_path, monkeypatch):
    _run_main(tmp_path, monkeypatch, ["--pacing-seed", "5"], out_name="run_a")
    with pytest.raises(SystemExit) as caught:
        _run_main(tmp_path, monkeypatch, ["--pacing-seed", "5"], out_name="run_b")
    assert "already used" in str(caught.value) and "run_a" in str(caught.value)
    assert not (tmp_path / "runs" / "run_b").exists()  # refused before any output or connection
    _run_main(tmp_path, monkeypatch, ["--pacing-seed", "6"], out_name="run_c")  # a new seed is fine


def test_reuse_override_is_recorded(tmp_path, monkeypatch):
    _run_main(tmp_path, monkeypatch, ["--pacing-seed", "5"], out_name="run_a")
    out = _run_main(tmp_path, monkeypatch, ["--pacing-seed", "5", "--allow-pacing-seed-reuse"], out_name="run_b")
    meta = json.loads((out / "run_meta.json").read_text(encoding="utf-8"))
    assert meta["pacing_seed_reuse"]["allowed"] is True
    assert meta["pacing_seed_reuse"]["reused_by"] and meta["pacing_seed_reuse"]["reused_by"][0].endswith("run_a")
