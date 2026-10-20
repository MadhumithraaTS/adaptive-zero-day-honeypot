import csv
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.pipeline import build_paths, existing_outputs, planned_outputs


REPO_ROOT = Path(__file__).resolve().parents[1]
PIPELINE = REPO_ROOT / "scripts" / "pipeline.py"
DEMO_RAW_LOG = REPO_ROOT / "data" / "demo_20261019_213439" / "raw" / "cowrie.json"
# The saved DEC artifacts need the dedicated DEC interpreter (newer pandas/scikit-learn).
DEC_PYTHON = REPO_ROOT / "ml" / "cowrie_dec_integration_skeleton" / ".venv-dec-smoke" / "Scripts" / "python.exe"
PROTECTED_DIRS = [
    REPO_ROOT / "data" / "parsed",
    REPO_ROOT / "data" / "processed",
    REPO_ROOT / "data" / "raw",
    REPO_ROOT / "models",
    REPO_ROOT / "ml" / "cowrie_dec_integration_skeleton" / "ml" / "cowrie_dec" / "artifacts",
]


def _snapshot(directories):
    hashes = {}
    for directory in directories:
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def test_default_paths_are_the_tracked_baseline_and_output_dir_paths_are_isolated(tmp_path):
    default = build_paths()
    assert default["details"] == "data/parsed/session_details.json"
    assert default["aux_scaler"] == "models/scaler.joblib"

    isolated = build_paths(str(tmp_path))
    for path in isolated.values():
        assert Path(path).resolve().is_relative_to(tmp_path.resolve())


def test_planned_outputs_cover_every_written_file(tmp_path):
    paths = build_paths(str(tmp_path))
    assert set(planned_outputs(paths, collect=True, preprocess=True)) == set(paths.values())
    assert paths["raw"] not in planned_outputs(paths, collect=False, preprocess=True)
    assert paths["aux_scaler"] not in planned_outputs(paths, collect=False, preprocess=False)


def test_existing_outputs_are_detected(tmp_path):
    paths = build_paths(str(tmp_path))
    Path(paths["details"]).parent.mkdir(parents=True)
    Path(paths["details"]).write_text("{}", encoding="utf-8")
    assert existing_outputs(planned_outputs(paths, collect=False, preprocess=True)) == [paths["details"]]


def test_pipeline_refuses_to_overwrite_existing_outputs(tmp_path):
    out = tmp_path / "run"
    details = Path(build_paths(str(out))["details"])
    details.parent.mkdir(parents=True)
    details.write_text('{"keep": true}', encoding="utf-8")
    raw = tmp_path / "cowrie.json"
    raw.write_text("", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(PIPELINE), "--skip-attack", "--raw-input", str(raw), "--output-dir", str(out)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120, check=False,
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "refusing to overwrite" in result.stderr
    assert details.read_text(encoding="utf-8") == '{"keep": true}'
    assert sorted(p.name for p in out.rglob("*") if p.is_file()) == ["session_details.json"]


@pytest.mark.skipif(not (DEC_PYTHON.is_file() and DEMO_RAW_LOG.is_file()), reason="DEC interpreter or demo log not present")
def test_pipeline_with_output_dir_leaves_baseline_models_and_artifacts_untouched(tmp_path):
    raw = tmp_path / "input" / "cowrie.json"
    raw.parent.mkdir()
    shutil.copyfile(DEMO_RAW_LOG, raw)
    out = tmp_path / "run"
    before = _snapshot(PROTECTED_DIRS)

    result = subprocess.run(
        [sys.executable, str(PIPELINE), "--skip-attack", "--raw-input", str(raw), "--output-dir", str(out),
         "--cluster-python", str(DEC_PYTHON)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=600, check=False,
    )

    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-3000:]
    assert _snapshot(PROTECTED_DIRS) == before

    paths = build_paths(str(out))
    for key in ("sessions", "features", "details", "model_input", "mapping", "aux_scaler", "dec_results"):
        assert Path(paths[key]).is_file(), key
    assert not Path(paths["raw"]).exists()

    details = json.loads(Path(paths["details"]).read_text(encoding="utf-8"))
    with open(paths["dec_results"], encoding="utf-8", newline="") as handle:
        dec_ids = [row["session_id"] for row in csv.DictReader(handle)]
    assert sorted(dec_ids) == sorted(details)
    assert not any(line.startswith(("ARI:", "NMI:")) for line in result.stdout.splitlines())


# --- DEC interpreter selection and failure propagation -------------------------------------------

from scripts import pipeline as pipeline_module  # noqa: E402


def _run_main(monkeypatch, argv, fake_run):
    monkeypatch.setattr(pipeline_module.subprocess, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["pipeline.py", *argv])
    pipeline_module.main()


def _recording_run(calls, fail_on=None, error=None):
    def run(command, *args, **kwargs):
        calls.append(list(command))
        if fail_on and fail_on in " ".join(map(str, command)):
            raise error
        return subprocess.CompletedProcess(command, 0)
    return run


def _isolated_args(tmp_path):
    raw = tmp_path / "cowrie.json"
    raw.write_text('{"session": "a", "eventid": "cowrie.session.connect"}\n', encoding="utf-8")
    return ["--skip-attack", "--raw-input", str(raw), "--output-dir", str(tmp_path / "run")]


def test_default_dec_interpreter_is_the_project_dec_environment_not_sys_executable():
    assert Path(pipeline_module.DEFAULT_DEC_PYTHON) == DEC_PYTHON
    assert Path(pipeline_module.DEFAULT_DEC_PYTHON) != Path(sys.executable)


def test_resolve_cluster_python_never_falls_back_to_active_interpreter(tmp_path, monkeypatch):
    explicit = tmp_path / "python.exe"
    explicit.write_bytes(b"")
    assert pipeline_module.resolve_cluster_python(str(explicit)) == str(explicit)
    assert pipeline_module.resolve_cluster_python(str(tmp_path / "missing.exe")) is None
    monkeypatch.setattr(pipeline_module, "DEFAULT_DEC_PYTHON", str(tmp_path / "absent.exe"))
    assert pipeline_module.resolve_cluster_python(None) is None


def test_exact_cluster_python_is_used_only_for_the_dec_step(tmp_path, monkeypatch):
    explicit = tmp_path / "dec-python.exe"
    explicit.write_bytes(b"")
    calls = []
    _run_main(monkeypatch, _isolated_args(tmp_path) + ["--cluster-python", str(explicit)], _recording_run(calls))

    dec_calls = [c for c in calls if "run_dec_evaluation.py" in " ".join(c)]
    other_calls = [c for c in calls if "run_dec_evaluation.py" not in " ".join(c)]
    assert len(dec_calls) == 1 and dec_calls[0][0] == str(explicit)
    assert other_calls and all(c[0] == sys.executable for c in other_calls)


def test_default_dec_interpreter_is_used_when_not_specified(tmp_path, monkeypatch):
    default = tmp_path / "default-dec-python.exe"
    default.write_bytes(b"")
    monkeypatch.setattr(pipeline_module, "DEFAULT_DEC_PYTHON", str(default))
    calls = []
    _run_main(monkeypatch, _isolated_args(tmp_path), _recording_run(calls))
    assert [c[0] for c in calls if "run_dec_evaluation.py" in " ".join(c)] == [str(default)]


def test_missing_default_dec_interpreter_is_a_usage_error(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline_module, "DEFAULT_DEC_PYTHON", str(tmp_path / "absent.exe"))
    calls = []
    with pytest.raises(SystemExit) as excinfo:
        _run_main(monkeypatch, _isolated_args(tmp_path), _recording_run(calls))
    assert excinfo.value.code == 2
    assert calls == []


def test_dec_step_failure_stops_pipeline_with_exit_1(tmp_path, monkeypatch):
    explicit = tmp_path / "dec-python.exe"
    explicit.write_bytes(b"")
    calls = []
    failing = _recording_run(calls, "run_dec_evaluation.py", subprocess.CalledProcessError(3, "dec"))
    with pytest.raises(SystemExit) as excinfo:
        _run_main(monkeypatch, _isolated_args(tmp_path) + ["--cluster-python", str(explicit)], failing)
    assert excinfo.value.code == 1


def test_uninvocable_dec_interpreter_stops_pipeline_with_exit_1(tmp_path, monkeypatch):
    explicit = tmp_path / "not-an-interpreter.txt"
    explicit.write_text("x", encoding="utf-8")
    calls = []
    failing = _recording_run(calls, "run_dec_evaluation.py", OSError(193, "not a valid application"))
    with pytest.raises(SystemExit) as excinfo:
        _run_main(monkeypatch, _isolated_args(tmp_path) + ["--cluster-python", str(explicit)], failing)
    assert excinfo.value.code == 1


def test_parse_failure_stops_pipeline_before_later_steps(tmp_path):
    raw = tmp_path / "cowrie.json"
    raw.write_text('{"session": "a"}\n{not json\n', encoding="utf-8")
    out = tmp_path / "run"
    result = subprocess.run(
        [sys.executable, str(PIPELINE), "--skip-attack", "--raw-input", str(raw), "--output-dir", str(out)],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "Malformed JSON on line 2" in result.stderr
    assert "Running step: Feature Extraction" not in result.stdout
    assert not any(p.is_file() for p in out.rglob("*"))
