import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import collect_logs as collect_module


REPO_ROOT = Path(__file__).resolve().parents[1]
COLLECT_SCRIPT = REPO_ROOT / "scripts" / "collect_logs.py"


def _fake_run(write_bytes=None, fail=False):
    def run(command, *args, **kwargs):
        if fail:
            raise subprocess.CalledProcessError(1, command)
        if write_bytes is not None:
            Path(command[-1]).write_bytes(write_bytes)
        return subprocess.CompletedProcess(command, 0)
    return run


def test_successful_non_empty_copy_returns_true(tmp_path, monkeypatch):
    monkeypatch.setattr(collect_module.subprocess, "run", _fake_run(write_bytes=b'{"session": "a"}\n'))
    assert collect_module.collect_logs("cowrie-project", str(tmp_path / "cowrie.json")) is True


def test_copy_failure_returns_false(tmp_path, monkeypatch):
    monkeypatch.setattr(collect_module.subprocess, "run", _fake_run(fail=True))
    assert collect_module.collect_logs("cowrie-project", str(tmp_path / "cowrie.json")) is False


def test_copy_failure_with_stale_file_is_not_reported_as_success(tmp_path, monkeypatch, capsys):
    stale = tmp_path / "cowrie.json"
    stale.write_text('{"session": "old"}\n', encoding="utf-8")
    monkeypatch.setattr(collect_module.subprocess, "run", _fake_run(fail=True))

    assert collect_module.collect_logs("cowrie-project", str(stale)) is False
    assert "stale" in capsys.readouterr().err


def test_missing_snapshot_after_copy_returns_false(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(collect_module.subprocess, "run", _fake_run())
    assert collect_module.collect_logs("cowrie-project", str(tmp_path / "cowrie.json")) is False
    assert "missing" in capsys.readouterr().err


def test_empty_snapshot_returns_false(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(collect_module.subprocess, "run", _fake_run(write_bytes=b""))
    assert collect_module.collect_logs("cowrie-project", str(tmp_path / "cowrie.json")) is False
    assert "empty" in capsys.readouterr().err


def test_cli_exits_non_zero_when_docker_is_unavailable(tmp_path):
    # PATH contains only the Python directory, so neither docker nor sudo can be found.
    env = dict(os.environ, PATH=os.path.dirname(sys.executable))
    result = subprocess.run(
        [sys.executable, str(COLLECT_SCRIPT), "--container", "no-such-container", "--dest", str(tmp_path / "cowrie.json")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert not (tmp_path / "cowrie.json").exists()


def _docker_fails_with_stderr(calls, sudo_error=None):
    def run(command, *args, **kwargs):
        calls.append(command[0])
        if command[0] == "docker":
            raise subprocess.CalledProcessError(1, command, stderr=b"Error response from daemon: No such container: cowrie-project")
        raise sudo_error or subprocess.CalledProcessError(1, command, stderr=b"sudo: a password is required")
    return run


def test_windows_docker_failure_reports_docker_error_and_skips_sudo(tmp_path, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(collect_module, "_sudo_fallback_available", lambda: False)
    monkeypatch.setattr(collect_module.subprocess, "run", _docker_fails_with_stderr(calls))

    assert collect_module.collect_logs("cowrie-project", str(tmp_path / "cowrie.json")) is False
    err = capsys.readouterr().err
    assert calls == ["docker"]
    assert "No such container: cowrie-project" in err
    assert "sudo" not in err


def test_posix_reports_both_docker_and_sudo_failures(tmp_path, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(collect_module, "_sudo_fallback_available", lambda: True)
    monkeypatch.setattr(collect_module.subprocess, "run", _docker_fails_with_stderr(calls))

    assert collect_module.collect_logs("cowrie-project", str(tmp_path / "cowrie.json")) is False
    err = capsys.readouterr().err
    assert calls == ["docker", "sudo"]
    assert "docker cp failed: exit status 1: Error response from daemon: No such container" in err
    assert "sudo -n docker cp fallback failed: exit status 1: sudo: a password is required" in err


def test_posix_sudo_fallback_success_still_validates_snapshot(tmp_path, monkeypatch):
    def run(command, *args, **kwargs):
        if command[0] == "docker":
            raise subprocess.CalledProcessError(1, command, stderr=b"permission denied")
        Path(command[-1]).write_bytes(b"")
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(collect_module, "_sudo_fallback_available", lambda: True)
    monkeypatch.setattr(collect_module.subprocess, "run", run)
    assert collect_module.collect_logs("cowrie-project", str(tmp_path / "cowrie.json")) is False


def test_missing_docker_binary_is_reported_as_not_found(tmp_path, monkeypatch, capsys):
    def run(command, *args, **kwargs):
        raise FileNotFoundError(2, "No such file", command[0])
    monkeypatch.setattr(collect_module, "_sudo_fallback_available", lambda: False)
    monkeypatch.setattr(collect_module.subprocess, "run", run)
    assert collect_module.collect_logs("cowrie-project", str(tmp_path / "cowrie.json")) is False
    assert "docker cp failed: command not found (docker)" in capsys.readouterr().err


def test_sudo_fallback_is_disabled_on_windows():
    assert collect_module._sudo_fallback_available() is (os.name != "nt")
