"""Connection lifecycle of dataset_builder/generate_labelled_traffic.py.

Regression for reports/cowrie_payload_observability_pilot/report.md section 8: a rejected login left the
SSH transport open until Cowrie's 120 s authentication_timeout. No Cowrie or Docker is used; the
integration tests run a local paramiko server on 127.0.0.1.
"""
import socket
import threading
import time

import paramiko
import pytest

from dataset_builder import generate_labelled_traffic as glt
from generator_fakes import install

FAST = glt.ReadinessPolicy(prompt_timeout_s=0.5, exit_timeout_s=0.2, poll_interval_s=0.001)


@pytest.fixture
def fake_ssh(monkeypatch):
    return install(monkeypatch, glt)


def _run(attempts, commands):
    return glt.run_session("h", 1, attempts, commands, glt.PacingPolicy(), glt.session_pacing_rng(1, 1), FAST)


def test_connect_success_returns_open_client(fake_ssh):
    fake_ssh.outcomes = [None]
    client = glt._connect("h", 1, "u", "p")
    assert client is fake_ssh.instances[0]
    assert client.closed == 0


@pytest.mark.parametrize("error", [
    paramiko.AuthenticationException("Authentication failed."),
    paramiko.SSHException("Error reading SSH protocol banner"),
    socket.timeout("timed out"),
    ConnectionRefusedError(10061, "refused"),
])
def test_connect_closes_client_and_reraises_original_error(fake_ssh, error):
    fake_ssh.outcomes = [error]
    with pytest.raises(type(error)) as caught:
        glt._connect("h", 1, "u", "p")
    assert caught.value is error  # the original exception object, not a wrapper
    assert fake_ssh.instances[0].closed == 1


def test_run_session_closes_every_failed_guess_and_the_session(fake_ssh):
    rejected = paramiko.AuthenticationException("Authentication failed.")
    fake_ssh.outcomes = [rejected, rejected, None]
    attempts = [["scan", "123456"], ["scan", "admin"], ["root", "toor"]]
    record = _run(attempts, ["uname -a", "id"])
    assert [c.closed for c in fake_ssh.instances] == [1, 1, 1]
    assert record["status"] == "ok" and record["error"] is None
    assert record["auth_success"] is True
    assert record["guess_errors"] == []
    assert record["commands_sent"] == ["uname -a", "id"]
    assert [line for line, _ in fake_ssh.instances[-1].shell.received] == ["uname -a", "id", "exit"]


def test_run_session_records_unexpected_guess_errors_without_aborting(fake_ssh):
    fake_ssh.outcomes = [ConnectionRefusedError(10061, "refused"), None]
    record = _run([["scan", "123456"], ["root", "toor"]], ["id"])
    assert record["guess_errors"] == ["scan: ConnectionRefusedError: [Errno 10061] refused"]
    assert record["status"] == "ok" and record["auth_success"] is True
    assert [c.closed for c in fake_ssh.instances] == [1, 1]


def test_run_session_final_login_failure_is_recorded_and_closed(fake_ssh):
    fake_ssh.outcomes = [paramiko.AuthenticationException("Authentication failed.")]
    record = _run([["root", "toor"]], ["id"])
    assert record["status"] == "error"
    assert record["error"] == "AuthenticationException: Authentication failed."
    assert record["auth_success"] is False and record["commands_sent"] == []
    assert fake_ssh.instances[0].closed == 1


# --- integration: a real SSH handshake against a local server that rejects every password -----------

class _RejectAll(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED


@pytest.fixture(scope="module")
def host_key():
    return paramiko.RSAKey.generate(2048)


def _serve_once(host_key, observe_seconds):
    """Accept one connection; report whether the client was still connected `observe_seconds` after auth."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    result = {}

    def serve():
        conn, _ = listener.accept()
        transport = paramiko.Transport(conn)
        transport.add_server_key(host_key)
        transport.start_server(server=_RejectAll())
        start = time.monotonic()
        while transport.is_active() and time.monotonic() - start < observe_seconds:
            time.sleep(0.05)
        result["still_connected"] = transport.is_active()
        result["seconds_until_closed"] = time.monotonic() - start
        transport.close()
        listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return listener.getsockname()[1], thread, result


def test_rejected_login_closes_the_connection_promptly(host_key):
    port, thread, result = _serve_once(host_key, observe_seconds=10)
    with pytest.raises(paramiko.AuthenticationException):
        glt._connect("127.0.0.1", port, "scan", "123456")
    thread.join(20)
    assert result["still_connected"] is False
    assert result["seconds_until_closed"] < 5


def test_control_without_cleanup_the_connection_stays_open(host_key):
    """The pre-fix pattern (connect raises, nothing closes the client) keeps the transport alive."""
    port, thread, result = _serve_once(host_key, observe_seconds=3)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        with pytest.raises(paramiko.AuthenticationException):
            client.connect(hostname="127.0.0.1", port=port, username="scan", password="123456", timeout=15,
                           look_for_keys=False, allow_agent=False,
                           disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]})
        thread.join(20)
        assert result["still_connected"] is True
    finally:
        client.close()
