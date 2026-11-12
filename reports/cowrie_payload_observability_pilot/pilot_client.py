"""Controlled Cowrie telemetry observability pilot (2026-11-10). Harmless inputs only; no exploits, no downloads.

Run with the project .venv against the isolated lab (127.0.0.1:2223):
    .venv/Scripts/python.exe reports/cowrie_payload_observability_pilot/pilot_client.py <out_dir>

Tests (each in its own SSH session, identified by username):
  A  pilot_a  one printable marker line
  B  pilot_b  one line with raw high bytes (0x90 run, a valid UTF-8 U+0090, a valid UTF-8 e-acute, 0xFF)
  C  pilot_c  provenance: write a one-line script into Cowrie's fake filesystem, then `sh` it
  D1 scan     failed login through dataset_builder's own _connect (client never closed explicitly)
  D2 scan     failed login with the transport closed explicitly right after the rejection
Writes <out_dir>/client_record.json with the exact bytes sent (hex) and client-side timestamps.
"""
import json
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import paramiko

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "dataset_builder"))
from generate_labelled_traffic import _connect  # noqa: E402  (exact generator connection code, for D1)

HOST, PORT = "127.0.0.1", 2223
RUN = uuid.uuid4().hex[:8]
out_dir = Path(sys.argv[1])
out_dir.mkdir(parents=True, exist_ok=False)
record = {"run_id": RUN, "host": HOST, "port": PORT, "paramiko": paramiko.__version__, "tests": {}}


def now():
    return datetime.now(timezone.utc).isoformat()


def shell_session(test, username, lines):
    """Log in, send each line as raw bytes followed by '\\n', then exit. Records what was sent."""
    entry = {"username": username, "start_utc": now(), "sent": []}
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(HOST, port=PORT, username=username, password=f"{username}-pw", timeout=15,
                       banner_timeout=20, auth_timeout=15, look_for_keys=False, allow_agent=False,
                       disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]})
        channel = client.invoke_shell()
        time.sleep(1.0)
        for line in lines + [b"exit"]:
            data = line + b"\n"
            channel.sendall(data)
            entry["sent"].append({"utc": now(), "hex": data.hex(), "length": len(data)})
            time.sleep(1.5)
            while channel.recv_ready():
                channel.recv(65535)
        time.sleep(0.5)
        entry["status"] = "ok"
    except Exception as exc:
        entry["status"] = f"error: {type(exc).__name__}: {exc}"
    finally:
        client.close()
    entry["end_utc"] = now()
    record["tests"][test] = entry


marker_a = f"PILOT_A_{RUN} ".encode() + b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_." * 4
marker_b = (f"PILOT_B_{RUN} ".encode() + b"\x90" * 8 + b" " + "\u0090".encode("utf-8") + b" "
            + "é".encode("utf-8") + b" " + b"\xff" + b" END")
shell_session("A", "pilot_a", [marker_a])
shell_session("B", "pilot_b", [marker_b])
shell_session("C", "pilot_c", [f"echo PILOT_C_{RUN}_line_from_script > /tmp/pilot_c.sh".encode(), b"sh /tmp/pilot_c.sh"])

# D1: the generator's failed-guess pattern: _connect raises, .close() is never reached.
d1 = {"username": "scan", "password": "123456", "start_utc": now()}
try:
    _connect(HOST, PORT, "scan", "123456").close()
    d1["auth"] = "unexpectedly succeeded"
except Exception as exc:
    d1["auth"] = f"rejected: {type(exc).__name__}"
d1["client_done_utc"] = now()
record["tests"]["D1"] = d1
time.sleep(5)

# D2: same rejected credentials, transport closed explicitly after the rejection.
d2 = {"username": "scan", "password": "123456", "start_utc": now()}
sock = socket.create_connection((HOST, PORT), timeout=15)
transport = paramiko.Transport(sock)
try:
    transport.start_client(timeout=15)
    try:
        transport.auth_password("scan", "123456")
        d2["auth"] = "unexpectedly succeeded"
    except paramiko.AuthenticationException as exc:
        d2["auth"] = f"rejected: {type(exc).__name__}"
finally:
    transport.close()
    d2["closed_utc"] = now()
record["tests"]["D2"] = d2

# Keep the process (and D1's lingering transport thread) alive past Cowrie's 120 s authentication_timeout.
time.sleep(135)
record["finished_utc"] = now()
(out_dir / "client_record.json").write_text(json.dumps(record, indent=2))
print(json.dumps({k: v.get("status", v.get("auth")) for k, v in record["tests"].items()}))
