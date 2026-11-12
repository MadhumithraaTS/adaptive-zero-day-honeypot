"""TEST/LOCAL MOCK smoke test of the witnessed relay adapter in the real Twisted reactor (pinned Cowrie image).

Run inside a throwaway container with --network none (loopback only). Ephemeral in-memory keys; nothing persisted.
Checks: relay_start confirmed before listeners open; a client session works only after its open record is confirmed;
a missed heartbeat halts the relay: BOTH listeners stop accepting and the in-progress session is aborted.
"""
import hashlib
import json
import socket
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/opt/project")
sys.path.insert(0, "/opt/project/cowrie/attributing_relay")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from twisted.internet import protocol, reactor  # noqa: E402

import witnessed_relay as wr  # noqa: E402
from client_attribution.framing import InProcessTransport  # noqa: E402
from client_attribution.witness import CheckpointStore, WitnessCore  # noqa: E402
from relay_gate import RecordWriterV2, RelayWitnessGate  # noqa: E402


def k():
    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, pem, hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()


relay_key, relay_pem, relay_sha = k()
wit_key, wit_pem, wit_sha = k()
tmp = Path(tempfile.mkdtemp())
now = lambda: datetime.now(timezone.utc)                                  # noqa: E731
writer = RecordWriterV2(relay_key, relay_sha, lambda: now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"), path=tmp / "relay.jsonl")
store = CheckpointStore(tmp / "cp.jsonl")
mock_status = lambda: {"remote_head_checkpoint_seq": 10 ** 9, "remote_head_checkpoint_hash": None,  # noqa: E731
                       "pushed_utc": now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "anchor_match": True, "mock": True}
witness = WitnessCore("smoke", relay_pem, relay_sha, wit_key, wit_sha, "a" * 64, store,
                      lambda: (tmp / "relay.jsonl").read_text().splitlines() if (tmp / "relay.jsonl").exists() else [], now,
                      replication_status=mock_status)
transport = InProcessTransport(witness.handle, timeout=2.0)


class MonoClock:
    monotonic = staticmethod(time.monotonic)


gate = RelayWitnessGate(writer, transport, wit_pem, wit_sha, relay_sha, "smoke", MonoClock(), [], timeout=2.0, halt_marker=tmp / "halt.json")
res = {"label": "TEST/LOCAL MOCK smoke test (network none, ephemeral keys)"}


class Echo(protocol.Protocol):
    def dataReceived(self, data):
        self.transport.write(data)


class EchoFactory(protocol.Factory):
    protocol = Echo


reactor.listenTCP(2299, EchoFactory(), interface="127.0.0.1")
listeners = [{"name": "published", "mode": "published", "bind": "127.0.0.1", "port": 2301},
             {"name": "demo", "mode": "demo", "bind": "127.0.0.1", "port": 2302}]
wr.start(gate, listeners, "127.0.0.1", 2299, heartbeat_seconds=60, listeners=listeners, backend="127.0.0.1:2299", public_key_sha256=relay_sha)
res["relay_start_confirmed_before_listen"] = store.all()[0]["kind"] == "attest" and store.all()[0]["relay_record_type"] == "relay_start"
client = {}


def client_session():
    s = socket.create_connection(("127.0.0.1", 2302), timeout=3)
    s.sendall(b"ping")
    client["echo"] = s.recv(16)
    client["sock"] = s


def after_halt():
    for p in (2301, 2302):
        try:
            socket.create_connection(("127.0.0.1", p), timeout=1).close()
            res[f"listener_{p}"] = "ACCEPTED"
        except OSError as e:
            res[f"listener_{p}"] = type(e).__name__
    s = client["sock"]
    s.settimeout(2)
    try:
        data = s.recv(16)
        res["in_progress_session"] = "closed" if data == b"" else f"open ({data!r})"
    except OSError as e:
        res["in_progress_session"] = f"aborted ({type(e).__name__})"


def step1():
    reactor.callInThread(client_session)
    reactor.callLater(1.0, step2)


def step2():
    res["echo_through_relay"] = client.get("echo") == b"ping"
    res["checkpoints_before_halt"] = [c["relay_record_type"] for c in store.all()]
    res["sessions_registered"] = len(gate.sessions)
    transport.down = True                                               # witness becomes unreachable
    res["heartbeat_ok"] = gate.heartbeat()
    res["halt_cause"] = gate.halt_cause
    reactor.callLater(0.5, lambda: reactor.callInThread(after_halt))
    reactor.callLater(3.0, finish)


def finish():
    res["sessions_left"] = len(gate.sessions)
    res["halt_marker"] = json.loads((tmp / "halt.json").read_text()) if (tmp / "halt.json").exists() else None
    print(json.dumps(res, indent=1))
    reactor.stop()


reactor.callLater(0.5, step1)
reactor.run()
