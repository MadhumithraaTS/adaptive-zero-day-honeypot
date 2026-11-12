"""TEST/LOCAL MOCK smoke test of the NON-BLOCKING witnessed relay in the real Twisted reactor (pinned Cowrie image,
--network none, ephemeral keys). Measures reactor responsiveness while a confirmation is delayed, concurrent
sessions, and the 2-s timeout halt of both listeners with session abort."""
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
from twisted.internet import protocol, reactor, task  # noqa: E402

import witnessed_relay as wr  # noqa: E402
from async_gate import AsyncRelayWitnessGate  # noqa: E402
from client_attribution.checkpoints import verify_checkpoint_chain  # noqa: E402
from client_attribution.witness import CheckpointStore, WitnessCore  # noqa: E402
from relay_gate import RecordWriterV2  # noqa: E402


def k():
    key = Ed25519PrivateKey.generate()
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, pem, hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()


relay_key, relay_pem, relay_sha = k()
wit_key, wit_pem, wit_sha = k()
tmp = Path(tempfile.mkdtemp())
now = lambda: datetime.now(timezone.utc)                                     # noqa: E731
iso = lambda: now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")                        # noqa: E731
writer = RecordWriterV2(relay_key, relay_sha, iso, path=tmp / "relay.jsonl")
store = CheckpointStore(tmp / "cp.jsonl")
witness = WitnessCore("smoke", relay_pem, relay_sha, wit_key, wit_sha, "a" * 64, store,
                      lambda: (tmp / "relay.jsonl").read_text().splitlines() if (tmp / "relay.jsonl").exists() else [], now,
                      replication_status=lambda: {"remote_head_checkpoint_seq": 10 ** 9, "pushed_utc": iso(), "anchor_match": True})
delay = {"attest": 0.05, "heartbeat": 0.05}
gate = None
transport = wr.LoopbackMockWitnessTransport(witness.handle, lambda: gate, delay=lambda f: delay[f["type"]])
gate = AsyncRelayWitnessGate(writer, transport, wit_pem, wit_sha, relay_sha, "smoke", wr.TwistedScheduler(), [], timeout=2.0,
                             heartbeat_interval=60.0, halt_marker=tmp / "halt.json")
res = {"label": "TEST/LOCAL MOCK async smoke test (network none, ephemeral keys)"}
ticks = []
task.LoopingCall(lambda: ticks.append(reactor.seconds())).start(0.02)


class Echo(protocol.Protocol):
    def dataReceived(self, data):
        self.transport.write(data)


class EchoF(protocol.Factory):
    protocol = Echo


reactor.listenTCP(2299, EchoF(), interface="127.0.0.1")
listeners = [{"name": "published", "mode": "published", "bind": "127.0.0.1", "port": 2301},
             {"name": "demo", "mode": "demo", "bind": "127.0.0.1", "port": 2302}]
clients = {}


def client(name, port=2302):
    t0 = time.monotonic()
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(name.encode())
    data = s.recv(32)
    clients[name] = {"echo": data.decode(), "latency": round(time.monotonic() - t0, 3), "sock": s}


def phase_a():                                               # responsiveness while confirmation is delayed 1.5 s
    delay["attest"] = 1.5
    res["a_t0"] = reactor.seconds()
    reactor.callInThread(client, "slow")
    reactor.callLater(2.5, phase_a_check)


def phase_a_check():
    win = [t for t in ticks if res["a_t0"] + 0.1 <= t <= res["a_t0"] + 1.5]
    gaps = [b - a for a, b in zip(ticks, ticks[1:]) if res["a_t0"] <= a <= res["a_t0"] + 2.0]
    res["a_ticks_during_pending_window"] = len(win)
    res["a_max_tick_gap_s"] = round(max(gaps), 3)
    res["a_slow_client"] = {k: v for k, v in clients.get("slow", {}).items() if k != "sock"}
    delay["attest"] = 0.2
    for n in ("c1", "c2", "c3"):                             # concurrent sessions
        reactor.callInThread(client, n)
    reactor.callLater(3.0, phase_b_check)


def phase_b_check():
    res["b_concurrent_clients"] = {n: clients[n]["echo"] == n for n in ("c1", "c2", "c3") if n in clients}
    recs = [json.loads(l) for l in (tmp / "relay.jsonl").read_text().splitlines()]
    res["b_records_in_order"] = [r["seq"] for r in recs] == list(range(1, len(recs) + 1))
    res["b_checkpoint_chain_ok"] = verify_checkpoint_chain(store.all(), wit_pem, wit_sha, "smoke")["ok"]
    res["b_max_outstanding"] = gate.stats["max_outstanding"]
    delay["heartbeat"] = 3.0                                 # the witness answers too late
    res["c_t0"] = reactor.seconds()
    gate.heartbeat()
    reactor.callLater(2.6, phase_c_check)


def phase_c_check():
    res["c_halted"], res["c_cause"] = gate.halted, gate.halt_cause
    res["c_halt_after_s"] = round(json.loads((tmp / "halt.json").read_text()) and (gate_halt_time[0] - res["c_t0"]), 3)
    reactor.callInThread(after_halt)
    reactor.callLater(2.0, finish)


gate_halt_time = []
gate.on_halt = lambda cause: gate_halt_time.append(reactor.seconds())


def after_halt():
    for p in (2301, 2302):
        try:
            socket.create_connection(("127.0.0.1", p), timeout=1).close()
            res[f"c_listener_{p}"] = "ACCEPTED"
        except OSError as e:
            res[f"c_listener_{p}"] = type(e).__name__
    out = {}
    for n in ("c1", "c2", "c3"):
        s = clients[n]["sock"]
        s.settimeout(2)
        try:
            out[n] = "closed" if s.recv(8) == b"" else "open"
        except OSError as e:
            out[n] = f"aborted ({type(e).__name__})"
    res["c_open_sessions_after_halt"] = out


def finish():
    res["c_sessions_left"] = len(gate.sessions)
    res["relay_start_confirmed_before_listen"] = store.all()[0]["relay_record_type"] == "relay_start"
    print(json.dumps(res, indent=1))
    reactor.stop()


wr.start(gate, listeners, "127.0.0.1", 2299, on_ready=lambda: reactor.callLater(0.3, phase_a),
         listeners=listeners, backend="127.0.0.1:2299", public_key_sha256=relay_sha)
reactor.run()
