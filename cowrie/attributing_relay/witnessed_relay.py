"""Witness-gated attributing relay: NON-BLOCKING Twisted adapter (Task 28B; replaces the synchronous Task 28A adapter).

NOT DEPLOYED. The running relay still executes the unchanged `attributing_relay.py`; switching to this module is part
of migration step M7, which has not been run. Production start is refused while D0 placeholders remain.

The reactor never waits for the witness: every record request returns a `Pending` at once and the 2-s confirmation
limit is a reactor timer (`AsyncRelayWitnessGate`). relay_start is confirmed before any listener opens; each client
stays paused (its bytes are buffered) until its connection_open record is confirmed; close records are confirmed; a
heartbeat runs every 60 s. On any halt the gate stops BOTH listeners and aborts ALL in-progress sessions (D12).
"""
import struct
import uuid
from datetime import datetime, timezone

from twisted.internet import protocol, reactor
from twisted.internet.error import AlreadyCalled, AlreadyCancelled

from async_gate import AsyncRelayWitnessGate, Halted  # noqa: F401  (re-exported for callers)
from client_attribution.framing import encode, respond


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class _Handle:
    def __init__(self, dc):
        self.dc = dc

    def cancel(self):
        try:
            self.dc.cancel()
        except (AlreadyCalled, AlreadyCancelled):
            pass


class TwistedScheduler:
    def call_later(self, seconds, fn):
        return _Handle(reactor.callLater(seconds, fn))

    def seconds(self):
        return reactor.seconds()


class WitnessStreamClient(protocol.Protocol):
    """Transport-independent frames over any Twisted stream (UNIX socket today, TLS later). Never blocks."""

    def __init__(self, gate_ref):
        self.gate_ref, self.buf = gate_ref, b""

    def send(self, frame):
        if self.transport is None:
            raise ConnectionError("witness not connected")
        self.transport.write(encode(frame))

    def dataReceived(self, data):
        import json
        self.buf += data
        while len(self.buf) >= 4:
            (n,) = struct.unpack(">I", self.buf[:4])
            if len(self.buf) < 4 + n:
                return
            body, self.buf = self.buf[4:4 + n], self.buf[4 + n:]
            self.gate_ref().on_response(json.loads(body.decode("utf-8")))

    def connectionLost(self, reason):
        self.gate_ref().transport_lost(reason.getErrorMessage())


class LoopbackMockWitnessTransport:
    """TEST/LOCAL MOCK: an in-reactor witness. Answers are delivered later via reactor.callLater (never inline)."""

    label = "TEST/LOCAL MOCK - not production trust"

    def __init__(self, witness_handle, gate_ref, delay=lambda frame: 0.0):
        self.handle, self.gate_ref, self.delay = witness_handle, gate_ref, delay

    def send(self, frame):
        resp = respond(self.handle, frame)
        d = self.delay(frame)
        if d is not None:                                          # None = the witness never answers
            reactor.callLater(d, self.gate_ref().on_response, resp)


class ListenerHandle:
    def __init__(self, port):
        self.port = port

    def stop(self):
        return self.port.stopListening()


class Upstream(protocol.Protocol):
    def connectionMade(self):
        s = self.factory.server
        if s.lost or s.gate.halted:
            self.transport.abortConnection()
            return
        s.upstream = self
        h, p = self.transport.getHost(), self.transport.getPeer()
        s.upstream_local = (h.host, h.port)
        pending = s.gate.append("connection_open", connection_id=s.cid, listener=s.listener["name"], listener_mode=s.listener["mode"],
                                ingress_listener=f"{s.listener['bind']}:{s.listener['port']}", client_ip=s.peer.host, client_port=s.peer.port,
                                accepted_local=f"{s.local.host}:{s.local.port}", accepted_utc=s.accepted_utc, upstream_local_ip=h.host,
                                upstream_local_port=h.port, upstream_peer=f"{p.host}:{p.port}", upstream_connected_utc=utc_now())
        pending.add_callbacks(lambda rec: s.confirmed(), lambda err: s.abort())

    def dataReceived(self, data):
        self.factory.server.transport.write(data)

    def connectionLost(self, reason):
        self.factory.server.transport.loseConnection()


class UpstreamFactory(protocol.ClientFactory):
    protocol = Upstream

    def __init__(self, server):
        self.server = server

    def clientConnectionFailed(self, connector, reason):
        self.server.transport.loseConnection()


class Server(protocol.Protocol):
    def connectionMade(self):
        self.gate, self.listener = self.factory.gate, self.factory.listener
        self.cid, self.accepted_utc = str(uuid.uuid4()), utc_now()
        self.peer, self.local = self.transport.getPeer(), self.transport.getHost()
        self.upstream, self.upstream_local, self.buffer, self.opened, self.lost = None, None, [], False, False
        if self.gate.halted or self.local.host != self.listener["bind"]:
            self.transport.abortConnection()
            return
        try:
            self.gate.register_session(self)
        except Halted:
            self.transport.abortConnection()
            return
        self.transport.pauseProducing()                            # client held until its open record is confirmed
        reactor.connectTCP(self.factory.backend_host, self.factory.backend_port, UpstreamFactory(self), timeout=10)

    def confirmed(self):
        if self.lost or self.gate.halted:
            return
        self.opened = True                                          # only now may bytes flow (open record confirmed)
        if self.buffer and self.upstream is not None:
            self.upstream.transport.write(b"".join(self.buffer))
            self.buffer = []
        self.transport.resumeProducing()

    def abort(self):                                                # called by the gate on halt (D12)
        if self.upstream is not None:
            self.upstream.transport.abortConnection()
        self.transport.abortConnection()

    def dataReceived(self, data):
        if self.opened and self.upstream is not None:
            self.upstream.transport.write(data)
        else:
            self.buffer.append(data)                               # held until the witness confirms the open record

    def connectionLost(self, reason):
        self.lost = True
        self.gate.unregister_session(self)
        if self.upstream is not None:
            self.upstream.transport.loseConnection()
        if self.opened and not self.gate.halted:
            self.gate.append("connection_close", connection_id=self.cid, listener=self.listener["name"], client_ip=self.peer.host,
                             client_port=self.peer.port, upstream_local_ip=self.upstream_local[0], upstream_local_port=self.upstream_local[1],
                             closed_utc=utc_now())


class ListenerFactory(protocol.Factory):
    protocol = Server

    def __init__(self, listener, backend_host, backend_port, gate):
        self.listener, self.backend_host, self.backend_port, self.gate = listener, backend_host, backend_port, gate


def start(gate, listeners_cfg, backend_host, backend_port, on_ready=None, **relay_start_fields):
    """Queue relay_start; open every listener (registered with the gate) only after it is confirmed; then start heartbeats."""
    def open_listeners(_rec):
        for lst in listeners_cfg:
            port = reactor.listenTCP(int(lst["port"]), ListenerFactory(lst, backend_host, int(backend_port), gate), interface=lst["bind"])
            gate.listeners.append(ListenerHandle(port))
        gate.start_heartbeats()
        if on_ready:
            on_ready()
    return gate.start(**relay_start_fields).add_callbacks(open_listeners, lambda err: None)
