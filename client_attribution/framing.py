"""Transport-independent relay-witness protocol (D13).

A frame is a 4-byte big-endian length followed by canonical JSON. Any reliable byte stream carries it: today a UNIX
socket on a shared named volume (or a socketpair in tests), later mutually authenticated TLS to a separate witness
machine. Security never depends on the transport: the witness re-reads and verifies each record itself, and the relay
verifies the witness's signed acknowledgement.
"""
import json
import socket
import struct
import time

MAX_FRAME = 1 << 20


class WitnessTimeout(RuntimeError):
    pass


class WitnessUnavailable(RuntimeError):
    pass


def encode(obj) -> bytes:
    body = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(body) > MAX_FRAME:
        raise ValueError("frame too large")
    return struct.pack(">I", len(body)) + body


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise WitnessUnavailable("connection closed")
        buf += chunk
    return buf


def read_frame(sock):
    (n,) = struct.unpack(">I", _recv_exact(sock, 4))
    if n > MAX_FRAME:
        raise WitnessUnavailable("frame too large")
    return json.loads(_recv_exact(sock, n).decode("utf-8"))


class StreamTransport:
    """Request/response over any connected stream socket, bounded by `timeout` seconds."""

    def __init__(self, sock, timeout=2.0):
        self.sock, self.timeout = sock, timeout

    def request(self, frame):
        deadline = time.monotonic() + self.timeout
        try:
            self.sock.settimeout(self.timeout)
            self.sock.sendall(encode(frame))
            self.sock.settimeout(max(0.001, deadline - time.monotonic()))
            return read_frame(self.sock)
        except socket.timeout as exc:
            raise WitnessTimeout(f"no witness confirmation within {self.timeout} s") from exc
        except (OSError, ValueError) as exc:
            raise WitnessUnavailable(str(exc)) from exc


def respond(handler, frame):
    """Witness side: answer one frame, echoing its `request_id` so the relay can match the confirmation (Task 28B)."""
    resp = dict(handler(frame))
    if isinstance(frame, dict) and "request_id" in frame:
        resp["request_id"] = frame["request_id"]
    return resp


def serve_stream(sock, handler, stop=lambda: False):
    """Witness side: answer frames on one connection until it closes or `stop()` is true."""
    while not stop():
        try:
            frame = read_frame(sock)
        except (WitnessUnavailable, OSError):
            return
        sock.sendall(encode(respond(handler, frame)))


class InProcessTransport:
    """Direct call to a handler (tests/local mock). `delay` simulates witness latency against an injected clock."""

    def __init__(self, handler, clock=None, delay=0.0, timeout=2.0):
        self.handler, self.clock, self.delay, self.timeout, self.down = handler, clock, delay, timeout, False

    def request(self, frame):
        if self.down:
            raise WitnessUnavailable("witness unreachable")
        if self.delay > self.timeout:
            if self.clock is not None:
                self.clock.advance(self.timeout)
            raise WitnessTimeout(f"no witness confirmation within {self.timeout} s")
        if self.clock is not None and self.delay:
            self.clock.advance(self.delay)
        return json.loads(json.dumps(self.handler(json.loads(json.dumps(frame)))))   # serialise like a real transport
