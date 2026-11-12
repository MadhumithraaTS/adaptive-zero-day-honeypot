"""Demo client for the isolated attribution network (Task 26A). Runs in the dedicated client containers.

    python3 demo_client.py banner --host 10.250.25.2 --port 2222
    python3 demo_client.py shell  --host 10.250.25.2 --port 2222 --user demo --password demo-pass --line "uname -a" ...

banner: one TCP connection, read the SSH banner, send nothing, close.
shell : one SSH session (Twisted Conch): password auth, pty + shell, send each --line after the prompt settles, then exit.
The Cowrie host key is accepted without verification (lab honeypot; documented). Prints a JSON summary.
"""
import argparse
import json
import socket
import sys
import time

from twisted.conch.ssh import channel, common, connection, transport, userauth
from twisted.internet import defer, protocol, reactor

RESULT = {"mode": None, "connected": False, "authenticated": False, "lines_sent": [], "output_bytes": 0, "error": None}


def banner(host, port):
    s = socket.create_connection((host, port), timeout=10)
    RESULT["client_local"] = "%s:%d" % s.getsockname()[:2]
    RESULT["connected"] = True
    s.settimeout(5)
    RESULT["banner"] = s.recv(256).decode("ascii", "replace").strip()
    time.sleep(1.0)
    s.close()


class Session(channel.SSHChannel):
    name = b"session"

    def channelOpen(self, _):
        term = common.NS(b"xterm") + b"\x00\x00\x00\x50\x00\x00\x00\x18" + b"\x00" * 8 + common.NS(b"")
        d = self.conn.sendRequest(self, b"pty-req", term, wantReply=True)
        d.addCallback(lambda _: self.conn.sendRequest(self, b"shell", b"", wantReply=True))
        d.addCallback(lambda _: reactor.callLater(2.0, self._next))
        d.addErrback(self._fail)

    def _next(self):
        lines = self.conn.factory_args["lines"]
        if lines:
            ln = lines.pop(0)
            self.write(ln.encode() + b"\n")
            RESULT["lines_sent"].append(ln)
            reactor.callLater(self.conn.factory_args["gap"], self._next)
        else:
            self.write(b"exit\n")
            reactor.callLater(2.0, self.loseConnection)

    def dataReceived(self, data):
        RESULT["output_bytes"] += len(data)

    def _fail(self, f):
        RESULT["error"] = str(f.value)
        self.loseConnection()

    def closed(self):
        self.conn.transport.loseConnection()


class Conn(connection.SSHConnection):
    def serviceStarted(self):
        RESULT["authenticated"] = True
        self.openChannel(Session(conn=self))


class Auth(userauth.SSHUserAuthClient):
    def __init__(self, user, password, conn):
        super().__init__(user.encode(), conn)
        self._password = password

    def getPassword(self, prompt=None):
        if getattr(self, "_used", False):
            return None
        self._used = True
        return defer.succeed(self._password.encode())

    def getPublicKey(self):
        return None


class Client(transport.SSHClientTransport):
    def connectionMade(self):
        RESULT["connected"] = True
        RESULT["client_local"] = "%s:%d" % (self.transport.getHost().host, self.transport.getHost().port)
        super().connectionMade()

    def verifyHostKey(self, pub, fp):
        RESULT["host_key_fingerprint"] = fp.decode() if isinstance(fp, bytes) else str(fp)
        return defer.succeed(True)          # lab honeypot: host key intentionally not pinned

    def connectionSecure(self):
        c = Conn()
        c.factory_args = self.factory.args
        self.requestService(Auth(self.factory.args["user"], self.factory.args["password"], c))

    def connectionLost(self, reason):
        super().connectionLost(reason)
        if reactor.running:
            reactor.stop()


class Factory(protocol.ClientFactory):
    protocol = Client

    def __init__(self, args):
        self.args = args

    def clientConnectionFailed(self, connector, reason):
        RESULT["error"] = reason.getErrorMessage()
        reactor.stop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["banner", "shell"])
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--user", default="demo")
    ap.add_argument("--password", default="demo-pass")
    ap.add_argument("--line", action="append", default=[])
    ap.add_argument("--gap", type=float, default=1.5)
    a = ap.parse_args()
    RESULT["mode"], RESULT["started_unix"] = a.mode, time.time()
    try:
        if a.mode == "banner":
            banner(a.host, a.port)
        else:
            reactor.connectTCP(a.host, a.port, Factory({"user": a.user, "password": a.password, "lines": list(a.line), "gap": a.gap}), timeout=10)
            reactor.callLater(120, reactor.stop)
            reactor.run()
    except Exception as exc:                 # report, never retry
        RESULT["error"] = f"{type(exc).__name__}: {exc}"
    RESULT["finished_unix"] = time.time()
    print(json.dumps(RESULT))
    sys.exit(0 if not RESULT["error"] else 1)


if __name__ == "__main__":
    main()
