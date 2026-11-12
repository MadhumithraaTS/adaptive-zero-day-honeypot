"""Attributing TCP relay for the Cowrie lab (Task 26A). Runs inside the hardened relay container (Twisted + cryptography).

    /cowrie/cowrie-env/bin/python3 attributing_relay.py --config relay_config.json

Behaviour per explicitly bound listener (never 0.0.0.0):
  accept -> check the accepted socket's LOCAL address equals the listener bind (weak-host-model guard) -> connect to the
  backend -> write a signed, hash-chained `connection_open` record with the client peer (getpeername of the accepted
  socket) and the relay->Cowrie upstream local tuple (getsockname of the upstream socket) -> copy bytes both ways ->
  write a signed `connection_close` record. Rejections are recorded as `connection_rejected`.
Identity comes only from the accepted socket; client bytes are never parsed. No enforcement is implemented here.
Records: canonical JSON (sorted keys, no whitespace) without `record_hash`/`signature` -> SHA-256 = record_hash;
signature = Ed25519 over the ASCII record_hash. The log is append-only and fsync'd per record.
"""
import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from twisted.internet import protocol, reactor
from twisted.python import log

RECORD_SCHEMA = "relay-mapping-record-1"
GENESIS = "0" * 64


def utc_now():
    return datetime.fromtimestamp(time.time(), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class RecordLog:
    def __init__(self, path, key, key_id):
        self.path, self.key, self.key_id = path, key, key_id
        self.seq, self.prev = 0, GENESIS
        if os.path.exists(path):                       # continue an existing chain (append-only)
            with open(path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        r = json.loads(line)
                        self.seq, self.prev = r["seq"], r["record_hash"]
        self.fh = open(path, "a", encoding="utf-8", newline="\n")

    def write(self, rtype, **fields):
        self.seq += 1
        rec = {"schema": RECORD_SCHEMA, "seq": self.seq, "prev_hash": self.prev, "record_type": rtype,
               "written_utc": utc_now(), "key_id": self.key_id, **fields}
        h = hashlib.sha256(canonical(rec).encode("utf-8")).hexdigest()
        rec["record_hash"] = h
        rec["signature"] = self.key.sign(h.encode("ascii")).hex()
        self.fh.write(canonical(rec) + "\n")
        self.fh.flush()
        os.fsync(self.fh.fileno())
        self.prev = h
        return rec


class Upstream(protocol.Protocol):
    def connectionMade(self):
        s = self.factory.server
        u_local, u_peer = self.transport.getHost(), self.transport.getPeer()
        if s.lost:                                        # client left before the upstream connected: no mapping is written
            s.factory_ctx.records.write("connection_rejected", connection_id=s.cid, listener=s.listener["name"],
                                        client_ip=s.peer.host, client_port=s.peer.port, accepted_utc=s.accepted_utc,
                                        reason=f"client_closed_before_upstream (upstream {u_local.host}:{u_local.port})")
            self.transport.loseConnection()
            return
        s.upstream = self
        s.upstream_local = (u_local.host, u_local.port)
        s.factory_ctx.records.write(
            "connection_open", connection_id=s.cid, listener=s.listener["name"], listener_mode=s.listener["mode"],
            ingress_listener=f"{s.listener['bind']}:{s.listener['port']}", client_ip=s.peer.host, client_port=s.peer.port,
            accepted_local=f"{s.local.host}:{s.local.port}", accepted_utc=s.accepted_utc,
            upstream_local_ip=u_local.host, upstream_local_port=u_local.port,
            upstream_peer=f"{u_peer.host}:{u_peer.port}", upstream_connected_utc=utc_now())
        s.transport.resumeProducing()
        if s.buffer:
            self.transport.write(b"".join(s.buffer))
            s.buffer = []

    def dataReceived(self, data):
        self.factory.server.bytes_out += len(data)
        self.factory.server.transport.write(data)

    def connectionLost(self, reason):
        self.factory.server.transport.loseConnection()


class UpstreamFactory(protocol.ClientFactory):
    protocol = Upstream

    def __init__(self, server):
        self.server = server

    def clientConnectionFailed(self, connector, reason):
        s = self.server
        s.factory_ctx.records.write("connection_rejected", connection_id=s.cid, listener=s.listener["name"],
                                    client_ip=s.peer.host, client_port=s.peer.port, accepted_utc=s.accepted_utc,
                                    reason=f"upstream_connect_failed: {reason.getErrorMessage()}")
        s.rejected = True
        s.transport.loseConnection()


class Server(protocol.Protocol):
    def connectionMade(self):
        self.cid, self.accepted_utc = str(uuid.uuid4()), utc_now()
        self.peer, self.local = self.transport.getPeer(), self.transport.getHost()
        self.listener, self.upstream, self.upstream_local = self.factory.listener, None, None
        self.buffer, self.bytes_in, self.bytes_out, self.rejected, self.closed, self.lost = [], 0, 0, False, False, False
        self.factory_ctx = self.factory
        if self.local.host != self.listener["bind"]:      # weak-host guard: accepted on an address other than the listener's
            self.factory.records.write("connection_rejected", connection_id=self.cid, listener=self.listener["name"],
                                       client_ip=self.peer.host, client_port=self.peer.port, accepted_utc=self.accepted_utc,
                                       reason=f"local_address_mismatch: {self.local.host} != {self.listener['bind']}")
            self.rejected = True
            self.transport.abortConnection()
            return
        self.transport.pauseProducing()
        reactor.connectTCP(self.factory.backend_host, self.factory.backend_port, UpstreamFactory(self), timeout=10)

    def dataReceived(self, data):
        self.bytes_in += len(data)
        if self.upstream:
            self.upstream.transport.write(data)
        else:
            self.buffer.append(data)

    def connectionLost(self, reason):
        self.lost = True
        if self.upstream:
            self.upstream.transport.loseConnection()
        if not self.rejected and not self.closed and self.upstream_local:
            self.closed = True
            self.factory.records.write("connection_close", connection_id=self.cid, listener=self.listener["name"],
                                       client_ip=self.peer.host, client_port=self.peer.port,
                                       upstream_local_ip=self.upstream_local[0], upstream_local_port=self.upstream_local[1],
                                       closed_utc=utc_now(), bytes_in=self.bytes_in, bytes_out=self.bytes_out)


class ListenerFactory(protocol.Factory):
    protocol = Server

    def __init__(self, listener, backend_host, backend_port, records):
        self.listener, self.backend_host, self.backend_port, self.records = listener, backend_host, backend_port, records


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    a = ap.parse_args(argv)
    cfg = json.load(open(a.config, encoding="utf-8"))
    if cfg.get("schema") != "attributing-relay-config-1":
        sys.exit("unsupported relay config schema")
    for lst in cfg["listeners"]:
        if lst["bind"] in ("0.0.0.0", "::", ""):
            sys.exit(f"listener {lst['name']}: wildcard binds are not allowed")
    key = serialization.load_pem_private_key(open(cfg["signing_key_path"], "rb").read(), password=None)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = hashlib.sha256(pub).hexdigest()[:16]
    records = RecordLog(cfg["record_log_path"], key, key_id)
    log.startLogging(sys.stdout)
    records.write("relay_start", config_sha256=hashlib.sha256(open(a.config, "rb").read()).hexdigest(),
                  listeners=[{k: l[k] for k in ("name", "mode", "bind", "port")} for l in cfg["listeners"]],
                  backend=f"{cfg['backend_host']}:{cfg['backend_port']}", public_key_sha256=hashlib.sha256(pub).hexdigest())
    for lst in cfg["listeners"]:
        reactor.listenTCP(int(lst["port"]), ListenerFactory(lst, cfg["backend_host"], int(cfg["backend_port"]), records),
                          interface=lst["bind"])
        log.msg(f"listener {lst['name']} ({lst['mode']}) on {lst['bind']}:{lst['port']} -> {cfg['backend_host']}:{cfg['backend_port']}")
    reactor.run()


if __name__ == "__main__":
    main()
