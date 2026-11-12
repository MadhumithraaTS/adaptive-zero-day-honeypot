"""Replicator (component 3). Holds ONLY the off-host append credential (C1). Never signs checkpoints or results and
cannot change trust anchors.

`run_once` reads new checkpoints from the witness store (read-only), verifies the chain before pushing, appends them to
the off-host witness log (fast-forward only), confirms the remote head, compares the local trust anchor with the
off-host trust-anchor repository, and writes an UNSIGNED, NON-AUTHORITATIVE status (D15). Authoritative delivery is
established only by the independent monitor (offhost_monitor.py).

Production remote: NOT IMPLEMENTED until D0 (the placeholder repository URL is never contacted). Only the
TEST/LOCAL MOCK repository in offhost_mock.py exists.
"""
from .checkpoints import verify_checkpoint_chain


class ReplicationError(RuntimeError):
    pass


class ProductionRemoteNotConfigured:
    """Stand-in for the real git remote. Refuses every operation while D0 is unresolved."""
    is_mock, production_trust, delivered_offhost = False, False, False

    def __init__(self, url, credential):
        self.url, self.credential = url, credential

    def _refuse(self, *a, **k):
        raise ReplicationError(f"off-host replication is not configured (D0 unresolved; {self.url!r} is a placeholder and is not contacted)")

    push = head = all_checkpoints = _refuse


class Replicator:
    def __init__(self, read_store, remote, anchor_repo, local_anchor_digest, witness_public_pem, witness_pin, log_id, clock):
        self.read_store, self.remote, self.anchor_repo, self.local_anchor = read_store, remote, anchor_repo, local_anchor_digest
        self.witness_pem, self.pin, self.log_id, self.clock = witness_public_pem, witness_pin, log_id, clock
        self.status = None                                        # last written status (diagnostic only)

    def run_once(self):
        now = self.clock()
        cps = self.read_store()
        v = verify_checkpoint_chain(cps, self.witness_pem, self.pin, self.log_id)
        if not v["ok"]:
            raise ReplicationError(f"refusing to push an invalid local chain: {v['reason']}")
        remote_seq, _ = self.remote.head()
        new = [c for c in cps if c["checkpoint_seq"] > remote_seq]
        if new:
            self.remote.push(new, now)                           # raises on failure: status is NOT advanced
        head_seq, head_hash = self.remote.head()
        try:
            anchor_match = self.anchor_repo.latest_digest() == self.local_anchor
        except Exception:                                        # noqa: BLE001 - unknown is treated as mismatch
            anchor_match = False
        self.status = {"remote_head_checkpoint_seq": head_seq, "remote_head_checkpoint_hash": head_hash,
                       "pushed_utc": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "anchor_match": anchor_match,
                       "mock": bool(getattr(self.remote, "is_mock", False)), "production_trust": False, "authoritative": False}
        return self.status

    def status_provider(self):
        return lambda: self.status
