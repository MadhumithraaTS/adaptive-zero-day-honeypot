"""TEST/LOCAL MOCK off-host infrastructure. NOT off-host, NOT production trust.

Stand-ins for the independently administered GitHub repositories, the two administrators and their signatures, used
only for development and tests until D0 is resolved. Every object carries `is_mock = True`,
`production_trust = False` and `delivered_offhost = False`, and the label below. Nothing here touches the network.
"""
import hashlib
import uuid

from cryptography.hazmat.primitives import serialization

from .placeholders import MOCK_LABEL
from .records import canonical
from .trust_root import SIG_SCHEME, doc_digest


class MockRejected(RuntimeError):
    pass


class _Mock:
    is_mock, production_trust, delivered_offhost, label = True, False, False, MOCK_LABEL


class MockWitnessLogRepository(_Mock):
    """Simulated private witness-log repository with ruleset: fast-forward only, no deletion, no force push."""

    def __init__(self):
        self._commits = []
        self.offline = False                                      # failure injection

    def head(self):
        if self.offline:
            raise MockRejected("mock remote unreachable")
        cps = [c for commit in self._commits for c in commit["checkpoints"]]
        return (cps[-1]["checkpoint_seq"], cps[-1]["checkpoint_hash"]) if cps else (0, None)

    def push(self, checkpoints, now, parent=None):
        if self.offline:
            raise MockRejected("mock remote unreachable")
        head = self._commits[-1]["commit_id"] if self._commits else None
        if parent is not None and parent != head:
            raise MockRejected("non-fast-forward push rejected by ruleset")
        commit = {"commit_id": hashlib.sha256((str(head) + canonical(checkpoints)).encode()).hexdigest(), "parent": head,
                  "checkpoints": [dict(c) for c in checkpoints], "pushed_utc": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")}
        self._commits.append(commit)
        return commit

    def force_push(self, commits):
        raise MockRejected("force push rejected by ruleset (bypass: administrators only)")

    def delete(self):
        raise MockRejected("deletion rejected by ruleset")

    def history(self):
        return [dict(c, checkpoints=[dict(x) for x in c["checkpoints"]]) for c in self._commits]

    # --- tamper hooks: simulate compromise of the hosting side, for monitor tests only
    def _tamper_rewrite(self, commits):
        self._commits = commits


class MockTrustAnchorRepository(_Mock):
    """Simulated administrator-only trust-anchor repository. Local components can read, never publish."""

    def __init__(self):
        self._manifests = []

    def publish(self, manifest, by):
        if not isinstance(by, MockAdministrator):
            raise MockRejected("only an administrator may publish to the trust-anchor repository")
        self._manifests.append(manifest)

    def latest(self):
        return self._manifests[-1] if self._manifests else None

    def latest_digest(self):
        m = self.latest()
        return doc_digest(m) if m else None


class MockAdministrator(_Mock):
    """Simulated independent administrator (A or B). In production the key never exists on this host."""

    def __init__(self, admin_id, private_key):
        self.admin_id, self._key = admin_id, private_key
        pub = private_key.public_key()
        self.public_key_pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        self.public_key_sha256 = hashlib.sha256(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()

    def entry(self):
        return {"name": f"TEST/LOCAL MOCK ADMINISTRATOR {self.admin_id}", "public_key_sha256": self.public_key_sha256,
                "public_key_pem": self.public_key_pem}

    def sign(self, doc):
        return {"admin": self.admin_id, "scheme": SIG_SCHEME, "key_sha256": self.public_key_sha256,
                "signature": self._key.sign(doc_digest(doc).encode("ascii")).hex()}


def signed(doc, *admins):
    d = {k: v for k, v in doc.items() if k != "signatures"}
    d["signatures"] = [a.sign(d) for a in admins]
    return d


def new_id():
    return str(uuid.uuid4())
