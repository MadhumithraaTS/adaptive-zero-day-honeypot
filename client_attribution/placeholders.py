"""Off-host trust configuration and production-readiness guard (Task 28A).

All D0-dependent values (repositories, administrators, replication credential, trust-anchor fingerprint) live in ONE
file, `configs/witness/offhost_pending.json`. While any of them is still a placeholder, every service refuses
PRODUCTION startup; only explicitly labelled TEST/LOCAL MOCK operation is possible. Placeholder URLs are never contacted.
"""
import json
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parents[1] / "configs" / "witness" / "offhost_pending.json"
SCHEMA = "offhost-trust-config-1"
PLACEHOLDER_MARKERS = ("PLACEHOLDER", "PENDING", "NOT_CONFIGURED")
D0_FIELDS = ("trust_anchor_repository", "witness_log_repository", "administrators", "replication_credential", "trust_anchor_fingerprint")
MOCK_LABEL = "TEST/LOCAL MOCK - not off-host, not production trust"


class ProductionNotReady(RuntimeError):
    pass


def load_offhost_config(path=None) -> dict:
    doc = json.loads(Path(path or DEFAULT_PATH).read_text(encoding="utf-8"))
    if doc.get("schema") != SCHEMA:
        raise ProductionNotReady(f"off-host config must have schema {SCHEMA!r}")
    for k in D0_FIELDS + ("parameters",):
        if k not in doc:
            raise ProductionNotReady(f"off-host config missing {k!r}")
    return doc


def _values(v):
    if isinstance(v, dict):
        for x in v.values():
            yield from _values(x)
    elif isinstance(v, (list, tuple)):
        for x in v:
            yield from _values(x)
    else:
        yield v


def placeholder_fields(cfg) -> list:
    return [k for k in D0_FIELDS if any(isinstance(x, str) and any(m in x.upper() for m in PLACEHOLDER_MARKERS) for x in _values(cfg[k]))]


def assert_production_ready(cfg):
    bad = placeholder_fields(cfg)
    if bad:
        raise ProductionNotReady(f"production startup refused: placeholder values remain in {bad} (D0 not resolved)")
    return True


def parameters(cfg) -> dict:
    return dict(cfg["parameters"])
