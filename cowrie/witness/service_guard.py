"""Common startup guard for the witness, replicator and recovery entry points (Task 28A).

PRODUCTION mode is refused while any D0 value in configs/witness/offhost_pending.json is a placeholder, and - even
once D0 is resolved - until migration step M7 wires the production services (not implemented here).
MOCK mode must be requested explicitly and is labelled TEST/LOCAL MOCK everywhere; it never reports production trust
or off-host delivery and never contacts the placeholder URLs.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from client_attribution.placeholders import MOCK_LABEL, ProductionNotReady, assert_production_ready, load_offhost_config  # noqa: E402


def guard(component, mode, offhost_config=None):
    cfg = load_offhost_config(offhost_config)
    if mode == "production":
        try:
            assert_production_ready(cfg)
        except ProductionNotReady as exc:
            raise SystemExit(f"{component}: {exc}")
        raise SystemExit(f"{component}: production wiring is created only by approved migration step M7 (not run)")
    if mode != "mock":
        raise SystemExit(f"{component}: mode must be 'production' or 'mock'")
    print(f"{component}: {MOCK_LABEL}", file=sys.stderr)
    return cfg
