"""Entry point for the checkpoint witness (Task 28A). Refuses PRODUCTION while D0 placeholders remain (see service_guard).

    python cowrie/witness/witness_service.py --mode production   -> refused (placeholders / migration not run)
    python cowrie/witness/witness_service.py --mode mock         -> TEST/LOCAL MOCK only; the logic lives in client_attribution
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from service_guard import guard  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=("production", "mock"))
    ap.add_argument("--offhost-config")
    a = ap.parse_args(argv)
    guard("witness", a.mode, a.offhost_config)
    print("witness: TEST/LOCAL MOCK mode selected; no service is started from this entry point (use the mock test harness)")
    return 0


if __name__ == "__main__":
    main()
