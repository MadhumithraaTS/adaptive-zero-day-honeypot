"""Command line: evaluate a Cowrie JSON log and write one evidence record per session (JSON Lines).

    python -m behavioural_evidence --input cowrie.json --output evidence.jsonl [--calibration cal.json]
        [--relay-source 172.22.0.2 ...] [--internal-host 192.0.2.5 ...] [--internal-network 10.0.0.0/8 ...]

No defence action is taken and no threat score is produced.
"""
import argparse
import json
from pathlib import Path

from .calibration import load_calibration
from .engine import EvidenceConfig, EvidenceEngine, read_jsonl
from .indicators import DEFAULT_INTERNAL_NETWORKS


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--calibration")
    p.add_argument("--relay-source", action="append", default=[])
    p.add_argument("--internal-host", action="append", default=[])
    p.add_argument("--internal-network", action="append", default=None)
    p.add_argument("--telemetry-schema", default="cowrie-json-2.9")
    a = p.parse_args(argv)
    cfg = EvidenceConfig(telemetry_schema=a.telemetry_schema, relay_sources=frozenset(a.relay_source),
                         internal_networks=tuple(a.internal_network) if a.internal_network else DEFAULT_INTERNAL_NETWORKS,
                         internal_hosts=tuple(a.internal_host), calibration=load_calibration(a.calibration) if a.calibration else None)
    result = EvidenceEngine(cfg).evaluate(read_jsonl(a.input))
    out = Path(a.output)
    with out.open("w", encoding="utf-8", newline="\n") as f:
        for r in result["sessions"]:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    meta = {k: v for k, v in result.items() if k != "sessions"}
    out.with_suffix(".meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
    print(f"{len(result['sessions'])} sessions -> {out}")


if __name__ == "__main__":
    main()
