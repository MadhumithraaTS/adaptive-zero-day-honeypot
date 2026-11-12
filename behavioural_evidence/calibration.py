"""Sensor calibration (kept separate from behavioural matching): emulator slow-command list and timing reference.

Calibration produces caveats only (ART-1, TIME-0 'unusual'). It is derived from sensor benchmarks or a reference
(training) period, never from evaluation or attacker-label data.
"""
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Tuple

from .errors import CatalogueError

CALIBRATION_SCHEMA = "sensor-calibration-1"


@dataclass(frozen=True)
class SensorCalibration:
    sensor: str
    version: str
    slow_commands: Tuple[str, ...] = ()            # exact recorded lines measured >= slow_threshold_s on this sensor
    slow_threshold_s: float = 5.0
    inter_input_gap_reference_p99_s: Optional[float] = None   # for the TIME-0 'unusual timing' caveat
    source: str = ""
    extra: dict = field(default_factory=dict)

    def digest(self):
        doc = {"sensor": self.sensor, "version": self.version, "slow_commands": list(self.slow_commands),
               "slow_threshold_s": self.slow_threshold_s, "inter_input_gap_reference_p99_s": self.inter_input_gap_reference_p99_s}
        return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()[:16]

    def is_slow(self, line: str) -> bool:
        return line.strip() in self.slow_commands


def load_calibration(path) -> SensorCalibration:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if doc.get("schema") != CALIBRATION_SCHEMA:
        raise CatalogueError(f"calibration {path}: schema {doc.get('schema')!r} is not {CALIBRATION_SCHEMA!r}")
    for k in ("sensor", "version", "slow_commands", "source"):
        if k not in doc:
            raise CatalogueError(f"calibration {path}: missing {k!r}")
    return SensorCalibration(sensor=doc["sensor"], version=doc["version"], slow_commands=tuple(doc["slow_commands"]),
                             slow_threshold_s=float(doc.get("slow_threshold_s", 5.0)),
                             inter_input_gap_reference_p99_s=doc.get("inter_input_gap_reference_p99_s"), source=doc["source"])
