"""Append-only, hash-chained audit log of assessment decisions. Records proposals and their inverse; executes nothing.

Each entry's `record_hash` is SHA-256 over the canonical JSON of the entry without `record_hash`; `previous_hash` links to
the prior entry (genesis = 64 zeros). verify_chain() detects modification, deletion, insertion and reordering.
A checkpoint (count + last hash) must be stored outside the log (see report limitations) to detect tail truncation.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

GENESIS = "0" * 64
AUDIT_SCHEMA = "threat-audit-1"


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(entry: dict) -> str:
    return hashlib.sha256(_canon({k: v for k, v in entry.items() if k != "record_hash"}).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, run_id: str, path: Optional[Path] = None, clock: Callable[[], str] = None, previous_hash: str = GENESIS):
        self.run_id, self.path = run_id, Path(path) if path else None
        self.clock = clock or (lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
        self.entries: List[dict] = []
        self._prev = previous_hash
        if self.path and self.path.exists():
            raise FileExistsError(f"{self.path} exists; audit logs are append-only per run and are never overwritten")

    def append(self, assessment: dict) -> dict:
        prop = assessment.get("proposed_action")
        e = {
            "schema": AUDIT_SCHEMA, "record_id": f"{self.run_id}-{len(self.entries) + 1:06d}", "sequence": len(self.entries) + 1,
            "previous_hash": self._prev, "timestamp": self.clock(),
            "session_ref": assessment["session_ref"], "finding_refs": [f["finding_id"] for f in assessment["findings"]],
            "source": assessment["src_ip"], "attribution": assessment["session_attribution"].get("state"),
            "finding_attribution": sorted({f["attribution"]["state"] for f in assessment["findings"]}),
            "evidence_and_severity": [{"finding_id": f["finding_id"], "interpretation": f["interpretation"], "evidence_level": f["evidence_level"],
                                       "severity": f["severity"], "outcome": f["outcome"]} for f in assessment["findings"]],
            "versions": assessment["versions"], "tier": assessment["tier"], "tier_reason": assessment["tier_reason"], "gates": assessment["gates"],
            "proposed_action": prop,
            "manual_approval_status": "pending" if prop else "not_applicable",
            "inverse_operation": prop["inverse"] if prop else None,
            "execution_status": "not_executed",
            "verification_status": "not_applicable",
            "rollback_status": "available_not_needed" if prop else "not_applicable",
        }
        e["record_hash"] = entry_hash(e)
        self._prev = e["record_hash"]
        self.entries.append(e)
        if self.path:
            with self.path.open("a", encoding="utf-8", newline="\n") as f:
                f.write(_canon(e) + "\n")
        return e

    def checkpoint(self) -> dict:
        return {"run_id": self.run_id, "entries": len(self.entries), "last_hash": self._prev}


def verify_chain(entries: List[dict], checkpoint: Optional[dict] = None, genesis: str = GENESIS) -> dict:
    prev = genesis
    for k, e in enumerate(entries):
        if e.get("previous_hash") != prev:
            return {"ok": False, "index": k, "reason": "previous_hash does not link (deletion, insertion or reordering)"}
        if e.get("record_hash") != entry_hash(e):
            return {"ok": False, "index": k, "reason": "record_hash mismatch (entry modified)"}
        if e.get("sequence") != k + 1:
            return {"ok": False, "index": k, "reason": "sequence gap"}
        if e.get("execution_status") != "not_executed":
            return {"ok": False, "index": k, "reason": "execution recorded although enforcement is disabled"}
        prev = e["record_hash"]
    if checkpoint is not None and (checkpoint.get("entries") != len(entries) or checkpoint.get("last_hash") != prev):
        return {"ok": False, "index": len(entries), "reason": "checkpoint mismatch (truncation or extension)"}
    return {"ok": True, "index": None, "reason": "chain intact", "entries": len(entries), "last_hash": prev}


def read_log(path) -> List[dict]:
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]
