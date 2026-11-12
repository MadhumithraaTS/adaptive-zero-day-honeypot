"""Response audit log (`response-audit-1`): separate from, and never touching, the threat-assessment audit log.

Append-only and hash-chained like threat_assessment.AuditLog. Each entry carries a unique `event_id`, a sequence number,
the previous hash, the state transition it performs and references to the documents it relies on. `verify_response_log`
detects modification, deletion, insertion, reordering, truncation (with a checkpoint), duplicate or replayed entries
and invalid state transitions (it re-runs the state machine)."""
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .common import canonical, sha256_hex
from .states import NON_STATE_EVENTS, TransitionError, next_state

AUDIT_SCHEMA = "response-audit-1"
GENESIS = "0" * 64


def entry_hash(entry: dict) -> str:
    return sha256_hex({k: v for k, v in entry.items() if k != "record_hash"})


class ResponseAuditLog:
    def __init__(self, path: Optional[Path] = None, clock: Callable[[], str] = None, id_factory: Callable[[], str] = None):
        self.path = Path(path) if path else None
        if self.path and self.path.exists():
            raise FileExistsError(f"{self.path} exists; response audit logs are never overwritten")
        self.clock = clock or (lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"))
        self.id_factory = id_factory or (lambda: str(uuid.uuid4()))
        self.entries: List[dict] = []
        self.state: Dict[str, Optional[str]] = {}
        self._prev = GENESIS

    def append(self, event: str, proposal_id: Optional[str], details: dict = None, refs: dict = None) -> dict:
        frm = self.state.get(proposal_id)
        to = next_state(frm, event)                       # raises TransitionError: nothing is written
        e = {"schema": AUDIT_SCHEMA, "sequence": len(self.entries) + 1, "event_id": self.id_factory(), "previous_hash": self._prev,
             "timestamp": self.clock(), "event": event, "proposal_id": proposal_id, "mode": "dry_run",
             "from_state": frm, "to_state": to, "details": details or {}, "refs": refs or {}}
        e["record_hash"] = entry_hash(e)
        self.entries.append(e)
        self._prev = e["record_hash"]
        if event not in NON_STATE_EVENTS:
            self.state[proposal_id] = to
        if self.path:
            with self.path.open("a", encoding="utf-8", newline="\n") as f:
                f.write(canonical(e) + "\n")
        return e

    def checkpoint(self) -> dict:
        return {"entries": len(self.entries), "last_hash": self._prev}


def verify_response_log(entries: List[dict], checkpoint: Optional[dict] = None) -> dict:
    prev, seen, state = GENESIS, set(), {}
    for k, e in enumerate(entries):
        if e.get("schema") != AUDIT_SCHEMA:
            return {"ok": False, "index": k, "reason": "unexpected schema"}
        if e.get("previous_hash") != prev:
            return {"ok": False, "index": k, "reason": "previous_hash does not link (deletion, insertion or reordering)"}
        if e.get("record_hash") != entry_hash(e):
            return {"ok": False, "index": k, "reason": "record_hash mismatch (entry modified)"}
        if e.get("sequence") != k + 1:
            return {"ok": False, "index": k, "reason": "sequence gap"}
        if e.get("event_id") in seen:
            return {"ok": False, "index": k, "reason": "duplicate event_id (replayed entry)"}
        if e.get("mode") != "dry_run":
            return {"ok": False, "index": k, "reason": "non-dry-run entry although enforcement is not implemented"}
        seen.add(e.get("event_id"))
        pid = e.get("proposal_id")
        try:
            to = next_state(state.get(pid), e.get("event"))
        except TransitionError as exc:
            return {"ok": False, "index": k, "reason": f"invalid state transition: {exc}"}
        if e.get("from_state") != state.get(pid) or e.get("to_state") != to:
            return {"ok": False, "index": k, "reason": "recorded transition does not match the state machine"}
        if e.get("event") not in NON_STATE_EVENTS:
            state[pid] = to
        prev = e["record_hash"]
    if checkpoint is not None and (checkpoint.get("entries") != len(entries) or checkpoint.get("last_hash") != prev):
        return {"ok": False, "index": len(entries), "reason": "checkpoint mismatch (truncation or extension)"}
    return {"ok": True, "index": None, "reason": "chain and transitions intact", "entries": len(entries), "last_hash": prev,
            "states": state}
