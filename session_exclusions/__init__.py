"""Programmatic exclusion of registered diagnostic/demo Cowrie sessions from dataset building, feature extraction and
evaluation preparation (Task 26C, F-7).

Data-preparation only: model behaviour and threat scoring never import this package. The authoritative list is
configs/session_exclusions_v2.json (v1 preserved unchanged; v2 keeps all v1 entries); it is validated (schema, ID format, no duplicates) and identified by its
canonical digest, which callers record next to their outputs.
"""
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

SCHEMA = "session-exclusions-1"
DEFAULT_PATH = Path(__file__).resolve().parents[1] / "configs" / "session_exclusions_v2.json"
_SID = re.compile(r"^[0-9a-f]{12}$")


class ExclusionConfigError(ValueError):
    pass


@dataclass(frozen=True)
class SessionExclusions:
    version: str
    digest: str
    ids: frozenset
    categories: Dict[str, str]

    def is_excluded(self, sid) -> bool:
        return sid in self.ids

    def filter_events(self, events: Iterable[dict]) -> Tuple[List[dict], Dict[str, int]]:
        """Drop every event whose `session` is excluded. Returns (kept_events, {session_id: events_dropped})."""
        kept, dropped = [], {}
        for e in events:
            sid = e.get("session") if isinstance(e, dict) else None
            if sid in self.ids:
                dropped[sid] = dropped.get(sid, 0) + 1
            else:
                kept.append(e)
        return kept, dropped

    def filter_sessions(self, sessions: Dict[str, object]) -> Tuple[Dict[str, object], List[str]]:
        """Drop excluded keys from a {session_id: ...} mapping. Returns (kept, dropped_ids)."""
        dropped = sorted(k for k in sessions if k in self.ids)
        return {k: v for k, v in sessions.items() if k not in self.ids}, dropped

    def assert_none(self, session_ids: Iterable[str], where: str = "input"):
        """Raise if any excluded session is present (guard for evaluation preparation)."""
        bad = sorted(set(session_ids) & self.ids)
        if bad:
            raise ExclusionConfigError(f"excluded session(s) present in {where}: {bad}")

    def summary(self) -> dict:
        return {"exclusions_version": self.version, "exclusions_digest": self.digest, "excluded_session_count": len(self.ids)}


def from_document(doc) -> SessionExclusions:
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise ExclusionConfigError(f"session exclusions must have schema {SCHEMA!r}")
    entries = doc.get("sessions")
    if not isinstance(entries, list) or not entries:
        raise ExclusionConfigError("sessions must be a non-empty list")
    ids, cats = [], {}
    for e in entries:
        sid = e.get("session_id") if isinstance(e, dict) else None
        if not isinstance(sid, str) or not _SID.match(sid):
            raise ExclusionConfigError(f"invalid Cowrie session id {sid!r}")
        if e.get("category") not in ("diagnostic", "demo"):
            raise ExclusionConfigError(f"{sid}: category must be diagnostic or demo")
        ids.append(sid)
        cats[sid] = e["category"]
    if len(ids) != len(set(ids)):
        raise ExclusionConfigError("duplicate session ids")
    digest = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
    return SessionExclusions(version=str(doc.get("config_version")), digest=digest, ids=frozenset(ids), categories=cats)


def load_exclusions(path=None) -> SessionExclusions:
    try:
        doc = json.loads(Path(path or DEFAULT_PATH).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExclusionConfigError(f"cannot read session exclusions: {exc}") from exc
    return from_document(doc)
