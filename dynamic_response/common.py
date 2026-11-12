"""Shared helpers for dynamic_response: canonical JSON, hashing and UTC timestamps."""
import hashlib
import json
from datetime import datetime, timezone


class ResponseError(ValueError):
    """Base class for refused response operations (always recorded, never silently ignored)."""


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(obj) -> str:
    return hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def ts(value) -> datetime:
    if not isinstance(value, str):
        raise ResponseError(f"timestamp must be an ISO-8601 string, got {type(value).__name__}")
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ResponseError(f"invalid timestamp {value!r}") from exc
    if t.tzinfo is None:
        raise ResponseError(f"timestamp {value!r} has no timezone")
    return t


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
