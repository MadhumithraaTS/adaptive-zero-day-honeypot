"""Input telemetry schema: required fields per Cowrie event type. Missing fields raise; nothing is inferred."""
from .errors import SchemaError

SUPPORTED_TELEMETRY_SCHEMAS = ("cowrie-json-2.9",)
REQUIRED_ALL = ("eventid", "timestamp", "session")
REQUIRED_BY_EVENT = {
    "cowrie.session.connect": ("src_ip",),
    "cowrie.login.failed": ("username", "password"),
    "cowrie.login.success": ("username", "password"),
    "cowrie.command.input": ("input",),
    "cowrie.command.failed": ("input",),
    "cowrie.session.closed": ("duration",),
    "cowrie.session.file_download": (),
    "cowrie.session.file_upload": (),
}
KNOWN_EVENTS = frozenset(REQUIRED_BY_EVENT) | {
    "cowrie.client.version", "cowrie.client.kex", "cowrie.client.size", "cowrie.client.var", "cowrie.session.params",
    "cowrie.log.closed", "cowrie.direct-tcpip.request", "cowrie.direct-tcpip.data", "cowrie.session.file_download.failed",
    "cowrie.client.fingerprint"}
SOURCE_DEPENDENT_EVENTS = ("cowrie.login.failed", "cowrie.login.success")


def check_schema_version(declared):
    if declared not in SUPPORTED_TELEMETRY_SCHEMAS:
        raise SchemaError(f"unsupported telemetry schema {declared!r}; supported {SUPPORTED_TELEMETRY_SCHEMAS}")


def validate_event(e, position):
    if not isinstance(e, dict):
        raise SchemaError(f"event {position}: not a JSON object")
    missing = [k for k in REQUIRED_ALL if k not in e or e[k] in (None, "")]
    missing += [k for k in REQUIRED_BY_EVENT.get(e.get("eventid"), ()) if k not in e]
    if missing:
        raise SchemaError(f"event {position} ({e.get('eventid')}): missing required field(s) {missing}")
    if "ackdat" in e or "ct_src_ltm" in e:
        raise SchemaError(f"event {position}: V1 feature fields are not Cowrie telemetry")
