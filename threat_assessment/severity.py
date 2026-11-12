"""S0-S3 severity per finding: fixed per interpretation, with the approved credential-access refinement.

Severity is the potential impact of the ATTEMPTED action on a real host. It never reads the evidence level and never
assumes success.
"""
from typing import Dict, List, Tuple

ORDER = ("S0", "S1", "S2", "S3")

TABLE: Dict[str, Tuple[str, str]] = {
    "repeated authentication failures": ("S1", "guessing alone; the observed outcome is rejected logins"),
    "credential guessing followed by login": ("S2", "account accessed after guessing; honeypot acceptance is configured (emulator-dependent)"),
    "privilege-context reconnaissance attempt": ("S2", "enumerates sudo/SUID/root; preparation, not elevation"),
    "credential-material access attempt": ("S2", "refined per match: see credential_severity"),
    "download attempt": ("S2", "attempted retrieval of tooling; content and outcome unknown unless a file_download event exists"),
    "download-and-execute attempt": ("S3", "attempted execution of retrieved code"),
    "upload attempt": ("S3", "attempted transfer of data off the host (attempt; success only with a file_upload event)"),
    "archive-and-upload attempt": ("S3", "staging plus attempted transfer"),
    "history tampering attempt": ("S2", "anti-forensics; no direct impact"),
    "persistence modification attempt": ("S3", "would survive logout/reboot on a real host"),
    "network probing attempt": ("S2", "probing internal targets or scanning; preparation for lateral movement"),
}
# Secret-bearing final path components. Public keys, known_hosts and ssh config are not secrets.
SECRET_FILES = {"shadow", "gshadow", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys", ".bash_history"}
CONTENT_OPERATIONS = {"cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "strings", "vi", "vim", "nano", "view",
                      "cp", "scp", "tar", "base64", "xxd", "od", "dd"}
LOCATE_OPERATIONS = {"find"}


def _final(path: str) -> str:
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    return parts[-1] if parts else path


def _operation(command: str) -> str:
    tok = command.split()
    while tok and tok[0] == "sudo":
        tok = tok[1:]
    return tok[0].rsplit("/", 1)[-1] if tok else ""


def credential_severity(cred_matches: List[dict]):
    """S3 only if a CRED-1 match reads/copies a secret file, or locates one by name with find; otherwise S2."""
    basis = []
    for m in cred_matches:
        op, target, detail = _operation(m.get("command", "")), m.get("token", ""), m.get("detail", "")
        name = _final(target)
        if detail == "credential file path" and name in SECRET_FILES and op in CONTENT_OPERATIONS:
            basis.append(f"{op} {target}: content operation on secret file")
        elif detail == "find for credential file name" and name in SECRET_FILES and op in LOCATE_OPERATIONS:
            basis.append(f"find -name {target}: locating secret file")
    if basis:
        return "S3", "; ".join(sorted(set(basis)))
    ex = sorted({f"{_operation(m.get('command', ''))} {m.get('token', '')} ({m.get('detail', '')})" for m in cred_matches})
    return "S2", "no content/locate operation on a secret file: " + "; ".join(ex[:4])


def finding_severity(interpretation: dict, indicators_by_id: Dict[str, dict]):
    name = interpretation["name"]
    if name not in TABLE:
        raise KeyError(name)
    if name == "credential-material access attempt":
        return credential_severity(indicators_by_id.get("CRED-1", {}).get("matches", []))
    return TABLE[name]
