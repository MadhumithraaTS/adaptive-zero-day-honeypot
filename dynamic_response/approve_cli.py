"""Approver tool: runs on the HUMAN APPROVER's own device, never in the controller or assessment environment.

    python -m dynamic_response.approve_cli --proposal proposal.json --key approver_key.pem --name "<approver>" \
        --decision approve --ttl 600 --out approval.json

It signs the exact rule for one proposal (approval role P5). No production approver key exists; tests use in-memory
fixture keys. The controller only verifies the resulting document.
"""
import argparse
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .approval import APPROVAL_SCHEMA, approval_hash
from .common import iso


def build_approval(proposal, decision, approver_name, approver_key_id, decided, ttl_seconds=None, reason="", rule_created=None):
    doc = {"schema": APPROVAL_SCHEMA, "approval_id": f"appr-{uuid.uuid4()}", "proposal_id": proposal["proposal_id"],
           "proposal_hash": proposal["proposal_hash"], "decision": decision, "reason": reason,
           "approver": {"name": approver_name, "key_id": approver_key_id}, "decided_utc": iso(decided), "rule": None}
    if decision == "approve":
        ttl = ttl_seconds or proposal["action"]["max_ttl_seconds"]
        created = rule_created or decided
        a = proposal["action"]
        doc["rule"] = {"rule_id": f"rule-{uuid.uuid4()}", "action": a["type"], "target": a["target"], "listener": a["listener"],
                       "ttl_seconds": ttl, "created_utc": iso(created), "expires_utc": iso(created + timedelta(seconds=ttl)),
                       "fingerprints": dict(proposal["fingerprints"])}
    return doc


def sign_approval(doc, private_key):
    body = {k: v for k, v in doc.items() if k not in ("approval_hash", "signature")}
    body["approval_hash"] = approval_hash(body)
    body["signature"] = private_key.sign(body["approval_hash"].encode("ascii")).hex()
    return body


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--proposal", required=True)
    ap.add_argument("--key", required=True, help="approver's private key (on the approver's device only)")
    ap.add_argument("--name", required=True)
    ap.add_argument("--decision", choices=("approve", "reject"), required=True)
    ap.add_argument("--ttl", type=int)
    ap.add_argument("--reason", default="")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    proposal = json.loads(Path(a.proposal).read_text(encoding="utf-8"))
    key = serialization.load_pem_private_key(Path(a.key).read_bytes(), password=None)
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    doc = build_approval(proposal, a.decision, a.name, hashlib.sha256(raw).hexdigest()[:16], datetime.now(timezone.utc), a.ttl, a.reason)
    Path(a.out).write_text(json.dumps(sign_approval(doc, key), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
