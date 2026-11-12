"""Proposal intake: turn a threat-assessment `propose` output into a response proposal. Reads assessment outputs and
the assessment audit chain; never modifies either. Only sessions attributed through the relay by a VERIFIED signed
attribution result qualify (R4); anything else is refused."""
from datetime import timedelta

from threat_assessment.audit import verify_chain

from .common import ResponseError, iso, sha256_hex
from .config import REQUIRED_ATTRIBUTION
from .rules import validate_target

PROPOSAL_SCHEMA = "response-proposal-1"


class ProposalRejected(ResponseError):
    pass


def fingerprints(policy, att, defence_policy) -> dict:
    """Configuration and policy fingerprints covered by every approval."""
    return {"response_policy": policy.digest, "address_safety": att.address_safety_digest, "defence_policy": defence_policy.digest,
            "attribution_config": att.digest}


def build_proposal(assessment: dict, audit_entries, policy, att, defence_policy, now) -> dict:
    if att.schema != "threat-attribution-config-3" or defence_policy.schema_version != "2.1":
        raise ProposalRejected("only signed-attribution assessments (attribution config v3, policy 2.1) qualify")
    if att.address_safety_digest != policy.address_safety_digest:
        raise ProposalRejected("response policy and attribution config pin different address-safety configs")
    if assessment.get("tier") != "propose" or not assessment.get("gates") or not all(assessment["gates"].values()):
        raise ProposalRejected("assessment is not a 'propose' tier with all gates true")
    prop = assessment.get("proposed_action")
    if not prop or prop.get("manual_approval") != "pending" or prop.get("execution") != "not_executed" or prop.get("mode") != "dry_run":
        raise ProposalRejected("assessment carries no pending, unexecuted dry-run proposal")
    sa = assessment.get("session_attribution") or {}
    m = sa.get("mapping") or {}
    accepted = {a.get("result_id") for a in ((assessment.get("versions") or {}).get("attribution_results") or {}).get("accepted", [])}
    if sa.get("state") != REQUIRED_ATTRIBUTION or prop.get("subject_basis") != REQUIRED_ATTRIBUTION:
        raise ProposalRejected(f"source is not attributed through the relay ({sa.get('state')}); R4 forbids restriction")
    if not m.get("result_id") or m["result_id"] not in accepted or (assessment["versions"]["attribution_results"].get("rejected")):
        raise ProposalRejected("attribution is not backed by a verified signed attribution result")
    client = (m.get("client") or {}).get("ip")
    if not client or client != sa.get("subject") or client != prop.get("subject"):
        raise ProposalRejected("proposal subject does not equal the verified attributed client")
    if m.get("connection_id") != prop.get("relay_connection_id"):
        raise ProposalRejected("proposal relay connection does not match the verified mapping")
    v = verify_chain(list(audit_entries))
    if not v["ok"]:
        raise ProposalRejected(f"assessment audit chain does not verify: {v['reason']}")
    match = [e for e in audit_entries if e.get("session_ref") == assessment["session_ref"] and e.get("tier") == "propose"
             and e.get("proposed_action") == prop]
    if len(match) != 1:
        raise ProposalRejected(f"expected exactly one matching assessment audit entry, found {len(match)}")
    entry = match[0]
    target = validate_target(f"{client}/32", att)
    doc = {
        "schema": PROPOSAL_SCHEMA, "proposal_id": f"prop-{entry['record_id']}", "created_utc": iso(now),
        "expires_utc": iso(now + timedelta(seconds=policy.proposal_validity_seconds)), "session_ref": assessment["session_ref"],
        "assessment_audit": {"record_id": entry["record_id"], "record_hash": entry["record_hash"]},
        "attribution": {"state": sa["state"], "result_id": m["result_id"], "result_hash": m.get("result_hash"),
                        "connection_id": m.get("connection_id"), "client_ip": client},
        "source_proposal": dict(prop),
        "action": {"type": policy.action, "target": target, "listener": policy.listener,
                   "max_ttl_seconds": min(int(prop["ttl_seconds"]), policy.max_ttl_seconds)},
        "fingerprints": fingerprints(policy, att, defence_policy),
        "findings": [{"interpretation": f["interpretation"], "severity": f["severity"], "evidence_level": f["evidence_level"]}
                     for f in assessment.get("findings", [])],
    }
    doc["proposal_hash"] = sha256_hex(doc)
    return doc
