"""Independent off-host monitor (interface + verification logic). In production it runs under the administrators'
control (e.g. a scheduled workflow in the witness-log repository), NOT on this host. Here it is exercised only
against TEST/LOCAL MOCK repositories, and its result says so.

Checks (D15): actual repository state (fast-forward history), signed checkpoints (P3 signatures + hash chain),
freshness (newest checkpoint <= 20 min old), trust-anchor digest equals the current signed manifest, and any
fault/halt checkpoint. Any problem raises an alert to BOTH administrators.
"""
from .checkpoints import verify_checkpoint_chain
from .records import ts


def check_repository(repo, witness_public_pem, witness_pin, log_id, manifest_digest, now, freshness_seconds=1200):
    alerts = []
    hist = repo.history()
    for k in range(1, len(hist)):
        if hist[k]["parent"] != hist[k - 1]["commit_id"]:
            alerts.append("history is not fast-forward (rewritten)")
            break
    cps = [c for commit in hist for c in commit["checkpoints"]]
    v = verify_checkpoint_chain(cps, witness_public_pem, witness_pin, log_id)
    if not v["ok"]:
        alerts.append(f"checkpoint chain invalid: {v['reason']}")
    if not cps:
        alerts.append("no checkpoints delivered")
    else:
        age = (now - ts(cps[-1]["attested_utc"])).total_seconds()
        if age > freshness_seconds:
            alerts.append(f"stale: newest checkpoint is {age:.0f} s old (> {freshness_seconds} s)")
        bad_anchor = sorted({c["trust_anchor_digest"] for c in cps if c["trust_anchor_digest"] != manifest_digest})
        if bad_anchor:
            alerts.append(f"trust-anchor digest differs from the signed manifest: {bad_anchor}")
        for c in cps:
            if c["kind"] in ("fault", "halt"):
                alerts.append(f"{c['kind']} checkpoint {c['checkpoint_seq']}: {c['details'].get('cause')}")
    mock = bool(getattr(repo, "is_mock", False))
    return {"ok": not alerts, "alerts": alerts, "notify": ["ADMIN_A", "ADMIN_B"] if alerts else [], "checkpoints": len(cps),
            "mock": mock, "production_trust": False if mock else None,
            "label": "TEST/LOCAL MOCK monitor result - not production assurance" if mock else "monitor result"}
