# Enforcement boundary for the first controlled demonstration (design)

## 1. Topology (proposed; nothing deployed)

```
dedicated test client container  --(demo_ingress, e.g. 172.30.0.0/29)-->  attributing relay :2222 (demo listener)
control client container         --(demo_ingress)----------------------^        |
                                                                                v (existing cowrie_internal, unchanged)
                                                                         cowrie-project 172.22.0.1:2222
```

- **`demo_ingress`** is a new `internal: true` Docker network with exactly three members:
  - the attributing relay;
  - the **test client** (`172.30.0.2`);
  - the **control client** (`172.30.0.3`).

  It has no internet access. The address plan must be confirmed against `docker network ls` at implementation time so it collides with no existing network.
- **Cowrie and `cowrie_internal` are not modified.** The relay already belongs to `cowrie_internal`.
- **The published `127.0.0.1:2223` path is not an enforcement target.** Its peer is not a client identity.

## 2. Boundary definition

| Item | Specification |
|---|---|
| **Enforcement point** | The attributing relay's accept handler on the **demo listener only**. A restricted peer's connection is closed immediately after accept, before any upstream connection to Cowrie. No host firewall, no Docker or iptables rule, no Cowrie change. This works with `cap_drop: ALL` |
| **Target identity** | One exact `/32`: the dedicated test client. It must come from a proposal whose attribution is `attributable_via_proxy_mapping` |
| **Hard safety allowlist** | `enforcement_target_allowlist = ["172.30.0.2/32"]`, configured separately from policy. The relay refuses any rule whose target is outside it (and outside `demo_ingress`), whatever the approval says. Protected networks (policy v2) are refused as well |
| **Rule scope** | New TCP connections from the target to the demo listener port. Existing sessions are not cut. The control client and every other path are unaffected |
| **Duration** | Demo TTL **15 minutes** (≤ the policy v2 maximum of 86,400 s). The relay ignores a rule after its `expires_utc`, so expiry is fail-open by design |
| **Rule format** | `{rule_id, proposal_id, approval_id, target, scope, created_utc, expires_utc, inverse: {type: remove_rule, rule_id}, signature, key_id}`, signed by the enforcement controller key and verified by the relay |
| **Delivery** | The controller writes signed rule files to a dedicated restriction volume, mounted **read-only** in the relay. The relay polls it (e.g. every 2 s) and validates signature, expiry, allowlist and protected networks. Invalid rules are ignored and logged |

## 3. Conditions for approval (all required)

1. Assessment tier `propose` with all 8 gates true (`threat_assessment`), and an attribution state of `attributable_via_proxy_mapping`.
2. Target ∈ `enforcement_target_allowlist` and not protected or shared.
3. A valid human approval (`approval_workflow.md`), not expired and not duplicated.
4. The audit chain and external checkpoint verify (`audit_and_recovery.md`).
5. Configuration digests match: attribution config v2, policy v2, and the restriction-allowlist config.

## 4. Verification after deployment

| Check | Pass condition |
|---|---|
| **State** | The relay logs `rule_loaded <rule_id>` with the rule's hash; the controller reads back the relay's active-rule list and its digest |
| **Positive** | A new connection from the test client is closed immediately, and the relay mapping log shows `restriction_check: rejected:<rule_id>` with no upstream connection, so no Cowrie `session.connect` exists for it |
| **Scope** | A connection from the control client succeeds and appears in Cowrie (exactly one correlated session). `127.0.0.1:2223` remains unaffected |
| **Audit** | `rule_deployed` and `rule_verified` entries are appended, hash-chained, and referencing the approval |

## 5. Inverse operation and rollback

- **Inverse:** delete the rule file; the relay unloads it at the next poll and logs `rule_unloaded <rule_id>`.
- **Rollback verification:**
  1. a new connection from the test client succeeds;
  2. the relay's active-rule list no longer contains the rule;
  3. a `rule_rolled_back` audit entry is appended.
- **Automatic rollback** triggers when:
  - post-deployment verification fails;
  - the control client is affected (scope breach);
  - the audit chain fails to verify;
  - the operator revokes.

## 6. Failure handling

| Failure | Handling |
|---|---|
| Rule file rejected by the relay (signature, expiry, allowlist) | No restriction; `rule_rejected` logged; proposal marked `deployment_failed`; no retry without new approval |
| Deployment verification fails | Immediate inverse; `deployment_failed` logged |
| Rollback fails (file cannot be removed) | TTL expiry still lifts the rule (fail-open). Escalate; a relay restart clears in-memory state; logged as `rollback_failed` until verified |
| Relay crashes | In-memory rules are lost; on restart the relay reloads only valid, unexpired, signed rules. The controller reconciles (`audit_and_recovery.md` §5) |
| Controller or host crash | Rules expire by TTL. On restart the controller reconciles desired vs actual from the audit log |
| Clock skew or wrong time | Rules carry absolute UTC expiry; the relay refuses rules with `created_utc` in the future beyond the skew budget |
