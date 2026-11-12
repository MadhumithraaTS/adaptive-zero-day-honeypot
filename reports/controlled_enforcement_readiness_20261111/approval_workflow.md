# Human approval workflow (design)

## 1. Separation of roles

| Role | Holds | Can do | Cannot do |
|---|---|---|---|
| Assessment engine (`threat_assessment`) | No signing key | Write `propose` records to its audit log | Approve, sign or deploy anything |
| Approval tool (separate CLI, separate process and user) | Approver private keys (one per person) | Show proposals; record a signed approve/reject decision | Change proposals; deploy rules |
| Enforcement controller | Controller key (rule signing) | Turn a valid, approved, unexpired proposal into a signed rule; deploy and roll back | Approve; act on unapproved or expired proposals |
| Relay | Relay mapping key | Sign mappings; enforce valid rules | Create rules |

**The assessment engine never approves its own proposals.** It has no approver key. Its identity (`assessment@<host>`) is excluded from the approver registry, and the controller rejects any approval whose `key_id` is not in the registry.

## 2. Proposal record (created from an audit entry with `tier = propose`)

| Field | Source |
|---|---|
| `proposal_id` | `prop-<audit record_id>`; unique |
| `assessment_record_ref` | Audit `record_id` and `record_hash` |
| `session_ref`, `finding_refs` | Audit entry |
| `source_attribution` | State (`attributable_via_proxy_mapping`), `connection_id`, mapping `record_hash`, and mapping signature verification result |
| `findings` | Interpretation, severity, **interpretation-specific** evidence level, and outcome for each |
| `versions` | Assessment version; evidence catalogue; attribution config version and digest; policy version and digest; allowlist digest |
| `proposed_action` | Type, target, scope, TTL, inverse (from the policy) |
| `proposal_expires_utc` | Proposal time + 30 minutes. An unapproved proposal expires |

## 3. Approval decision (signed)

```json
{"approval_id": "appr-<uuid>", "proposal_id": "...", "proposal_hash": "<sha256 of the canonical proposal>",
 "audit_record_hash": "<record_hash of the propose entry>", "decision": "approve | reject",
 "approver": {"name": "...", "key_id": "..."}, "reason": "free text (required for reject)",
 "approved_action": {"target": "172.30.0.2/32", "ttl_seconds": 900}, "decided_utc": "...",
 "signature": "<Ed25519 over the canonical document without signature>"}
```

**Controller validation** (all required; otherwise reject and log `approval_invalid:<reason>`):
1. The signature verifies with a key in the **approver registry** (a versioned, digest-pinned file listing name, key ID, public key and validity dates).
2. `key_id` ≠ the assessment identity, and the approver is valid on `decided_utc`.
3. `proposal_hash` and `audit_record_hash` match the stored proposal and the verified audit chain.
4. `decided_utc` < `proposal_expires_utc`, and the decision is not in the future (skew budget).
5. `approved_action` equals the proposal's action, or is stricter (shorter TTL); never broader.
6. **No previous decision exists for this `proposal_id`.** A duplicate approval or a conflicting decision gives `approval_duplicate` and no action. A rejection is final.
7. The target is still inside the allowlist and outside protected networks, and configuration digests are unchanged since the proposal.

## 4. Audit-chain references

Every step appends a hash-chained entry to the controller audit log, referencing the previous step's hash:
- `proposal_created` → `approval_recorded` / `rejection_recorded` → `rule_signed` → `rule_deployed` → `rule_verified` → `rule_expired` / `rule_rolled_back`;
- or `deployment_failed` / `rollback_failed`.

The approval document's hash is stored in `approval_recorded`.

## 5. Optional hardening

- A two-person rule (two distinct approver keys) for any TTL above the demo value.
- Approver keys on hardware tokens.
