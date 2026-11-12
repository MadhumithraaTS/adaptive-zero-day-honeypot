# Audit, checkpoints and recovery (design)

## 1. Logs in scope

| Log | Writer | Chain |
|---|---|---|
| Assessment audit | `threat_assessment.AuditLog` (existing; append-only per run; verified by `verify_chain`) | SHA-256 chain |
| Relay mapping log | Attributing relay | SHA-256 chain + Ed25519 per record |
| Controller audit (proposal → approval → rule → verification → expiry or rollback) | Enforcement controller | SHA-256 chain + Ed25519 per record |
| Cowrie JSON log | Cowrie (unchanged) | Hashed into each checkpoint |

## 2. External signed checkpoints

- **Frequency:** after every assessment run, every controller decision, and at least hourly while the relay runs.
- **Contents:** log name, entry count, last `record_hash`, SHA-256 of the log file, previous checkpoint hash, UTC time.
- **Signature:** Ed25519 by a separate **checkpoint key**.
- **Storage:** outside the storage domain of the logs (a different disk, host or offline medium). Optionally a printed or out-of-band digest for the demo.
- **Verification:** `verify_chain(entries, checkpoint)`, already implemented, runs before every approval and every deployment, and on schedule. A mismatch freezes all approvals and deployments and is itself logged.

## 3. Key custody and retention

| Key | Holder | Never available to |
|---|---|---|
| Relay mapping key | Relay container (read-only Docker secret) | Assessment, controller, approvers |
| Approver keys | Named people (approval tool) | Assessment, controller, relay |
| Controller key | Enforcement controller | Assessment, approvers, relay (relay gets the public key) |
| Checkpoint key | Audit custodian | Every other component |

- Keys have recorded IDs and validity periods; rotation appends a signed key-change entry.
- On a single-host lab every key is on one machine: documented as a limitation, acceptable for a demonstration only.

**Retention:** Cowrie logs, mapping logs, assessment and controller audits, checkpoints, approver registry versions, configs (attribution, policy, allowlist) and rule files are kept together for at least the project's evaluation period. They are never edited; rotation creates new files, linked by checkpoint.

## 4. Tamper detection

Implemented today for the assessment log: modification, deletion, insertion, reordering, truncation (with checkpoint), hash recomputation, and a forged execution status (Task 24, 16/16 detected). The same `verify_chain` construction is reused for the mapping and controller logs, with signature verification added.

## 5. Recovery

| Situation | Procedure |
|---|---|
| Controller restart | Rebuild the desired state from the controller audit: approved, deployed, not expired, not rolled back. Read the relay's active rules. Remove any active rule without a matching chain of entries (`orphan_rule_removed`). Re-verify the rest. Log `reconciled` |
| Relay restart | Loads only signed, unexpired, allowlisted rules from the read-only volume; logs `rule_loaded` for each; the controller reconciles |
| Host crash | All rules have absolute expiry, so they lapse by TTL even if nothing restarts. After restart: verify chains and checkpoints, then reconcile. Expired rules are logged as `rule_expired` with the observation time |
| Audit verification failure | Freeze: no new approvals or deployments; existing rules are left to expire (no extension); escalate |
| Rollback verification failure | Retry once; then `rollback_failed`; rely on TTL; manual relay restart as a last resort (clears in-memory rules) |

**Expired restrictions:**
- The relay ignores expired rules (fail-open).
- The controller logs `rule_expired`, then verifies the target can connect again (`expiry_verified`).
- An expired rule is never renewed automatically; renewal needs a new proposal and approval.
