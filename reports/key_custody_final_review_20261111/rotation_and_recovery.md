# Rotation, revocation, compromise response and backup recovery

## Rotation

| Key | Cadence (proposed) | Procedure |
|---|---|---|
| P1 relay | at expiry of the configured window (2026-12-11) or on compromise | <ol><li>Generate the new key in a one-shot container into a named volume (this also completes the B1 move off NTFS).</li><li>New attribution config version: `proxy_client_mapping.public_key_sha256` = the new key, plus a `previous_keys` list of `{sha256, not_after}` for verifying history.</li><li>Restart **only** the relay with the new mount. Its signed `relay_start` announces the new key.</li><li>Records from before the switch keep verifying with the old pin through the history list.</li></ol>A `key_rollover` record signed by the old key would make the hand-over explicit. That is a code change, not implemented |
| P2 attribution result | 30 days | <ol><li>New key; new config/policy version pinning it.</li><li>Results signed by the old key verify only during their own validity, at most 1 h, so no overlap list is needed.</li></ol> |
| P3 witness | 30 days | <ol><li>New key; the new config pins **both** keys for the overlap period.</li><li>The first checkpoint under the new key must re-attest the head already attested by the old key.</li></ol> |

Every rotation is a new config and policy version. Old files stay unchanged for historical verification. The pin change is visible as a different `attribution_config_digest` and `policy_digest` in every assessment and audit entry.

## Revocation
- A config version lists revoked keys as `{sha256, revoked_at, reason}`. This is a new field and needs a small loader change.
- The verifiers then reject anything signed by a revoked key at or after `revoked_at`.
- Until that field exists, revocation = re-pin to a new key. Results and records signed by the old key then fail the pin.

## Compromise response

| Compromised | Immediately | Trust decisions | Recovery |
|---|---|---|---|
| P1 relay key | Stop the relay (attribution stops; it fails closed) | Relay records after the last witness checkpoint before the compromise are untrusted. Earlier ones stay trusted only if covered by a checkpoint that was stored off-host | Rotate P1; review every proposal whose `relay_connection_id` falls after that checkpoint |
| P2 result key | Switch the assessment to v3.0.0 / 2.2.0 (pending → nothing attributable) | All results signed by P2 since the compromise are untrusted; results are short-lived (≤ 1 h) | Rotate P2; re-issue results only for sessions whose relay records are still within the age limit |
| P3 witness key | Stop `log-witness` | Checkpoints after the compromise are untrusted, so tail-deletion protection is lost back to the last off-host copy | Rotate P3; re-attest from the off-host copy |
| Host account / Docker administrator | Treat P1–P3 as compromised | Everything not anchored off-host is untrusted | Rebuild; see `residual_risks.md` |

Every incident and every key change is recorded in the assessment audit chain (Task 24 `AuditLog`). Pending proposals made under a compromised key are withdrawn, never approved.

## Backup and recovery
- **Private keys (P1–P3): not backed up, deliberately.**
  - Loss is handled by rotation.
  - A Docker Desktop reset (volumes lost) or a deleted file means: rotate, re-pin, and continue. Past evidence stays verifiable with the retained public keys.
  - The reviewer found no copy of P1 outside `secrets/`. The Task 26A, 26B and 26C backups contain no attribution private key.
- **Backed up:**
  - public keys (current and previous);
  - every config and policy version;
  - relay record logs;
  - checkpoint stores, with an off-host copy;
  - signed results;
  - assessment audit logs and checkpoints.

  They are needed to verify history and must be stored where the host account cannot silently alter them, i.e. off-host.
- **Restoring configs:** after a restore, the pinned digests must match the policy and the recorded assessment `versions`. A mismatch means the restored set is not the approved one.
