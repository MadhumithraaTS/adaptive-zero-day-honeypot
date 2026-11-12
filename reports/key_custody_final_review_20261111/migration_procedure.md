# Migration procedure (proposed; nothing executed)

Goal: provision P2 (attribution-result key) and P3 (checkpoint witness key), and activate signed attribution, without weakening fail-closed behaviour. The relay key P1 stays in place (option B1).

## Preconditions (blocking; must be done and approved first)
1. **Fix K-1:** the config loader must reject a key pinned for more than one role. Today, attribution config v3 accepts the relay key (P1) pinned as the attribution-result key. The rule: relay, result, witness and (later) approval pins must all differ. Add a test.
2. **Fix K-2:** a corrupt result public key must raise `AssessmentConfigError`, not a raw `ValueError`. Today it still fails closed, but inconsistently.
3. **Preserve the scratch-only attack inputs** (`scratch_cleanup_review.md`) before any cleanup.
4. **Fix K-3 (separately approved):** restrict or remove the world-readable/writable copies of the Cowrie SSH host keys in `cowrie/backups/pre_isolation_20261110/`.
5. **Approve these decisions** explicitly:
   - separate P3 witness key (recommended) vs. reusing P2;
   - 30-day validity for P2/P3;
   - checkpoint interval;
   - off-host copy destination;
   - B1 for the relay key.

## Order of execution (each step verified before the next)

| Step | Action | Verification | Rollback |
|---|---|---|---|
| 0 | Snapshot: back up `cowrie/docker-compose.yml`, `configs/`, ACLs (`icacls /save`) and container IDs/start times; record SHA-256 sums | manifest written | — |
| 1 | Create named volumes `cowrie_attribution_result_key`, `cowrie_checkpoint_witness_key`, `cowrie_checkpoint_store`, `cowrie_attribution_output` | `docker volume inspect` | `docker volume rm` (empty volumes only) |
| 2 | **Generate P2** in a one-shot container (pinned image, `--network none`, `--read-only`, cap_drop ALL; mounts: P2 volume read-write and a public-export directory read-write, nothing else). Write the private key 0400, uid 999. Write **only** the public key to `cowrie/attribution_keys/public/`. Remove the container | Private key **not** on NTFS: search `cowrie/attribution_keys` for a PEM private header → none. Public SHA-256 recorded | Destroy the P2 volume (key never used); no config references it yet |
| 3 | **Generate P3**, same as step 2 | same | same |
| 4 | New configs, leaving every existing file unchanged: <ul><li>`threat_attribution_v3_1.json`: `attribution_result` provisioned with the P2 SHA-256, `public_key_path`, `key_validity`; new `checkpoint_witness` block with the P3 SHA-256</li><li>`defence_policy_v2_3.json`: pins the v3.1 digest and the unchanged address-safety digest</li></ul> | Configs load and cross-verify. Every pin differs from every other (K-1 rule). Test suite green | Delete the two new files (live config untouched) |
| 5 | Compose: add services `log-witness` (profile `witness`) and `attribution-signer` (profile `attribution`). The assessment service additionally mounts `cowrie/attribution_keys/public` and the attribution output volume, both read-only. **No change to Cowrie or relay services** | Additive diff only (as in 26C). Probes in each new container: P2 visible only in the signer, P3 only in the witness, neither in the assessment | Restore the step-0 compose backup |
| 6 | Dry run with v3.1 against existing captured data: witness → signer → isolated assessment | Same outcomes as the 26C validation. Every 26C attack rejected. Isolation `ok` in every container | Stop services; nothing live changed |
| 7 | **Activation:** run the signer and assessment with v3.1 / policy 2.3. This is the only step that makes relay sessions attributable. Requires explicit approval at that time | First real result verifies. Checkpoint chain consistent. Proposals stay dry-run with approval pending | Run the assessment with v3.0.0 / 2.2.0 again (result key pending → everything unattributed, fail-closed); stop the `attribution` and `witness` profiles |

**Notes:**
- The relay records captured on 2026-11-11T17:19Z exceed the 24 h `max_record_age_seconds` after 2026-11-12T17:19Z. After that point, step 6 needs a **new** controlled demo session (which needs separate approval) or a validation-only config with a longer age limit.
- Rollback at any step returns to today's state, where attribution is disabled and fail-closed. No step touches Cowrie, the relay process, P1, behavioural evidence or severity definitions.
- **Destroying a generated key** (rollback of steps 2–3 after any use) is irreversible. It is done only for a key that is unused or compromised, and must be recorded.
