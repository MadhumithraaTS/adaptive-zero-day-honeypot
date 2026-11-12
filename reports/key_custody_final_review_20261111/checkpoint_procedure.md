# Checkpoint signing and independent storage (procedure; not deployed)

## Decision recommended: a separate witness key and component
Task 26C validation signed checkpoints with the attribution-result key. For deployment, the review recommends a **separate checkpoint witness key (P3)** in a separate **`log-witness`** component:
- A compromise of the attribution signer must not also let the attacker re-issue history attestations. Separating the keys keeps the two failure domains apart.
- The witness needs only read access to the relay log. It needs no Cowrie log, no attribution output and no network.

## Components and storage

| Item | Location | Writable by | Readable by |
|---|---|---|---|
| P3 private key | named volume `cowrie_checkpoint_witness_key` (file 0400, uid 999, directory 0500) | nobody after generation (mounted read-only) | `log-witness` only |
| Checkpoint store | named volume `cowrie_checkpoint_store`, append-only JSONL `relay_log_checkpoints.jsonl` | `log-witness` only | attribution signer (read-only); operator export |
| Off-host copy | exported checkpoint file sent outside this machine (e.g. emailed, or committed to a separate repository the operator does not control) after each interval | — | auditors |
| P3 public key | `cowrie/attribution_keys/public/checkpoint_witness_ed25519.pub.pem`, pinned in the next attribution config | operator (pin change = new config version) | correlator |

`log-witness` service, profile `witness`:
- **Hardening:** the same as the other services: pinned image, cap_drop ALL, no-new-privileges, read-only root, `network_mode: none`, uid 999.
- **Mounts:** relay records (read-only), the P3 key volume (read-only), the checkpoint store (read-write).
- **Never mounted:** the relay key, Cowrie volumes, assessment code and the Docker socket.

## Procedure
1. **Interval.** Every 5 minutes, and when signalled by the attribution signer before it issues a result, `log-witness`:
   - verifies the relay log with the pinned relay public key (`verify_records`);
   - requires `ok` (no rejected lines, gaps or divergence from its own last checkpoint). If the log is not intact, it writes **no** checkpoint and records a fault entry;
   - writes `relay-log-checkpoint-1` `{log_id, seq, record_hash, record_written_utc, attested_utc}` signed with P3 (`make_checkpoint`);
   - appends it to the store. Each checkpoint must extend the previous one: same hash at the previous `seq`, and a higher `seq` or the same head.
2. **Consumers** (attribution signer and correlator) load all checkpoints, run `verify_checkpoints` with the pinned P3 key, and pass them to `verify_records`. Outcomes:
   - divergence → the log is untrusted;
   - log shorter than the newest checkpoint → `tail_incomplete`, and affected sessions get `log_gap`;
   - records after the newest checkpoint → `unattested_after_checkpoint`.
3. **Liveness.** If the newest checkpoint is older than 2 intervals, the attribution signer must refuse to issue results (proposed fail-closed rule; it needs a small code change in the signer, not implemented).
4. **Signed results** carry the checkpoint status (`relay_log.checkpoints`, `tail`), so the assessment record shows what was attested.

## What checkpoints do and do not guarantee
- **Detected:** deletion or rewrite of records up to the newest checkpoint, provided the checkpoint store is intact.
- **Not detected:**
  - deletion of records written after the newest checkpoint;
  - deletion of the checkpoint store and log together by someone with host or Docker access, unless the off-host copy exists.

Without an independently stored (off-host) checkpoint, **complete deletion detection is not claimed**.
