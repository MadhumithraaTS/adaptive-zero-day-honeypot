# Record integrity

## Hash-chain validation (`client_attribution/records.py`, `verify_records`)
The verifier makes one pass over the whole log; any failure makes the whole log untrusted. For each non-empty line, in order:
1. It must be valid JSON with schema `relay-mapping-record-1`, and carry all required fields for its `record_type`. An unknown type fails.
2. `seq` must equal n+1. This catches deletion, insertion, reordering and replay anywhere except at the tail.
3. `prev_hash` must equal the previous `record_hash`. The first record links to 64 zeros.
4. The SHA-256 of the canonical JSON of the record, without `record_hash` and `signature`, must equal `record_hash`.

## Signature validation
5. `key_id` must equal the first 16 hex characters of the pinned public-key SHA-256.
6. The Ed25519 signature (hex) must verify over the ASCII `record_hash`, using the public key whose SHA-256 equals the pin. `correlate()` checks the supplied PEM against the pin before calling the verifier.
7. `written_utc` must fall inside the configured key validity.
8. A `relay_start` record must announce the pinned key.

The signature covers the hash and the hash covers every other field, so any change needs the private key.

## Rejection tests on the captured log (in-memory copies)

| Case | Verifies | Reason | Attributed sessions |
|---|---|---|---|
| unmodified | yes | chain and signatures verify | 4 |
| altered field (S4 `client_port`) | **no** | record_hash mismatch | 0 |
| altered `client_ip` with `record_hash` recomputed (attacker without key) | **no** | signature invalid | 0 |
| reordered (seq 8 ↔ 9) | **no** | sequence gap | 0 |
| duplicated record (seq 8 replayed mid-log) | **no** | sequence gap | 0 |
| duplicated record appended at end | **no** | sequence gap | 0 |
| record age > 24 h (evaluated +25 h) | yes (log) | per-session `mapping_expired` | 0 |
| record written after key validity end | **no** | outside key validity | 0 |
| **last 1 record deleted** | **yes** | — | 3 (S5 → `close_inconsistent`) |
| **last 2 records deleted** | **yes** | — | 3 (S5 → `mapping_missing`) |
| **last 4 records deleted** | **yes** | — | 2 (S4, S5 → `mapping_missing`) |
| **all after S4 close deleted** | **yes** | — | 3 |
| **all after `relay_start` deleted** | **yes** | — | 0 |

The 52 unit tests in `tests/test_client_attribution.py` cover the same classes with synthetic data and an ephemeral key. They also cover duplicated `connection_id`, duplicated close records, and an inserted record that links correctly but is signed with another key.

## Why deleting the newest records cannot be detected (F-4)
- **The verifier has no outside reference for the log's latest state.** Every check is relative to the records before it. A prefix of a valid chain is itself a valid chain: it starts at genesis, its `seq` values are continuous, and every link and signature is intact.
- **Nothing anchors the latest state.** No closing record exists, the relay writes no periodic heartbeat, and no copy of the head (`seq`, `record_hash`) is stored where the log's writer cannot reach it.
- **The writer can truncate.** The records directory is writable by the relay and by every authenticated host user (F-9), so truncation is a simple file operation that needs no key.
- **The effect fails safe but is silent.** Sessions whose records vanish become `mapping_missing`, or `close_inconsistent` if only the close vanishes; nothing gains attribution. Even so, the absence of evidence is not reported as tampering.

## External signed-checkpoint requirement (documented only; not implemented)
To detect tail deletion and to bound key compromise, a checkpoint mechanism would need all of the following:
1. **Periodic checkpoints.** At a fixed interval and at relay start/stop, the relay emits `{log_id, seq, record_hash, time}` for the current head.
2. **Separate storage.** Each checkpoint goes to a store the relay and the log directory cannot rewrite: an append-only witness on a different host account, a WORM or transparency log, or a print to the audit chain of the assessment run.
3. **Independent counter-signature.** The witness counter-signs each checkpoint with its own key, held by a different custodian. A compromised relay key then cannot forge history after the last witnessed checkpoint.
4. **Verifier rule.** The verifier must require that the log extends the latest witnessed checkpoint (same `record_hash` at that `seq`). A log that is shorter than, or diverges from, the checkpoint is **untrusted**, not merely missing.
5. **Liveness rule.** A missing checkpoint for longer than the interval counts as a relay or log fault, and attribution for that period is withheld.
6. **Compromise boundary.** After a key compromise, only records covered by checkpoints witnessed before the compromise time stay trusted.

No audit infrastructure was introduced in this task.
