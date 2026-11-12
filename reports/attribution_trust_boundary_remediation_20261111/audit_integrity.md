# Record integrity (F-4, F-6, F-9)

## Malformed records handled independently (F-6), strict chain preserved
`client_attribution/records.verify_records` now verifies each line on its own, then links the verified records:

| Situation | Handling |
|---|---|
| malformed JSON, unknown schema, missing fields, hash mismatch, wrong `key_id`, bad signature, outside key validity | that line is **rejected**; the rest of the log stays usable |
| next verified record has `seq` = previous + 1 | `prev_hash` must link (strict). A correctly signed record that does **not** link is a **fork**, and the whole log is untrusted |
| next verified record skips `seq` values | explicit **gap** `{after_seq, before_seq, missing, start_utc, end_utc, kind: missing_records}`; a new segment starts |
| first verified record is not seq 1 / genesis | gap `head_missing` |
| `seq` ≤ previous (replay, duplicate, reorder) | rejected |
| inserted record signed by another key, with no seq gap | rejected; no gap |
| `relay_start` announcing another key | whole log untrusted |

Correlation (`correlate.py`) then withholds only the sessions that a gap could affect:
- **Open records:** a gap (records strictly between two verified records, or before the first / after the last) that overlaps a session's **open-record window** (connect ± skew) gives `unattributed:log_gap`.
- **Close records:** a missing relay close whose close window overlaps a gap also gives `unattributed:log_gap`.

Every other session keeps its normal decision. The signed result reports `intact`, gaps, rejected-line count and tail status.

| Test | Result |
|---|---|
| one malformed line in the middle (3 sessions) | s0, s2 attributable; s1 `log_gap`; gap `missing: 1` |
| two records deleted from the middle | gap `missing: 2`; s1 and s2 (open window touches the gap) `log_gap`; s0 attributable |
| fork (pinned key, non-linking record) | whole log untrusted |
| altered, unsigned or truncated-signature open record (Task 26A tests) | that session `log_gap`; nothing attributed from the damaged record |
| appended garbage / forged insertion | rejected individually; the session stays correctly attributed to its genuine client |

## External signed checkpoints (F-4)
**Format** (`client_attribution/checkpoints.py`): `relay-log-checkpoint-1` = `{checkpoint_id, log_id, seq, record_hash, record_written_utc, attested_utc, witness_key_id, checkpoint_hash, signature}`.
- **Who signs:** the **witness key**, which is the attribution component's key and is never held by the relay.
- **Signing rule:** `make_checkpoint` refuses a log that is not fully intact.
- **Verifying a checkpoint** (`verify_checkpoints`) checks: exact fields, hash, pinned witness, signature, and `log_id`.

How the verifier uses checkpoints:

| Log vs. verified checkpoint | Result |
|---|---|
| record at checkpoint `seq` has the same hash | `consistent` |
| record at checkpoint `seq` has a different hash | **divergence**: whole log untrusted (history rewritten) |
| log ends before the checkpoint `seq` | **tail incomplete**: explicit gap `tail_incomplete`; affected sessions `log_gap`; `tail.status = incomplete` |
| log ends at the newest checkpoint | `tail.status = attested` |
| records after the newest checkpoint | `tail.status = unattested_after_checkpoint` (reported, not hidden) |
| no checkpoint | `tail.status = unattested` |

| Test | Result |
|---|---|
| last 2 records deleted, **no** checkpoint | log verifies; `tail: unattested`; s2 only `mapping_missing`. **Deletion is not detectable** |
| same deletion **with** a checkpoint at the old head | `tail: incomplete`, `tail_incomplete` gap, s2 `log_gap`, log not `ok` |
| different history with the same seq numbers | divergence, untrusted |
| forged checkpoint (seq/log_id changed, bad signature, missing signature, unpinned witness) | rejected |
| real 26A relay log + checkpoint at seq 11 | `consistent`, `tail: attested` |

**Limit, stated explicitly:** tail deletion is detectable **only** up to the newest checkpoint that is stored where the log's writer cannot change it.
- **Today:** checkpoints and signed results are produced only in validation, with an ephemeral witness key. No checkpoint store is deployed; it needs the attribution key (migration plan A).
- **Operator access:** even when deployed, the operator account can write every location, so checkpoints are independent of the **relay**, but not of the operator.

**Requirements for the deployed store:**
- the attribution signer writes checkpoints at start, at a fixed interval and with each signed result, into its own output volume, which the relay never mounts;
- a copy goes off-host or to WORM storage for operator independence;
- the verifier is given the newest checkpoint;
- a checkpoint missing for longer than its interval counts as a fault.

## Unauthorised writes to relay records (F-9)
- **Windows:** the records folder and file ACLs now grant only `MADHUMITHRAA\madhu` (Modify). *Authenticated Users: Modify* and *Users: Read* are removed.
- **Containers:** the relay is the only container with a writable mount of the records. The assessment container has none, and the planned attribution signer mounts them read-only.
- **Remaining:** the operator account can still write the records. Modification, insertion, reordering and mid-log deletion are detected; tail deletion is detected only against a checkpoint.
- **Live log:** unchanged by this task: 11 lines, SHA-256 `496b5a0f…`, identical to the Task 26A evidence copy.
