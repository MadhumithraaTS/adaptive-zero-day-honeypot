# Task 28B — Non-Blocking Relay-to-Witness Communication

Date: 2026-11-12 · Implemented and tested (TEST/LOCAL MOCK only).
- **Deployment untouched:** no production key, placeholder URL, repository, credential, live-relay change, Cowrie/relay restart, compose overlay application or migration.
- **Nothing activated:** attribution and response enforcement remain disabled. Nothing committed.

Basis: `reports/checkpoint_witness_mock_implementation_20261112/report.md`. That report's synchronous adapter could block the reactor for up to 2 s per record; this task removes that.

## 1. Changed files

| File | Change |
|---|---|
| `cowrie/attributing_relay/async_gate.py` | **new:** `AsyncRelayWitnessGate` (reactor-agnostic, non-blocking) and `Pending` (one-shot result) |
| `cowrie/attributing_relay/witnessed_relay.py` | **rewritten:** the Twisted adapter now uses the async gate. Adds `TwistedScheduler` (`reactor.callLater`), `WitnessStreamClient` (framed protocol over any Twisted stream), and `LoopbackMockWitnessTransport` (TEST/LOCAL MOCK). Clients are paused (`pauseProducing`) until their `connection_open` is confirmed. **Not deployed** (M7) |
| `client_attribution/framing.py` | adds `respond()`: the witness echoes the request's `request_id`; `serve_stream` uses it. Existing behaviour unchanged |
| `tests/test_async_witness_gate.py` | **new:** 23 deterministic tests |
| `reports/…/twisted_async_smoke_test.py` | **new:** real-reactor smoke test (container, `--network none`) |

**Unchanged:**
- `relay_gate.py` (the synchronous gate and `RecordWriterV2`, reused), `witness.py`, `checkpoints.py`, the assessment side and all configs;
- the live `attributing_relay.py`, `relay_config.json`, the relay key (metadata unchanged), `cowrie/docker-compose.yml` and the compose overlay;
- threat-assessment gates and severity, and behavioural evidence (9/9).

## 2. Implementation
- **Interfaces:** `scheduler.call_later(seconds, fn) → handle.cancel()` and `scheduler.seconds()`; `transport.send(frame)` never blocks, and the transport delivers frames by calling `gate.on_response(frame)` / `gate.transport_lost(reason)`.
  - **Twisted:** `reactor.callLater` and a protocol over a UNIX/TCP/TLS stream.
  - **Tests:** a deterministic `FakeScheduler` and a controllable mock witness transport around the real `WitnessCore`.
- **`append(rtype, **fields)` / `heartbeat()` / `start()`** return a `Pending` immediately. The adapter acts only in callbacks:
  - it opens the listeners after `relay_start` is confirmed;
  - it resumes a client after its `connection_open` is confirmed;
  - it aborts the client on failure.
- **Engine (`_pump`):**
  1. Takes the next queued item.
  2. **Writes the record only now** (so `witness_ack` = the last confirmation).
  3. Assigns a unique `request_id`.
  4. Sends the frame.
  5. Starts a **2.0-s timer** for that request.
- **`on_response`:** a confirmation is accepted only if **all** of the following hold; any failure halts:
  - it matches the outstanding `request_id`;
  - it arrives strictly before the timer;
  - it is an `ack` with a checkpoint signed by the pinned witness key;
  - the checkpoint kind matches (attest or heartbeat) and the log ID matches;
  - it links to the previous confirmation;
  - for attests, it names exactly this record (seq and hash).

  It then cancels the timer, stores the confirmation, resolves the `Pending` and pumps the next item.
- **Heartbeats:** `start_heartbeats()` schedules a heartbeat every 60 s through the same queue. A heartbeat that is not confirmed within 2 s halts with `heartbeat_missing`.
- **Recovery:** `recover(authorisation)` is asynchronous. It is accepted only while halted and idle, and its answer is routed by `request_id`. It clears HALTED only on a verified `recovery` checkpoint. The D11 thresholds are unchanged (one signature for ordinary, both for elevated), and so is the halt-marker rule: `start()` raises if the marker exists.

## 3. Concurrency guarantees
1. **The reactor never waits.** All calls return at once; waiting is done by timers. Measured in the real reactor: a 50 Hz `LoopingCall` ran **70 times** during a 1.5-s pending confirmation, with a **maximum gap of 21 ms**.
2. **At most one witness request is outstanding** (`max_outstanding = 1`, asserted in unit and smoke tests). Concurrent sessions are served FIFO. A session's bytes are held (client paused) only until its own record is confirmed; other sessions keep relaying.
3. **Ordering:**
   - records are written at dequeue time, so on-disk `seq` order = confirmation order;
   - every record's `witness_ack` names the previous confirmation, including interleaved heartbeats (verified record by record);
   - the witness checkpoint chain verifies.
4. **Queued records are never written after a halt.** On halt, the outstanding and all queued requests fail with `Halted`, and new appends fail immediately.

## 4. Timeout behaviour (exactly 2 s)
- **Timer:** each request's timer starts when its frame is sent and fires at exactly `sent_at + 2.0`.
- **Tie-breaking:** events at equal times run in scheduling order, and the timer is scheduled before any response. A confirmation arriving at exactly 2.0 s is therefore **late** and the relay halts (tested). As a second guard, `on_response` also rejects anything at or after 2.0 s.
- **Queued requests:** a request waiting behind others is not penalised. Eight queued requests at 0.5 s each completed over 4 s without a halt, because the timer runs per request from its own send.
- **After a halt:** a late confirmation is ignored and counted (`rejected_after_halt`). It never resolves a request and never un-halts.
- **Measured in the real reactor:** halt **2.002 s** after the heartbeat was sent, with the witness answering at 3 s.

**Halt causes:**

| Cause | Trigger |
|---|---|
| `ack_timeout` | an attest not confirmed within 2 s |
| `heartbeat_missing` | a heartbeat not confirmed within 2 s |
| `late_confirmation` | defensive guard |
| `out_of_order_confirmation` | wrong `request_id` |
| `unexpected_confirmation` | a confirmation while idle (duplicate or replay) |
| `invalid_ack` | bad signature, wrong kind or log, broken link, a different record, or an old confirmation replayed |
| `nack:<cause>` | the witness refused |
| `witness_unavailable` | send failure or lost transport |

Every halt does all of the following:
- stops **both** listeners;
- aborts **all** in-progress sessions;
- cancels the heartbeat loop and timers;
- fails all pending requests;
- writes the halt marker.

## 5. Test results
**`tests/test_async_witness_gate.py`: 23 passed**, 0 failed (`test_results_async_gate.txt`; deterministic clock, controlled mock witness, real `WitnessCore`).

| Required | Tests |
|---|---|
| slow witness responses | `test_slow_witness_within_two_seconds_is_accepted` (1.9 s accepted) |
| two-second timeout | `test_timeout_is_exactly_two_seconds` (not halted at 1.999 s; halted at 2.000 s; request failed) |
| late confirmation | `test_confirmation_at_exactly_two_seconds_is_late`, `test_late_confirmation_after_halt_is_ignored` |
| invalid signature | `test_invalid_signature_halts` |
| out-of-order confirmations | `test_out_of_order_confirmation_halts`, `test_replayed_previous_confirmation_halts`, `test_conflicting_confirmation_for_another_record_halts` |
| duplicate / replayed confirmations | `test_duplicate_confirmation_is_rejected`, replay test above |
| concurrent sessions | `test_concurrent_sessions_are_serialised_one_outstanding` (sends exactly one round-trip apart; `max_outstanding = 1`), `test_queued_requests_do_not_time_out_behind_others` |
| multiple simultaneous record writes | `test_multiple_simultaneous_writes_keep_order_and_cross_links` (5 records + 1 heartbeat; order, `witness_ack` chain and checkpoint chain verified) |
| heartbeat expiry | `test_heartbeats_run_every_60s_and_expiry_halts` (heartbeat at 60 s confirmed; dropped heartbeat at 120 s halts at +2 s; loop cancelled) |
| relay halt during active sessions | `test_halt_during_active_sessions_stops_everything` (both listeners, 4 sessions, 4 pending requests, queue emptied, no queued record written, marker) |
| event-loop responsiveness | `test_event_loop_stays_responsive_during_delayed_confirmation` (append returns with zero elapsed time; 18 ticks and another session's work run while the confirmation is pending) |
| restart with halt marker | `test_restart_with_halt_marker_refused_and_async_recovery` (restart refused; one-signature elevated recovery rejected; ordinary recovery accepted; marker removed; next record links to the recovery confirmation) |
| other | `test_start_is_asynchronous_and_listeners_wait_for_confirmation`, `test_witness_nack_halts`, `test_send_failure_and_lost_transport_halt`, `test_lost_request_leaves_record_explicitly_unattested`, `test_recovery_refused_unless_halted_and_idle`, `test_recovery_needs_two_signatures_for_elevated_faults`, `test_pending_callbacks_after_resolution` |

**Real Twisted smoke test** (`twisted_async_smoke_test_output.txt`; pinned image, `--network none`, read-only, cap_drop ALL; mounts only the code files, never the relay `secrets/`):

| Check | Result |
|---|---|
| reactor ticks during a 1.5-s delayed confirmation | **70** (max gap **0.021 s**); the client's echo arrived after **1.52 s** |
| 3 concurrent clients | all echoed; records in order; checkpoint chain OK; `max_outstanding = 1` |
| witness answers after 3 s | halted after **2.002 s** (`heartbeat_missing`); both listeners `ConnectionRefusedError`; all 3 open sessions `ConnectionResetError`; 0 sessions left |
| `relay_start` confirmed before listening | true |

**Suites:**

| Suite | Result | Notes |
|---|---|---|
| related (`test_results_related.txt`) | **492 passed** | checkpoint witness, trust boundary, client attribution, key-role separation, threat assessment, dynamic response, behavioural evidence |
| full (`test_results_full.txt`) | **821 passed**, 0 failed | previously 798; +23 |

The Task 28A synchronous-gate tests still pass unchanged. The Task 28A smoke-test script targeted the previous synchronous adapter API; it is superseded by the async smoke test here.

## 6. Remaining production dependencies
1. **D0:** the independent administrators, both repositories and their rulesets, the trust-anchor fingerprint, the replication credential, and the administrators' signing format (SSHSIG verifier if `ssh-keygen -Y` is used).
2. **A production witness server** that listens on the shared UNIX socket (or TLS later) and answers asynchronously, echoing `request_id`. `serve_stream` is a simple threaded reference; a Twisted- or asyncio-based witness service is still to be wired in `cowrie/witness/witness_service.py` (production start is refused today).
3. **Socket wiring at M7:** connecting `WitnessStreamClient` to the `cowrie_witness_socket` volume. Reconnect policy: none, by design; a lost connection halts the relay.
4. **Migration M0–M8:** production key generation, manifest v1 signed by both administrators, configs v3.1 / 2.3, the coordinated relay-key rotation with records on the `cowrie_relay_records` named volume, switching the relay to `witnessed_relay.py`, and the dry run.
5. **Activation A1** and response enforcement: separate approvals.

## 7. Confirmation
- **No production change:** no production key was generated or modified, no placeholder URL was contacted, and no repository or credential was created.
- **Live deployment untouched:** the live relay and Cowrie were not modified or restarted (relay `a5e156cbca02` and Cowrie `0bec5a78b1cb` both have 0 restarts and the same start times). The compose overlay was not applied, and no witness volume exists.
- **Nothing run or activated:** no migration step was run, attribution and response enforcement remain disabled, and there are no firewall rules for the demo clients.
- **Assessment rules unchanged:** threat-assessment gates, severity definitions and behavioural evidence are unchanged.
- **No protected data:** no Dataset V2 or sealed evaluation output was accessed, and no repository-wide search was run. Nothing was committed.

Stopped.
