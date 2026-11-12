# Task 28A — Checkpoint Witness Architecture with Placeholders and TEST/LOCAL MOCK Infrastructure

Date: 2026-11-12 · Implemented and tested in **mock mode only**.

- **Production disabled:** production trust, key provisioning, off-host replication, migration (M0–M8), activation (A1), live attribution and response enforcement **remain disabled**.
- **No external contact:** no placeholder URL was contacted, no repository or credential was created, and no production key was generated.
- **Live deployment untouched:** the running relay was not changed or restarted.
- **Nothing committed.**

Basis: `reports/checkpoint_witness_implementation_readiness_20261112/report.md`, including the decision record D10–D16.

## 1. Files created and modified

**Created:**

| File | Component / purpose |
|---|---|
| `configs/witness/offhost_pending.json` | **The single placeholder location.** Trust-anchor repository `https://github.com/PLACEHOLDER/honeypot-trust-anchor.git`; witness-log repository `https://github.com/PLACEHOLDER/honeypot-witness-log.git`; administrators `ADMIN_A_PENDING` / `ADMIN_B_PENDING`; replication credential `NOT_CONFIGURED`; trust-anchor fingerprint `PENDING_PROVISIONING`; protocol parameters (2 s, 60 s, 900 s, 120 s, 1200 s, 5 s) |
| `client_attribution/placeholders.py` | loads that file; `placeholder_fields`, `assert_production_ready` (refuses while any D0 field contains PLACEHOLDER/PENDING/NOT_CONFIGURED); `MOCK_LABEL` |
| `client_attribution/framing.py` | **transport-independent protocol (D13):** length-prefixed canonical JSON; `StreamTransport` (any socket, 2-s timeout), `InProcessTransport` (tests), `serve_stream` |
| `client_attribution/trust_root.py` | `trust-root-manifest-1`: six-role distinctness (plus the approval role as a seventh), thresholds, change classification, fingerprint pinning; `recovery-authorisation-1` with D11 thresholds |
| `client_attribution/witness.py` | **Witness** (component 2): `WitnessCore`, durable `CheckpointStore`, replication-lag rule |
| `client_attribution/replicator.py` | **Replicator** (component 3): verifies the chain before pushing, unsigned non-authoritative status; `ProductionRemoteNotConfigured` refuses everything |
| `client_attribution/offhost_monitor.py` | **independent monitor interface**: history, signatures/chain, freshness, anchor digest, fault/halt alerts |
| `client_attribution/offhost_mock.py` | **TEST/LOCAL MOCK** witness-log repository, trust-anchor repository and administrators |
| `cowrie/attributing_relay/relay_gate.py` | **Relay** (component 1) gate: `RecordWriterV2` (records carry `witness_ack`), `RelayWitnessGate` (confirm-before-proceed, 2-s timeout, heartbeat, HALTED, recovery) |
| `cowrie/attributing_relay/witnessed_relay.py` | Twisted adapter using the gate (**not deployed**; M7) |
| `cowrie/witness/service_guard.py`, `witness_service.py`, `replicator_service.py`, `recover.py` | entry points. **Production refused** (placeholders, and then "M7 not run"); mock only when explicitly requested |
| `cowrie/docker-compose.witness-mock.yml` | **overlay, not applied:** new `witness-mock` profile services (relay-witnessed, log-witness, replicator; all `network_mode: none`) and named volumes `cowrie_relay_records` (D14), `cowrie_witness_socket`, `cowrie_checkpoint_store`, `cowrie_replication_status`. Validated with `docker compose config`; existing services render identically with and without it |
| `tests/test_checkpoint_witness.py` | 70 tests |
| `reports/…/twisted_smoke_test.py` | real-Twisted smoke test in a network-less container |

**Modified (intentionally):**

| File | Change |
|---|---|
| `client_attribution/checkpoints.py` | **appended** `relay-log-checkpoint-2`: `make_checkpoint_v2`, `verify_checkpoint_v2`, `verify_checkpoint_chain`, `v1_view`. v1 is unchanged |
| `client_attribution/result.py` | **Attribution signer** (component 4): `witness_evidence()` refuses to sign with a stale checkpoint (> 120 s) or unconfirmed off-host replication (> 900 s); `build_result(..., witness=)` adds `relay_log.witness` |
| `threat_assessment/config.py` | optional v3 `checkpoint_witness` block (pin distinct from relay/result, Ed25519 identity, max age ≤ 600, lag ≤ 900, pinned anchor digest; status `mock` refused unless `allow_mock_witness=True`). Absent block = existing behaviour |
| `threat_assessment/signed_attribution.py` | **Assessment verifier** (component 5): when a witness is pinned, the result must have tail `attested` and a witness checkpoint that is independently verified (hash, pinned key, signature), covers the log head, uses the pinned anchor, is fresh, and is replicated off-host within the bound. Accepted results are labelled `TEST/LOCAL MOCK (not production trust)` |
| `tests/test_client_attribution.py` | the existing private-key test now also allows `.sign(` in the explicitly mock `offhost_mock.py` (mock administrators); otherwise unchanged |

**Unchanged (verified, `unchanged_checks.txt`):**
- the live relay `attributing_relay.py`, `relay_config.json`, relay public key, and relay private key (metadata only);
- `cowrie/docker-compose.yml` (`5d94ba5f…`);
- all configs;
- `threat_assessment/{assessment,attribution,severity,audit}.py` (gates and severity unchanged);
- `behavioural_evidence/` (9/9);
- `dynamic_response/` (13/13).

The running relay `a5e156cbca02` has 0 restarts, no witness volume exists, and there are no firewall rules.

## 2. Component architecture

| Component | Implementation | Holds | Communicates |
|---|---|---|---|
| 1 Relay | `RelayWitnessGate` + `RecordWriterV2` (+ Twisted adapter) | relay key only | → witness: `attest` / `heartbeat` / `recovery` frames; ← signed acks |
| 2 Witness | `WitnessCore` + `CheckpointStore` | witness key only | reads relay records itself (read-only); writes checkpoints durably; reads the replication status (not authoritative) |
| 3 Replicator | `Replicator` | replication credential only (mock: none) | reads the checkpoint store; pushes to the witness-log repository; reads the trust-anchor repository |
| 4 Attribution signer | `client_attribution.result` (`witness_evidence`, `build_result`, `sign_result`) | attribution-result key only | reads checkpoints and the replication status |
| 5 Assessment verifier | `threat_assessment.signed_attribution` + config | public keys only | verifies results and witness checkpoints independently (no import from `client_attribution`) |

**Protocol (D13):**
- **Frames:** canonical JSON with a 4-byte length. The same handler ran over an in-process transport and over a real socket pair (test `test_two_second_timeout_real_stream_transport`).
- **Witness validation per record** (re-reads the record from the log; ignores the request content):
  - schema and fields;
  - `record_hash`;
  - pinned relay key and signature;
  - relay-key validity;
  - sequence (duplicate → refusal; different content → conflict; skip → gap);
  - `prev_hash` link;
  - `witness_ack` cross-link to its own previous confirmation;
  - ±5 s clock skew;
  - replication lag;
  - trust-anchor match.
- **Acknowledgement:** only after a durable append (fsync of the file, plus the directory where supported) does it answer.

## 3. Mock versus production boundaries

| Item | Mock (implemented) | Production (blocked) |
|---|---|---|
| Witness-log repository | `MockWitnessLogRepository`: in memory; fast-forward only; force-push, deletion and non-fast-forward pushes rejected; offline injection | `ProductionRemoteNotConfigured`: every call raises ("D0 unresolved; placeholder … not contacted") |
| Trust-anchor repository | `MockTrustAnchorRepository`: only a `MockAdministrator` may publish | none |
| Administrators | `MockAdministrator` A/B with in-memory test keys, named "TEST/LOCAL MOCK ADMINISTRATOR" | `ADMIN_A_PENDING` / `ADMIN_B_PENDING` |
| Signatures | `ed25519-canonical-v1` by mock administrators | administrators' tool to be agreed (planned `ssh-keygen -Y sign`) |
| Monitor | `check_repository` on mock repositories; result labelled mock, `production_trust: False` | runs under the administrators' control (scheduled workflow) |
| Replication acknowledgement | status `{mock: true, production_trust: false, authoritative: false}` | none |
| Assessment | a `mock` witness config is refused unless explicitly allowed; accepted results labelled `TEST/LOCAL MOCK (not production trust)` | `provisioned` status needs real pins and anchor |
| Services | entry points run in mock only when `--mode mock` is requested, printing the mock label | `--mode production` refused: placeholders remain (and then "M7 not run") |

Every mock object has `is_mock = True`, `production_trust = False`, `delivered_offhost = False` and the label "TEST/LOCAL MOCK - not off-host, not production trust".

## 4. Key-role separation (D16)
- **Six roles:** relay record, attribution result, checkpoint witness, administrator A, administrator B, replication credential. Human approval is a separate seventh role.
- **Where distinctness is enforced:**

  | Point | Rule |
  |---|---|
  | manifest | rejects any shared identity, including the approval role (`test_six_roles_must_be_distinct`, `test_approval_role_is_a_distinct_seventh_role`) |
  | witness, relay gate | refuse witness key = relay key |
  | assessment config | refuses a witness pin equal to the relay or result pin |
  | existing K-1 rule | relay ≠ result (unchanged) |

- **Test keys:** all six (plus approval) are ephemeral in-memory **test fixtures**. No production key was generated, and none is stored.
- **No key material in the new modules:** they load no private key and contain no network client. The witness signs only through `make_checkpoint_v2`, with the key it is given; the relay gate signs only relay records.

## 5. Checkpoint and heartbeat implementation
- **Format:** `relay-log-checkpoint-2` (kinds `attest`, `heartbeat`, `fault`, `halt`, `recovery`, `key_rollover`). It has `checkpoint_seq` (+1) and `prev_checkpoint_hash` (hash chain from 64 zeros), names the relay record (seq, hash, type, time), carries `trust_anchor_digest` and the witness key ID, and is Ed25519-signed.
- **Every accepted record is confirmed,** including `relay_start`, before the relay proceeds:
  - listeners open only after `relay_start` is confirmed;
  - a client resumes only after its `connection_open` is confirmed (Twisted adapter).
- **Cross-linking:** each relay record after the first carries `witness_ack` = the previous confirmation.
- **Heartbeats (60 s):** the relay sends a heartbeat request every 60 s (`task.LoopingCall` in the adapter). The witness writes a `heartbeat` checkpoint re-attesting the head and the anchor, and replication delivers it like any other.
- **Signer:** refuses checkpoints older than 120 s, or no off-host confirmation within 900 s.
- **Assessment:** rejects results whose relay log is not confirmed, or whose checkpoint is stale or unreplicated (§7).

## 6. Failure and recovery behaviour

| Event | Behaviour (all fail closed) |
|---|---|
| no confirmation within **2 s** (injected clock and real socket), witness unreachable, nack, invalid or mismatched ack | relay HALTED |
| missed heartbeat | relay HALTED (`heartbeat_missing`); monitor alerts after 20 min without new checkpoints |
| replication lag > **15 min**, a missing or stale status, a status claim contradicted by age | witness `fault` (`replication_lag`) → nack → HALTED. A status can only make the lag larger (D15) |
| trust-anchor mismatch reported by the replicator | witness `fault` (`anchor_mismatch`, elevated) → HALTED |
| invalid record, signature, key, chain, cross-link, conflict, gap, expired relay key, clock skew | witness `fault` checkpoint → HALTED |
| tampered checkpoint store at witness restart | witness starts in an elevated fault and refuses all requests |

**HALTED (D12):** both listeners stop, all in-progress sessions are aborted, the halt marker is written, and no further records are accepted. A restart with the marker present is refused.

**Manual recovery (D11):**
- **Authorisation:** `recovery-authorisation-1` (≤ 1 h validity, operator, incident reference, `halt_ref` = the witness head). Signature thresholds:

  | Recovery type | Signatures |
  |---|---|
  | **Ordinary** | one administrator |
  | **Elevated** (witness fault category elevated, or an elevated cause) | **both** administrators |

  A single signature is rejected for an elevated halt.
- **Witness checks before resuming:** it re-verifies the checkpoint chain, the relay chain and the off-host head (if they disagree, recovery is refused). It writes a `recovery` checkpoint with the authorisation hash, category, signers and any **unattested record sequence numbers**, which are listed and never attested. The relay clears HALTED only after a verified `recovery` ack.

**Trust-root changes (D10):**
- the first manifest, administrator, threshold, digest or revocation changes need **both** administrators;
- a routine rotation of a role key needs **either**;
- changes are authorised by the *current* administrators (a takeover attempt is rejected);
- the first manifest cannot be trusted while the anchor fingerprint is `PENDING_PROVISIONING`.

## 7. Test results
- **`tests/test_checkpoint_witness.py`:** **70 passed**, 0 failed (`test_results_checkpoint_witness.txt`).

  | Required test | Tests |
  |---|---|
  | invalid and duplicate records | `test_invalid_record_faults_and_halts` (4), `test_duplicate_and_replayed_attest_requests`, `test_gap_and_unknown_requests_fault` |
  | replay and expiry | duplicate/replay test; `test_expired_relay_key_faults`; `test_recovery_authorisation_expiry_and_forgery`; `test_manifest_expiry_and_thresholds_cannot_be_weakened` |
  | broken hash chains | `test_broken_relay_chain_faults`, `test_witness_ack_cross_link_enforced`, `test_checkpoint_chain_tampering_detected` (4), `test_witness_restart_on_tampered_store_refuses` |
  | invalid signatures | record bad signature or unknown key; `test_invalid_ack_signature_halts`; forged recovery administrator; checkpoint re-signed with another key |
  | missing confirmation | `test_missing_confirmation_halts`, `test_ack_for_another_record_halts` |
  | 2-second timeout | `test_two_second_timeout_injected_clock` (1.9 s ok; 2.5 s and 30 s halt), `test_two_second_timeout_real_stream_transport` (real socket, halts at ~2 s) |
  | replication failure; 15-minute stale replication | `test_replication_failure_beyond_15_minutes_halts`, `test_stale_or_missing_status_counts_as_not_replicated`, `test_status_claim_cannot_override_lag`, `test_replicator_refuses_invalid_local_chain_and_production_remote`, `test_anchor_mismatch_halts_as_elevated` |
  | missing heartbeat | `test_missing_heartbeat_halts_both_listeners_and_aborts_sessions`, `test_monitor_alerts_on_missing_heartbeats` |
  | both-listener halt; session abortion | same test (both fake listeners stopped, 3 sessions aborted, registration refused, marker written), `test_halt_marker_blocks_restart`, **and the real Twisted smoke test below** |
  | one-signature ordinary recovery | `test_ordinary_recovery_with_one_signature` |
  | one signature rejected for elevated recovery | `test_elevated_recovery_rejects_one_signature_and_accepts_two`, `test_recovery_authorisation_validation` (4), `test_recovery_refused_when_offhost_disagrees` |
  | two-signature trust-root changes | `test_trust_root_establishment_needs_both_signatures`, `test_trust_root_change_needs_two_routine_rotation_needs_one`, `test_replacing_an_administrator_needs_current_administrators` |
  | placeholder rejection in production mode | `test_repository_offhost_config_is_placeholder_and_blocks_production`, `test_entry_points_refuse_production` (3), `test_production_refused_even_without_placeholders`, `test_pending_fingerprint_cannot_establish_trust` |
  | mock repository tampering | `test_mock_repositories_are_labelled_and_enforce_rulesets`, `test_monitor_detects_mock_repository_tampering` (4: rewritten history, edited checkpoint, dropped checkpoint, foreign anchor) |
  | assessment verification of unconfirmed results | `test_unconfirmed_results_are_rejected` (6), each failing on its own check: no witness checkpoint, tail not attested, modified checkpoint, stale, other trust anchor, no off-host confirmation. Also `test_confirmed_result_is_accepted_but_marked_mock`, `test_signer_refuses_stale_or_unreplicated_evidence`, `test_mock_witness_config_refused_outside_mock_mode_and_role_separation`, `test_existing_configs_have_no_witness_requirement` |
  | six key roles | `test_six_roles_must_be_distinct` (4), `test_approval_role_is_a_distinct_seventh_role`, `test_six_test_key_roles_are_distinct_and_witness_holds_only_its_key` |

- **Real Twisted smoke test** (`twisted_smoke_test_output.txt`): pinned image, `--network none`, read-only, cap_drop ALL. Only `client_attribution/`, `relay_gate.py` and `witnessed_relay.py` were mounted, **never** the relay `secrets/` directory.
  - `relay_start` was confirmed before listening;
  - an echo through the relay worked only after `connection_open` was confirmed;
  - after a missed heartbeat: **both** listeners gave `ConnectionRefusedError`, the in-progress session was aborted (`ConnectionResetError`), 0 sessions remained, and the halt marker was written.
- **Full suite** (`test_results_full.txt`): **798 passed**, 0 failed (previously 728; +70).

## 8. Remaining D0 dependencies
1. **Repositories:** the two administrators create the private witness-log repository and the trust-anchor repository, with rulesets (no force-push or deletion, linear history, bypass = administrators) and the scheduled monitor. Then the real URLs replace the placeholders in `configs/witness/offhost_pending.json`.
2. **Trust-root keys:** each administrator generates their key on their own device; the out-of-band fingerprint replaces `PENDING_PROVISIONING`; the administrators' signing format is agreed (an SSHSIG verifier, if `ssh-keygen -Y` is used, is still to be implemented).
3. **Production remote:** a replication credential (deploy key) and a git implementation replacing `ProductionRemoteNotConfigured`, plus an egress-only network for the replicator.
4. **Migration M0–M8** (separately approved):
   - production key generation for the relay, result and witness keys;
   - manifest v1 signed by both administrators;
   - configs v3.1 / 2.3;
   - the coordinated relay-key rotation with records moved to `cowrie_relay_records`, switching to `witnessed_relay.py` (M7);
   - a dry run.
5. **Hardening before M7:** a non-blocking (Deferred-based) witness client in the Twisted adapter (the current call blocks the reactor for at most 2 s), and witness attestation of the response audit log.
6. **Activation A1** and enforcement activation: separate approvals.

## 9. Confirmation
- **Production trust is disabled.** Every service refuses production startup (placeholders remain, and migration M7 has not been run). Every mock is labelled and never reports production trust or off-host delivery. No placeholder URL was contacted.
- **No keys were provisioned or changed:**
  - no production key of any role was generated or stored;
  - the existing relay key is unchanged (not rotated, replaced or read);
  - the Cowrie host keys are untouched.
- **Migration, activation and live use are not running:**
  - no migration step (M0–M8) or activation (A1) was run;
  - live attribution is not activated, since the deployed v3 config has no witness block and its result key is still pending;
  - response enforcement stays disabled;
  - the running deployment (Cowrie, relay, demo clients, base compose) is unchanged.
- **Assessment rules unchanged:** threat-assessment gates and severity definitions, behavioural evidence and the ML models are unchanged.
- **No protected data:** no Dataset V2, sealed output or protected report folder was accessed, and no repository-wide search was run. Nothing was committed.

Stopped.
