# Task 26D-5 — Checkpoint Witness Implementation Readiness and Migration Prerequisites

Date: 2026-11-12 · Type: **read-only preparation** · Updated by Task 26D-6 (approved decisions D10–D16 recorded; documentation only). Nothing implemented, provisioned, created, configured, run or committed.

> **KEY PROVISIONING BLOCKED — INDEPENDENT ADMINISTRATOR AND OFF-HOST TRUST DESTINATION NOT CONFIRMED.**

Baseline: `reports/checkpoint_witness_key_custody_plan_20261112/report.md` (read first). It is superseded here only where the Task 26D-5 approved decisions change it.

## Decision record (Task 26D-6, 2026-11-12)

**Status:**
- The design decisions D10–D16 below are **APPROVED** and are reflected throughout this report.
- **Implementation, key provisioning and migration (M0–M8) remain UNAUTHORISED** until D0 is resolved; activation (A1) additionally needs its own approval.
- **D0 remains BLOCKED:** no independent administrator or off-host destination has been confirmed.

| # | Approved decision | Where applied |
|---|---|---|
| **D10** | **Both** trust-root administrators sign trust-root changes. **Either** administrator can approve routine key rotations | §3, §8, §9 (M0, M5), §11 |
| **D11** | **Either** administrator may approve recovery from ordinary operational failures. **Both** must approve recovery after suspected compromise, broken checkpoint chains or trust-anchor changes | §4 (12, 13), §7, §9 (M8) |
| **D12** | **Abort all in-progress sessions** when either relay listener is halted | §2.1, §4 (10, 11), §7, §9 (M7) |
| **D13** | Relay–witness communication stays **transport-independent** | §2.3, §5 |
| **D14** | Relay records move into a **Docker named volume** during the coordinated relay-key rotation | §2.3, §9 (M3, M7) |
| **D15** | Replication status may be unsigned but is **not authoritative**. Independent monitoring must verify the actual off-host repository state, the signed checkpoints and freshness | §2.3, §6, §7 |
| **D16** | **Six** current key roles, including **two separately counted** trust-root administrators. **Human approval is a separate seventh role** | §3, §4 (15) |

The approval categories used below:

| Category | Approvals | Applies to |
|---|---|---|
| **Trust-root change** | **2-of-2** (P4-A **and** P4-B) | <ul><li>the first manifest (trust-root establishment);</li><li>adding, replacing or revoking a trust-root key;</li><li>changing the approval threshold;</li><li>changing any config/policy digest pinned in the manifest;</li><li>revocations after a suspected compromise;</li><li>re-baselining after a broken chain.</li></ul> |
| **Routine key rotation** | **1-of-2** (P4-A **or** P4-B) | a manifest whose only change is the scheduled replacement of P1′, P2, P3 or C1 by a new key. It keeps the same roles, threshold and digests and adds the predecessor to `previous_*`/expiry lists. Verifiers reject a 1-of-2 manifest that changes anything else |
| **Ordinary recovery** | **1-of-2** | halts caused by: witness or replicator unavailability, ack timeout, network or replication lag, disk/fsync errors, an expired key awaiting routine rotation — **provided** the relay chain, the checkpoint chain and the off-host head all re-verify and the trust anchor is unchanged |
| **Elevated recovery** | **2-of-2** | halts with suspected compromise, a broken or conflicting relay/checkpoint chain, an invalid signature, an anchor mismatch, or any trust-anchor change |

## 1. Current implementation architecture (as audited)

| Component | Files (exact) | Current behaviour relevant to the witness |
|---|---|---|
| Relay | `cowrie/attributing_relay/attributing_relay.py`; `relay_config.json` (`attributing-relay-config-1`, listeners `published` 172.21.0.2:2222 and `demo` 10.250.25.2:2222, key `/run/relay/relay_mapping_ed25519.pem`, log `/var/relay_records/relay_mapping.jsonl`) | <ul><li>`RecordLog.write` (L51–62) signs with P1, appends and fsyncs. There is **no external acknowledgement**.</li><li>`Server.connectionMade` (L112–126) pauses the client and dials Cowrie. `Upstream.connectionMade` writes `connection_open` (L77) and **immediately** resumes the client (L83).</li><li>`main` (L154–176) writes `relay_start` (L169), then calls `listenTCP` for each listener (L173) **without keeping the port objects**, so listeners cannot currently be stopped.</li><li>The relay does not enforce key validity.</li><li>At start it continues an existing chain by trusting the last line (L40–49) without verifying it.</li></ul> |
| Relay-record verifier | `client_attribution/records.py` (`verify_records` L82; `REQUIRED` L20; tail/checkpoint handling L122–145) | Per-line verification with a strict chain, gaps, and v1 checkpoint comparison (`tail`: `unattested`/`attested`/`incomplete`/`unattested_after_checkpoint`) |
| Checkpoints | `client_attribution/checkpoints.py` (`relay-log-checkpoint-1`, `FIELDS` L13, `make_checkpoint` L17, `verify_checkpoints` L30) | Periodic head attestation only. **No chain between checkpoints, no acknowledgement, no kinds, no trust-anchor digest** |
| Correlation | `client_attribution/correlate.py` (`correlate` L85, passes checkpoints to `verify_records` L107) | Sessions overlapping gaps → `log_gap`. Unattested tails are tolerated |
| Attribution signer | `client_attribution/result.py` (`build_result` L57, carries `relay_log.tail`/`checkpoints` L71; `sign_result` L78) | Library only; no service, no key provisioned |
| Result verifier | `threat_assessment/signed_attribution.py` (`_check_entry` L50, `verify_result` L130, K-1 checks L140–155, `verify_results` L185) | Pinned P2, K-1 (relay ≠ result). **Does not require an attested tail or check checkpoint freshness** |
| Config / pins | `threat_assessment/config.py` (`_pin` L72, `ed25519_public_key_identity` L80, `relay_key_sha256` L135/L260, `load_attribution_config` L264); `configs/threat_attribution_v3.json` (result key `pending_provisioning`); `configs/defence_policy_v2_2.json` | K-1 covers relay vs. result only. No witness, trust-root, revocation or previous-relay-key fields |
| Assessment isolation | `threat_assessment/run_signed.py` (`FORBIDDEN_PATHS` L18, `isolation_report` L33) | Refuses non-isolated environments. Does not know the witness, replicator or signer paths |
| Compose | `cowrie/docker-compose.yml` | <ul><li>Services: `cowrie`, `ssh-relay` (mounts L55–58, records on an **NTFS bind**), `demo-test-client`, `demo-control-client`, `threat-assessment` (profile `assessment`, `network_mode: none`, L98–117).</li><li>Networks: `cowrie_internal` (internal), `relay_frontend`, `demo_ingress` (internal).</li><li>No witness, replicator or signer services, and no egress-only network.</li></ul> |
| Custody docs | `reports/attribution_trust_boundary_remediation_20261111/key_custody.md`; `reports/key_custody_final_review_20261111/{rotation_and_recovery,checkpoint_procedure,migration_procedure,residual_risks}.md`; `reports/attribution_key_role_separation_20261112/report.md`; `reports/checkpoint_witness_key_custody_plan_20261112/report.md` | The 26D-4 plan is current; the earlier migration procedure is superseded |

## 2. Proposed implementation changes

### 2.1 Existing files to modify

| File | Change |
|---|---|
| `cowrie/attributing_relay/attributing_relay.py` | <ul><li>**Witness client** (async, Twisted `Deferred` with a 2 s `callLater` timeout) over a UNIX stream socket.</li><li>`RecordLog.write` adds `witness_ack {checkpoint_seq, checkpoint_hash}` of the previous record, then requests attestation of the new record.</li><li>`Upstream.connectionMade`: `resumeProducing()` only after the open record is acknowledged.</li><li>`Server.connectionLost`: the close record is attested.</li><li>`main`:<ul><li>verify the existing chain before continuing it;</li><li>enforce the relay key validity from the trust-root manifest;</li><li>attest `relay_start` **before** any `listenTCP`;</li><li>keep the port objects;</li><li>start a 60 s heartbeat `LoopingCall`;</li><li>add the **HALTED** state (D12): if either listener is halted, `port.stopListening()` on **both** listeners and **abort all in-progress sessions** on both (`transport.abortConnection()` on the client and upstream sides); write no further records;</li><li>refuse to start while a halt marker exists without a verified recovery authorisation.</li></ul></li></ul> |
| `client_attribution/checkpoints.py` | Add `relay-log-checkpoint-2`: kinds `attest` / `heartbeat` / `key_rollover` / `fault` / `halt` / `recovery`, `checkpoint_seq`, `prev_checkpoint_hash`, `trust_anchor_digest`. Add chain verification. Keep v1 for history |
| `client_attribution/records.py` | `witness_ack` becomes an optional field (required on v2 relay logs after the first record). Cross-link verification against v2 checkpoints. Records without a confirmation become an **unattested gap** |
| `client_attribution/correlate.py` | Load and verify v2 checkpoints. A session whose records are not attested → `unattributed:log_gap` |
| `client_attribution/result.py` | Include the newest checkpoint `{checkpoint_seq, checkpoint_hash, attested_utc}`, the off-host replicated head and the `trust_anchor_digest` in `relay_log` |
| `threat_assessment/config.py` | <ul><li>New attribution config schema minor version: `checkpoint_witness` pin, `trust_root` block (two admin public keys and threshold), `previous_relay_keys[]`, `revoked_keys[]`.</li><li>K-1 extended to all roles (§3).</li><li>Manifest digest pinning.</li></ul> |
| `threat_assessment/signed_attribution.py` | Require `relay_log.tail.status == attested`, checkpoint freshness (≤ 120 s at issue, off-host lag ≤ 15 min) and `trust_anchor_digest` equal to the verified manifest |
| `threat_assessment/run_signed.py` | Extend `FORBIDDEN_PATHS` with the witness socket, checkpoint store, replicator and signer key paths. Require the trust-root manifest to verify before assessing |
| `cowrie/docker-compose.yml` | Add `log-witness`, `replicator`, `attribution-signer` (profiles), named volumes, and an egress-only network for the replicator. The relay mounts the witness socket volume and the new relay config. Records move to a named volume (§2.3) |

### 2.2 New files and components (within the existing five-component design; no unrelated modules)

| New file | Purpose |
|---|---|
| `cowrie/attributing_relay/relay_config_v2.json` | witness socket path, 2 s timeout, 60 s heartbeat, `log_id`, trust-root manifest path, halt-marker path (v1 file kept) |
| `cowrie/witness/witness_service.py` | witness: socket server, independent record validation, checkpoint signing (P3), durable append, ack, heartbeats, halt and recovery handling |
| `cowrie/witness/replicator.py` | replicator: pushes new checkpoints to the private witness-log repository with C1; writes a delivery status file; compares the trust anchors |
| `cowrie/witness/recover.py` | operator recovery tool: verifies a recovery authorisation signed by a trust-root administrator and submits it to the witness |
| `client_attribution/trust_root.py` | SSHSIG (`ssh-keygen -Y sign`) verifier and manifest checks, used by the relay, witness and signer |
| `threat_assessment/trust_root.py` | **independent** SSHSIG verifier for the assessment (it must not import `client_attribution`) |
| `cowrie/attribution_signer/run_signer.py` | signer service entry point (`client_attribution` + P2) |
| `configs/threat_attribution_v3_1.json`, `configs/defence_policy_v2_3.json`, `configs/trust_root/{manifest.json, manifest.json.sig.A, manifest.json.sig.B, allowed_signers}` | new versions; existing files unchanged |
| `tests/test_checkpoint_v2.py`, `tests/test_trust_root.py`, `tests/test_witness_service.py`, `tests/test_relay_witness_gating.py` | <ul><li>Protocol, chain, cross-link, freshness, halt and recovery tests.</li><li>The relay gating tests run inside the pinned image, because Twisted is not installed on the host.</li></ul> |

### 2.3 Service-to-service communication

| From → to | Channel | Content | Authentication |
|---|---|---|---|
| relay → witness | **transport-independent protocol (D13):** length-prefixed canonical JSON frames over any reliable byte stream. Today: UNIX stream socket on named volume `cowrie_witness_socket` (relay rw, witness rw; no IP path). Later: mutually authenticated TLS to a separate witness machine, with no protocol change | `{type: attest\|heartbeat, log_id, seq, record_hash}` | none needed at message level: the witness re-reads and verifies the record itself, and the relay verifies P3-signed acks. Security never depends on the transport |
| witness → relay | same socket | `ack {checkpoint_seq, checkpoint_hash}` or `nack {reason}` | the relay verifies the ack signature against the pinned P3 public key |
| witness → store | named volume `cowrie_checkpoint_store` (witness rw only) | append-only JSONL, fsync file + directory | — |
| replicator → store | same volume, **read-only** | reads new checkpoints | — |
| replicator → witness | named volume `cowrie_replication_status` (replicator rw, witness ro) | `{remote_head_checkpoint_seq, remote_commit, pushed_utc, anchor_match}` | **unsigned and not authoritative (D15).** The witness uses it only to halt *earlier*: a bad or stale status halts, a good status never overrides a halt. Authoritative delivery is established only by the independent off-host monitor (§6) |
| replicator → off-host | HTTPS/SSH on a dedicated egress network `replicator_egress` (no other members) | git fast-forward pushes | C1 deploy key |
| signer ← records, store, Cowrie log | read-only mounts | — | verifies P1 records and P3 checkpoints |
| assessment ← signer output, public keys, manifest | read-only mounts | — | verifies P2, P4-A/B |

**Relay records move to a named volume (`cowrie_relay_records`) during the coordinated relay-key rotation (D14, step M7).**
- Durable acknowledgement depends on a real `fsync`, and fsync semantics through the Docker Desktop Windows bind are not guaranteed.
- The existing NTFS log receives its final `key_rollover` record (signed by P1) and is then closed and kept read-only for history.
- The new log under P1′ starts in the named volume.

## 3. Key-role separation matrix

**Approved (D16):** six current key roles, with the two trust-root administrators counted separately. Human approval is a separate **seventh** role, not yet designed. The six distinct identities are:

| # | Role | Key | Held by (only) | Never accessible to | Validity | Pinned in |
|---|---|---|---|---|---|---|
| 1 | Relay record signing | **P1′** Ed25519 (**rotated**; P1 retired) | relay container (named volume, 0400) | witness, signer, replicator, assessment | 30 days | trust-root manifest + attribution config; P1 listed in `previous_relay_keys` |
| 2 | Attribution-result signing | **P2** Ed25519 | attribution-signer container | relay, witness, replicator, assessment | 30 days | manifest + `attribution_result` |
| 3 | Checkpoint witness | **P3** Ed25519 | witness container (later: separate machine) | relay, signer, replicator, assessment | 30 days | manifest + `checkpoint_witness` |
| 4 | Trust root, administrator A | **P4-A** Ed25519 (SSH signing) | administrator A's own device | this host entirely | 1 year | `configs/trust_root/allowed_signers` + trust-anchor repository |
| 5 | Trust root, administrator B | **P4-B** Ed25519 (SSH signing) | administrator B's own device | this host entirely | 1 year | same |
| 6 | Off-host append credential | **C1** SSH deploy key (authentication only) | replicator container | all other components | 30 days | the witness-log repository's deploy keys (administrator-managed) |
| **7** (separate role, future) | Human approval of proposals | **P5** | approver's device | this host; every role 1–6 | TBD (approval task) | must be distinct from roles 1–6; out of scope until the approval task |

**What each trust-root signature authorises (D10, D11):**

| Action | P4-A | P4-B | Required |
|---|---|---|---|
| Trust-root change (first manifest, trust-root key change, threshold change, pinned digest change, compromise revocation, re-baseline) | ✓ | ✓ | **both** |
| Routine 30-day rotation of P1′ / P2 / P3 / C1 | ✓ or | ✓ | **either** |
| Ordinary recovery authorisation | ✓ or | ✓ | **either** |
| Elevated recovery (suspected compromise, broken chain, anchor change) | ✓ | ✓ | **both** |

The manifest and the recovery-authorisation verifiers enforce these thresholds by comparing the requested change with the previous manifest. A 1-of-2 document that changes anything outside its category is rejected.

- **Rule, extended K-1:**
  - all six public identities are pairwise distinct;
  - every manifest load rejects a duplicate;
  - every verifier rejects a signature whose key belongs to another role (for example, a P1′ signature on a checkpoint, or a P3 signature on a result).
- **Signed formats** carry a typed key role (`relay_record`, `attribution_result`, `checkpoint_witness`, `trust_root`).
- **Git:** no private key is ever in Git. Private keys are generated inside containers into named volumes (P1′–P3, C1) or on the administrators' devices (P4-A/B). `cowrie/attribution_keys/public/` holds public halves only, and a pre-commit check plus a test reject any PEM private header there.

## 4. Trust-boundary analysis (required security properties)

| # | Property | How it is met | Verified by (planned) |
|---|---|---|---|
| 1 | The relay cannot sign attribution results | relay holds only P1′; result verifier pins P2 and rejects relay-role keys (K-1, already enforced) | existing `test_key_role_separation`; new role-typed signature tests |
| 2 | The relay cannot approve its own attribution | attribution needs P2 (signer) **and** P3 checkpoints; approval (future) needs P5 off-host; the relay has none of these | probe: relay mounts contain only P1′ |
| 3 | The witness cannot modify assessment policy | witness mounts the manifest and pins read-only; no `configs/` write; policy digests are pinned by a P4-signed manifest | mount probe; manifest verification test |
| 4 | The witness cannot access P2 | P2 is only in the signer's volume | mount probe in the witness container |
| 5 | The replicator cannot sign results or modify trust anchors | replicator holds only C1 (an authentication key); trust-anchor repository is admin-write only; local manifest is read-only to it | probe; ruleset test push (M0) |
| 6 | The assessment cannot access private keys, Docker socket or relay credentials | existing isolation + extended `FORBIDDEN_PATHS`; network none | `run_signed` self-check + probe |
| 7 | No private key in Git | generation inside containers / admin devices; public-only export directory; test plus pre-commit check | test |
| 8 | Every accepted record is confirmed | relay requests attestation for every record type, including `relay_start`; no listener opens before `relay_start` is acknowledged; no client resumes before its open record is acknowledged | gating tests |
| 9 | Every confirmation is linked | `prev_checkpoint_hash` chain + `checkpoint_seq`; relay `witness_ack` cross-link | chain tests |
| 10 | Missing confirmation within 2 s → both listeners stop | the timeout triggers HALTED → `stopListening()` on both listeners **and abort of all in-progress sessions (D12)** | fault-injection test (witness killed): both ports closed, zero established sessions |
| 11 | Replication > 15 min → both listeners stop | witness refuses attestation when the oldest un-replicated checkpoint is > 15 min old → nack → HALTED (both listeners, sessions aborted). The unsigned status can only cause a halt, never prevent one (D15) | fault test (replicator blocked; replicator reporting a false "ok" while the off-host monitor flags staleness) |
| 12 | Stale heartbeat or broken chain prevents automatic recovery | after restart, the witness refuses to attest until the relay chain, the checkpoint chain and the off-host head re-verify; there is never automatic recovery. A broken chain is classified **elevated** and needs both administrators (D11) | tests |
| 13 | Recovery needs explicit manual approval and an audit record | a `recovery-authorisation-1` document (SSHSIG) names the halt checkpoint hash and the recovery category. **Ordinary:** one administrator; **elevated** (suspected compromise, broken chain, anchor change): both (D11). The witness verifies the category against the halt cause, writes a `recovery` checkpoint (replicated off-host), and only then does the relay clear HALTED | recovery tests, including a 1-of-2 authorisation rejected for an elevated halt |
| 14 | Replacing local config + policy cannot silently re-root | the manifest pins every digest and key and **needs both administrators for any trust-root change (D10)**; the manifest digest appears in every checkpoint; the off-host trust-anchor repository and the administrator-side monitor are not locally writable | tests + M0/M8 checks |
| 15 | Six current roles distinct with lifecycles; approval a separate seventh | §3 + §8 (D16) | manifest K-1 test across the six roles; P5 slot reserved |

## 5. Witness and checkpoint protocol

**Format `relay-log-checkpoint-2`:**
- **Fields:** `schema`, `log_id`, `checkpoint_seq` (from 1, +1), `prev_checkpoint_hash` (64 zeros for the first), `kind` ∈ {attest, heartbeat, key_rollover, fault, halt, recovery}, `relay_seq`, `relay_record_hash`, `relay_record_type`, `relay_record_written_utc`, `attested_utc`, `trust_anchor_digest`, `witness_key_id`, `checkpoint_hash`, `signature`.
- **Signing:** `checkpoint_hash` = SHA-256 over the canonical JSON without `checkpoint_hash`/`signature`; `signature` = Ed25519 (P3) over the ASCII hash.

**Independent validation by the witness, for each attest request:**
1. Read record `seq` from the relay log (read-only mount). **Ignore the record content in the request.**
2. Run the `_check_one` equivalent: schema, fields, `record_hash`, P1′ signature, key validity from the manifest, key not revoked.
3. `seq == last_attested_relay_seq + 1` and `prev_hash ==` the previous record hash.
4. `witness_ack` in the record equals the witness's own previous `{checkpoint_seq, checkpoint_hash}`. A `relay_start` after a rollover follows the rollover rules.
5. The record's `written_utc` is within ±5 s of the witness clock.
6. The record type is known.

**Rejections:**

| Record condition | Response |
|---|---|
| duplicate or replayed `seq` (≤ last attested) | nack `duplicate` |
| gap (> last + 1) | nack `gap` → fault |
| bad hash or signature, unknown key, revoked key | nack `invalid` → fault |
| expired key or `written_utc` outside validity | nack `expired` |
| malformed JSON or missing fields | nack `malformed` → fault |
| conflicting: same `seq` with a different hash than already attested | `fault` checkpoint, permanent refusal |

Every `fault` makes the relay halt.

**Acknowledgement:**
1. Build, sign and append the checkpoint.
2. `fsync(file)`, then `fsync(dir)`.
3. Reply `ack`.
4. The relay verifies the ack signature (P3 public key) and `prev_checkpoint_hash` continuity, then stores it for the next record's `witness_ack`.

**Heartbeat (every 60 s):** the relay sends a `heartbeat` request. The witness writes a `heartbeat` checkpoint re-attesting the current head and the anchor digest, then acks within 2 s. A missing ack → HALTED. Heartbeats are replicated like every other checkpoint.

**Staleness:**
- The **signer** refuses to sign when the newest checkpoint is older than 120 s, or when the off-host head is older than 15 min.
- The **assessment** rejects results without an attested, fresh tail.
- The **witness** refuses attestation when replication is more than 15 min behind.

## 6. Off-host replication design

**Destination** (to be created by the administrators, **not** created here):
- **Private `zdh-witness-log`:** the replicator can push fast-forward with C1. Rulesets: no force-push, no deletion, linear history; bypass list = the two administrators.
- **`zdh-trust-anchor`:** write access for administrators only. It holds the manifests (each signed by P4-A and/or P4-B, see D10), the `allowed_signers` file and the manifest history.
- **Independent monitoring (authoritative, D15):** a scheduled workflow in `zdh-witness-log`, owned by the administrators and not by this host, checks:
  1. the **actual repository state**: the newest commit time, and that the history is fast-forward only;
  2. the **signed checkpoints** in the repository: P3 signatures and the `prev_checkpoint_hash` chain, verified against the P3 key in the latest manifest from `zdh-trust-anchor`;
  3. **freshness**: the newest checkpoint `attested_utc` is no more than 20 min old (a 60 s heartbeat plus a 15 min lag bound plus margin);
  4. that every checkpoint's `trust_anchor_digest` equals the current signed manifest.

  It alerts **both** administrators on any failure, and on any `fault`/`halt` checkpoint. The local replication status file is diagnostic only and is never used to conclude that delivery succeeded.

**Replicator loop:**
1. Every 30 s, read new checkpoints from the store (read-only).
2. Verify the chain and P3 signatures (it does not push garbage).
3. Append them to `checkpoints/<date>.jsonl`, commit and push.
4. Run `git ls-remote` to confirm the remote head contains the pushed commit.
5. Write `cowrie_replication_status`.
6. Fetch `zdh-trust-anchor`, verify the latest manifest (P4 signatures), and compare it with the local manifest. On a mismatch, set `anchor_match=false`; the witness then writes `fault` and halts.

**Failure detection:** the push is rejected, the network fails, or `ls-remote` does not show the commit. Then the status shows `remote_head_checkpoint_seq` falling behind, and the witness computes `lag = now − attested_utc(oldest unreplicated checkpoint)`. Above 15 min it nacks → the relay halts.

Because the status is unsigned and not authoritative (D15):
- a **missing, unparseable or stale** status file (older than 2 min) is treated as "not replicated" and counts toward the lag;
- a status claiming delivery is never trusted beyond allowing normal operation to continue. Actual delivery is confirmed only by the independent monitor above, which alerts the administrators if the claim is false.

## 7. Failure and recovery behaviour

**HALTED (D12):** both listeners `stopListening()`; **all in-progress sessions on both listeners aborted** (client and upstream connections closed); no new records; a halt marker is written to the relay volume.

| Event | Immediate | Recorded | Recovery category (D11) | Automatic recovery? |
|---|---|---|---|---|
| no ack ≤ 2 s / socket error / witness down | relay HALTED | a `halt` checkpoint if the witness is reachable; otherwise the last relay record remains unattested | **ordinary**, if all chains re-verify at recovery; otherwise **elevated** | **no** |
| witness unavailable to append (disk full, fsync error) | nack → relay HALTED | `fault` (storage) | ordinary (if chains intact) | **no** |
| replication lag > 15 min, or missing/stale status file | witness nack → relay HALTED | `fault` (replication) | ordinary (if the off-host head matches the local chain) | **no** |
| heartbeat missing | relay HALTED | — | ordinary (if chains intact) | **no** |
| P3 / P1′ expired, awaiting routine rotation | nack → relay HALTED | `fault` (expired) | ordinary, after a 1-of-2 rotation manifest | **no** |
| invalid record signature, unknown or revoked key, conflicting seq, gap, broken relay or checkpoint chain | `fault`, permanent nack → relay HALTED | `fault` (integrity) | **elevated** | **no** |
| trust-anchor mismatch (local ≠ off-host manifest) | `fault` → relay HALTED | `fault` (anchor) | **elevated** | **no** |
| suspected compromise (operator or administrator declares) | relay HALTED by operator command | `halt` (compromise) | **elevated** | **no** |
| replicator falsely reports delivery | local halt may not trigger | the independent monitor alerts within 20 min (D15); an administrator then declares a suspected compromise if warranted | elevated (if declared) | **no** |

**Manual recovery** (always; properties 12 and 13; D11):
1. **Diagnose.** The operator diagnoses and fixes the cause and records an incident note. The halt cause in the last `halt`/`fault` checkpoint fixes the **minimum** recovery category, and an administrator may always raise it to elevated.
2. **Authorise.** The administrators, on their own devices, sign `recovery-authorisation-1` `{log_id, halt_checkpoint_hash, category: ordinary|elevated, cause, incident_ref, valid_until (≤ 1 h), operator}` with `ssh-keygen -Y sign -n zdh-recovery`.
   - **Ordinary:** a signature from **either** administrator.
   - **Elevated** (suspected compromise, broken checkpoint or relay chain, invalid signature, conflict, trust-anchor change or mismatch): signatures from **both** administrators over the same document.
3. **Submit.** The operator runs `cowrie/witness/recover.py` with the authorisation and its signature(s).
4. **Witness checks.** The witness:
   - verifies every signature against `allowed_signers`, and that the number of distinct administrator signatures meets the threshold for the **declared** category;
   - rejects an `ordinary` authorisation if the halt cause requires `elevated`;
   - re-verifies the relay log, the local store and the off-host head (they must agree). If they disagree, an `ordinary` authorisation is invalid by definition, and only an elevated **re-baseline** can proceed. That re-baseline needs a new 2-of-2 manifest;
   - attests any pending record **only if** it verifies;
   - writes a `recovery` checkpoint `{authorisation_hash, category, signers}` that is replicated off-host as the audit record.
5. **Resume.** The relay removes the halt marker only after acknowledging the `recovery` checkpoint, then re-opens both listeners. Sessions aborted at the halt are not resumed; clients reconnect.
6. **If recovery is refused,** attribution stays disabled and both listeners stay closed.

## 8. Key lifecycle (all roles)

| Role | Provisioning | 30-day expiry / rotation | Revocation | Backup | Compromise recovery |
|---|---|---|---|---|---|
| P1′ relay | one-shot container `--network none` into `cowrie_relay_signing_key`; public half exported; **P1 retired** with a final `key_rollover` record signed by P1 naming P1′ | at day 25: new key + rollover record (old key signs) + manifest | manifest `revoked_keys` | none | HALT relay; trust stops at the last off-host checkpoint; rotate |
| P2 result | one-shot container into `cowrie_attribution_result_key` | day 25: new key + manifest; results live ≤ 1 h | manifest | none | pending config (fail closed); rotate |
| P3 witness | one-shot container into `cowrie_checkpoint_witness_key` (later: separate machine) | day 25: `key_rollover` checkpoint signed by both keys; overlap ≤ 5 days | manifest | none | witness `fault` → relay HALTED; re-baseline from off-host; rotate |
| P4-A / P4-B | on each administrator's device | 1 year; the successor is a **trust-root change**, so both must sign (D10) | **trust-root change:** both administrators sign. If one administrator's key is suspected compromised, the remaining administrator immediately publishes a halt notice, and the revocation and successor take effect only with a manifest signed by the **remaining** key **plus** the replacement administrator key, confirmed out of band (this procedure must be agreed in M0) | administrators' own offline copies | elevated: re-root with a 2-of-2 manifest; local verifiers refuse until the new manifest is off-host |

**Routine rotations (P1′, P2, P3, C1)** need **one** administrator's signature (D10). A routine-rotation manifest may only:
- replace the scheduled key;
- extend expiry lists;
- record the predecessor.

Anything else (roles, threshold, digests, administrator keys) is a trust-root change requiring both signatures.
| C1 | one-shot replicator container; public half given to the administrators | 30 days: administrators add new and remove old | administrators delete the deploy key | none | revoke; attacker can only append (detectable) |

## 9. M0–M8 migration checklist (activation **A1** separate)
The commands below are the **intended** commands, listed for review. **None was run.** Every rollback returns to today's state: v3.0.0 / policy 2.2.0, result key pending, attribution **disabled**, current relay code and P1.

| Step | Preconditions | Exact actions | Verification commands | Expected output | Failure conditions | Rollback |
|---|---|---|---|---|---|---|
| **M0** Off-host + trust root | **D0 resolved** (two named administrators); **implementation and provisioning authorised** | Administrators: <ul><li>create private `zdh-witness-log` and `zdh-trust-anchor`;</li><li>rulesets (no force-push or deletion, linear history, bypass = administrators);</li><li>the **independent monitor** workflow (D15 checks: repository state, signed checkpoints, freshness, anchor digest);</li><li>each runs `ssh-keygen -t ed25519 -f zdh_trust_root_<A\|B> -C "<name> zdh-trust-root"` on their own device;</li><li>publish `allowed_signers`;</li><li>agree in writing the approval thresholds (D10/D11) and the single-administrator-compromise procedure (§8).</li></ul> | <ul><li>administrator: `git push --force` to the protected branch;</li><li>`ssh-keygen -lf zdh_trust_root_A.pub` read out of band;</li><li>monitor run on a repository seeded with a stale test checkpoint.</li></ul> | force push **rejected** by ruleset; fingerprints match on both sides; the monitor alerts both administrators on staleness | push accepted; fingerprint mismatch; monitor silent | administrators delete the repositories; nothing local changed |
| **M1** Code (separate implementation approval) | M0 complete; implementation approved | the §2 changes; tests | `python -m pytest -q tests`; container tests for relay gating | all pass; the 26C/26D-1 attacks still rejected | any failure | revert the code (no deployment) |
| **M2** Snapshot | M1 | back up compose, configs, relay config, ACLs (`icacls /save`), container IDs/start times; SHA-256 manifest | `sha256sum -c` on the snapshot | all OK | missing item | — |
| **M3** Volumes | M2 | `docker volume create` for `cowrie_relay_signing_key`, `cowrie_relay_records`, `cowrie_attribution_result_key`, `cowrie_checkpoint_witness_key`, `cowrie_checkpoint_store`, `cowrie_witness_socket`, `cowrie_replication_status`, `cowrie_replicator_credential`, `cowrie_attribution_output` | `docker volume inspect <each>` | 9 volumes, empty | name clash | `docker volume rm` (empty only) |
| **M4** Generate P1′, P2, P3, C1 | M3 + **provisioning approval** | one-shot containers (pinned image, `--network none --read-only --cap-drop ALL --user 999`), each mounting only its own key volume + a public-export directory | public-only export: no file in `cowrie/attribution_keys/public/` matches a PEM private header; four distinct SHA-256 identities | 4 public keys, pairwise distinct | duplicate identity; private material outside volumes | destroy the unused volumes (record it) |
| **M5** Manifest v1 (trust-root establishment) | M4 | <ul><li>administrators add C1 as a deploy key;</li><li>sign manifest v1 (P1′, P2, P3, C1 pins + `previous_relay_keys=[P1]` + thresholds `{trust_root_change: 2, routine_rotation: 1, ordinary_recovery: 1, elevated_recovery: 2}` + new config/policy digests);</li><li>a **trust-root change**, so **both** P4-A and P4-B sign (D10);</li><li>publish it in `zdh-trust-anchor`; copy it to `configs/trust_root/`.</li></ul> | `ssh-keygen -Y verify -f allowed_signers -I <admin> -n zdh-trust-root -s manifest.json.sig.<A\|B> < manifest.json` for A **and** B; manifest-verifier test with only one signature | `Good "ed25519" signature for <admin>` ×2; local = remote byte-for-byte; the single-signature variant is **rejected** | bad or missing signature; mismatch; the one-signature manifest is accepted | administrators publish a revocation manifest (2-of-2); delete local copies |
| **M6** New configs | M5 | add `threat_attribution_v3_1.json`, `defence_policy_v2_3.json`, `relay_config_v2.json` (existing files unchanged) | config load test; digest = manifest | loads; K-1 across 6 roles passes | mismatch | delete the new files |
| **M7** Services + coordinated relay-key rotation | M6 | <ul><li>compose: add `log-witness`, `replicator`, `attribution-signer`;</li><li>P1 writes the final `key_rollover` into the old NTFS log, which is then closed read-only;</li><li>the relay switches to new code/config, P1′ and the **`cowrie_relay_records` named volume (D14)**;</li><li>`up -d --no-deps --force-recreate ssh-relay log-witness replicator`.</li></ul> | <ul><li>per-container mount probes;</li><li>`docker inspect cowrie-ssh-relay` shows records on the named volume (no NTFS bind);</li><li>`relay_start` attested as checkpoint 1;</li><li>with a test session open, kill the witness → relay HALTED within 2 s;</li><li>`ss -tln` / `/proc/net/tcp` inside the relay;</li><li>block egress → HALTED after 15 min (test value);</li><li>delete the status file → treated as not replicated.</li></ul> | keys only in their own container; records on the named volume; on halt **both listeners closed and the open test session aborted (D12)**; halts behave as specified | any key visible elsewhere; listener open without ack; a session survives a halt; NTFS records still written | restore compose, relay code, P1 mount and the NTFS records bind; re-create the relay as today (the old log is untouched apart from the appended `key_rollover`, which still verifies with P1) |
| **M8** Dry run | M7 + **approval of a new controlled demo session** (the 26A records are older than the 24 h age limit) or a validation-only config | <ul><li>relay → witness → replicator → signer → isolated assessment;</li><li>all §7 fault injections;</li><li>recovery tests: (a) an **ordinary** halt recovered with **one** administrator signature; (b) an **elevated** halt (injected chain break) where a one-signature authorisation is **rejected** and a **two-signature** authorisation (re-baseline) is accepted;</li><li>a false "replicated" status while the off-host repository is stale → the independent monitor alerts.</li></ul> | <ul><li>checkpoint chain verify;</li><li>`git ls-remote` head;</li><li>monitor reports fresh / stale as injected;</li><li>assessment result `tail=attested`;</li><li>`recovery` checkpoints carry `category` and `signers`.</li></ul> | as specified; the 26C attacks are rejected | any property in §4 fails; any recovery accepted below its threshold | stop profiles; relay back to today's code; attribution disabled |
| **A1** Activation | M8 + **separate human approval** | assessment/signer switched to v3.1 / 2.3 | first real verified result | dry-run proposals only, approval pending | — | back to v3.0.0 / 2.2.0 |

**Deadline:** the current relay key's configured validity ends **2026-12-11**. If M7 is not complete by then, relay records stop verifying. That is fail-closed (attribution disabled), not unsafe.

## 10. D0 prerequisites and current status
**Status: BLOCKED.** No independent administrator has been named, no off-host destination exists, and none was created or contacted. Checked read-only: only `git` and `ssh-keygen` are available. The only remote is the operator's own GitHub account, whose credentials are on this host.

Required before M0:
1. **Two named independent administrators** (for example, the project guide and a department representative), each with their own GitHub account and their own device, neither with access to this host.
2. Their agreement to own `zdh-trust-anchor` and the private `zdh-witness-log`, to configure rulesets and the freshness workflow, to hold P4-A/P4-B, and to sign manifests and recovery authorisations.
3. Outbound access from the replicator container to `github.com` (SSH 22 or HTTPS 443).
4. An agreed channel for confirming fingerprints out of band.
5. GitHub plan support: private-repository rulesets and scheduled workflows on the administrators' accounts or organisation, to be confirmed by them.

## 11. Security risks and unresolved decisions

**Decisions D10–D16: APPROVED (Task 26D-6)**; see the decision record at the top. Their effect is recorded in §§2–9. Nothing in them is implemented.

| # | Approved decision |
|---|---|
| D10 | both administrators sign trust-root changes; either approves routine rotations |
| D11 | either administrator approves ordinary recovery; both approve recovery after suspected compromise, broken chains or trust-anchor changes |
| D12 | abort all in-progress sessions when either listener is halted |
| D13 | relay–witness communication is transport-independent |
| D14 | relay records move to a named volume during the coordinated relay-key rotation |
| D15 | replication status may be unsigned, is not authoritative; independent monitoring verifies repository state, signed checkpoints and freshness |
| D16 | six current key roles (two trust-root administrators counted separately); human approval is a separate seventh role |

**Still open:**
- **D0** (BLOCKED): the two independent administrators and the off-host destination.
- The **single-administrator-compromise procedure** (§8): it must be agreed by the administrators in M0.
- The **seventh role (P5)**: designed in the future human-approval task.

**Residual risks** (unchanged in kind; see the 26D-4 report §7):
- **Local Windows account or Docker administrator:**
  - **Can:** read every local private key (P1′, P2, P3, C1) through Docker or `\\wsl.localhost`, forge local records, checkpoints and results, and replace local configs and the manifest.
  - **Cannot:** rewrite off-host history, forge P4-A/P4-B signatures, or suppress the off-host freshness alarm. Forgeries are therefore detectable, but not prevented.
  - **Prevention would need:** the witness on a separate machine (D13 / future decision) and hardware-backed keys.
- **Administrator compromise:** both administrators would have to collude, or both be compromised, to re-root under 2-of-2.
- **Availability:**
  - any witness, replicator or network failure halts the honeypot until a manual, administrator-authorised recovery. This is the intended fail-closed trade-off;
  - GitHub or network outages longer than 15 min halt intake.
- **Clock skew:** the witness accepts ±5 s. Signers self-assert time, cross-checked against GitHub commit times by the administrators.
- **Implementation risk:** the Twisted relay changes (async ack gating, listener stop) are the highest-risk code. They need in-container fault-injection tests before M7.

## 12. Confirmation
- **Task 26D-6 update:** this file is the only one changed (plus its `SHA256SUMS`). Design decisions D10–D16 are **approved**. **Implementation, key provisioning and migration (M0–M8) remain unauthorised until D0 is resolved**, and activation (A1) requires its own separate approval.
- **No changes:** no code, configuration, Docker Compose, keys (relay, Cowrie host, any other), credentials, repositories or services were created, modified, generated, rotated, exported, deleted or contacted. No migration step (M0–M8) or activation was run. Attribution and automated response remain disabled. Nothing was committed.
- **Inspection scope:** the design report, the named custody documents, and the named code/config files (`attributing_relay.py`, `relay_config.json`, `checkpoints.py`, `records.py`, `correlate.py`, `result.py`, `signed_attribution.py`, `config.py`, `run_signed.py`, `docker-compose.yml`), plus read-only tool checks recorded in the 26D-4 report.
- **No protected data:** no Dataset V2, sealed evaluation output, test data or protected report folder was accessed, no repository-wide content search was run, and the earlier possible search breach was not re-investigated.

> **KEY PROVISIONING BLOCKED — INDEPENDENT ADMINISTRATOR AND OFF-HOST TRUST DESTINATION NOT CONFIRMED.**

Stopped. No implementation or migration will begin without further human approval.
