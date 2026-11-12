# Task 26D-4 — Checkpoint Witness and Key Custody Plan (design only)

Date: 2026-11-12 · Design and audit only. Nothing implemented. No key generated, rotated, replaced, exported or deleted. No migration step run. Nothing committed.

## 0. Verdict
**Key provisioning remains BLOCKED.** No independently administered off-host destination exists in this environment (§3), and two approved decisions conflict with assumptions in the earlier plan (§9). The architecture below is implementation-ready. It can proceed once an independent administrator and destination exist, and once the decisions in §9 are made.

## 1. Inputs reviewed (exact paths)
- **Documents:**
  - `reports/attribution_trust_boundary_remediation_20261111/key_custody.md`
  - `reports/key_custody_final_review_20261111/{rotation_and_recovery.md, checkpoint_procedure.md, migration_procedure.md}` (read in full)
  - `reports/key_custody_final_review_20261111/residual_risks.md`
  - `reports/attribution_key_role_separation_20261112/report.md`
- **Code** (by name, from the Task 26C/26D-1 work):

  | Role | Module |
  |---|---|
  | relay signer | `cowrie/attributing_relay/attributing_relay.py` (`RecordLog`: fsync per record; no witness interaction) |
  | relay-record verifier | `client_attribution/records.py` (`verify_records`, optional verified checkpoints) |
  | checkpoint v1 | `client_attribution/checkpoints.py` (`make_checkpoint`, `verify_checkpoints`; v1 has no chain between checkpoints and no acknowledgement) |
  | attribution-result signer | `client_attribution/result.py` |
  | attribution-result verifier | `threat_assessment/signed_attribution.py` |
  | pins and K-1 rule | `threat_assessment/config.py` |

- **Current pins:**
  - `configs/threat_attribution_v3.json`: `proxy_client_mapping.public_key_sha256 = a52b8c52…` (relay, validity 2026-11-11 → **2026-12-11**); `attribution_result.status = pending_provisioning`.
  - No witness pin exists.
  - The K-1 rule covers the relay and result roles only.
- **Environment, checked read-only:**
  - Installed: `git` and `ssh-keygen` (Windows OpenSSH).
  - **Not installed:** `gh`, `aws`, `az`, `gcloud`, `rclone`, `restic`, `gpg`, `minisign`.
  - The only remote is `origin = github.com/MadhumithraaTS/adaptive-zero-day-honeypot`. Its credentials are held by Git Credential Manager **on this host** for that same account.
  - OneDrive is running under the same Microsoft account; it does not sync the repository.

## 2. Recommended architecture and trust boundaries

```
 demo/published clients
          │
   ┌──────▼───────┐  1 append record (P1)   ┌───────────────┐ 3 append checkpoint (P3)  ┌────────────────────┐
   │ ssh-relay    │────────────────────────▶│ relay records │◀── read-only ───┐          │ checkpoint store   │
   │ (holds P1)   │  2 attest request ──────────────────────────────────────▶│ log-witness (P3) ├────────▶│ (append-only vol)  │
   │              │◀──── 4 durable ack (checkpoint hash) ── UNIX socket ─────┘          └─────────┬──────────┘
   └──────────────┘                                                                               │ read-only
                                                                                       ┌──────────▼──────────┐ 5 push (C1)  ┌───────────────────────────┐
                                                                                       │ replicator (no keys │─────────────▶│ OFF-HOST witness-log repo │
                                                                                       │ except C1)          │◀── compare ──│ OFF-HOST trust-anchor repo│
                                                                                       └─────────────────────┘   anchors    │ (independent admin, P4)   │
                                                                                                                             └───────────────────────────┘
 attribution-signer (P2): reads relay records + checkpoint store (ro) + Cowrie log (ro) → signed results
 threat-assessment (public keys + trust-root manifest only, network none) → verifies everything
```

| Component | Holds | Can write | Network | Never has |
|---|---|---|---|---|
| `ssh-relay` | P1 | relay records; the witness request socket | demo/frontend/internal (unchanged) | P2, P3, C1, store write access |
| `log-witness` (new) | P3 | checkpoint store | **none** (UNIX socket on a shared volume) | P1, P2, C1, Cowrie data |
| `replicator` (new) | C1 (repo-scoped push credential) | nothing local | egress to the off-host host only | P1–P3; store write access |
| `attribution-signer` (new) | P2 | its output volume | none | P1, P3, C1 |
| `threat-assessment` (existing) | public keys + trust-root manifest | its work output | none | any private key or credential |
| Independent administrator | P4 trust-root key (own device), off-host repository admin rights | trust-anchor repo; repo rulesets | — | access to this host |

Trust boundaries:
1. The relay can produce records but cannot attest them.
2. The witness can attest but cannot create relay records or results.
3. The signer can attribute but cannot attest.
4. The assessment can only verify.
5. **Only the independent administrator** can define the trust root or rewrite off-host history.

## 3. Off-host destination

**Finding: no suitable destination exists today.**
- The existing GitHub account and repository are controlled from this host (Git Credential Manager), so a local compromise also controls them.
- OneDrive is the same personal account.
- No cloud account or immutable-storage service was found, and none is assumed.

**Recommendation: two GitHub repositories owned by an independent administrator** (for example, the project guide or a department/organisation account they administer, *not* `MadhumithraaTS`). Only `git` is needed, which is already installed.

| Repository | Content | Who writes | Protection (GitHub ruleset on the default branch; bypass list = independent admin only) |
|---|---|---|---|
| `zdh-trust-anchor` | signed trust-root manifests (§6), P4 public key, history of approved digests | **independent admin only** | block force-push, block deletion, require linear history, require signed commits |
| `zdh-witness-log` | `checkpoints/<YYYY-MM-DD>.jsonl`, append-only, one commit per batch | `replicator`, using **C1 = an SSH deploy key with write access to this repository only** | block force-push, block deletion, require linear history (fast-forward only). An `on: schedule` workflow **owned by the admin** raises an alert if no commit arrives within the freshness bound |

| Aspect | Design |
|---|---|
| **Access control** | <ul><li>This host can only fast-forward `zdh-witness-log`. It can append, but cannot rewrite or delete history, and cannot change rulesets.</li><li>It has read access only to `zdh-trust-anchor` (public, or read-only token).</li><li>C1 is not a personal credential; revoking it is a single admin action.</li></ul> |
| **Retention** | <ul><li>Indefinite in GitHub.</li><li>The admin also exports a monthly archive to their own storage.</li><li>Local stores are kept for at least the full lifetime of every key that signed into them.</li></ul> |
| **Independent recovery** | <ol><li>The admin clones both repositories to a fresh machine.</li><li>Verify the trust-anchor manifests with P4 (`ssh-keygen -Y verify`).</li><li>Verify the checkpoint chain (§5) with the P3 public keys listed in those manifests.</li><li>Compare against any surviving local relay log.</li></ol>None of this requires anything from the compromised host |
| **Visibility** | Checkpoints contain only hashes, sequence numbers and timestamps, with no session content. A public repository is acceptable, but reveals activity timing (see §9) |

**Prerequisites (blocking):**
1. A named independent administrator with their own GitHub account and a device that is not this host.
2. They create both repositories and their rulesets, and the scheduled freshness workflow.
3. They generate P4 on their own device and publish its public key.
4. They add C1 (generated in the replicator container, public half only) as a write deploy key.
5. Outbound HTTPS/SSH to `github.com` must be allowed for the replicator container.

**Alternatives** (each also needs an independent account):
- object storage with compliance-mode retention (S3 Object Lock / Azure immutable blob / GCS bucket lock);
- an institutional WORM or append-only log server;
- a second physical machine (for example a single-board computer) running `log-witness` and the store. This is strongest for P3, because it removes the key from this host entirely.

## 4. Key roles and lifecycle

| Role | Key | Status | Generated where | Stored / mounted | Pinned in | Validity | Rotation | Revocation | Backup | Compromise response |
|---|---|---|---|---|---|---|---|---|---|---|
| Relay record signing | **P1** Ed25519 | live, retained | (exists) | NTFS `secrets/` (madhu:R) → relay read-only | attribution config `proxy_client_mapping`; trust-root manifest | config window ends **2026-12-11** (decision D1) | new key in a one-shot container into a named volume; `key_rollover` record signed by the old key; new config/manifest | manifest `revoked` entry + new config version | none (rotate on loss) | stop the relay; records after the last **off-host** checkpoint untrusted; rotate |
| Attribution-result signing | **P2** Ed25519 | not generated | one-shot container, `--network none`, into `cowrie_attribution_result_key` | volume, 0400 uid 999 → signer only | `attribution_result`; manifest | **30 days** | at day 25: new key, new manifest, cut-over (results live ≤ 1 h, so no overlap needed) | manifest `revoked`; verifier rejects at/after `revoked_at` | none | switch the assessment to the pending config (fail closed); results since compromise untrusted; rotate |
| Checkpoint witness | **P3** Ed25519 | not generated | one-shot container into `cowrie_checkpoint_witness_key` | volume, 0400 uid 999 → `log-witness` only | new `checkpoint_witness` block; manifest | **30 days** | at day 25: new key; the first checkpoint under the new key is a `key_rollover` checkpoint signed by **both** keys, re-attesting the current head; overlap ≤ 5 days | manifest `revoked` | none | stop the witness → the relay halts (§5); trust stops at the last off-host checkpoint before the compromise; rotate; re-attest from the off-host log |
| Trust root | **P4** Ed25519 (SSH signing key, namespace `zdh-trust-root`) | not generated | **admin's own device** | never on this host | public key in `zdh-trust-anchor` and pinned locally (§6) | 1 year (decision D5) | admin signs a manifest naming the successor; both are published | admin publishes a revocation manifest | admin's responsibility (offline copy) | admin re-roots publicly; local verifiers refuse until the new root is confirmed off-host |
| Off-host push credential | **C1** SSH deploy key (authentication only, never a signing role) | not generated | replicator one-shot container | volume → replicator only | GitHub deploy-key list (admin) | **30 days** | add new, remove old (admin) | admin deletes the deploy key | none | admin revokes; an attacker can only append to the log, which stays detectable, and cannot rewrite it |
| Human approval | P5 | future task | off-host, approver device | never on this host | manifest | TBD | — | — | — | out of scope |
| Cowrie SSH host keys | (honeypot identity) | live | — | Cowrie volume | — | — | per the K-3 report | — | — | not an attribution role |

**Key-role rule extension (code, not implemented).** The K-1 check (distinct canonical pins) must cover P1, P2, P3, P4 and C1's public key. The manifest verifier rejects any manifest in which two roles share a key.

**Expiry enforcement (code, not implemented):**
- Every signer refuses to start, or to sign, outside its key's `not_before`/`not_after` from the manifest.
- Verifiers already reject signatures made outside validity.
- At 30 days without rotation, the system fails closed: no new checkpoints → relay halts → no attribution.

## 5. Checkpoint protocol (`relay-log-checkpoint-2`)

**Format** (canonical JSON):
- **Fields:**

  | Field | Meaning |
  |---|---|
  | `schema` | `relay-log-checkpoint-2` |
  | `log_id` | the relay log being attested |
  | `checkpoint_seq` | witness counter, +1 per checkpoint, from 1 |
  | `prev_checkpoint_hash` | links to the previous checkpoint; 64 zeros for the first |
  | `kind` | `attest` / `heartbeat` / `key_rollover` / `fault` |
  | `relay_seq`, `relay_record_hash`, `relay_record_type`, `relay_record_written_utc` | the relay record being attested |
  | `attested_utc` | time of attestation |
  | `trust_anchor_digest` | SHA-256 of the active signed trust-root manifest |
  | `witness_key_id` | identity of the signing witness key |
  | `checkpoint_hash`, `signature` | see the hashing rule below |

- **Hashing and signing:** `checkpoint_hash` = SHA-256 over the canonical JSON without `checkpoint_hash`/`signature`. `signature` = Ed25519 (P3) over the ASCII `checkpoint_hash`.

**Linkage:**
- **Two chains:** the checkpoint chain (by `prev_checkpoint_hash`) and the relay chain (by relay `seq`/`prev_hash`).
- **Cross-linking:** each attest checkpoint names exactly one relay record. Each relay record after the first carries `witness_ack {checkpoint_seq, checkpoint_hash}` for the **previous** record, a relay format extension. Rewriting either side alone therefore breaks the other.

**Per-append protocol (approved: one checkpoint per accepted record):**
1. The relay writes and fsyncs record *n* (as today).
2. The relay sends `{log_id, seq: n, record_hash}` to the witness over a UNIX socket on a shared named volume (no IP path).
3. The witness **reads record *n* from the relay log itself** (read-only mount; it never trusts the message). It verifies the P1 signature, that `seq = last_attested + 1`, that `prev_hash` links, and that `witness_ack` in *n* equals its own previous checkpoint.
4. The witness builds and signs the checkpoint, appends it to the store, and runs `fsync(file)` then `fsync(directory)`. That is the **durable local acknowledgement**.
5. The witness replies `ack {checkpoint_seq, checkpoint_hash}`. The relay requires an ack within **T_ack = 2 s** (decision D3).
6. Only after the ack does the relay resume the client (for an open record) or count the close as complete.
7. The replicator pushes new checkpoints to `zdh-witness-log` at most every **R = 30 s**, with a lag bound **L_max** (decision D2).

**Heartbeats.** With no relay activity, the witness writes a `heartbeat` checkpoint every **60 s**, re-attesting the head and the trust-anchor digest. The replicator pushes them too, so off-host freshness is observable.

**Failure behaviour (approved: stop accepting new records):**

| Failure | Behaviour |
|---|---|
| no ack, negative ack, witness unreachable, store fsync error | The relay enters **HALTED**: it stops both listeners (no new connections, so no new records). The pending record stays on disk as `unattested`; established sessions are closed. Correlation treats unattested records as a gap → `log_gap` (fail closed) |
| witness detects a broken relay chain or bad signature | writes a `fault` checkpoint, refuses further attestation → relay HALTED |
| replicator lag > L_max, or off-host push rejected | the witness refuses new attestations (configurable, D2) → relay HALTED |
| trust-anchor digest mismatch (local vs. off-host) | the replicator signals the witness; the witness writes `fault` and halts |
| P3 outside validity / revoked | the witness refuses → relay HALTED |

**Freshness checks:**
- **Attribution signer:** refuses to sign if the newest local checkpoint is older than **120 s**, or if the newest **off-host** checkpoint (read back through the replicator status) is older than **L_max**.
- **Assessment:** accepts a signed result only if its `relay_log.tail.status = attested` and its checkpoint is within the freshness bound (verifier rule, not implemented).

**Recovery:**
1. The operator fixes the cause.
2. The witness restarts. It re-verifies the whole relay log against its store and the off-host log, and attests the pending record(s) in order if the chain is intact.
3. The relay leaves HALTED **only by an explicit operator command** that is itself recorded (decision D4).
4. If the chains disagree, the off-host log wins. Everything after the divergence is untrusted and attribution stays disabled until the next manifest.

**Stale or rolled-back store.** If a local store is older than the off-host log (for example after a restore), the witness refuses to continue until it has replayed the off-host checkpoints and verified that they extend its local chain.

## 6. Trust anchors that one local account cannot silently replace
1. **Trust-root manifest** (`zdh-trust-root-manifest-1`, JSON), signed by **P4 on the admin's device** (SSH signature, namespace `zdh-trust-root`, made with `ssh-keygen -Y sign`). Contents:
   - `version`, `issued_utc`, `valid_until`, `previous_manifest_sha256`;
   - `roles {relay_record, attribution_result, checkpoint_witness, replicator_push}` → `{sha256, not_before, not_after}`, plus a `revoked[]` list;
   - `digests {attribution_config, policy, address_safety, session_exclusions}`.
2. **Published** in `zdh-trust-anchor`, which only the admin can write. Locally, the signed manifest, its signature and the P4 public key sit in `configs/trust_root/`.
3. **Verifiers** (signer, witness, assessment) refuse to start unless:
   - the manifest signature verifies with P4;
   - every loaded pin and config/policy digest equals the manifest;
   - the K-1 rule holds across all roles.
4. **Why local replacement is not silent:** an attacker with the local account can replace the configs, the policy, the local manifest and the local P4 copy together. They still cannot:
   - write the off-host `zdh-trust-anchor` repository, whose rulesets and admin are independent;
   - stop the change appearing off-host. Every witness checkpoint carries `trust_anchor_digest`, so a new root changes that field in the very next heartbeat, which is pushed to `zdh-witness-log` that the attacker cannot rewrite;
   - stop the check. The replicator compares the local manifest with `zdh-trust-anchor` before every push and halts on mismatch. If the attacker disables the replicator, the admin's scheduled workflow raises a freshness alert;
   - fool the admin's own check: the admin verifies `trust_anchor_digest` against their own manifest history.
5. **Result:** a local re-rooting can make local components accept new keys, but it **cannot do so silently**. It shows up off-host within one heartbeat interval plus the push interval, or as a freshness alarm. This is detection, not prevention.

## 7. Threat analysis and residual risks

| Threat | Effect with this design | Residual |
|---|---|---|
| Relay process compromise | can sign false records for real sessions (P1). Cannot attest, sign results, or rewrite already-attested history (cross-links + off-host log) | false mappings for new sessions until detected; limited to registered clients; only .3 can be a proposal subject |
| Assessment process compromise | holds no private key or credential; network none; cannot forge results or checkpoints | none for key material |
| Attribution-signer compromise | can sign false results for ≤ 1 h validity windows; cannot attest the log | rotate P2 |
| Witness compromise | can sign false checkpoints locally, but cannot rewrite the off-host log or the relay's `witness_ack` cross-links | detected on comparison with off-host |
| Replicator / C1 compromise | can push extra commits; cannot rewrite or delete history (rulesets) | an append is detectable (signature check fails on non-P3 content) |
| Network outage | replication lag → relay halts after L_max (if D2 = halt) | honeypot unavailable during the outage (availability cost, by design) |
| **Local Windows account / Docker administrator compromise** | controls P1, P2, P3, C1 and every local config, store and container; can read all named volumes via `\\wsl.localhost` and Docker (Task 26C). Can forge new records, checkpoints and results locally, and can re-root locally | **Cannot rewrite off-host history or the off-host trust root.** Forgeries after the compromise are local-only and detectable through `trust_anchor_digest`, checkpoint-chain comparison and freshness alarms. Everything after the last off-host checkpoint before the compromise must be distrusted. Prevention would require P3 (and ideally P1/P2) off this host (second machine) or in non-exportable hardware |
| Independent administrator compromise | could re-root and rewrite off-host history | out of scope; mitigate with 2 admins / organisation ownership |
| Clock manipulation | signers self-assert time | cross-checked against GitHub commit times and admin-side freshness |

## 8. Step-by-step migration plan (supersedes `key_custody_final_review_20261111/migration_procedure.md`)
Rollback at **every** step returns to today's state: v3.0.0 / policy 2.2.0 with the result key pending (attribution disabled, fail closed), the current relay code and P1 unchanged.

| Step | Preconditions | Action | Verification | Rollback |
|---|---|---|---|---|
| M0 | all of §9 decided; independent admin named | admin creates `zdh-trust-anchor` and `zdh-witness-log`, rulesets and freshness workflow; generates P4 on their device; publishes the P4 public key | the rulesets block force-push and deletion (admin test push); the P4 fingerprint is confirmed out-of-band (e.g. read aloud or on paper) | admin deletes the repositories; nothing local changed |
| M1 | M0 | **code (separate approved implementation task):** checkpoint v2 + witness service; relay witness client with HALTED state and `witness_ack`; replicator; trust-root manifest verifier; K-1 rule over all roles; signer/assessment freshness rules; key-validity enforcement at signer start; revocation list. Full tests, including every failure in §5 | test suite green; 26C/26D-1 attacks still rejected | revert the code; nothing deployed |
| M2 | M1 | snapshot: compose, configs, ACLs, container IDs, manifests (SHA-256) | manifest written | — |
| M3 | M2 | create volumes (P2, P3, C1, checkpoint store, witness socket, signer output) | `docker volume inspect` | remove the empty volumes |
| M4 | M3, approval | generate P2, P3 and C1 in one-shot, network-less containers; export **public halves only** | no private header outside the volumes; three distinct identities; K-1 check | destroy the unused volumes |
| M5 | M4 | admin adds C1 as a deploy key; admin signs manifest v1 (P1, P2, P3, C1 pins + new config/policy digests) and publishes it | local manifest = off-host manifest; signature verifies with P4 | admin publishes a revocation manifest; delete the local copies |
| M6 | M5 | new configs `threat_attribution_v3_1.json` / `defence_policy_v2_3.json` (existing files unchanged) | they load; their digests equal the manifest | delete the new files |
| M7 | M6 | compose: add `log-witness`, `replicator`, `attribution-signer` (profiles); relay mounts the witness socket and the new code. **This is the relay restart:** P1 is unchanged and `relay_start` is attested as checkpoint 1 | additive compose diff; per-container probes (each key only in its own container); the relay refuses to accept connections without the witness (kill the witness → HALTED) | restore the compose and relay code; restart the relay as today |
| M8 | M7 | dry run: new controlled demo session (needs **separate** approval) or a validation-only config; full chain relay → witness → replicator → signer → isolated assessment | per-append checkpoints; off-host commits; the admin workflow sees freshness; all §5 failure injections behave as specified | stop the profiles; return the relay to today's code |
| **A1** | M8 + **separate activation approval** | run the signer and assessment with v3.1 / policy 2.3 | first real result verifies with `tail = attested` | switch the assessment back to v3.0.0 / 2.2.0; stop the profiles |

Constraint: the Task 26A captured relay records are older than the 24 h age limit, so M8 needs a new approved demo session or a validation-only config.

## 9. Unresolved decisions requiring human input

| # | Decision | Recommendation |
|---|---|---|
| **D0** | **Who is the independent administrator, and which destination?** (blocking) | the project guide or an organisation account; the two GitHub repositories of §3 |
| **D1** | **Relay key window conflict.** "Retain P1" vs. its configured validity ending **2026-12-11**, after which records are rejected (fail closed). Rotate P1 before then (new 30-day key), or approve one validity extension through a signed manifest? | rotate P1 at M4, alongside P2/P3, under the same 30-day policy |
| **D2** | Should off-host replication lag halt the relay, and what is L_max? | yes; L_max = 15 min |
| **D3** | Witness ack timeout T_ack | 2 s |
| **D4** | Relay recovery from HALTED: manual only, or automatic after the witness recovers? | manual, recorded |
| **D5** | P4 validity, and one or two independent administrators | 1 year; two admins if available |
| **D6** | `zdh-witness-log` public or private (timing visibility vs. ease of independent audit) | private, with read access for auditors |
| **D7** | Should the HALTED state stop both listeners (strict reading of the approved rule) or only the demo listener? | both |
| **D8** | Approval of the code changes in M1, which change relay behaviour (an earlier plan said "no relay change"; the approved per-append checkpoint rule requires one) | approve as a separate implementation task |
| **D9** | Long-term: move P3 (and the store) to a second physical machine | recommended when hardware is available |

## Confirmations
- Design only. No keys were generated or modified; the relay key, configs, policy, gates, severity, behavioural evidence and the live Cowrie host keys are unchanged; no migration step was run.
- Inspection was limited to the named documents, the named code modules and environment tool checks. No Dataset V2, sealed output, test data or protected report folder was accessed, and no repository-wide search was run.

Stopped.
