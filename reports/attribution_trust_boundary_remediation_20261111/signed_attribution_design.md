# Signed attribution results (F-1)

## Problem (Task 26B)
`ThreatAssessor.assess()` accepted the correlation output as a plain dict. The only check was its attribution config digest, which is public. A forged dict produced dry-run proposals against 10.250.25.3 (from the control client's session S5) and against an unregistered address (S4 → 203.0.113.9).

## Roles

| Component | Holds | Does |
|---|---|---|
| Relay (`cowrie/attributing_relay`) | relay record key (private) | signs relay mapping records (unchanged) |
| Attribution component (`client_attribution`) | relay record **public** key; attribution-result key (**private**, not yet provisioned) | verifies relay records, correlates sessions and authentication, **signs the complete result** (`result.py`), signs relay-log checkpoints (`checkpoints.py`) |
| Threat assessment (`threat_assessment`) | attribution-result **public** key only, pinned by SHA-256 in config v3 | **independently verifies** each result (`signed_attribution.py`); never imports `client_attribution`; contains no signing or private-key code (tested); runs in the isolated `threat-assessment` container (`run_signed.py`) |

## Format `signed-attribution-result-1`
Canonical JSON (sorted keys, `,`/`:` separators, UTF-8). `result_hash` = SHA-256 of the document without `result_hash` and `signature`. `signature` = Ed25519 over the ASCII `result_hash`. The signature therefore covers **every** field, including `signer`.

| Field | Content |
|---|---|
| `schema`, `result_id`, `issued_utc`, `not_after_utc`, `evaluation_time_utc` | identity and validity window (≤ `max_validity_seconds`, 3600 in config v3) |
| `attribution_config` | `{schema, config_version, digest}`; must equal the verifier's loaded config digest |
| `relay_log` | relay key SHA-256, verification reason, `intact`, record count, chain head, gaps, rejected lines, tail status, checkpoint results |
| `cowrie_input` | event count, first/last timestamp, SHA-256 of the canonical events |
| `sessions[]` | one entry per Cowrie session (below) |
| `signer` | `{key_id, public_key_sha256}` |
| `result_hash`, `signature` | as above |

Each session entry has exactly these fields:

| Field | Content |
|---|---|
| `cowrie_session_id` | Cowrie session ID |
| `decision`, `reason` | correlation decision (`attributable_via_proxy_mapping` or an explicit `unattributed:*` / `excluded_diagnostic`) |
| `client` | `{ip, port, role}` when attributable, otherwise `null` |
| `relay_listener` | `{ip, port, name, mode, accepted_local}` |
| `relay_to_cowrie` | `{src_ip, src_port, dst_ip, dst_port}`, the relay→Cowrie connection tuple |
| `timestamps` | relay accepted, relay upstream connected, Cowrie connect, relay closed, Cowrie closed |
| `relay_records` | `{connection_id, open {seq, record_hash}, close {seq, record_hash} \| null}`, the relay record identity |
| `close_check` | `consistent` / `session_open` |
| `authentication` | session-level login correlation (see `authentication_correlation.md`) |

Example, the real S4 entry from the validation run (`evidence/signed_result_genuine.json`):
```json
{"cowrie_session_id": "3eede5e19e25", "decision": "attributable_via_proxy_mapping",
 "client": {"ip": "10.250.25.3", "port": 42370, "role": "test_client"},
 "relay_listener": {"ip": "10.250.25.2", "port": 2222, "name": "demo", "mode": "demo", "accepted_local": "10.250.25.2:2222"},
 "relay_to_cowrie": {"src_ip": "172.22.0.2", "src_port": 59090, "dst_ip": "172.22.0.1", "dst_port": 2222},
 "timestamps": {"relay_accepted_utc": "2026-11-11T17:19:28.188322Z", "relay_upstream_connected_utc": "2026-11-11T17:19:28.190665Z",
                "cowrie_connect_utc": "2026-11-11T17:19:28.191662Z", "relay_closed_utc": "2026-11-11T17:19:37.829584Z",
                "cowrie_closed_utc": "2026-11-11T17:19:37.839892Z"},
 "relay_records": {"connection_id": "cbc790bd-c8a5-4a76-98a1-b2d679b4d773",
                   "open": {"seq": 8, "record_hash": "7730fc4d…"}, "close": {"seq": 9, "record_hash": "98b7a1cd…"}},
 "close_check": "consistent",
 "authentication": {"state": "login_success_observed", "login_success_utc": "2026-11-11T17:19:28.648479Z", "username": "demo",
                    "sensor": "0bec5a78b1cb", "n_login_success": 1, "n_login_failed": 0, "reason": "…"}}
```
Passwords are never copied into results.

## Verification inside threat assessment (`threat_assessment/signed_attribution.py`)
A result is accepted only if **all** of the following hold. Otherwise it is rejected as a whole, and none of its claims are used.
1. It is a JSON object with **exactly** the expected top-level fields and schema. Results that are unsigned (no `signature` / `result_hash` / `signer`) are rejected.
2. The attribution config is v3 with a **provisioned** result key. Configs v1/v2, and v3 with `pending_provisioning`, accept nothing.
3. `signer.public_key_sha256` equals the pin, and `key_id` = pin[:16].
4. `result_hash` is recomputed over the complete document.
5. The configured public key's SHA-256 equals the pin, and the Ed25519 signature verifies.
6. `issued_utc` is inside the key validity; validity ≤ the maximum; `issued ≤ now ≤ not_after` (not yet valid / expired are both rejected).
7. `attribution_config.digest` equals the loaded config (mismatched → rejected).
8. Session IDs are unique (duplicated entries → rejected).
9. Every entry is internally consistent (defence in depth, even for correctly signed content):
   - exact entry field set and a known decision;
   - unattributed entries name no client;
   - attributable entries need:
     - a client in the **pinned registry** with the same role;
     - a configured **demo** listener whose `accepted_local` equals the listener;
     - a relay→Cowrie source that is a configured relay address;
     - complete relay record identity;
     - `accepted ≤ upstream_connected`, `|connect − upstream_connected| ≤ skew`, accept not after connect + skew;
     - a close consistent with `close_check`;
     - for excluded diagnostic sessions, never attributable;
   - `login_success_observed` must fall within connect..close.

Across several supplied results:
- An exact duplicate is counted once.
- A `result_id` reused with different content is rejected.
- A session covered by two different results becomes `unattributed:result_conflict`.

In the assessment:
- **Cross-check:** the entry's `relay_to_cowrie.src_ip` must equal the evidence record's Cowrie-observed `src_ip`, otherwise the session is `unattributed:result_inconsistent`.
- **Registry and address checks:** the client is re-checked against the registry, then against the protected / shared / enforcement-excluded lists from the address-safety config.
- **Invalid documents:** if any supplied document is invalid, gate 7 fails for that batch, so a forged document fails closed even next to a genuine one.

The API takes signed documents only. `assess(record, attribution_results, now)` and `assess_sessions(records, assessor, attribution_results, now)` verify internally, so a pre-built verification object cannot be injected (tested).

## The assessment cannot produce or modify a valid result
- **No signing capability in code:** `threat_assessment` has no signing code, no private-key loading and no import of the signer package; tests enforce all three.
- **Any modification is detected:** changing a signed result breaks `result_hash`. Recomputing the hash breaks the signature. Re-signing with another key fails the pin.
- **No key to sign with:** the result private key is never available to the assessment.
  - The deployment key is not yet generated.
  - When it is, the plan in `key_custody.md` keeps it out of the assessment container. The container has no key mounts, no Docker socket and no network, and the probe showed it.

## Versioning
- **threat-assessment 1.2.0.** Attribution config **v3** (`configs/threat_attribution_v3.json`, digest `8b79be3c…`) pairs with policy schema **2.1** (`configs/defence_policy_v2_2.json`, 2.2.0). Any other pairing is refused at construction.
- **Withdrawn:** config v2 / policy 2.1.0 (Task 26A). Their files are unchanged, but an unsigned mapping can no longer attribute anything.
- **Legacy:** v1 / policy 2.0 remain for historical reproduction; 4,447/4,447 sessions are identical.
