# Authentication evidence (F-2)

## Cowrie `login.success` structure (captured S4 event)
```json
{"eventid": "cowrie.login.success", "username": "demo", "password": "demo-pass", "message": "login attempt [demo/demo-pass] succeeded",
 "sensor": "0bec5a78b1cb", "uuid": "bafc61de-…", "timestamp": "2026-11-11T17:19:28.648479Z", "src_ip": "172.22.0.2",
 "session": "3eede5e19e25", "protocol": "ssh"}
```
- There is no `src_port` (as with `session.closed`), so the event can be tied to a connection only by **session ID**.
- `uuid` is the sensor instance ID, not an event ID.

## Session-level correlation (`client_attribution/authentication.py`)
This runs in the attribution component, independently of `behavioural_evidence`, which is unchanged. For each Cowrie session ID:

| Condition | State |
|---|---|
| exactly one `session.connect`, exactly one `login.success`, at most one `session.closed`; success `src_ip` = connect `src_ip`; sensor equal (when present); connect ≤ success ≤ close | `login_success_observed` |
| no `login.success` under this session ID | `indeterminate:no_login_success_event` |
| several connects, several successes, several closes, source or sensor mismatch, success outside connect..close, unparseable time | `indeterminate:ambiguous` |

Command input is never examined. The output carries `login_success_utc`, `username`, `sensor`, and the success/failure counts; the password is never copied. The block is included in every signed session entry and verified by threat assessment, which re-checks that the login time lies within connect..close.

## Eligibility rule (policy schema 2.1, `require_authentication_event: true`, cannot be relaxed)
`ThreatAssessor._authentication_event`:

| Source | Successful login is established only by | Otherwise |
|---|---|---|
| Direct (not relay / trusted proxy) | `authentication_status` ∈ {`success_without_repeated_failures`, `repeated_failures+success`}, which the evidence engine derives from `cowrie.login.success` | gate 4 fails |
| Relay | a **verified** signed result whose session entry is `login_success_observed`, whose relay tuple matches the record's `src_ip` | gate 4 fails; `authentication_evidence.state` explains why (`indeterminate:no_verified_result`, `indeterminate:no_login_success_event`, `indeterminate:ambiguous`) |

- `n_input_lines` is never consulted under policy 2.1: **typed commands alone cannot establish authentication.**
- `authentication_status` from behavioural evidence is passed through unchanged. It stays `indeterminate:shared_source` for relay sessions, and indeterminate interpretation is preserved.
- Legacy policy 2.0 keeps the Task 24 rule (input basis), only so that historical V1 results reproduce exactly (4,447/4,447).

## Results

| Case | Gate 4 |
|---|---|
| Real S4 (signed, verified) | **true**: "cowrie.login.success at 2026-11-11T17:19:28.648479Z correlated by session ID (signed result task26c-validation-genuine)" |
| Real S5 | true (17:19:45.563217Z); S5 still never proposes (`enforcement_excluded`) |
| Real S1–S3 (banners) | `indeterminate:no_login_success_event` |
| Synthetic relay session with 4 typed commands and no `login.success` | **false**; tier review |
| Login event inside a rejected or forged result | false (`indeterminate:no_verified_result`) |
| Direct source, commands but no login event | false |
| Missing / duplicated / before-connect / after-close / source-mismatch / sensor-mismatch / double-connect login | indeterminate (7 tests) |
