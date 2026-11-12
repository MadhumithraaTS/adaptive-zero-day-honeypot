# Authentication analysis

## How successful authentication is established

**1. Evidence engine** (`behavioural_evidence/engine.py`, `_auth`, unchanged since Task 22). For each session:
- If there are no `login.failed` or `login.success` events, the status is `no_authentication_events`.
- **Else, if `src_ip` ∈ `relay_sources`** (172.22.0.2), the status is **`indeterminate:shared_source`**. The engine stops here: it does not evaluate success or failure patterns, because failures from many clients behind one relay would be pooled per source.
- Otherwise, the AUTH-1/AUTH-2 window logic gives `repeated_failures[+success]`, `below_threshold` or `success_without_repeated_failures`.

**2. Assessment** (`threat_assessment/assessment.py`, gate 4, unchanged since Task 24). The login basis is:
- `authentication_status=<status>` if the status is `success_without_repeated_failures` or `repeated_failures+success`;
- otherwise **"command input recorded"** if `n_input_lines > 0`;
- otherwise none, and gate 4 fails.

The input basis was approved and documented in Task 24 (`implementation_inventory.md` row 4; `limitations.md` §13): Cowrie records command input only after authentication.

## Can verified client attribution influence authentication status? No.
- **Order of processing:** `authentication_status` is computed by the evidence engine before, and independently of, any attribution. It depends only on the session's `src_ip` and its auth events. Relay sessions are `indeterminate:shared_source` whatever the real client is.
- **Separation of code:** `client_attribution` only reads Cowrie events and relay records. `attribute()` reads the record and returns a new dict. `assess()` deep-copies the record first.
- **Probe:** S4 with and without the mapping gave `authentication_status` = `indeterminate:shared_source` and the same login basis both times. The record was unchanged after assessment.
- **Regression:** the 26A findings were identical with and without the mapping for all five sessions.

## Can an indeterminate status satisfy the successful-login requirement? Not by itself. (verified)

| Probe (in-memory copy of S4) | `authentication_status` | input lines | Gate 4 | Tier |
|---|---|---|---|---|
| as captured | indeterminate:shared_source | 4 | **true** (basis: command input) | propose |
| input removed | indeterminate:shared_source | 0 | **false** | review |
| status set to `success_without_repeated_failures`, input removed | success… | 0 | true (basis: status) | propose |
| status set to `no_authentication_events`, input kept | no_authentication_events | 4 | true (basis: command input) | propose |

`indeterminate:shared_source` is not in `LOGIN_STATUSES`, so it is never itself a basis. For relay sessions, however, gate 4 is always decided by the input basis alone.

## Finding F-2 (Medium): the gate 4 basis is an inference, not an observed login event
- **Design vs implementation:** the Task 23 mapping (`defence_policy_mapping.md` line 8) required that "the subject session must have `cowrie.login.success` (a logged-in session with input)". Task 24 implemented the requirement as status **or** input, and documented that choice.
- **What the record lacks:** for relay sessions, the evidence record contains no field showing that `login.success` occurred. The AUTH rules are skipped, and no login-success indicator is emitted.
- **The gap:** the last probe shows that gate 4 also passes for a record whose status says *no authentication events* but which has input. Normal Cowrie telemetry cannot produce such a session. Even so, gate 4 does not consult login events.
- **Effect on S4: none.** S4 has both the input and a raw `cowrie.login.success` event (17:19:28.648479Z, user `demo`), so it satisfies the design wording and the implementation.
- **Not changed (audit only).** A future option, for a separately approved task, would expose per-session login success in the evidence record and require it in gate 4. That requires a new evidence catalogue version.

## Context
- On this honeypot, "successful login" means configured acceptance: `userdb.txt` accepts almost any credential. It does not indicate a real compromise; this is unchanged from Task 23 limitations.
- AUTH-based findings stay indeterminate for relay sessions even when the client is attributed. Attribution decides *who*; it does not reinterpret behaviour (requirement 12 of Task 26A).
