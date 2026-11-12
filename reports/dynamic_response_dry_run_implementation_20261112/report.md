# Task 27B — Dynamic Response & Feedback: Dry-Run Implementation

Date: 2026-11-12 · **DRY-RUN ONLY.** No real response executed, no firewall command, no address restricted, relay listeners untouched, enforcement not enabled, live attribution not activated, no production key generated. Nothing committed.

Design: `reports/dynamic_response_feedback_design_20261112/report.md` (R1–R6 approved).

## 1. Files created and modified

**Created:**

| File | Purpose |
|---|---|
| `dynamic_response/__init__.py` | package (`dynamic-response-1.0.0-dry-run`) |
| `dynamic_response/common.py` | canonical JSON, SHA-256, UTC timestamps, `ResponseError` |
| `dynamic_response/config.py` | `response-policy-1` loader; **refuses** `mode ≠ dry_run`, `enforcement_activated ≠ false`, TTL > 900 s, attribution ≠ relay-mapped, unsupported actions; approver registry (public keys only) |
| `dynamic_response/rules.py` | target validation (single IPv4 /32 from the address-safety allowlist) and time-window validation |
| `dynamic_response/proposals.py` | proposal intake from threat-assessment `propose` outputs plus the assessment audit chain (read-only) |
| `dynamic_response/approval.py` | approval verification (`response-approval-1`); never creates approvals |
| `dynamic_response/approve_cli.py` | approver tool for the **approver's own device**; the only signing code in the package; tests use in-memory fixture keys |
| `dynamic_response/controller.py` | dry-run response controller |
| `dynamic_response/states.py` | lifecycle state machine |
| `dynamic_response/audit.py` | separate response audit log (`response-audit-1`) + verifier |
| `dynamic_response/relay_interface.py` | relay enforcement boundary, **explicitly disabled** (every call raises) |
| `dynamic_response/feedback.py` | outcome records, annotations, review queue, metrics |
| `configs/response_policy_v1.json` | `mode: dry_run`, `enforcement_activated: false`, `max_ttl_seconds: 900`, `proposal_validity_seconds: 1800`, skew 5 s; address-safety digest `657aa680…` pinned; **approver registry `pending_provisioning`, empty** |
| `tests/test_dynamic_response.py` | 105 tests (T1–T20) |

**Modified: none.** Unchanged and verified (`unchanged_and_no_enforcement.txt`):
- `threat_assessment/*`, including `assessment.py`, `attribution.py`, `config.py`, `signed_attribution.py`, `audit.py` and `severity.py`;
- `behavioural_evidence/` (9/9);
- configs (v3 attribution, policy 2.2.0, address safety);
- relay code, config and public key;
- `cowrie/docker-compose.yml`;
- the frozen models (16/16 in the novelty freeze manifest).

The assessment audit log is not weakened: its `execution_status = not_executed` invariant is untouched.

## 2. Approval workflow (R1, R3)
1. **Proposal:** the controller creates a `response-proposal-1` (proposal ID `prop-<assessment record_id>`, `proposal_hash`, 30-minute validity).
2. **Signing:** the approver (one person, R3) signs **the exact rule** with `approve_cli.py` on their own device. The signed `response-approval-1` covers:
   - proposal ID and proposal hash;
   - decision and reason, approver name and key ID, decision time;
   - the rule: `rule_id`, action `restrict_new_connections`, target `a.b.c.d/32`, listener `demo`, `ttl_seconds`, `created_utc`, `expires_utc`, and the **fingerprints** of the response policy, address-safety config, defence policy and attribution config.

   `approval_hash` is the SHA-256 of the canonical document; the Ed25519 signature is over `approval_hash`.
3. **Verification:** the controller **verifies only**. **Any modification invalidates the approval** (tested on target, duration, expiry, fingerprints, proposal ID, decision, action and approver name). It checks:
   - the exact field set;
   - the hash;
   - the key is in the registry and is not a key of another role (relay or result key);
   - the name matches the registry;
   - the signature;
   - the approver key is valid at the decision time, and the decision is not dated in the future;
   - the approval refers to this exact proposal, and was decided within the proposal's validity;
   - action, listener and target equal the proposal;
   - the fingerprints equal both the proposal and the current configuration;
   - duration ≤ the proposal maximum (≤ 900 s), and expiry = creation + duration;
   - the rule is not expired.
4. **One decision per proposal.** Replayed documents are rejected, and **a rejection is final.**
5. **No production approver key exists.** The repository registry is empty, so no approval can verify until P5 is provisioned through a 2-of-2 trust-root manifest.

## 3. Controller architecture
**Pipeline:** `intake` → `submit_decision` → `execute` (dry-run) → `record_verification` → automatic simulated rollback on failure, expiry or revocation → `record_rollback_verification`, with `tick` handling expiry.
- **Every refused operation** is written as `operation_rejected` with its reason (never ignored silently).
- **No keys or privileged access** (static and runtime tests, T8): the controller holds **no private key**, does not import the approver tool, has **no Docker, process, socket, HTTP or firewall code**, and writes nothing except the response audit file (when a path is given). It cannot modify trust anchors or configs.
- **Relay boundary:** `DisabledRelayEnforcement` raises `EnforcementDisabledError` on every call. The controller never calls it in dry-run (a spy recorded **0 calls** across complete workflows), and `execute(mode="enforce")` is refused with `enforcement_not_activated`.

## 4. Allowlist and expiry enforcement
- **Targets** (`rules.validate_target`) are checked against `configs/address_safety_v1.json` through the v3 attribution config, at intake, at approval and at execution:
  - only a single IPv4 `/32` inside `enforcement_allowlist` is accepted (today only **10.250.25.3/32**);
  - rejected: the control client (10.250.25.4), protected networks (relay, Docker networks, loopback), shared sources, non-allowlisted addresses, multiple addresses (comma/space lists, `/31`, `/28`), IPv6 and IPv4-mapped IPv6, malformed and non-string input;
  - the allowlist is never expanded, and the response policy must pin the same address-safety digest as the attribution config.
- **Attribution (R4):** intake requires all of the following, otherwise there is no proposal:
  - tier `propose` with all gates true;
  - a pending, unexecuted dry-run proposal;
  - `session_attribution = attributable_via_proxy_mapping` from a result listed as **accepted** in the assessment's verified signed-attribution results, with no rejected results;
  - subject = mapped client = proposal subject, and the relay connection matches;
  - exactly one matching entry in a **verifying** assessment audit chain.

  Direct (non-relay) sources and unattributed sessions are refused.
- **Expiry (R2):**
  - maximum 900 s (the loader refuses higher, and approvals are rejected above the proposal maximum);
  - expiry must equal creation + duration;
  - proposals expire after 30 minutes, and approvals decided after that are rejected;
  - rules that expire before execution are refused;
  - `tick` expires active responses and starts the rollback;
  - **nothing is ever renewed**: re-execution and new approvals after expiry are rejected.

## 5. Verification and rollback (R5)
**Operator-supplied verification** `{verification_id, proposal_id, kind, restriction_observed, control_unaffected, verified_utc, operator, evidence_ref, result}`:
- **Dry-run expectation, recorded with each verification:** no real restriction observed **and** the control client unaffected.
- **Success** (`verification_passed`, state `verified_dry_run`): all fields complete **and** both expectations met **and** `result = pass`.
- **Never success:** missing or blank evidence/operator, non-boolean observations, unknown result → `incomplete` → `verification_failed`. Partial outcomes, `unexpected_effect` and operator-reported failure also give `verification_failed`. A future-dated or foreign verification is refused.
- **Replays:** a replayed verification ID is refused.
- **Reserved state:** `verified_effective` (real enforcement confirmed) does not exist in this version.

**Rollback** (simulated inverse `remove_restriction`, `relay_contacted: false`):

| Case | Behaviour |
|---|---|
| failed or partial verification | `verification_failed` → `rollback_started` automatically |
| expiry | `rule_expired` (`renewed: false`) → `rollback_started (reason: expiry)` |
| normal (revocation) | `revoked` → `rollback_started`; a second revoke is rejected |
| rollback verification passes | `rollback_verified` → `rolled_back` |
| rollback verification fails | `rollback_failed`; it **remains failed**. At TTL it becomes `rollback_failed_closed` and never `rolled_back` |
| duplicate rollback attempt | rejected (`duplicate or invalid rollback attempt`) |

## 6. Response audit implementation
`response-audit-1`, separate from the assessment audit:
- **Entry fields:** `sequence`, unique `event_id`, `previous_hash`, `record_hash`, `event`, `proposal_id`, `mode: dry_run`, `from_state`, `to_state`, `details` and `refs` (proposal, assessment-record, approval, rule and evidence hashes or IDs).
- **On append:** the state machine is enforced, so invalid transitions cannot be written (tested: 6 events from an empty state).
- **`verify_response_log` detects:**
  - modification, deletion, reordering;
  - truncation (with a checkpoint);
  - forged states (re-chained);
  - non-dry-run entries;
  - skipped transitions;
  - an injected `verified_effective`;
  - duplicate `event_id`s (replayed entries);
  - replayed state events with fresh IDs.

## 7. Feedback implementation (R6)
`feedback.py` reads the response audit only:
- **`outcomes`:** final state, events, verification outcome, rollback result, labels, rejected-operation count, `response_success` and `failure`.
- **`annotate`:** an operator label `true_positive|false_positive|inconclusive` plus a note, written as an `annotation_recorded` audit event.
- **`review_queue`:** failed verification, failed rollback, false-positive labels, rejected operations.
- **`metrics`:** counts, explicitly marked "dry-run metrics; no real response was executed".

It **imports nothing** from `threat_assessment`, `behavioural_evidence` or the ML packages, writes no files and does not touch configs. No package of the assessment or attribution layer imports `dynamic_response`. The T19 test confirms:
- assessment findings, gates and tiers are identical before and after feedback;
- the hashes of the policy, attribution, address-safety and response configs and of `severity.py` / `assessment.py` are unchanged.

Any policy change suggested by feedback needs a separate human-approved policy version.

## 8. Safety test results (`test_results_dynamic_response.txt`): **105 passed, 0 failed**

| # | Test (design §10) | Tests | Result |
|---|---|---|---|
| T1 | no execution without approval; proposal expiry | 1 | pass |
| T2 | invalid approval: unregistered key, wrong signature, another role's key (relay), unknown name, empty registry | 5 | pass |
| T3 | duplicate/conflicting decisions, replayed approval, rejection final | 1 | pass |
| T4 | target safety: control client, protected, shared, outside allowlist, multiple IPs, non-IPv4, malformed; control-client session gives no proposal; only 10.250.25.3 qualifies | 21 | pass |
| T5 | modified approval (8 fields); re-hashed without key; re-signed broader target / stale fingerprints | 9 | pass |
| T6 | excessive or invalid duration (5); policy cannot raise TTL, enable enforcement or change attribution/action (6); expiry mismatch | 12 | pass |
| T7 | unattributed relay session; direct source (R4); forged or inconsistent assessment (7); tampered assessment audit | 10 | pass |
| T8 | controller access restrictions (10 modules, static) + runtime (no key material, no trust-anchor or config writes) | 11 | pass |
| T9/T10 | failed and partial verification never succeed → rollback | 4 | pass |
| T11 | failed rollback stays failed; duplicate rollback rejected; closes at TTL as failure | 1 | pass |
| T12 | expiry → rollback, no renewal; approved-but-unexecuted rule expires | 2 | pass |
| T13 | revocation + successful rollback; duplicates rejected | 1 | pass |
| T14 | response-log tampering (8 attacks) | 8 | pass |
| T15 | replayed records (duplicate entry, replayed state event, replayed verification); invalid transitions unwritable | 4 | pass |
| T16 | relay boundary disabled and never called; enforce mode refused | 2 | pass |
| T17 | duplicate execution and duplicate intake rejected | 1 | pass |
| T18 | missing or incomplete verification evidence (6); future-dated or foreign verification | 7 | pass |
| T19 | feedback outcomes, queue, metrics, annotations; feedback isolation | 2 | pass |
| T20 | expired approvals: decided after proposal expiry, rule expired before execution, approver key expired, stale submission | 1 | pass |
| — | full dry-run workflow (0 relay calls, all `dry_run`, log verifies); repository policy is dry-run with an empty registry | 2 | pass |

## 9. Full test-suite results
- **Related suites** (`test_results_related.txt`): threat assessment, trust boundary, client attribution, key-role separation and behavioural evidence: **317 passed**.
- **Full suite** (`test_results_full.txt`): **728 passed**, 0 failed (previously 623; +105 new).

## 10. No real response executed
- **No enforcement path:** the controller has no enforcement path (`relay_interface` disabled; 0 calls). Every audit entry is `mode: dry_run`, and every `simulated` entry records `enforced: false`.
- **Host checks:** no iptables (filter/nat/mangle/raw) or nft rule mentions 10.250.25.3 or .4 (`unchanged_and_no_enforcement.txt`).
- **Relay untouched:** `a5e156cbca02` has 0 restarts and the same start time; its listeners and code are unchanged.
- **Compose unchanged:** `cowrie/docker-compose.yml` is unchanged, and no response service was added.

## 11. Live attribution and key provisioning remain disabled
- **Attribution:** `configs/threat_attribution_v3.json` still has `attribution_result.status = pending_provisioning`, and no signed attribution result can verify in deployment.
- **Approvers:** `configs/response_policy_v1.json` has an **empty** approver registry (`pending_provisioning`).
- **Keys:** no production key of any role was generated, rotated or provisioned. Test approver, relay and result keys are ephemeral in-memory fixtures. No migration step (M0–M8) or activation (A1) was run.
- **Data:** no Dataset V2, sealed output or protected report folder was accessed, and no repository-wide search was run.

## 12. Remaining dependencies for real enforcement
1. **D0** (independent administrators + off-host destination) → **M0–M8** → **A1**: trusted, witnessed attribution.
2. **P5 provisioning:** approver keys signed into the trust-root manifest by both administrators (D10). Then a provisioned registry in a new response-policy version.
3. **A relay enforcement implementation** to replace `DisabledRelayEnforcement`: rule loader, P5 signature check in the relay, demo-listener accept-handler restriction, attested `rule_loaded`/`rule_unloaded` records. Plus a response-policy schema version that permits enforcement, and enforce-mode states (`verified_effective`).
4. **A separate human enforcement-activation approval**, and the enforce-mode safety tests (probe-based positive and scope verification against the live relay).
5. **Witness attestation of the response audit log** (a second `log_id`), and a `cowrie/docker-compose.yml` `response-controller` service (no Docker socket, network none).

Stopped. Enforcement not activated.
