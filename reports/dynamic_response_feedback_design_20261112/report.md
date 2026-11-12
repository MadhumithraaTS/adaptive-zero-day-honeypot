# Task 27A — Dynamic Response & Feedback: Design and Readiness Audit

Date: 2026-11-12 · Type: **design and read-only audit**. Nothing implemented, executed, deployed, enabled or committed. No firewall command run, no address restricted, no key generated.

## 0. Verdict
- **Dry-run response workflow:** implementable after approval of this design. It needs no live keys and no live attribution.
- **Real enforcement:** **BLOCKED**. It depends on, in order:
  1. D0 and checkpoint migration M0–M8 with activation A1 (trusted, witnessed attribution);
  2. provisioning of the human-approval role P5;
  3. a separate enforcement-activation approval.
- **Two design decisions need human input:** §12, R1–R6.

## 1. Inputs audited (exact paths, read-only)
- **Earlier response design (Task 25):** `reports/controlled_enforcement_readiness_20261111/{report.md, enforcement_boundary.md, approval_workflow.md, audit_and_recovery.md}`.
- **Code:** `threat_assessment/assessment.py` (proposal generation, L167–186), `threat_assessment/audit.py` (`AuditLog`, `verify_chain`), `cowrie/attributing_relay/attributing_relay.py` (accept handler), `scripts/pipeline.py`.
- **Configs:** `configs/defence_policy.json` (v1), `configs/defence_policy_v2_2.json`, `configs/address_safety_v1.json`.
- **Custody and witness design:** `reports/checkpoint_witness_implementation_readiness_20261112/report.md`.

The Task 25 design is reused where it still holds and updated where later tasks superseded it (§2.3).

## 2. Existing response-related implementation

### 2.1 What exists

| Item | Location | Behaviour |
|---|---|---|
| Proposal generation | `threat_assessment/assessment.py` L167–186 | Only when **all 8 gates** pass (tier `propose`). Builds `{type, subject, scope, mode, ttl_seconds, inverse {type, subject}, manual_approval: "pending", execution: "not_executed", subject_basis, relay_connection_id}` from the policy's `proposed_action`. The subject is the attributed client (`attributable_via_proxy_mapping`) or the direct `src_ip` (`attributable`) |
| Action definition | `configs/defence_policy_v2_2.json` | `proposed_action = {type: block_source_ip, scope: "this sensor only", mode: dry_run, ttl_seconds: 86400, inverse: unblock_source_ip}`; `enforcement: disabled`; `manual_approval_required: true` (policy loader rejects anything else) |
| Audit | `threat_assessment/audit.py` | Hash-chained, append-only per run. Each entry records the proposal, `manual_approval_status: pending`, `inverse_operation`, `execution_status: "not_executed"`, `verification_status: not_applicable`, `rollback_status`. **`verify_chain` treats any other `execution_status` as tampering** |
| Allowlist / exclusions | `configs/address_safety_v1.json` | `enforcement_allowlist: ["10.250.25.3/32"]` (test client only); `enforcement_excluded_sources: ["10.250.25.4/32"]` (control client); protected CIDRs including the relay and Docker networks. Validated so that the allowlist cannot overlap protected, shared or excluded addresses |
| Potential enforcement point | `cowrie/attributing_relay/attributing_relay.py` `Server.connectionMade` (L112–126) | The accept handler already rejects on a local-address mismatch (writes `connection_rejected`, aborts). **No restriction check exists** |
| Pipeline | `scripts/pipeline.py` | Attack → collect → parse → features → (preprocess) → DEC. **No response or feedback stage**; threat assessment runs separately (`threat_assessment/run_signed.py`) |

### 2.2 What does not exist
- An approval tool or approver registry.
- An enforcement controller.
- A rule format, a rule delivery path, or a relay restriction check.
- Response verification, rollback execution or reconciliation.
- A response audit log.
- A feedback path.
- **No code anywhere executes a response.** (Task 26C check: no `iptables`/`nft`/`subprocess` in the assessment, attribution or evidence packages, or in the relay.)

### 2.3 Task 25 design: what still holds and what changes

| Task 25 element | Status now |
|---|---|
| Enforcement at the relay accept handler, demo listener only, no firewall/iptables/Cowrie change | **kept** |
| Target `172.30.0.2/32`, demo network `172.30.0.0/29` | **superseded**: demo network `10.250.25.0/28`, target `10.250.25.3/32` from `address_safety_v1.json` |
| Separate approval tool with an approver registry; assessment never approves | **kept**; the approver key is the **seventh key role, P5** (D16) |
| Controller-signed rules (separate controller key) | **revised**: see R1. Rules are proposed to be **approver-signed**, so the controller holds no signing key |
| Checkpoint key + external checkpoints | **superseded** by the witness architecture (P3, off-host witness log; D0 blocked) |
| TTL 15 min for demo; policy max 86,400 s | kept: response cap 15 min (R2) |

## 3. Proposed workflow

```
threat_assessment (tier=propose, all 8 gates, verified signed attribution)          [unchanged]
        │ assessment audit entry (hash-chained)
        ▼
dynamic_response.proposals ── builds a proposal record (+ proposal_expires_utc = +30 min) ──► response audit log
        │
        ▼  (human, on approver device, P5)
approval tool ── signed decision: approve (exact rule) | reject ──► approval document
        │
        ▼
dynamic_response.controller (no signing key)
   validates proposal + approval + allowlist + TTL + digests + attribution + checkpoint freshness
   mode = dry_run  → simulate, verify nothing, record "simulated"                       (always available)
   mode = enforce  → stage the approver-signed rule on the restriction volume (only when enforcement is activated)
        │
        ▼
ssh-relay (accept handler, demo listener)
   independently re-verifies the approver signature, allowlist, protected/excluded, expiry
   loads rule → relay record `rule_loaded` (P1′-signed, witness-attested)
   rejects new connections from target → `connection_rejected reason=restricted:<rule_id>`
        │
        ▼
controller: verification (positive, scope, state) → `verified_effective` or `verification_failed` → rollback
        │  expiry / revocation / failure → inverse → rollback verification
        ▼
dynamic_response.feedback ── outcome records → assessment annotations, review queue, evaluation metrics
```

## 4. Human approval mechanism (where enforced)

| Enforcement point | Check |
|---|---|
| **1. Proposal creation** (`dynamic_response.proposals`) | Source audit entry exists in a verified assessment chain; tier `propose`; all 8 gates true; `subject_basis` ∈ {`attributable_via_proxy_mapping`} **with a verified signed attribution result** (direct `attributable` sources are not enforceable on this sensor: R4) |
| **2. Approval tool** (approver's own device, P5) | Shows the proposal and its evidence; produces a signed decision. Approve = an **exact rule document**; reject = final. The tool never deploys |
| **3. Controller** | The approval signature verifies against an **approver registry** pinned by the trust-root manifest; the approver is not any of roles 1–6; `proposal_hash` and `audit_record_hash` match; `decided_utc` < `proposal_expires_utc` (30 min); **one decision per proposal** (a duplicate or conflict means no action); the approved rule equals or is narrower than the proposal; digests unchanged; attribution still verified; checkpoint fresh |
| **4. Relay** | Re-verifies the approver signature, allowlist, protected/excluded lists and expiry **independently** before loading a rule. A compromised controller therefore cannot create a rule |

The **assessment engine cannot approve**: it holds no P5, P5 is excluded from roles 1–6 (K-1 rule extended), and the assessment container has no access to the approval or restriction volumes.

**Approval document** `response-approval-1` (signed by P5): `{approval_id, proposal_id, proposal_hash, audit_record_hash, decision, reason, approver {name, key_id}, decided_utc, rule {rule_id, action: restrict_new_connections, target: "<ip>/32", listener: "demo", not_before_utc, expires_utc, ttl_seconds}}`.

## 5. Target allowlisting design
1. **The only target type is a single `/32`,** equal to the proposal subject.
2. **The target must be ∈ `address_safety_v1.json → enforcement_allowlist`** (currently `10.250.25.3/32`). It must also be ∉ `protected_cidrs`, ∉ `shared_source_cidrs` and ∉ `enforcement_excluded_sources`.
   - This is checked at proposal creation, at approval (the tool refuses), in the controller, and in the relay (four independent checks).
   - The address-safety digest must equal the value pinned by the policy and the trust-root manifest.
3. **The subject must come from a verified signed attribution result** for the same session (`relay_connection_id` matches); unverified, expired, conflicting or `unattributed:*` attribution is never used (§9).
4. **Scope:** new TCP connections from the target to the **demo listener** only. The published listener (`127.0.0.1:2223`, peer = Docker proxy) is **never** a restriction target, because its peer is not a client identity.
5. **Allowlist changes** are trust-root changes (both administrators, D10): the address-safety digest is pinned in the trust-root manifest.

## 6. Response expiry and verification

**Expiry:**
- **Cap:** every rule has absolute `not_before_utc` / `expires_utc`, with TTL ≤ **900 s** (R2). This is never above the policy `ttl_seconds` (86,400) and never above `response_policy.max_ttl_seconds`.
- **Relay behaviour:** the relay ignores a rule outside its window (fail-open), refuses `not_before_utc` more than 5 s in the future, and writes `rule_expired`.
- **No automatic renewal:** a further restriction needs a new proposal and a new approval.
- **Bounded by key validity:** a rule cannot outlive P5's validity or the current trust-root manifest; if the trust anchor changes, rules lapse.

**Verification** (enforce mode). The controller's state machine reaches `verified_effective` **only** when all of these succeed within 60 s of staging:

| Check | Evidence (all from P1′-signed, witness-attested relay records or Cowrie logs) |
|---|---|
| **State** | relay record `rule_loaded {rule_id, rule_hash}` exists and is attested |
| **Positive** | an operator-initiated probe from the test client (documented `demo_client.py banner` command, R5) produces relay `connection_rejected reason=restricted:<rule_id>` with **no** upstream connection and **no** Cowrie `session.connect` for that tuple |
| **Scope** | an operator-initiated probe from the control client succeeds, giving exactly one correlated Cowrie session; the published listener is unaffected |
| **Integrity** | the relay chain, checkpoint chain and response audit chain verify; checkpoint fresh |

- **Failure:** any check failing or timing out → `verification_failed` → rollback (§7).
- **Recorded status:** "deployed" is **never** recorded as success. Only `verified_effective` is, and only with references to the evidence records.

## 7. Rollback design

| Trigger | Action | Rollback verified when |
|---|---|---|
| verification failed / timed out | controller removes the staged rule file and stages a P5-independent **revocation marker** (the relay honours removals from the controller; it never honours additions without P5) | relay record `rule_unloaded {rule_id}` (attested) + a test-client probe succeeds + control unaffected |
| scope breach (control client or published path affected) | immediate rollback + **freeze** (no further deployments until a human review) | as above + freeze recorded |
| expiry reached | relay unloads on its own (fail-open); controller verifies | `rule_expired` record + test-client probe succeeds |
| human revocation (approver or operator) | rollback | as above |
| audit, checkpoint or attribution verification failure | rollback + freeze | as above |
| relay HALTED by witness (D12) | nothing to roll back (listeners closed); rules are re-validated on recovery and expire by TTL | rules re-loaded only if still valid; otherwise `rule_expired` |
| controller crash | on restart: reconcile the desired state (audit) with the actual state (relay `rule_loaded`/`rule_unloaded` records); remove orphans; never re-extend | `reconciled` entry |
| rollback fails (file cannot be removed / relay unresponsive) | record `rollback_failed` (**never** "rolled back"); TTL lifts the rule at `expires_utc`; escalate | `rule_expired` + probe; until then the status stays `rollback_failed` |

## 8. Response audit records
- **Log:** a new log, separate from the assessment audit. The assessment log keeps its `execution_status = not_executed` invariant, so `verify_chain` remains a tamper check for the assessment.
- **Format:** `dynamic_response/audit.py`, schema `response-audit-1`. It is hash-chained like `AuditLog`. Each entry has `sequence`, `previous_hash`, `timestamp`, `event`, `proposal_id`, `refs` (assessment `record_hash`, approval hash, rule hash, relay record hashes, checkpoint hashes), `mode` (dry_run | enforce) and `status`.
- **Events:** `proposal_created`, `proposal_expired`, `approval_recorded`, `rejection_recorded`, `approval_invalid:<reason>`, `simulated` (dry-run), `rule_staged`, `rule_loaded_observed`, `verified_effective`, `verification_failed`, `rule_expired`, `rollback_started`, `rollback_verified`, `rollback_failed`, `revoked`, `frozen`, `reconciled`, `orphan_rule_removed`.
- **Illegal transitions** (verifier-enforced): `verified_effective` without loaded+positive+scope refs; `rollback_verified` without an unload and a probe ref; any enforce-mode event while enforcement is not activated; any event after `proposal_expired` except `rejection_recorded`.
- **Integrity:** the log becomes a second `log_id` attested by the witness (after M8). Until then its hash chain is verifiable locally only.

## 9. Feedback mechanism into the existing assessment workflow
- **Outcome record** `response-outcome-1` per proposal: `{proposal_id, session_ref, subject, final_status (simulated | verified_effective | verification_failed | rollback_verified | rollback_failed | expired | rejected | approval_expired), evidence_refs, human_label (true_positive | false_positive | inconclusive | null, set by the approver/reviewer), notes}`.
- **Feedback paths** (none changes gates, severities, behavioural evidence, clustering or novelty):
  1. **Annotation:** a new, optional `response_context` field in assessment output for sessions whose subject has an active, expired or failed response, with the outcome reference. It is **informational only**: tier and gates are computed exactly as now.
  2. **Duplicate suppression in the response layer, not the assessment:** a new proposal for a subject with an active `verified_effective` rule is recorded as `proposal_superseded` and not offered for approval. The assessment still records its own `propose` tier unchanged.
  3. **Review queue:** `verification_failed`, `rollback_failed`, scope breach and every `false_positive` label raise a human review item.
  4. **Evaluation metrics:** counts of proposals, approvals, rejections, verified effects, failures and false positives per policy version. These are inputs to a **human-approved** future policy revision; there is no automatic threshold change.
  5. **Data hygiene:** all response test and demo sessions are added to `configs/session_exclusions_v*` (a new version), so they never enter datasets.

## 10. Failure scenarios and safety tests (all required before any enforce-mode run)

| # | Scenario | Expected |
|---|---|---|
| T1 | proposal without approval | no rule; `proposal_expired` after 30 min |
| T2 | approval signed by an unregistered key / a role 1–6 key / the assessment | `approval_invalid`; no rule |
| T3 | duplicate or conflicting approvals | `approval_duplicate`; no action; a rejection is final |
| T4 | target outside the allowlist, or protected / shared / excluded (control client) | refused at proposal, tool, controller **and** relay (4 tests) |
| T5 | approval broader than the proposal (TTL or target) | refused |
| T6 | TTL > 900 s, or expires beyond P5 / manifest validity | refused |
| T7 | proposal based on unverified, expired, conflicting or unattributed attribution, or a direct (non-relay) source | no proposal record (§4) |
| T8 | controller compromised: writes a rule without a P5 signature | relay refuses to load it |
| T9 | rule loads but the positive probe is not rejected | `verification_failed` → rollback; **never** success |
| T10 | control client or published path affected | rollback + freeze |
| T11 | rollback cannot be completed | `rollback_failed`; rule lapses at TTL; never "rolled back" |
| T12 | expiry | relay unloads; `rule_expired`; probe succeeds |
| T13 | controller or relay crash mid-deployment | reconcile; orphans removed; no extension |
| T14 | response audit tampering (modify / delete / reorder / forge status) | `verify_chain`-style detection; freeze |
| T15 | witness halts the relay during an active rule | listeners closed; on recovery the rule is re-validated or expired |
| T16 | dry-run mode | full workflow with `simulated` status; **no** file on the restriction volume; relay never sees a rule |
| T17 | enforcement not activated but `mode = enforce` requested | refused (`enforcement_not_activated`) |
| T18 | existing assessment unchanged | the 623-test suite still passes; gates, tiers and severities identical on fixtures with and without `response_context` |
| T19 | assessment container | still no access to the approval, restriction or controller volumes, or the Docker socket |
| T20 | clock skew > 5 s | rules refused or ignored |

## 11. Exact files

**Modified (later, when approved):**

| File | Change |
|---|---|
| `cowrie/attributing_relay/attributing_relay.py` | Rule loader (polls a read-only restriction volume every 2 s; verifies P5 signature, allowlist, protected/excluded, window). Restriction check in `Server.connectionMade` (L112–126) **for the demo listener only**. New relay record types `rule_loaded`, `rule_unloaded`, `rule_expired`, `rule_rejected`, and `connection_rejected` with `reason=restricted:<rule_id>` |
| `client_attribution/records.py` | `REQUIRED` gains the new record types |
| `threat_assessment/assessment.py` | **Only** the optional, informational `response_context` annotation (no gate or tier logic change). Alternatively, R6: keep the annotation entirely in the response layer and leave the assessment untouched |
| `threat_assessment/run_signed.py` | `FORBIDDEN_PATHS` adds the approval, restriction and controller paths |
| `cowrie/docker-compose.yml` | Service `response-controller` (profile `response`, network none, mounts: assessment output ro, approvals ro, restriction volume rw, relay records ro, checkpoint store ro). Relay mounts the restriction volume **ro** |
| `configs/session_exclusions_v2.json` | new version for response test sessions (v1 unchanged) |

**New:**

| File | Purpose |
|---|---|
| `dynamic_response/__init__.py`, `proposals.py`, `approval.py`, `rules.py`, `controller.py`, `audit.py`, `feedback.py` | the component |
| `dynamic_response/approve_cli.py` | approver tool (runs on the approver's device) |
| `configs/response_policy_v1.json` | `mode` (dry_run default), `enforcement_activated: false`, `max_ttl_seconds: 900`, `proposal_validity_seconds: 1800`, `verification_timeout_seconds: 60`, `supported_actions: [restrict_new_connections]`, approver registry reference. Its digest is pinned by the trust-root manifest |
| `tests/test_dynamic_response.py` | T1–T20 (relay tests run in the pinned image) |

**Unchanged:** `behavioural_evidence/`, `threat_assessment/severity.py`, the gates and tiers in `assessment.py`, `configs/defence_policy_v2_2.json`, `configs/address_safety_v1.json`, the Cowrie service and its keys.

## 12. Dependencies and decisions

**Dependencies for real enforcement (all required, in order):**
1. **D0 resolved** → M0–M8 → **A1** (separate approval). Only then do signed attribution results exist with an attested, fresh tail; without them §4.1 never creates an enforceable proposal.
2. **P5 provisioned:** the approver registry is signed into the trust-root manifest (a trust-root change, so both administrators sign, D10).
3. `response_policy_v1.enforcement_activated: true`, through a **separate human enforcement-activation approval**.
4. T1–T20 passing; the witness attesting the response audit log (second `log_id`).

**Decisions needed (R1–R6):**

| # | Decision | Recommendation |
|---|---|---|
| **R1** | Rule signing: approver-signed rules (no controller key) vs. a controller key (would be an **eighth** key role) | approver-signed rules; the controller holds no signing key |
| **R2** | Maximum response TTL | 900 s (demo), below the policy's 86,400 s; no automatic renewal |
| **R3** | One approver or two for responses | one P5 approver for TTL ≤ 900 s; two for anything longer (if ever allowed) |
| **R4** | Direct-source (`attributable`, non-relay) subjects | not enforceable on this sensor: the only enforcement point is the relay demo listener |
| **R5** | Verification probes: operator-run vs. an automated probe (which would need Docker or exec access for the controller) | operator-run documented probes. The controller gets **no** Docker socket |
| **R6** | Feedback annotation inside `threat_assessment` vs. response layer only | response layer only (zero assessment change), plus a report join |

## 13. Dry-run vs. real enforcement

| Aspect | Dry-run (available after design approval; no live keys) | Real enforcement (blocked) |
|---|---|---|
| Proposal source | assessment `propose` records (synthetic or captured fixtures, ephemeral test keys) | live verified signed attribution (after A1) |
| Approval | test approver keys (in-memory, tests only) | P5 from the trust-root manifest |
| Rule | built and validated, **never staged**; the relay never sees it | approver-signed rule staged on the restriction volume |
| Effect | none; status `simulated` | relay rejects new demo-listener connections from the test client |
| Verification | logical checks only (allowlist, TTL, signatures, chains) | positive + scope + state probes |
| Audit | `response-audit-1` with `mode: dry_run` | same, with `mode: enforce`; witness-attested |
| Switch | `response_policy.mode = dry_run` (default); `enforcement_activated: false` | only by a new response-policy version with `enforcement_activated: true`, pinned by a 2-of-2 manifest, after separate approval |

## 14. Confirmation
- **No execution or change:** no firewall command was executed, and no rule, IP block or network change was made. No enforcement was enabled, no attribution activated, no key generated, rotated or provisioned, and no migration step run. Behavioural evidence, threat-assessment policy, gates and severities are unchanged. No code or config was modified, and nothing was committed.
- **Inspection scope:** only the named files and folders listed in §1 (plus directory listings of `scripts/` and `threat_assessment/`). No Dataset V2, sealed output or protected report folder was accessed, and no repository-wide search was run.

Stopped. Implementation needs approval of this design and decisions R1–R6. Real enforcement additionally needs D0 → M0–M8 → A1, P5 provisioning, and a separate enforcement-activation approval.
