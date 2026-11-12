# Controlled defensive-enforcement readiness design (Task 25)

**Date:** 2026-11-11.

**Design and readiness review only.**

**Unchanged** (SHA-256 identical before and after; `evidence/hashes_*.txt`):
- `behavioural_evidence/`, `threat_assessment/`;
- the attribution config, policy v1 and v2;
- `cowrie/docker-compose.yml`.

**Not done:**
- no enforcement activated;
- no Cowrie networking modified (inspected read-only only);
- the sealed test and exfiltration data were not accessed;
- no historical dataset modified;
- nothing committed.

## 1. Readiness verdict

**Not ready for enforcement.** The current deployment cannot attribute any client:
- Cowrie sees only the relay (`172.22.0.2`).
- The relay is Twisted's generic port forwarder. It logs no connection mapping and cannot run a packet filter (`cap_drop: ALL`).
- The only published path, `127.0.0.1:2223`, probably reaches the relay through Docker Desktop's port proxy, so even the relay may not see the client address *(unverified)*.

A safe demonstration is feasible after five components are built and tested:

| Component | Design |
|---|---|
| An **attributing relay** that signs an exact connection→client mapping, with no Cowrie change | `relay_attribution_design.md` |
| A **dedicated demo ingress network** with a test client and a control client, and an application-level, allowlisted, TTL-bound restriction at the relay accept handler | `enforcement_boundary.md` |
| A **separate human approval tool** with registered approver keys; the assessment engine can never approve | `approval_workflow.md` |
| An **enforcement controller** with signed rules, verification, inverse, reconciliation and fail-open expiry | `enforcement_boundary.md`, `audit_and_recovery.md` |
| **External signed checkpoints** and key custody | `audit_and_recovery.md` |

## 2. Architecture reviewed (read-only)

| Component | Relevant facts |
|---|---|
| `behavioural_evidence` (v2-evidence-1.1) | Produces session evidence. Unchanged and reused as-is |
| `threat_assessment` 1.0.0 | Gates 1–8; attribution from `src_ip` only; `proxy_client_mapping` must be null; hash-chained audit with `verify_chain`; proposals are dry-run with inverse, `manual_approval: pending`, `execution: not_executed` |
| `configs/threat_attribution_v1.json` | Relay 172.22.0.2 is a trusted proxy; protected 172.19/16, 172.21/16, 172.22/16; internal 172.21/16, 172.22/16 |
| `configs/defence_policy_v2.json` | Enforcement disabled; manual approval required; TTL 86,400 s; dry-run `block_source_ip` / `unblock_source_ip` |
| Deployment | `cowrie-ssh-relay`: `twistd portforward --port=tcp:2222 --host=cowrie --dest_port=2222`, user `cowrie`, read-only, `cap_drop ALL`, on `cowrie_internal` and `relay_frontend`, published `127.0.0.1:2223`. `cowrie-project` is only on the internal network |

## 3. Key design decisions

1. **Attribution comes from the relay's own socket peer, never from client data.**
   - A Cowrie session correlates by an **exact** match of Cowrie's `src_ip:src_port` to the relay's signed `upstream_local_ip:port`, within ±2 s.
   - Zero, multiple or unverifiable matches give explicit unattributed states, which block proposals.
   - Dataset V2 sessions are permanently unattributable.
2. **The enforcement point is the attributing relay's accept handler on the demo listener only.**
   - The target is one `/32`, the dedicated test client, which must also be in a separate hard allowlist; protected networks are refused.
   - The demo TTL is 15 minutes, and rules are ignored after expiry (fail-open).
   - Verification covers a positive case (the test client is closed at accept, with no Cowrie session) and a scope case (the control client is unaffected).
   - The inverse is rule removal, with rollback verification.
   - There is no host firewall, no iptables, no Cowrie or `cowrie_internal` change, and no new container capabilities.
3. **Approval is a separate, signed human decision.** The controller checks:
   - the approver key is in a registry and is not the assessment identity;
   - the proposal and audit hashes match;
   - the proposal has not expired (30 minutes);
   - this is the only decision for the proposal (a duplicate or conflict means no action, and a rejection is final);
   - the action is not broader than proposed;
   - the configuration is unchanged.
4. **Audit and recovery.**
   - Three hash-chained logs: the assessment audit (existing), the relay mapping log and the controller audit. The last two add Ed25519 signatures.
   - External signed checkpoints, with four separately held keys.
   - Reconciliation on restart removes orphan rules.
   - TTL bounds every failure mode.
5. **20 safety tests** (`safety_test_plan.md`), including all 11 required:
   - benign traffic, unattributable relay sessions, NAT, protected addresses;
   - expired proposals, duplicate approvals, invalid approval identity, incorrect digest;
   - failed deployment, failed rollback, audit tampering;
   - plus spoofing, allowlist escape, expiry, crash recovery, and novelty/caveat/single-failure non-triggering.

## 4. Prerequisites before implementation (each needs approval)

1. Verify the Docker Desktop peer-address behaviour with one controlled connection.
2. Approve the attributing relay, which replaces only the relay service's entrypoint; Cowrie is unchanged.
3. Approve the `demo_ingress` address plan, checked against existing networks.
4. Approve attribution config v2 (proxy mapping) and `threat_assessment` 1.1 (mapping-based states).
5. Approve the approval tool, enforcement controller, approver registry, allowlist and key custody.
6. Run the safety test plan; the demonstration (S14) happens only after S1–S13 pass.

## 5. Files

| File | Content |
|---|---|
| `relay_attribution_design.md` | Current state; mapping, correlation, integrity, expiry, spoofing |
| `enforcement_boundary.md` | Topology, enforcement point, target, scope, TTL, approval conditions, verification, inverse, rollback, failures |
| `approval_workflow.md` | Roles, proposal and approval records, validation, audit references |
| `audit_and_recovery.md` | Checkpoints, keys, retention, tamper detection, recovery, expiry |
| `safety_test_plan.md` | S1–S20 |
| `limitations.md` | Limitations |
| `evidence/` | Read-only relay/Cowrie inspection, Task 24 network inspection copy, hashes before and after |
