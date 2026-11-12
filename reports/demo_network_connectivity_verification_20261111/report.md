# Controlled demo network connectivity verification (Task 25C-pre)

**Date:** 2026-11-11.

**Result: stopped at preflight.** Two required checks failed, so, as the task instructs, nothing was created and the controlled connection was **not** made.

**Not done or created:**
- no network, container, endpoint, connection, relay change, firewall rule, Cowrie change, or attribution/policy/evidence/assessment change;
- Dataset V2 and sealed-test data were not accessed;
- nothing was committed.

**Excluded:** diagnostic session `99732d516898`, from everything.

## 1. Preflight summary (`preflight_checks.md`)

| # | Check | Result |
|---|---|---|
| 1 | Subnet overlap (`10.250.25.0/28`) | PASS: no overlap with any Docker network, host interface or route, protected/internal/trusted-proxy CIDR, Docker Desktop VM range, or Docker default pool |
| 2 | Relay image; local SSH client | PASS with note: relay `cowrie/cowrie@sha256:bf371c37…cc13a`. No minimal SSH-client image locally; the same pinned image provides Twisted Conch `conch` (no pull needed) |
| 3 | Digest and capabilities | PASS: relay CapEff = 0, NoNewPrivs = 1, read-only, user `cowrie` |
| 4 | Relay listeners | `0.0.0.0:2222` (the forwarder), `127.0.0.11:43835` (Docker DNS) |
| 5 | Demo listener without exposing the forwarder on the demo interface | **FAIL**: the only forwarder binds `0.0.0.0:2222`. Attaching the relay to the demo network exposes it at `10.250.25.2:2222`, and a demo-only listener needs a relay change (prohibited) |
| 6 | Preserve `172.22.0.2` | PASS (plan): `docker network connect` on the running container keeps existing endpoints and ID |
| 7 | Cleanup and restoration defined | PASS |
| 4b | Relay does not forward IP packets (experiment step 4) | **FAIL**: `net.ipv4.ip_forward = 1` in the relay namespace. Disabling it requires recreating the relay with a sysctl (prohibited) |

## 2. Findings

1. **The existing relay cannot host an isolated demo listener as-is.** Any network it joins can reach its Cowrie forwarder on port 2222.
2. **The relay namespace has IP forwarding enabled.** This contradicts the Task 25B design premise that the relay "is not a router", which had been flagged there as unverified.
   - **The current relay**, with both `relay_frontend` (not internal) and `cowrie_internal` attached, has the same property.
   - **Not tested:** whether any VM-side host could route to Cowrie through `172.21.0.2`. It is recorded for review in `isolation_results.md`; nothing was probed.
3. **The question of this task stays open:** whether a demo client's connection reaches the relay with peer `10.250.25.3`. **No peer address was observed**, and no correlation was performed.

## 3. Options (each needs explicit approval; `limitations.md` §5)

- **(a)** Proceed with the existing relay and accept both failed conditions (forwarder exposed on the demo interface; forwarding left on). Isolation then rests on the clients' dropped capabilities.
- **(b)** Recreate the relay with `net.ipv4.ip_forward = 0`, and optionally a demo-only bind. This changes the relay deployment.
- **(c)** Verify the peer address with the future attributing relay, which has per-interface binds and forwarding disabled.

**Recommendation:** (b) or (c). Forwarding-off and explicit binds are needed for the final design anyway, and (a) would test the address question on a topology whose isolation premise is already known to be false.

## 4. State verification (`cleanup_verification.md`)

Unchanged:
- relay `8d3bafb35f38` (same start time, 0 restarts, 172.22.0.2 and 172.21.0.2);
- Cowrie `0bec5a78b1cb` (172.22.0.1);
- the network list and IDs (no `cowrie_demo_ingress`);
- the 10 containers;
- the compose, attribution-config and policy-v2 hashes.

## 5. Files

| File | Content |
|---|---|
| `preflight_checks.md` | All checks, with evidence |
| `relay_peer_observation.txt` | Not performed (reason), plus the listeners seen |
| `cowrie_correlation.txt` | Not performed |
| `isolation_results.md` | No test run; forwarding and bind findings |
| `cleanup_verification.md` | Nothing created; the future cleanup plan; state verified unchanged |
| `limitations.md` | Open question, assumptions, options |
| `evidence/` | Preflight inspection, host interfaces and routes, overlap recheck, state after preflight |
