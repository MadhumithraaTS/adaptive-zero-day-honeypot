# Isolated attribution demo network: design and feasibility (Task 25B)

**Date:** 2026-11-11.

**Design only.**
- **Inspection was read-only:** `docker network inspect`, `docker info` / `docker version`, `docker inspect`, `Get-NetIPAddress` / `Get-NetRoute` (`evidence/`).
- **No changes:** no Compose, network, container, relay, firewall, attribution-config, policy, behavioural-evidence or threat-assessment change.
- **Nothing run or accessed:** no connections; no Dataset V2 or sealed-test data accessed.
- **Excluded:** diagnostic session `99732d516898`, from everything.
- **Not done:** nothing committed.

**Nothing here has been experimentally verified.**

## 1. Findings from inspection

- **Current topology:**
  - `cowrie_cowrie_internal` 172.22.0.0/16 (internal, isolated gateway): Cowrie `172.22.0.1`, relay `172.22.0.2`.
  - `cowrie_relay_frontend` 172.21.0.0/16 (gateway `172.21.0.1`): relay `172.21.0.2`, published `127.0.0.1:2223`.
  - Other bridges: `bridge` 172.17/16, `rezumy_default` 172.18/16, `cowrie_default` 172.19/16, `et-ai_default` 172.20/16. Their only containers are exited.
- **Engine:** Docker Desktop on WSL2, engine 29.1.2, API 1.52, default address pools (none configured).
- **Host:** WSL vEthernet 172.27.0.0/20, VirtualBox host-only 192.168.56.0/24, Wi-Fi 172.20.10.0/28, link-local, loopback.
  - Pre-existing conflict: the host Wi-Fi lies inside `et-ai_default`; this design does not introduce it.
- **Relay:** `twistd portforward` binding `0.0.0.0:2222`; user `cowrie`, `cap_drop ALL`, read-only, no sysctls.
- **Task 25A:** the published path presents `172.21.0.1` (proxy) to the relay; Cowrie's `session.connect` carries the relay's outbound `src_port`; `session.closed` does not.

## 2. Design summary

| Item | Proposal |
|---|---|
| Network | `cowrie_demo_ingress`: user-defined bridge, `internal: true`, `gateway_mode_ipv4: isolated`, IPv6 off |
| Subnet | `10.250.25.0/28`; dynamic pool `10.250.25.8/29`; no gateway; `.1` deliberately unassigned |
| Relay | `10.250.25.2` (MAC `02:fa:19:00:00:02`); demo listener bound explicitly to `10.250.25.2:2222`; keeps `172.22.0.2` and `172.21.0.2` |
| Test client | `10.250.25.3` (MAC `02:fa:19:00:00:03`); the only future enforcement target (`/32` allowlist) |
| Control client | `10.250.25.4` (MAC `02:fa:19:00:00:04`); never a target |
| Members | Exactly these three. Cowrie is not a member, and no other service is |
| Overlap | None with any Docker network, host interface or route, Docker default pool, or protected, internal or trusted-proxy CIDR (`evidence/overlap_check.txt`) |

**How the relay tells the clients apart.** Its accepted-socket peer (`getpeername()`) on the demo listener is compared with a digest-pinned client registry (IP and expected MAC):
- `10.250.25.3` → test client;
- `10.250.25.4` → control client;
- anything else → rejected, `unregistered_peer`, never attributable.

**Correlation.** Exact relay upstream tuple = Cowrie `session.connect` `src_ip:src_port`, within ±2 s, with the demo listener, a verified signed mapping and a consistent close (the close is joined by session ID, since `session.closed` has no port). Missing, ambiguous, duplicate, unverifiable, unregistered or inconsistent → unattributed (`attribution_path.md`).

**Isolation** (`isolation_analysis.md`):
- Clients reach only the relay's demo listener, not Cowrie, the VM, the host, the internet or unrelated containers.
- The relay is not a router (no `NET_ADMIN`, forwarding off).
- The relay must bind per interface; today's `0.0.0.0` bind would otherwise expose the published-path forwarder on the demo network.

**Spoofing and allowlist** (`safety_checks.md`, R1–R11):
- Clients have `cap_drop ALL`, so no `NET_ADMIN` or `NET_RAW`: no IP change, no spoofed or raw packets, no ARP spoofing.
- Fixed IPs and MACs; an exact-membership check, plus the relay's neighbour table, before each run.
- The allowlist is `10.250.25.3/32` only, with the relay refusing other targets.
- The demo and published listeners are separated.
- Abort on any failed check.

## 3. Feasibility conclusion

**Feasible in principle on the current Docker Desktop environment; not verified.**
- **What it uses:** user-defined internal bridges, fixed per-network addresses and MACs, and isolated gateway mode are standard features of this engine and Compose version. Isolated mode already works here for `cowrie_internal`.
- **Why it should give the real client address:** container-to-container traffic on a user-defined bridge stays inside the VM and does not pass the published-port proxy, so the relay's socket peer is expected to be the client container's real address.
- **What must be checked first:** the seven unverified assumptions in `limitations.md`. The most important are the client address seen at the relay on the container path, isolated-gateway behaviour on the new network, and keeping the relay at `172.22.0.2` on recreation.
- **A constraint:** the demo cannot be driven from the Windows host. Host traffic only arrives through the proxy, so the clients must be containers on `demo_ingress`.

## 4. Next steps (each requires approval)

1. Approve the address plan and the exactly-three-member topology.
2. Approve how the client containers are provided (a pinned local image; no pulls without approval).
3. Approve keeping or pinning the relay's `172.22.0.2` on recreation.
4. An approved, single, controlled verification that the relay sees `10.250.25.3` as the socket peer on the demo listener. This mirrors Task 25A, with the same one-connection discipline.
5. Only then: implement the attributing relay (Task 25 design).

## 5. Files

| File | Content |
|---|---|
| `address_plan.md` | Network, subnet, fixed addresses, listeners, registry |
| `isolation_analysis.md` | Reachability matrix, boundaries, protected networks |
| `attribution_path.md` | Client→relay→Cowrie flow, correlation rule, unattributed outcomes, exclusions |
| `safety_checks.md` | Risks R1–R11 with controls and pre-run checks |
| `limitations.md` | Unverified assumptions and Docker Desktop constraints |
| `evidence/` | Docker inspection, host interfaces and routes, overlap check |
