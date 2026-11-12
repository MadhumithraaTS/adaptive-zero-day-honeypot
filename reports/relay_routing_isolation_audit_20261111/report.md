# Read-only relay routing and isolation audit (Task 25C-1)

**Date:** 2026-11-11.

**Read-only.**
- **Inspection only:** `ip … show`, `/proc/sys` reads, `iptables-nft-save` / `ip6tables-nft-save` / `iptables-legacy-save` / `nft list ruleset` listings, `/proc/net` socket tables and `docker inspect`. These ran as root in the `docker-desktop` WSL distribution through `nsenter` into the relay's, Cowrie's and the engine's namespaces (`evidence/audit_readonly.sh`, full output in `evidence/audit_readonly_output.txt`).
- **No probes:** no connections or network probes.
- **No changes:** no sysctl, route, rule, listener, Docker, container, relay or Cowrie change.
- **No other data or code:** no Dataset V2 or sealed data; behavioural evidence, assessment, policy and attribution configs untouched.
- **Excluded:** diagnostic session `99732d516898`.
- **Not done:** nothing committed.

**Labels:** [O] observed; [I] inferred; [U] unverified.

## Findings

| # | Finding | Evidence | Status |
|---|---|---|---|
| F1 | Relay: `net.ipv4.ip_forward = 1`; `conf.{all,eth0,eth1}.forwarding = 1`; `rp_filter = 2`; IPv6 disabled on its interfaces | sysctls | [O] |
| F2 | Relay routes: `172.22.0.0/16` dev eth0, `172.21.0.0/16` dev eth1, default via 172.21.0.1. So it has routes between its two networks | `ip route` | [O] |
| F3 | Relay namespace: **no filter table**, so nothing blocks forwarding; no NAT for forwarded traffic (only Docker DNS NAT) | `iptables-nft-save`, `nft` | [O] |
| F4 | Relay listener `0.0.0.0:2222`, exposed on eth0 (172.22.0.2), eth1 (172.21.0.2) and lo. Docker DNS on 127.0.0.11 only | `/proc/net/tcp`, `/proc/net/udp` | [O] |
| F5 | Cowrie routes: only `172.22.0.0/16`. No default route, so no return path to sources outside it | `ip route` | [O] |
| F6 | VM: no route to `172.22.0.0/16` (the isolated bridge has no address); default via 192.168.65.1 | `ip route` | [O] |
| F7 | VM `DOCKER-INTERNAL` drops frames entering `br-8de3` (`cowrie_internal`) with a source outside 172.22.0.0/16, evaluated before the bridge accept. `bridge-nf-call-iptables = 1`. The bridge-accept counter is **192,466** packets, proving bridged relay↔Cowrie frames pass this hook. The drop counters are 0 | VM `iptables-nft-save`, `nft` counters | [O] rules and counters; [I] applies to relay-forwarded frames |
| F8 | Capabilities: relay and Cowrie both have all capabilities dropped (CapEff = 0), `no-new-privileges`, read-only root, user `cowrie`. IPv6 paths absent | `docker inspect`, `/proc/self/status` | [O] |

## Conclusions

1. **Is forwarding enabled?** **Yes.** IPv4 forwarding is enabled in the relay's network namespace on all interfaces [O]. IPv6 forwarding is off in the relay.
2. **Do the actual forwarding rules permit traffic?**
   - **Inside the relay namespace, yes:** there is no filter table, so forwarded IPv4 is accepted by default [O].
   - **At the Docker VM bridge layer, no, for traffic from outside 172.22.0.0/16:** `DOCKER-INTERNAL` drops it before it reaches Cowrie's bridge [O rules; I applicability].
3. **Is a route from the Docker VM side to Cowrie established, blocked or unverified?**
   - **Blocked by configuration; not probe-verified.** Three independent controls stand in the way: the sender has no route (F6), the internal-bridge source filter drops such frames (F7), and Cowrie has no return route (F5).
   - **Kernel forwarding capability in the relay (F1–F3) is not demonstrated reachability.** No end-to-end path exists in the current configuration [I]. This was not tested by sending traffic [U].
4. **Changes required before the demo network can be considered isolated** (none applied; each needs approval):
   1. **Disable forwarding in the relay namespace:** `sysctls: net.ipv4.ip_forward: 0` (and `conf.all.forwarding: 0`) on the relay service. This requires recreating the relay.
   2. **Bind listeners per interface** instead of `0.0.0.0:2222`: published-path listener on `172.21.0.2`, demo listener only on `10.250.25.2`. This requires the attributing relay or a changed forwarder command.
   3. **Make isolation explicit rather than Docker-default dependent:**
      - verify, after each Docker Desktop restart or upgrade, that `DOCKER-INTERNAL`, `bridge-nf-call-iptables = 1` and the isolated gateway are still present;
      - give the demo network the same `internal: true` plus isolated-gateway treatment.
   4. **Keep the relay's `172.22.0.2`** on recreation, or pin it, and keep the attribution config consistent.
   5. **After changes:** repeat this audit (expecting `ip_forward = 0` and the explicit binds). Then perform the approved single-connection peer verification and the client isolation tests (Task 25B `safety_checks.md` R7).

## Files

| File | Content |
|---|---|
| `routing_tables.md` | Interfaces, routes and rules for the relay, Cowrie and the VM |
| `forwarding_and_firewall.md` | Sysctls and all firewall listings, with counters |
| `listener_exposure.md` | Every listener and the interfaces it is exposed on |
| `network_boundary_analysis.md` | Attachments, security options, hop-by-hop path analysis |
| `risk_assessment.md` | Risks K1–K6 |
| `limitations.md` | What is and is not established |
| `evidence/` | Read-only scripts, their outputs, VM section extract |
