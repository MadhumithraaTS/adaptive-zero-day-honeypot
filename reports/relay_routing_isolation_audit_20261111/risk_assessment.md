# Risk assessment

| # | Risk | Likelihood (current deployment) | Impact | Basis | Status |
|---|---|---|---|---|---|
| K1 | Relay forwards VM-side packets into `cowrie_internal` | Low: needs a route the VM does not have, plus a source the internal bridge filter allows, plus a return path Cowrie does not have | Medium (would bypass the relay's application-level forwarding) | `network_boundary_analysis.md` | Blocked by configuration [O/I]; not probe-tested |
| K2 | Isolation depends on Docker's `DOCKER-INTERNAL` rule and `bridge-nf-call-iptables = 1` | Low now. They are Docker-managed and **not persistent under our control**: Docker Desktop upgrades, a disabled br_netfilter, or network recreation could change them | Medium | VM firewall listing | Dependency to monitor |
| K3 | Relay forwarding is enabled (`ip_forward = 1`) although the relay only needs socket-level proxying | Present | Removes a defence-in-depth layer; makes K1 possible if K2 changes | sysctls | Hardening gap |
| K4 | Forwarder bound to `0.0.0.0:2222`, so it is also reachable from `cowrie_internal` (Cowrie side) and from any future network | Present | Low today: a Cowrie→relay→Cowrie loop, and the emulator blocks 172.16/12. Blocks the demo design (Task 25C-pre) | listeners | Hardening gap / demo blocker |
| K5 | A demo network attached to the relay as-is | Would add a third L2 segment to a forwarding namespace with no filter. Demo clients could reach the forwarder, and a client with routing capability could use the relay as a router towards 172.22/16. `DOCKER-INTERNAL` would still drop non-172.22 sources | Medium | sysctls + listeners + rules | Not acceptable as an isolated demo without changes |
| K6 | IPv6 paths | None observed: container interfaces have `disable_ipv6 = 1`, container IPv6 forwarding 0, networks IPv6 off | — | sysctls | Not a current risk [O] |

**Overall:** the existing honeypot isolation is **not broken** by the relay's forwarding setting. Docker's internal-bridge filter and the missing routes block the path. But the relay is a forwarding, unfiltered, wildcard-bound dual-homed namespace. That is not the "not a router" premise the demo design assumed, and its safety currently rests on Docker-managed rules outside the project's configuration.
