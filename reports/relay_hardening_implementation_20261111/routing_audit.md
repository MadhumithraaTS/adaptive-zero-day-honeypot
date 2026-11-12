# Repeated read-only routing and isolation audit

**Method:**
- `evidence/audit_dynamic.sh` is the Task 25C-1 audit, with PIDs located by command line. It was run as root in the `docker-desktop` WSL distribution through `nsenter`, using listing commands only.
- Before: relay pid 2890 (`cowrie/backups/pre_relay_hardening_20261111T165756Z/audit_before.txt`). After: relay pid 6386 (`evidence/audit_after.txt`). Cowrie pid 2837 and engine pid 165 in both.

| Item | Task 25C-1 / before | After | Change |
|---|---|---|---|
| Relay `ip_forward`, `conf.{all,default,eth0,eth1}.forwarding` | 1 | **0** | Fixed |
| Relay routes | default via 172.21.0.1; 172.21/16 eth1; 172.22/16 eth0 | same | none (routes exist, but the kernel no longer forwards between them) |
| Relay `rp_filter` | 2 | 2 | none |
| Relay filter table | none | none (only Docker DNS NAT; DNS ports re-randomised) | none |
| Relay TCP listeners | `0.0.0.0:2222`, `127.0.0.11:43835` | **`172.21.0.2:2222`**, `127.0.0.11:34069` | Fixed (no wildcard) |
| Relay capabilities | 0, NoNewPrivs 1 | 0, NoNewPrivs 1 | none |
| Cowrie netns (addresses, routes, sysctls, firewall, listeners) | — | identical (ignoring counters and timestamps) | none |
| VM `iptables-nft-save` | — | identical (ignoring timestamps) | none |
| VM IPv4 routes | no route to 172.22.0.0/16 | same | none |

**Updated hop-by-hop assessment** (Task 25C-1 `network_boundary_analysis.md`) for a packet from the VM side to Cowrie through the relay:

| Hop | Before | After |
|---|---|---|
| 1. Sender route | none | none |
| 2. Relay forwards | **would forward** | **would not forward** (`ip_forward = 0`) [O] |
| 3. `DOCKER-INTERNAL` source filter | blocks | blocks |
| 4. Cowrie return route | missing | missing |

The relay's kernel forwarding capability is removed, so the path now has four independent blocks instead of three. This is still a configuration-based conclusion; no probe was sent.

**Listener exposure after the change:**
- The Cowrie forwarder is reachable only at `172.21.0.2:2222`.
- It is no longer bound on `172.22.0.2`. Cowrie-side hosts connecting to the relay's internal address on 2222 would now be refused [I; not probed].
- **Weak-host residual:** a host with a route to `172.21.0.2` through another relay interface could still reach it. None exists today.
