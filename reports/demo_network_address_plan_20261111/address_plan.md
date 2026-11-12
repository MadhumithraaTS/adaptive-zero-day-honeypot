# Address plan: isolated attribution demo network (proposed; not created)

## 1. Network

| Item | Value | Reason |
|---|---|---|
| Name | `cowrie_demo_ingress` (Compose network `demo_ingress`) | Separate from `cowrie_internal` and `relay_frontend` |
| Driver | `bridge` (user-defined) | Container-to-container traffic stays inside the Docker Desktop VM and never passes the published-port proxy that Task 25A showed rewrites the source to `172.21.0.1` |
| `internal` | `true` | No NAT or default route out of the network |
| `com.docker.network.bridge.gateway_mode_ipv4` | `isolated` | The bridge gets no IPv4 address, so members cannot reach Docker Desktop VM services through a gateway (the Task 13 port-111 lesson). The same option already works for `cowrie_internal` on this engine (29.1.2) |
| `com.docker.network.enable_ipv6` | `false` | No IPv6 path |
| ICC | default (enabled) | Required: disabling ICC would also block client→relay. Isolation between the two clients is handled in `safety_checks.md` |
| **Subnet** | **`10.250.25.0/28`** (10.250.25.0–10.250.25.15) | Overlaps nothing (`evidence/overlap_check.txt`): no Docker network (172.17–172.22/16), the Docker Desktop VM range 192.168.65.0/24, the host interfaces (172.27.0.0/20, 192.168.56.0/24, 172.20.10.0/28), the Docker default pools (172.16/12, 192.168/16), or any protected, internal or trusted-proxy CIDR |
| **Gateway** | **none** (isolated mode: "invalid IP", as observed on `cowrie_internal`) | No gateway endpoint exists. **10.250.25.1 is left unassigned**: on `cowrie_internal`, Docker assigned `.1` to a container in isolated mode (Cowrie = 172.22.0.1), so `.1` must not be relied on as reserved |
| `ip_range` (dynamic pool) | `10.250.25.8/29` | Every planned member has a fixed address below `.8`. Any unplanned container that attaches gets `.8`–`.15`, which the membership check rejects |

## 2. Fixed members (exactly three)

| Member | Container | IPv4 (fixed `ipv4_address`) | MAC (fixed per-network `mac_address`, locally administered) | Other networks |
|---|---|---|---|---|
| Attributing relay (future; replaces `cowrie-ssh-relay` in place) | `cowrie-ssh-relay` | **`10.250.25.2`** | `02:fa:19:00:00:02` | `cowrie_internal` (must remain `172.22.0.2`), `relay_frontend` (`172.21.0.2`) |
| Dedicated **test client** | `cowrie-demo-test-client` | **`10.250.25.3`** | `02:fa:19:00:00:03` | none |
| Dedicated **control client** | `cowrie-demo-control-client` | **`10.250.25.4`** | `02:fa:19:00:00:04` | none |

There are no other clients or services. Cowrie (`cowrie-project`) is **not** a member.

## 3. Listeners and identities

| Listener (attributing relay) | Bind | Peer seen | Attribution meaning |
|---|---|---|---|
| Demo ingress | **`10.250.25.2:2222` only** (explicit bind, not `0.0.0.0`) | The client container's own address | `10.250.25.3` = test client; `10.250.25.4` = control client; anything else → rejected, `unexpected_peer`, never attributable |
| Published path (unchanged behaviour) | `172.21.0.2:2222` (reached from `127.0.0.1:2223`) | `172.21.0.1` (Docker Desktop proxy; Task 25A) | Protected / trusted proxy, never attributable |

The client registry (a future config, digest-pinned):

```json
{"10.250.25.3": {"role": "test_client", "mac": "02:fa:19:00:00:03"}, "10.250.25.4": {"role": "control_client", "mac": "02:fa:19:00:00:04"}}
```

Future enforcement target allowlist: `["10.250.25.3/32"]` only. The control client and the relay's own `10.250.25.2` are never targets; the relay address would be added to the protected list.

## 4. Unchanged

These stay unchanged:
- `cowrie_internal` (members: Cowrie `172.22.0.1`, relay `172.22.0.2`; options unchanged);
- `relay_frontend`;
- the published port `127.0.0.1:2223`;
- the Cowrie container and its configuration;
- `configs/threat_attribution_v1.json` and the policies.

The relay gains one extra network attachment in the future implementation; that is the only change to an existing container.
