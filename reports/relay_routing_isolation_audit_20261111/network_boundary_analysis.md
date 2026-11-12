# Network boundary analysis: can VM-side traffic reach Cowrie through the relay?

## Container attachments and security (read-only `docker inspect`; Task 25C-pre `evidence/preflight_inspection.txt` and this audit)

| Container | Networks | Caps | Security options | Root FS | User |
|---|---|---|---|---|---|
| `cowrie-ssh-relay` | `cowrie_internal` 172.22.0.2; `cowrie_relay_frontend` 172.21.0.2 | all dropped (CapEff/CapPrm/CapBnd = 0) | `no-new-privileges:true` | read-only | `cowrie` |
| `cowrie-project` | `cowrie_internal` 172.22.0.1 | all dropped | `no-new-privileges:true` | read-only | `cowrie` |

| Network | Internal | Gateway | Driver options |
|---|---|---|---|
| `cowrie_cowrie_internal` (`br-8de3b00259f2`) | true | none (isolated) | `gateway_mode_ipv4: isolated`, IPv6 off |
| `cowrie_relay_frontend` (`br-c94e904b8861`) | false | 172.21.0.1 | IPv6 off |

## Hop-by-hop analysis for a packet from the Docker VM side (frontend) to Cowrie `172.22.0.1:2222`

| Hop | Requirement | Finding | Status |
|---|---|---|---|
| 1 | A sender on the frontend side routes `172.22.0.0/16` via `172.21.0.2` | The VM has **no route** to 172.22.0.0/16 (default via 192.168.65.1). The frontend network has no other members. The relay's own sockets are not forwarded traffic | **Not established** [O for the route table; I that no other sender exists] |
| 2 | The relay accepts and forwards it | `ip_forward = 1`, routes to both networks, no filter table, `rp_filter = 2` | **Would forward** (kernel capability) [O config; not demonstrated] |
| 3 | The frame enters `br-8de3` (`cowrie_internal`) | The relay does no SNAT, so the source stays e.g. 172.21.0.1. VM `DOCKER-INTERNAL`: `! -s 172.22.0.0/16 -o br-8de3… -j DROP`, before the bridge accept. br_netfilter is active (`bridge-nf-call-iptables = 1`; the accept counter is 192,466) | **Blocked** [O rules + counters; I applied to such a frame] |
| 4 | Cowrie replies | Cowrie has a route only to 172.22.0.0/16. A reply to 172.21.0.1 has no route | **Blocked** [O] |
| 4′ | Variant: the sender spoofs a 172.22.x source to pass hop 3 | Cowrie would answer on L2 to the spoofed 172.22.x address, not through the relay. Only one-way packets are possible, and crafting them needs root in the VM (which already controls Docker) | **No bidirectional path** [I] |

## Conclusion

**Kernel forwarding capability exists in the relay**, and **end-to-end reachability from the VM side to Cowrie through the relay is blocked** by three independent observed controls:
1. no route at the sender;
2. Docker's `DOCKER-INTERNAL` source filter on the internal bridge;
3. no return route in Cowrie.

**Not demonstrated by a probe.** No connectivity test was made (prohibited). The block is a configuration-based conclusion, not an experimental one.
