# Routing tables (read-only)

**Commands** (from the `docker-desktop` WSL distribution as root; `evidence/audit_readonly.sh`, full output in `evidence/audit_readonly_output.txt`):

```
nsenter --net=/proc/<pid>/ns/net ip -o link show | ip -o addr show | ip route show table all | ip -6 route show table all | ip rule show | ip neigh show
```

Targets: relay pid 2890 (`net:[4026532546]`), Cowrie pid 2837 (`net:[4026532405]`), Docker engine/VM pid 165. PIDs come from `/proc/*/cmdline` (`evidence/probe_tools_output.txt`).

## Relay (`cowrie-ssh-relay`)

| Interface | MAC | Address | Network |
|---|---|---|---|
| eth0@if30 | de:ee:4b:cd:e2:ad | 172.22.0.2/16 | `cowrie_internal` (bridge `br-8de3b00259f2`) |
| eth1@if31 | 62:7a:84:74:cf:15 | 172.21.0.2/16 | `cowrie_relay_frontend` (bridge `br-c94e904b8861`) |
| lo | — | 127.0.0.1/8, ::1 | — |

```
default via 172.21.0.1 dev eth1
172.21.0.0/16 dev eth1 scope link src 172.21.0.2
172.22.0.0/16 dev eth0 scope link src 172.22.0.2
(ip -6 main table: no routes; rules: default local/main/default only)
```

- **[O]** The relay has connected routes to **both** attached networks, plus a default route via the frontend gateway `172.21.0.1`.
- **[I]** Together with forwarding enabled (`forwarding_and_firewall.md`), the relay's kernel would route a packet arriving on eth1 for `172.22.0.0/16` out of eth0.

## Cowrie (`cowrie-project`)

```
eth0 9a:ec:a1:47:ba:dc 172.22.0.1/16
172.22.0.0/16 dev eth0 scope link src 172.22.0.1
(no default route; no other routes; ip -6: none)
```

**[O]** Cowrie can reach only `172.22.0.0/16`. A reply to any source outside it (e.g. `172.21.0.1`) has **no route**: a return path is missing for any connection that does not originate inside `172.22.0.0/16`.

## Docker Desktop VM (engine namespace, pid 165)

```
default via 192.168.65.1 dev eth0
172.17.0.0/16 dev docker0          172.18.0.0/16 dev br-e0f9fc878c71   172.19.0.0/16 dev br-29dbe112c59e
172.20.0.0/16 dev br-ace391997e9b  172.21.0.0/16 dev br-c94e904b8861 src 172.21.0.1
192.168.65.0/24 dev eth0           192.168.65.7 dev services1
rules: 0 local, 32766 main, 32767 default, 32866 to 192.168.65.254 lookup 2, 33066 lookup 2
```

- **[O]** There is **no route to 172.22.0.0/16** in the VM. The `cowrie_internal` bridge has no address (`gateway_mode_ipv4: isolated`).
- **[I]** VM-originated traffic to `172.22.0.0/16` would follow the default route to `192.168.65.1` (out of the VM), **not** via the relay at `172.21.0.2`.
