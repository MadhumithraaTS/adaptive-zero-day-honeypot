# Forwarding sysctls and firewall rules (read-only)

**Commands:**
- **sysctls:** `nsenter --net=/proc/<pid>/ns/net sh -c 'cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/conf/*/{forwarding,rp_filter,accept_source_route,proxy_arp,route_localnet} /proc/sys/net/ipv6/conf/*/{forwarding,disable_ipv6} /proc/sys/net/bridge/bridge-nf-call-ip{,6}tables'`
- **firewall:** `nsenter --net=/proc/<pid>/ns/net --mount=/proc/165/ns/mnt {iptables-nft-save | ip6tables-nft-save | iptables-legacy-save | nft list ruleset}`. These are listing commands only; the engine mount namespace provides the binaries.

## 1. Sysctls

| Setting | Relay | Cowrie | VM engine |
|---|---|---|---|
| `net.ipv4.ip_forward` | **1** | 1 | 1 |
| `conf.{all,eth0,eth1}.forwarding` | **1** | 1 | 1 |
| `rp_filter` (all/ifaces) | 2 (loose) | 2 | — |
| `accept_source_route` | 0 | 0 | — |
| `proxy_arp` | 0 | 0 | — |
| `route_localnet` | 0 | 0 | — |
| IPv6 `conf.all.forwarding` | 0 | 0 | 1 |
| IPv6 `disable_ipv6` on container ethX | 1 | 1 | — |
| `bridge-nf-call-iptables` / `-ip6tables` | 1 / 1 | 1 / 1 | **1 / 1** |

- **[O]** IPv4 forwarding is enabled in the relay namespace on every interface.
- **[O]** IPv6 is disabled on the container interfaces, and IPv6 forwarding is 0 in both containers.
- **[O]** Loose reverse-path filtering (`rp_filter = 2`) would not reject a forwarded packet whose source is reachable through any interface.

## 2. Relay namespace firewall

```
*nat  (only table present)
-A OUTPUT      -d 127.0.0.11/32 -j DOCKER_OUTPUT           (Docker embedded DNS)
-A POSTROUTING -d 127.0.0.11/32 -j DOCKER_POSTROUTING
DOCKER_OUTPUT/POSTROUTING: DNAT/SNAT 127.0.0.11:53 <-> 127.0.0.11:43835 (tcp), :33834 (udp)
ip6tables-nft-save: empty; iptables-legacy-save: empty; nft: only "table ip nat" (the same DNS rules)
```

- **[O]** There is **no filter table** in the relay namespace: no `FORWARD` chain and no policy, so forwarded IPv4 is accepted by default.
- **[O]** There is no NAT/masquerade for forwarded traffic, so the relay would forward packets **with their original source address**.

## 3. Cowrie namespace firewall

**[O]** Identical structure: only the Docker DNS NAT rules (`127.0.0.11` ↔ `:33177` tcp / `:35616` udp). No filter rules.

## 4. Docker Desktop VM firewall (engine namespace; excerpts)

```
*raw    -A PREROUTING -d 127.0.0.1/32 ! -i lo -p tcp --dport 2223 -j DROP
*nat    -A DOCKER -d 127.0.0.1/32 -p tcp --dport 2223 -j DNAT --to-destination 172.21.0.2:2222
        -A POSTROUTING -s 172.21.0.0/16 ! -o br-c94e904b8861 -j MASQUERADE  (frontend egress NAT; none for 172.22.0.0/16)
*filter :INPUT ACCEPT  :FORWARD ACCEPT  :OUTPUT ACCEPT
        -A FORWARD -j DOCKER-USER ; -A FORWARD -j DOCKER-FORWARD
        DOCKER-FORWARD: -j DOCKER-CT ; -j DOCKER-INTERNAL ; -j DOCKER-BRIDGE ; -i <each non-internal bridge> -j ACCEPT ;
                        -i br-8de3b00259f2 -o br-8de3b00259f2 -j ACCEPT
        DOCKER-INTERNAL: ! -s 172.22.0.0/16 -o br-8de3b00259f2 -j DROP
                         ! -d 172.22.0.0/16 -i br-8de3b00259f2 -j DROP
        DOCKER: -d 172.21.0.2/32 ! -i br-c94e904b8861 -o br-c94e904b8861 -p tcp --dport 2222 -j ACCEPT ; ! -i br-c94e… -o br-c94e… -j DROP ; …
```

**nft counters** (`nft list ruleset`, VM):

| Rule | Packets |
|---|---:|
| `iifname "br-8de3b00259f2" oifname "br-8de3b00259f2" … accept` | **192,466** (52.9 MB) |
| `DOCKER-INTERNAL: oifname "br-8de3…" ip saddr != 172.22.0.0/16 … drop` | 0 |
| `DOCKER-INTERNAL: iifname "br-8de3…" ip daddr != 172.22.0.0/16 … drop` | 0 |

**What this shows:**
- **[O]** With `bridge-nf-call-iptables = 1`, frames bridged on `br-8de3` (relay eth0 ↔ Cowrie eth0) traverse the VM's `FORWARD` hook. The 192,466-packet counter proves it: that is the relay↔Cowrie traffic.
- **[O]** `DOCKER-INTERNAL` is evaluated before that accept rule, and drops any frame entering `br-8de3` whose IPv4 source is outside `172.22.0.0/16`.
- **[I]** A packet the relay forwarded from the frontend side (source e.g. `172.21.0.1`, unchanged because the relay does no NAT) would be dropped by `DOCKER-INTERNAL` on its way to Cowrie.
- **[O]** The zero drop counters mean no such frame has been seen. This is consistent with no attempt, but proves nothing about blocking by itself.
