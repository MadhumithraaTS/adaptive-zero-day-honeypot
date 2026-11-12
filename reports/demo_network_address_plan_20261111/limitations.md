# Limitations and unverified assumptions (Task 25B)

**Nothing is verified experimentally.** No network, container, Compose change or connection was made; all inspection was read-only.

**Unverified assumptions (each needs a check at implementation, with approval):**
1. **Client address at the relay.** On a user-defined bridge, the relay's accepted-socket peer is expected to be the client container's own address (`10.250.25.3` / `10.250.25.4`), because container-to-container traffic does not pass the published-port proxy. This is standard Docker bridge behaviour but **not observed** in this environment.
2. **Isolated gateway behaviour.** `gateway_mode_ipv4: isolated` together with `internal: true` and a custom subnet is expected to behave as on `cowrie_internal` (no bridge IP, no VM reachability). This was verified there in Task 14A, not for the new network.
3. **Fixed addresses.** Per-network `ipv4_address` / `mac_address` and a restricted `ip_range` are expected to be honoured by Compose v2.40.3 and engine 29.1.2 (API 1.52). Not tested here.
4. **Relay namespace forwarding.** No sysctls are set, and the container default `net.ipv4.ip_forward = 0` is assumed but not read.
5. **The relay keeps 172.22.0.2.** The current `cowrie_internal` address is dynamically assigned. Recreating the relay as the attributing relay must keep `172.22.0.2` (Task 14A's recreation did), or the attribution config's trusted-proxy entry and correlation would break. Pinning it would add an `ipv4_address` to the relay's `cowrie_internal` attachment. That is a relay-side change that needs approval; the network definition itself would be unchanged.
6. **Client tooling.** The client containers need a pinned, locally available image with an SSH client. Whether the pinned Cowrie image's Python/Twisted can act as a client was not checked. No image may be pulled without approval (`pull_policy: never` convention).
7. **Correlation timing.** The ±2 s budget comes from one Task 25A sample (+1.08 s, client connect → Cowrie connect, via the published proxy). On the direct container path, the hop is expected to be shorter. Not measured.

**Docker Desktop constraints:**
- **No inbound route from the host.** Docker networks live inside the Docker Desktop VM (WSL2 kernel 6.18.58.1), and the Windows host has no route to them. The demo must therefore be driven from containers on `demo_ingress`, not from the host. Host-originated traffic only arrives through the published-port proxy, where Task 25A showed the client address is lost.
- **Possible upgrade changes.** Docker Desktop updates may change proxy and network internals; re-verify after any upgrade.
- **Default address pools.** Docker uses its defaults (`DefaultAddressPools` = null). Future auto-created networks will not take `10.250.25.0/28`, which is outside them, but this is reassessed at implementation.
- **A pre-existing conflict** (host Wi-Fi `172.20.10.0/28` inside `et-ai_default` 172.20.0.0/16) exists independently of this design.

**Scope:**
- **Lab demonstration only.** This proves attribution and enforcement mechanics for a controlled client. It says nothing about real internet attackers reaching the published `127.0.0.1` path.
- **No enforcement, approval tooling, attributing relay, attribution-config or policy changes** were made or designed in code here.
