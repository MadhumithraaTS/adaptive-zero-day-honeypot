# Isolation analysis (design)

## 1. Intended reachability matrix

| From \ To | Relay demo listener 10.250.25.2:2222 | Cowrie 172.22.0.1:2222 | Other client | Docker Desktop VM / host services | Internet | Unrelated containers |
|---|---|---|---|---|---|---|
| Test client 10.250.25.3 | **yes** | no (not on `cowrie_internal`) | L2-adjacent (ICC); no listener; see `safety_checks.md` | no (no gateway, `internal`) | no | no (not attached) |
| Control client 10.250.25.4 | **yes** | no | as above | no | no | no |
| Relay | n/a | **yes** (existing `cowrie_internal`) | yes (same bridge) | as today | no (`cowrie_internal` is internal; `relay_frontend` exists today, unchanged) | no |
| Cowrie | no (not on demo network) | n/a | no | no (unchanged) | no | no |

## 2. Why each boundary should hold

1. **No route out of the demo network.**
   - `internal: true`: no NAT, no default route.
   - `gateway_mode_ipv4: isolated`: no bridge IP, so there is no gateway endpoint through which members could reach VM-side services. This is the same mechanism verified on `cowrie_internal` in Task 14A.
2. **No direct client→Cowrie path.**
   - Clients are attached only to `demo_ingress`, and Cowrie is not.
   - Docker programs isolation rules between user-defined bridges, so traffic is not forwarded between them.
   - The only way to Cowrie is through the relay process.
3. **The relay is not a router.**
   - It is multi-homed, but routing between its interfaces would require IP forwarding in its network namespace and `NET_ADMIN` to change it.
   - The relay runs with `cap_drop: ALL`, `no-new-privileges`, a read-only root and user `cowrie`, and no sysctls are set (`evidence/docker_inspection.txt`).
   - Clients therefore reach only the relay's listening sockets.
   - To verify at implementation time: `net.ipv4.ip_forward = 0` inside the relay namespace.
4. **The relay listens only where intended.** Today's `twistd portforward` binds `0.0.0.0:2222`. Attaching it unchanged to the demo network would expose the *published-path* forwarder on `10.250.25.2` too. The attributing relay must therefore bind the demo listener explicitly to `10.250.25.2`, and the published-path listener to `172.21.0.2`, so the ingress path is unambiguous in every mapping record.
5. **Unrelated containers are not reachable.**
   - The containers on `et-ai_default`, `rezumy_default` and the default `bridge` (all exited today) are on different bridges and never attached to `demo_ingress`.
   - Embedded DNS only resolves names of containers sharing a network.
   - Attribution never uses names, only socket addresses.
6. **No exposure to the host.**
   - No `ports:` on the demo network or the client containers.
   - With Docker Desktop, the Windows host has no route into VM bridge subnets: `10.250.25.0/28` is absent from the host routes in `evidence/host_interfaces.txt`.

## 3. Protected networks (current attribution config and policy v2) and the demo network

- **Protected today:**
  - `127.0.0.0/8`, `::1/128`, `169.254.0.0/16`, `fe80::/10`;
  - `172.19.0.0/16`, `172.21.0.0/16`, `172.22.0.0/16`.

  None overlaps `10.250.25.0/28`.
- **Future attribution config v2** (not created here) would:
  - list `10.250.25.2/32` (the relay demo address) as protected;
  - treat `10.250.25.3` and `10.250.25.4` as attributable only via a verified relay mapping;
  - keep `172.21.0.1` (Docker proxy) protected.

  The demo subnet must **not** be added to `internal_cidrs`: it is an ingress network, not a probe target.
- **Pre-existing host conflict (not introduced here):** the host Wi-Fi `172.20.10.0/28` lies inside Docker's `et-ai_default` 172.20.0.0/16. It does not affect this design.
