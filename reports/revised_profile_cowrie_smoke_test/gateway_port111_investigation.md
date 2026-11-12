# Gateway 172.22.0.1 TCP 111 exposure: read-only investigation

Date: 2026-11-10, about 11:58–12:10 UTC. Follows the Task 13 stop report (`report.md`, this folder).

**Scope kept:**
- no new network probes or port scans, no RPC requests, no Cowrie traffic;
- no Docker, container, firewall or configuration change, and no restart;
- no dataset generation and no test-set access.

**Method:** read-only file reads only:
- `/proc` socket tables, process metadata and `/sys` attributes in the Docker Desktop VM, read from the
  `docker-desktop` WSL distribution;
- `docker inspect`, `docker network inspect` and `docker network ls`;
- Cowrie source and configuration files, read inside the container with `docker exec … python3`;
- one `iptables-nft-save` listing of the VM firewall (a listing only, nothing changed).

The scripts used are saved in `evidence/gateway_ns_readonly_inspect*.sh`.

**Evidence:**
- `evidence/gateway_port111_listeners.json`
- `evidence/docker_vm_iptables_save_20261110T1202Z.txt`
- `evidence/preflight_isolation.json` (from the stop report)

## 1. Summary

The TCP 111 listener on 172.22.0.1 is **rpcbind** (`/usr/sbin/rpcbind -f`), part of the Docker Desktop VM's
built-in NFS client services. **Confirmed** from the kernel socket table: the listening socket's inode is held
by the rpcbind process.

- **Binding:** rpcbind listens on **all interfaces** (`0.0.0.0:111`, `[::]:111`, TCP and UDP) in the Docker engine's
  network namespace. `rpc.statd` in the same namespace also listens on all interfaces (TCP 32775, UDP 51113,
  plus IPv6 ports).
- **Why Cowrie can reach it:** every Docker bridge address, including 172.22.0.1, is a local address of that
  namespace. Docker's `internal=true` rules apply only to *forwarded* traffic. The VM's INPUT chain is
  `ACCEPT` with no rules, so traffic from Cowrie *to the bridge address itself* is delivered to these
  listeners.
- **Cowrie's own controls:** Cowrie's emulated network commands (`nc`, `wget`, `curl`, `ftpget`) refuse
  172.16.0.0/12 at the application level, and SSH port forwarding is configured to fake rather than connect.
- **Conclusion:** none of Cowrie's attacker-facing features can reach 172.22.0.1. The exposure is at network
  level, and protection rests on a single application-level control.

## 2. Confirmed findings

| # | Finding | Evidence |
|---|---|---|
| C1 | **The listener is rpcbind.** TCP `0.0.0.0:111` (inode 1258), TCP6 `[::]:111` (1260), UDP `0.0.0.0:111` (1257) and UDP6 `[::]:111` (1259) are owned by pid 100: `/usr/sbin/rpcbind`, cmdline `/sbin/rpcbind -f`, uid 100. Identified from the socket-inode → process fd mapping, not from the port number | `gateway_port111_listeners.json` |
| C2 | rpcbind, `rpc.statd` (pid 102, `-d -F`) and `rpc.idmapd` (pid 128) are children of pid 59 `/initd services`. That is the Docker Desktop VM's own init, launched by `wsl-bootstrap run --base-image …/docker-desktop.iso`. The VM image ships `/etc/init.d/rpcbind` and `/etc/init.d/nfs-common`. These are Docker Desktop components, **not** part of the honeypot deployment | process tree, init scripts |
| C3 | They run in network namespace `net:[4026532223]`, the same namespace as `dockerd` (pid 165) and containerd. The WSL distributions' namespace `net:[4026531833]` (docker-desktop and Ubuntu-22.04 shells) has only `lo` and `eth0` and **no** port-111 listener | `/proc/*/ns/net` |
| C4 | **Bound to all interfaces.** Local IPv4 addresses of that namespace are 127.0.0.1, 172.17.0.1, 172.18.0.1, 172.19.0.1, 172.20.0.1, 172.21.0.1, **172.22.0.1**, 192.168.65.3 and 192.168.65.6. rpcbind and statd are reachable on any of them that a peer can route to. They are not exposed on the internal gateway alone | `fib_trie` LOCAL entries, socket table |
| C5 | Complete TCP listener set in that namespace: rpcbind 111 (all interfaces), rpc.statd 32775 (all), rpc.statd 34279 (IPv6 all), and dockerd **127.0.0.1:2223** (the relay's published port, loopback only; a raw-table rule drops non-`lo` packets to it). Nothing else listens on TCP. The Docker API is not on TCP. UDP: rpcbind 111, statd 51113, 37837 (IPv6) and 662 (127.0.0.1) | socket table |
| C6 | `172.22.0.1` is the address of bridge `br-72ab93e8020b` (= `cowrie_cowrie_internal`, IPAM gateway `172.22.0.1`). Cowrie's ARP cache maps 172.22.0.1 to `0e:b4:01:56:10:3b`, the bridge's own MAC. The bridge has two ports: the veths of Cowrie and the relay | `/sys/class/net`, `/proc/net/arp` |
| C7 | **Why `internal=true` does not block it.** The filter table has `INPUT ACCEPT` with **zero INPUT rules**. The `DOCKER-INTERNAL` drops (`! -d 172.22.0.0/16 -i br-72ab…`, `! -s 172.22.0.0/16 -o br-72ab…`) are reached only from `FORWARD`. Packets from Cowrie addressed to 172.22.0.1 are local delivery (INPUT), not forwarding | iptables listing |
| C8 | **Why other host addresses remain unreachable.** Cowrie's routing table has only `172.22.0.0/16` on `eth0` and no default route. 172.21.0.1, 192.168.65.3 and the other local addresses are therefore unreachable from Cowrie, even though the same listeners are bound there. **172.22.0.1 is the only VM address Cowrie can reach** | Cowrie `/proc/net/route` (stop report) |
| C9 | IPv6: `cowrie_cowrie_internal` has `enable_ipv6=false`. Cowrie has only `::1` and no IPv6 route beyond loopback, so the IPv6 listeners are not reachable from Cowrie | Cowrie `/proc/net/if_inet6`, network options |
| C10 | **Origin of the Task 2 audit error.** `docker inspect cowrie-project` reports the container's `Gateway` as empty (`invalid IP`), because an internal network gives containers no default gateway. The *network* still has IPAM gateway 172.22.0.1, and Docker assigns it to the bridge. The audit's "no gateway" is accurate for the container's route and inaccurate for the bridge address. Separately, the audit's diagram lists the internal IPs the other way round (Cowrie is now 172.22.0.3 and the relay 172.22.0.2, since the 09:03 re-creation) | inspect outputs |
| C11 | **Cowrie's application-level controls** (pinned build source, read-only): (a) `nc`, `wget`, `curl` and `ftpget` call `core/network.py::communication_allowed()`, which refuses `BLOCKED_IPS`, including **172.16.0.0/12**, 10/8, 192.168/16, 127/8, 169.254/16 and 0/8. DNS names are checked after resolution, and in the isolated lab no name resolves. (b) SSH `direct-tcpip` forwarding: `forwarding=true`, but `forward_redirect=false` and `forward_tunnel=false`, so every request gets `FakeForwardingChannel` ("does not forward, but just logs requests"). (c) The only enabled output plugin is `output_jsonlog`; the backend is `shell`, so no LLM or proxy backend connects out. (d) `shell/protocol.py` performs a UDP `connect()` to 8.8.8.8 to learn its own address; this sends no packet and fails here | `cowrie.cfg.dist` (no `cowrie.cfg` override), `src/cowrie/…` |
| C12 | The 111/TCP connection recorded in the stop report came from the isolation probe itself: a Python socket run by the investigator via `docker exec`, not by Cowrie or an attacker path. It sent no data | stop report §5 |
| C13 | Pre-existing and unrelated to Tasks 12/13. The network was created at 08:23:45 UTC, and rpcbind starts with the Docker Desktop VM. The same condition applies to every Docker bridge on this machine, for example `rezumy_default` and `et-ai_default` | network metadata |

## 3. What is reachable from Cowrie, and by whom

| Actor inside `cowrie-project` | Can reach 172.22.0.1:111 / :32775? |
|---|---|
| Attacker in Cowrie's emulated shell (`nc`, `wget`, `curl`, `ftpget`) | **No.** Blocked by `communication_allowed()` (C11a) |
| Attacker using SSH port forwarding (`ssh -L` / `direct-tcpip`) | **No.** Fake channel; no connection is opened (C11b) |
| Downloaded or uploaded files | **No execution path.** Cowrie emulates execution and never runs binaries |
| Code running with real container privileges (only after a Cowrie/Twisted/Python compromise, or via `docker exec`) | **Yes**: TCP/UDP 111 (rpcbind) and TCP 32775 / UDP 51113 (rpc.statd) on 172.22.0.1. Nothing else on the VM is reachable (C5, C8) |

**Functionality on those ports** (from the service type; no RPC request was sent to confirm):
- rpcbind answers portmapper queries such as program listing (`DUMP`), lookup (`GETPORT`/`GETADDR`) and,
  from non-local callers normally refused, `SET`/`UNSET`, plus `CALLIT`/indirect calls where enabled.
- rpc.statd serves the NSM status protocol used by NFS locking.

## 4. Hypotheses (not verified, no RPC traffic sent)

| # | Hypothesis | Why plausible / how to verify |
|---|---|---|
| H1 | rpcbind and statd run because Docker Desktop's VM image enables NFS client support (for example, NFS volumes) | `/etc/init.d/nfs-common`, `rpc.idmapd`, `/run/rpc_pipefs`; no NFS mount is currently active in the engine namespace. Verify against Docker Desktop documentation or release notes |
| H2 | rpcbind would disclose registered programs (portmapper, status) to an unauthenticated `DUMP` | Standard rpcbind behaviour; would require an RPC request, which was excluded |
| H3 | The rpcbind/statd versions may be affected by known rpcbind issues (for example CVE-2017-8779 "rpcbomb" memory exhaustion) or UDP reflection | Versions could not be read: the VM image has no dpkg status for these packages. Could be checked read-only via `/proc/100/root/usr/sbin/rpcbind` file metadata or Docker Desktop's SBOM |
| H4 | A full compromise of the Cowrie process could use rpcbind/statd for VM-local reconnaissance or a denial of service against the Docker engine VM's NFS services | Requires the precondition in §3, last row. Impact would be on the Docker Desktop VM, which also runs unrelated containers (C13) |
| H5 | Recreating the internal network with a bridge that has no IPv4 address would remove the exposure without affecting relay ↔ Cowrie traffic | That traffic is bridged at layer 2 between the two veths (`-i br-72ab… -o br-72ab… ACCEPT`) and never uses 172.22.0.1. The driver option name and support on Engine 29.1.2 must be checked in Docker documentation (candidates: `com.docker.network.bridge.inhibit_ipv4`, or the bridge `gateway_mode_ipv4=isolated` mode for internal networks) |

## 5. Security implications

- **Current lab posture:** low practical risk.
  - Cowrie SSH is reachable only from the Windows host loopback.
  - Every attacker-facing network feature of Cowrie refuses the 172.16.0.0/12 range or fakes the connection.
  - The listeners reachable from Cowrie are limited to rpcbind and statd on one address.
- **Defence in depth is weaker than the audit stated.** Network-level isolation from the VM is incomplete. A
  Cowrie code-execution flaw (Twisted, Python or a Cowrie bug) would give a reachable path to two root/rpc
  services on the Docker Desktop VM, which also hosts unrelated projects' containers. The audit's "no gateway"
  wording should be corrected.
- **Not affected:**
  - Internet isolation (no route, DNS fails);
  - host-LAN isolation (192.168.65.254 and the Windows interfaces are unreachable);
  - loopback-only publication;
  - the relay path (unaffected by every remediation in §6).
- **For the smoke test:** the revised profiles never address 172.16.0.0/12; Cowrie would block it anyway. The
  test traffic would not touch rpcbind.

## 6. Remediation options (none applied)

| Option | What it does | Preserves relay ↔ Cowrie | Persistence / cost | Assessment |
|---|---|---|---|---|
| R1. Accept and document | Correct the Task 2 audit; record C7/C11 as residual risk with Cowrie's `BLOCKED_IPS` as the compensating control | yes | none | Adequate for a loopback-only research lab, but relies on one application control |
| R2. No IPv4 address on the internal bridge | Recreate `cowrie_cowrie_internal` with a bridge driver option that suppresses the gateway address (H5) | yes (layer-2 bridging) | Persistent in `docker-compose.yml`; requires `docker compose down/up` (container re-creation, network re-creation; data volumes kept) | **Preferred structural fix**, provided Engine 29.1.2 supports the option. Verify afterwards: no LOCAL `172.22.0.1`, Cowrie gets "unreachable" to 172.22.0.1, the relay banner works |
| R3. VM INPUT rule | e.g. `iptables -I INPUT -i br-72ab93e8020b -j DROP` in the Docker Desktop VM | yes (bridged traffic does not traverse INPUT; must not block established replies for the relay's own sockets, which also do not use INPUT) | **Not persistent** (lost on Docker Desktop restart); the bridge name changes when the network is recreated; touches the VM firewall, which the project's standing rules exclude | Not recommended except as a temporary measure with explicit approval |
| R4. Disable rpcbind/statd in the VM | Stop the NFS client services | n/a | Not supported or persistent in Docker Desktop's ISO-based VM; may break NFS volume features; affects all projects | Not recommended |
| R5. Bind rpcbind to loopback (`-h 127.0.0.1`) | Restrict listening addresses | n/a | Same problem as R4: VM image files are not user-managed | Not recommended |
| R6. Run Cowrie with no network and a socket-based relay | Removes Cowrie's IP stack (`network_mode: none`) and connects the relay over a shared Unix socket | requires relay redesign | Substantial change; Cowrie listens on TCP, so a socket-forwarding sidecar is needed | Overkill for the current goal |
| R7. Run the lab on a dedicated Linux VM or host without NFS services | Removes the services from the honeypot's host namespace | yes | Infrastructure change | Option for later, production-like deployments |

**Recommendation for review:** R1 now (documentation and audit correction), and R2 as the structural fix,
subject to approval and to confirming the driver option. R3–R5 are not recommended.

## 7. Status

The smoke test (Task 13) remains stopped. No traffic, configuration, firewall, container or file outside this
report folder was changed. Waiting for a decision: proceed under R1, or apply R2 first.

**Update, 2026-11-10 (Task 13B):**
- R1 was explicitly approved: the exposure is accepted as a documented residual risk.
- The Task 2 audit was corrected.
- The 21-session smoke test then ran; see `report.md`.
- R2 is not applied.
