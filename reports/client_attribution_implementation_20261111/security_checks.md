# Security checks

Inspections were read-only: `docker inspect` / `network inspect`, plus `nsenter` into the namespaces through the `docker-desktop` WSL distro. Raw output is in `evidence/namespace_inspection.txt`, `evidence/isolation_probes.json.txt` and `evidence/final_state.txt`.

| Requirement | Check | Result |
|---|---|---|
| IP forwarding disabled | `/proc/sys/net/ipv4/{ip_forward,conf/all/forwarding,conf/default/forwarding}` in each namespace | relay 0/0/0; test client 0/0/0; control client 0/0/0. The clients first came up with 1/1/1 (Docker default); this was fixed by sysctls and the clients were recreated **before any session**. Cowrie's namespace (1/1/1, single interface) is pre-existing and was not modified, per the task restrictions |
| Weak-host hardening on the relay | sysctls | `arp_ignore=1`, `arp_announce=2`; plus the application-level local-address guard |
| Dropped capabilities and hardening | `docker inspect` | relay and both clients: user `cowrie` (999), CapDrop ALL, CapAdd none, read-only rootfs, no-new-privileges, not privileged, pids 64/32/32, 128 MiB. Relay `restart: unless-stopped`; clients `restart: no` |
| Cowrie unchanged | container ID, start time, restart count, rendered service | `0bec5a78b1cb`, started 2026-11-10T12:30:30Z, 0 restarts; rendered compose service identical to the backup |
| 172.22.0.2 preserved | `network inspect` | relay 172.22.0.2/16 on `cowrie_cowrie_internal` (8de3b00259f2, not recreated); 172.21.0.2/16 on `cowrie_relay_frontend` |
| Demo network membership | `network inspect cowrie_demo_ingress` | exactly 3 members: .2 relay `02:fa:19:00:00:02`, .3 test `02:fa:19:00:00:03`, .4 control `02:fa:19:00:00:04`; internal; IPv6 off; no gateway; isolated gateway mode |
| No host-side presence on the demo bridge | `ip addr` / routes on `br-1b475c1cf6e9` in the VM | no IPv4 address; no host route to 10.250.25.0/28; no NAT rules |
| Bridge isolation | iptables | `DOCKER-INTERNAL`: drop anything not from 10.250.25.0/28 out of the bridge, and anything not to 10.250.25.0/28 into it; `bridge-nf-call-iptables=1` |
| Listeners | `/proc/<pid>/net/tcp` LISTEN sockets | relay: `10.250.25.2:2222`, `172.21.0.2:2222`, and Docker DNS 127.0.0.11 only. No wildcard bind, no IPv6 listener. The published forwarder is not bound on the demo interface. Clients: Docker DNS only |
| Client routes | `ip -4 route` | each client has only `10.250.25.0/28 dev eth0`; no default route |
| Isolation before accepting clients | TCP connects and DNS lookups from both clients, run before any demo session | 172.22.0.1/.2:2222, 172.21.0.2/.1:2222, 192.168.65.1/.254/.7, 1.1.1.1, 8.8.8.8 → **Network unreachable**; 10.250.25.1 → timeout; `cowrie`, `cowrie-project`, `host.docker.internal`, `gateway.docker.internal`, `example.com` → no resolution. `ssh-relay` resolves to 10.250.25.2, which is the intended service. 10.250.25.2:22 → refused (no other listener) |
| Key custody | mounts | the private key is mounted read-only into the relay only. Clients mount only `demo_client.py`. `client_attribution` and `threat_assessment` contain no private-key loading or signing code (tested). No approval-signing keys exist |
| Control client excluded | config and assessment | `enforcement_excluded_sources: ["10.250.25.4/32"]`; S3/S5 → `enforcement_excluded`, never propose |
| No enforcement | firewall | no iptables (filter/nat/mangle/raw) or nft rule references 10.250.25.3 or .4. The S4 proposal is `dry_run`, `manual_approval: pending`, `execution: not_executed` |
| Diagnostic sessions | input check and config | `99732d516898` and `b806554e19b9` are not in the processed input (assertion in `run_attribution.py`) and are listed in `excluded_diagnostic_sessions` |
| No retroactive attribution | input scope | only Cowrie events after the pre-session baseline (line 21,855 onward) were correlated; a unit test shows that historical sessions cannot match |
| Protected artefacts | prior SHA256SUMS manifests | `behavioural_evidence` package (32/32), novelty and model freeze (16/16), Dataset V2 feature freeze (8/8), Dataset V2 training validation (60/60): all match. The 4 `threat_assessment` files differ, as intended (1.1.0). The sealed test set and the sealed exfiltration evaluation were not accessed |
| Backup | `cowrie/backups/pre_client_attribution_20261111T171555Z/` | compose file, inspect output for relay, Cowrie and networks, network list, with SHA256SUMS |
