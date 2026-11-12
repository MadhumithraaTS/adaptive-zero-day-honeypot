# Verification results (V1–V14 except V12)

**Evidence:**
- `evidence/verification_inspect.txt` (Docker inspections);
- `evidence/audit_after.txt` (read-only `nsenter` audit; before = backup `audit_before.txt`);
- `evidence/cowrie_log_after.txt`;
- `evidence/file_hashes_after.txt`.

| # | Check | Before | After | Result |
|---|---|---|---|---|
| V1 | Relay running | `8d3bafb35f38`, started 2026-11-10T12:30:31Z | **`54b551d98e1a`**, `running`, started 2026-11-11T16:59:16Z, 0 restarts. Command has `--port=tcp:2222:interface=172.21.0.2`. Log: `ProxyFactory starting on 2222`, no errors | PASS (the container ID changes by design on recreation) |
| V2 | Sysctls declared | none | `{"net.ipv4.conf.all.forwarding":"0","net.ipv4.conf.default.forwarding":"0","net.ipv4.ip_forward":"0"}` | PASS |
| V3 | Forwarding effective (relay netns) | `ip_forward = 1`; all/default/eth0/eth1 `forwarding = 1` | `ip_forward = 0`; all/default/eth0/eth1 `forwarding = 0`; IPv6 forwarding 0; eth0/eth1 `disable_ipv6 = 1` | PASS |
| V4 | Addresses | 172.22.0.2 / 172.21.0.2 | **172.22.0.2** (`cowrie_internal`, net `8de3b00259f2`) / **172.21.0.2** (`relay_frontend`, net `c94e904b8861`) | PASS |
| V5 | Listeners | `0.0.0.0:2222` (`00000000:08AE`), `127.0.0.11:43835` | **`172.21.0.2:2222` (`020015AC:08AE`)** and `127.0.0.11:34069` (Docker DNS; port re-randomised on recreation). UDP: Docker DNS `127.0.0.11` only. No wildcard listener | PASS |
| V6 | Hardening | cap_drop ALL, no-new-privileges, read-only, user `cowrie`, pids 64, mem 128 MiB, tmpfs /tmp, restart unless-stopped | identical; `/proc/<pid>/status`: CapInh/Prm/Eff/Bnd/Amb = 0, NoNewPrivs = 1, Uid 999 | PASS |
| — | Image digest | `sha256:bf371c37…cc13a` | same | PASS |
| V7 | Volumes | `4492a68c…` (etc), `fba87a59…` (var) | same two anonymous volumes mounted | PASS |
| V8 | Cowrie unchanged | `0bec5a78b1cb`, started 2026-11-10T12:30:30.630598884Z, 0 restarts, 172.22.0.1 | identical. Field-by-field: ID, Image, StartedAt, RestartCount, Cmd, Labels, Binds, CapDrop, ReadonlyRootfs and Mounts unchanged | PASS |
| — | Cowrie log | 21,852 lines, `28e1c576…` | 21,852 lines, `28e1c576…` (byte-identical) | PASS |
| V9 | Networks | — | Both networks: Id, Options, IPAM, Labels and Internal identical to the backup. Members unchanged ({Cowrie .1, relay .2}; {relay .2}). Network list unchanged (8 networks, same IDs). Published port `127.0.0.1:2223` | PASS |
| V10 | VM isolation rules | `DOCKER-INTERNAL` drops, raw 2223 drop, DNAT `127.0.0.1:2223 → 172.21.0.2:2222` | `iptables-nft-save` (VM) **identical** apart from timestamps | PASS |
| V11 | Routes | relay: default via 172.21.0.1, 172.21/16 eth1, 172.22/16 eth0 | identical. Cowrie netns (routes, sysctls, rules, listeners) identical. VM IPv4 routes identical; IPv6 link-local entries for the new relay veth pair replace the old ones (expected) | PASS |
| V12 | Cowrie connectivity (one connection) | — | **Not performed**: prohibited in this task; awaiting approval | — |
| V13 | Files | — | Only `cowrie/docker-compose.yml` changed (`cd84da48…` → `903f0b95…`). 19 recorded files (`behavioural_evidence/`, `threat_assessment/`, `configs/threat_attribution_v1.json`, `configs/defence_policy.json`, `configs/defence_policy_v2.json`) match the Task 25 hashes. `cowrie/userdb.txt` unchanged (`46d68fb5…`) | PASS |
| V14 | Re-audit | — | `routing_audit.md` | PASS |

**No stop condition occurred:**
- the relay started;
- both addresses were retained;
- the listener is bound only to the intended interface;
- forwarding is off;
- Cowrie was not restarted or changed;
- no unrelated configuration changed.
