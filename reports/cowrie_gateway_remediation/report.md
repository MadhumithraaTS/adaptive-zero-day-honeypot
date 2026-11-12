# Task 14A / 14A.1 — Remove Cowrie → Docker gateway access (R2)

**Date:** 2026-11-10.

**Status: complete and verified.**
- **Task 14A** applied `gateway_mode_ipv4: isolated` to Cowrie's internal network. That removed the gateway
  exposure, but it stopped at verification: the relay's target hostname `cowrie` no longer resolved.
- **Task 14A.1** ran the approved Option A (`docker compose up -d --force-recreate`). That restored the Compose
  service alias, with all volumes preserved. **All ten verification checks pass**, and one approved
  loopback banner read confirmed the end-to-end path.

**Not done:** no attack, smoke-test or dataset traffic, no test-set access, no firewall change, no change to
Docker Desktop VM services (rpcbind and statd still run), no generator, extractor, profile, Cowrie or model
change, and no commit. The only configuration change is the network diff in §2.

## 1. Docker Engine compatibility evidence

**Installed versions:** Docker Engine (client and server) **29.1.2**, API 1.52 (minimum 1.44), Docker Compose
**v2.40.3-desktop.1**, Docker Desktop on WSL2.

**Authoritative documentation:**
- [Bridge network driver](https://docs.docker.com/engine/network/drivers/bridge/):
  - `com.docker.network.bridge.gateway_mode_ipv4` / `_ipv6`, default `nat`.
  - `com.docker.network.bridge.inhibit_ipv4`, default `false`: "Prevent Docker from assigning an IP address to
    the bridge"; user-defined bridges only.
- [Port publishing — gateway modes](https://docs.docker.com/engine/network/port-publishing/), modes `nat`,
  `nat-unprotected`, `routed` and `isolated`:
  - "Mode `isolated` can only be used when the network is also created with CLI flag `--internal`."
  - "No address is assigned to the bridge when the network is created with gateway mode `isolated`."
  - The page also notes that in other internal networks the bridge normally does get an address that containers
    can reach. That was the Task 13 exposure.
- **History:** gateway modes were added in Engine 27.0. `isolated` is described in moby/moby PR 49262 (Engine 28
  line). `inhibit_ipv4` dates from 2018 and was not changed in 28.0. Sources:
  [docs commit 3520fa2](https://gitea.cncfstack.com/docker/docs/commit/3520fa2ed947c203126668dc7331d57a0bb522e0),
  [Engine v28 networking blog](https://www.docker.com/blog/docker-engine-28-hardening-container-networking-by-default/),
  [moby bridge labels](https://git.causa-arcana.com/kotovalexarian-likes-github/moby--moby/src/commit/10027e8c01ba98f2598f03bed177a71caec5b69c).

**Empirical check on the installed engine** (Task 14A, before any lab change):
- Two throwaway internal networks were created, inspected and deleted:
  - `gateway_mode_ipv4=isolated` and `inhibit_ipv4=true` were both accepted. Neither bridge had an IPv4 address
    or route in the Docker engine namespace, and the gateway was reported as none.
  - `isolated` on a non-internal network was rejected: `gateway mode 'isolated' can only be used for an internal
    network`.
- Two throwaway containers from the pinned image (`--pull never`, hardened) on the isolated test network checked
  connectivity:
  - name resolution worked;
  - TCP connection and data exchange worked;
  - each container had only the subnet route.
- **Observation:** with no gateway reserved, IPAM gives the first container the `.1` address.
- No test object remains.

**Choice:** `gateway_mode_ipv4: isolated`, the documented mode for internal networks, which the engine refuses
unless `internal: true`.

## 2. Configuration diff and backups

Only `cowrie/docker-compose.yml` changed (SHA-256 `67aa9e6b…` → `cd84da48…`). Diff in
`evidence/docker-compose.diff`:

```diff
@@ -40,4 +40,9 @@
 networks:
   cowrie_internal:
     internal: true
+    # No gateway address on the bridge, so Cowrie cannot reach Docker Desktop VM services (rpcbind 111, statd)
+    # via 172.22.0.1. Relay <-> Cowrie traffic is bridged at layer 2 and is unaffected.
+    # Engine >= 28 only; requires internal: true. See reports/cowrie_gateway_remediation/report.md.
+    driver_opts:
+      com.docker.network.bridge.gateway_mode_ipv4: isolated
   relay_frontend: {}
```

**Backups:**
- `cowrie/backups/pre_gateway_remediation_20261110/` (with `SHA256SUMS`, re-verified OK before 14A.1): the
  original compose file, container and network inspects, `cowrie.json` (963 lines, `d59ca2d4…`), the log
  directory listing and `config.diff`.
- `evidence/pre_recreate/`: state immediately before the 14A.1 recreation (container inspects, network inspect,
  resolved Compose config, IDs and mounts, volume list, Cowrie `var` state).

## 3. What was done

| Time (UTC) | Step | Result |
|---|---|---|
| 12:25:00–05 | 14A: `docker compose up -d` (after a dry run) | `cowrie_cowrie_internal` removed and recreated (`8de3b00259f2`, `isolated`). The *existing* containers were stopped and started, which reconnected them **without Compose service aliases**: `cowrie` stopped resolving. Stopped for review |
| 12:30:00 | 14A.1 Phase 1: state recorded | IDs `2a3c9e98967e` / `884f35bbb307`; volumes etc `f51e84a3…`, var `268411d7…` (Cowrie) and `4492a68c…` / `fba87a59…` (relay), all existing local volumes labelled anonymous. Cowrie log 963 lines `d59ca2d4…`; rotated log `cowrie.json.2026-10-24` 40,190 lines `d88daba6…`; 1,741 TTY files; 127 downloads |
| 12:30:25–32 | 14A.1 Phase 2: `docker compose up -d --force-recreate` | `cowrie-project` and `cowrie-ssh-relay` recreated and started. **The network was not touched.** No `down`, no volume removal or prune |
| 12:31:26 | Check 2: relay → `cowrie:2222` direct TCP, banner read only | 1 Cowrie session (`831186ee1418`, connect + closed) |
| 12:31:44 | Phase 5: one banner read via `127.0.0.1:2223` | 1 Cowrie session (`0295b45a0cd2`, connect + closed) |

## 4. Preservation after recreation

| Item | Result |
|---|---|
| Containers | **New** IDs `0bec5a78b1cb` (Cowrie) and `8d3bafb35f38` (relay); both running, RestartCount 0 |
| Images | Both `sha256:bf371c37638bf8b49efed87b66f5d0bf48432a499c6b3fa3c44c03ebf02cc13a`, configured as `cowrie/cowrie@sha256:bf371c37…` |
| Volumes | **Same four volumes** re-attached at the same mount points, read-write. The `userdb.txt` bind mount is read-only |
| Cowrie logs | `cowrie.json` **963 lines, 461,838 bytes, `d59ca2d4…` (unchanged)**; `cowrie.json.2026-10-24` unchanged (`d88daba6…`); 1,741 TTY files and 127 downloads unchanged; `etc` unchanged. No rotation |
| Hardening | Both: read-only root filesystem, `/tmp` tmpfs, `cap_drop ALL`, no `cap_add`, `no-new-privileges:true`, not privileged |
| Limits | Cowrie PIDs 256, memory 512 MiB; relay PIDs 64, memory 128 MiB (unchanged) |
| Network | `cowrie_cowrie_internal` is still `8de3b00259f2`, `internal=true`, `gateway_mode_ipv4=isolated`, no gateway. Bridge `br-8de3b00259f2` has no IPv4 address; ports `veth61f719d` and `vetheda3871` |
| Aliases | Cowrie `[cowrie-project, cowrie]` (**restored**); relay `[cowrie-ssh-relay, ssh-relay]` |

## 5. Verification (all ten checks)

| # | Check | Result |
|---|---|---|
| 1 | Relay resolves `cowrie` | **Pass.** `cowrie` → 172.22.0.1; `cowrie-project` → 172.22.0.1 |
| 2 | Relay connects directly to Cowrie over the internal bridge | **Pass.** From the relay, TCP to `cowrie:2222` reached peer `172.22.0.1:2222` and received `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`. Nothing was sent; Cowrie logged one connect/closed (session `831186ee1418`, `src_ip` 172.22.0.2) |
| 3 | Cowrie cannot reach the Docker VM gateway | **Pass.** The Docker VM's local IPv4 addresses (127.0.0.1, 172.17–172.21.0.1, 192.168.65.3, 192.168.65.6) contain **no 172.22.x address**, and the VM has no route to 172.22.0.0/16. 172.22.0.1 is Cowrie's own address |
| 4 | Cowrie cannot reach rpcbind or rpc.statd | **Pass.** 192.168.65.3:111, 192.168.65.3:32775, 172.21.0.1:111 and 172.17.0.1:111 are *Network is unreachable*. rpcbind still listens in the VM; it was not changed |
| 5 | Cowrie cannot reach the Docker Desktop host | **Pass.** 192.168.65.254 is *Network is unreachable*; `host.docker.internal` does not resolve |
| 6 | Cowrie cannot reach external networks | **Pass.** 1.1.1.1 and 8.8.8.8 are *Network is unreachable*; `example.com` does not resolve |
| 7 | No default route | **Pass.** Only `172.22.0.0/16` on `eth0` |
| 8 | SSH only on `127.0.0.1:2223` | **Pass.** `docker port cowrie-ssh-relay` → `127.0.0.1:2223`; Cowrie publishes nothing (its `2222-2223/tcp` are image `EXPOSE` entries only). 172.27.0.1, 192.168.56.1 and 172.20.10.5 do not accept on 2223 |
| 9 | Log collection works | **Pass.** The generator's `capture_log_baseline('cowrie-project')` returned 965 after check 2. `docker cp` of `cowrie.json` works. Cowrie's console has no errors since the recreation |
| 10 | No unexpected exposure; containers healthy on pinned images | **Pass.** No new published port or network. `cowrie_relay_frontend` is unchanged. Both containers are running on the pinned digest with hardening intact (§4) |

**Phase 5 — single SSH banner read through `127.0.0.1:2223`** (12:31:43.97 UTC; read banner, close; no
authentication or commands):

| | Lines | Bytes | SHA-256 |
|---|---|---|---|
| Before recreation / before check 2 | 963 | 461,838 | `d59ca2d4831d2d9ce630dabbeaacaac33b6e3dac095ee570c47f8bac0e343240` |
| After check 2 (= before Phase 5) | 965 | 462,468 | `578a45ec4d63975b8df500235d3e695377a4a8df46a738269d5e80f30ba20adc` |
| After Phase 5 | 967 | 463,098 | `5eefaad1022d673330f97b967931f1fba348c09dd6fc1757d8d801cf9ef4ff1a` |

- **Banner:** `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`.
- **New Cowrie events:** exactly one session, `0295b45a0cd2`, from `172.22.0.2:41682` to `172.22.0.1:2222`
  (`session.connect`, then `session.closed` after 0.0 s).
- **Prefix check:** the first 963 lines of the final log still hash to `d59ca2d4…`.
- **The four new lines** (two sessions) are saved in `evidence/cowrie_new_events_task14a1.json`.

## 6. Topology

**Before (Tasks 2–13):**
```
host 127.0.0.1:2223 ─► relay (frontend 172.21.0.2 | internal 172.22.0.2) ─► cowrie (172.22.0.3)
                                      bridge br-72ab… = 172.22.0.1 on the Docker VM
                                      └─ reachable from Cowrie: rpcbind 111, rpc.statd 32775/51113
```

**After (verified 12:31 UTC):**
```
host 127.0.0.1:2223 ─► relay (frontend 172.21.0.2 | internal 172.22.0.2) ─► cowrie (172.22.0.1, alias "cowrie")
                                      bridge br-8de3… has NO IPv4 address (gateway_mode_ipv4=isolated)
                                      the Docker VM has no address or route in 172.22.0.0/16
                                      └─ Cowrie's only reachable peers: the relay (layer 2) and itself
```

## 7. Rollback

1. Restore the previous compose file:
   `cp cowrie/backups/pre_gateway_remediation_20261110/docker-compose.yml cowrie/docker-compose.yml`
   (SHA-256 `67aa9e6b…`).
2. In `cowrie/`, run `docker compose up -d --force-recreate`. Compose detects the network config change,
   recreates `cowrie_cowrie_internal` without the option, and recreates both containers with their aliases.
   - **Use `--force-recreate`:** a plain `up -d` reconnects the existing containers without service aliases
     (observed in 14A).
   - **Never use `docker compose down`:** it detaches the anonymous volumes, and new containers would start with
     empty `var`/`etc`. The old data would be orphaned, not deleted.
3. Re-verify: aliases, the relay banner via `127.0.0.1:2223`, the log prefix hash, and the VM address table
   (172.22.0.1 would reappear, reopening the R1 exposure).

## 8. Remaining limitations

- **Relay egress:** the relay (frontend network) still has outbound connectivity, as recorded in the Task 2
  audit. It runs only Twisted's port forwarder.
- **Docker Desktop VM services:** rpcbind and statd still listen on all VM interfaces. Cowrie has no route or
  on-link path to any of those addresses. Any other container on a non-isolated bridge (for example the
  relay's frontend network) can still reach them on its own gateway. The relay's forwarder does not do so.
- **New internal addresses:** Cowrie 172.22.0.1, relay 172.22.0.2. Relayed sessions still show `src_ip`
  172.22.0.2, and `dst_ip` is now 172.22.0.1. This affects logged metadata only, not features.
- **Recreation counts:** the containers were recreated twice today (09:03 and 12:30). Cowrie did not rotate its
  log (same day).
- **Compose behaviour:** recreating only the network drops service aliases. Any future network change must be
  applied with `--force-recreate`.
- **Engine requirement:** `gateway_mode_ipv4: isolated` requires Engine 28 or later (verified on 29.1.2) and
  `internal: true`. Older engines reject the configuration.

**Stopped. Waiting for approval before generating the larger dataset.**
