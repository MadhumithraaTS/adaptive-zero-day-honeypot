# Minimal relay hardening: implementation (Task 25C-3)

**Date:** 2026-11-11.

**Result:** the approved hardening was applied to `ssh-relay` and every non-connection verification passed. No rollback was needed.

**Not done:**
- no demo network, attributing relay or attribution records;
- no enforcement;
- no client or banner connection;
- no Cowrie or internal-network change;
- no evidence, assessment, attribution or policy change;
- no Dataset V2 or sealed data;
- nothing committed.

**Excluded:** diagnostic session `99732d516898`.

## 1. What changed (`configuration_changes.md`)

- **File:** `cowrie/docker-compose.yml`, service `ssh-relay` only. Baseline `cd84da48…` → new `903f0b95…`.
  - `--port=tcp:2222` → `--port=tcp:2222:interface=172.21.0.2`
  - added `sysctls`: `net.ipv4.ip_forward`, `net.ipv4.conf.all.forwarding`, `net.ipv4.conf.default.forwarding` = `"0"`
- **Validated** with `docker compose config --quiet`. A same-project render diff shows only these two changes.
- **Applied** with `docker compose -f cowrie/docker-compose.yml up -d --no-deps --force-recreate ssh-relay` (rc 0).
- **Backup:** `cowrie/backups/pre_relay_hardening_20261111T165756Z/`.

## 2. Verification (`verification_results.md`)

| Check | Result |
|---|---|
| Relay starts | Running, 0 restarts. New container `54b551d98e1a` (replaced `8d3bafb35f38` by design) |
| `172.21.0.2` / `172.22.0.2` | Both retained (same network IDs) |
| Kernel IPv4 forwarding | `ip_forward = 0` |
| Per-interface forwarding | all / default / eth0 / eth1 = 0; IPv6 forwarding 0 |
| Listeners | Only `172.21.0.2:2222`, plus Docker DNS on `127.0.0.11`. The `0.0.0.0:2222` wildcard is gone |
| Hardening | cap_drop ALL (CapEff = 0), no-new-privileges, read-only, user `cowrie`, limits, tmpfs, restart policy unchanged |
| Image digest | Unchanged (`sha256:bf371c37…cc13a`) |
| Volumes, network membership | Unchanged (`4492a68c…`, `fba87a59…`; members and network ID, options, IPAM and labels identical) |
| Cowrie | ID, start time, restarts, command, labels, binds, caps and mounts unchanged; its network namespace is identical |
| Cowrie log | Byte-identical (21,852 lines, `28e1c576…`) |
| Docker VM isolation rules | `iptables-nft-save` identical (`DOCKER-INTERNAL`, raw 2223 drop, DNAT 2223 → 172.21.0.2:2222) |
| Unexpected listeners or routes | None. VM IPv4 routes identical; only IPv6 link-local entries for the new veth pair changed |
| Other files | `behavioural_evidence/`, `threat_assessment/`, attribution config and policies match recorded hashes (19/19); `userdb.txt` unchanged |

## 3. Repeated routing audit (`routing_audit.md`)

The relay no longer forwards. The VM-side path to Cowrie through the relay now meets four independent blocks:
1. no sender route;
2. no relay forwarding;
3. the `DOCKER-INTERNAL` source filter;
4. no Cowrie return route.

The Cowrie forwarder is bound only to the published-path address. These remain configuration-based conclusions; no probe was sent.

## 4. Pending (needs approval)

**V12: a single controlled connection** through `127.0.0.1:2223`:
- read the banner only;
- confirm the Cowrie `session.connect` comes from `src_ip 172.22.0.2`, with `src_port` equal to the relay's outbound port;
- exclude that session from all data.

This would confirm the hardened relay still proxies end to end.

## 5. Files

| File | Content |
|---|---|
| `configuration_changes.md` | Baseline, backup, diff, validation, apply output |
| `verification_results.md` | V1–V14 (V12 pending) |
| `routing_audit.md` | Before/after audit comparison |
| `rollback_results.md` | Not needed; readiness |
| `limitations.md` | Limitations |
| `evidence/` | Diff, renders, apply output, inspections, before/after audits, Cowrie log hashes, file hashes, audit script |
