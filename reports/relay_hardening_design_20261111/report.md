# Relay hardening design for controlled defence integration (Task 25C-2)

**Date:** 2026-11-11.

**Design only.**
- No container recreated or restarted; no Compose, network, Cowrie, relay, config or policy change.
- No demo network; no enforcement; no data access.
- Nothing committed.

**Read-only inputs:**
- `cowrie/docker-compose.yml`;
- `docker inspect` / `docker network inspect`;
- the installed Twisted 25.5.0 `twisted/tap/portforward.py` source (read via `docker exec python3`);
- Compose v2.40.3-desktop.1, engine 29.1.2 (`evidence/readonly_inspection.txt`).

## 1. Summary of the design

| Requirement | Design |
|---|---|
| 1 Disable kernel forwarding | Relay service `sysctls`: `net.ipv4.ip_forward: "0"`, `net.ipv4.conf.all.forwarding: "0"`, `net.ipv4.conf.default.forwarding: "0"` |
| 2 Preserve the TCP proxy | Unchanged `ProxyFactory` (userland accept → connect → copy). It needs no kernel forwarding; the VM's DNAT into the relay is local delivery |
| 3 Explicit listeners | Published path: `--port=tcp:2222:interface=172.21.0.2`. `--port` is a strports string and the TCP parser supports `interface=`, so this is a **command-argument change only**. The demo listener `10.250.25.2` is **not** added now |
| 4 No exposure on demo | The generic forwarder never binds `10.250.25.2` or `0.0.0.0`. The relay joins the demo network only together with the future attributing relay. Weak-host residual handled by an accepted-socket local-address check (future) and by clients having no route |
| 5 Keep `172.22.0.2` | Recreate only the relay (`--no-deps --force-recreate`). Cowrie and the networks are unchanged; IPAM is expected to reassign `.2` (precedent: Task 14A.1). Verified afterwards; **abort and roll back** if different. Pinning would require network recreation, so it is excluded |
| 6 Keep hardening | The `*hardening` anchor, image digest, limits, user, ports and networks are untouched |
| 7 Minimum change | One file, one service: `command` (`--port` argument) plus a new `sysctls` block. No code, no image, no network change |
| 8 Backend mapping | Published `172.21.0.2:2222` → `cowrie:2222` (172.22.0.1) now. Future: the attributing relay maps `172.21.0.2:2222` (published, never attributable) and `10.250.25.2:2222` (demo, mapping plus restriction) to `cowrie:2222` |
| 9 Rollback | Backup, then restore the file (hash `cd84da48…`) and run the same single-service force-recreate. Never `compose down` (`rollback_plan.md`) |
| 10 Verification | V1–V14 (`verification_plan.md`): state, sysctls, effective forwarding, addresses, listeners, hardening, volumes, Cowrie and networks unchanged, VM isolation rules, routes, one approved banner connection with `src_port` correlation, file hashes, re-audit |

## 2. Exact changes required for implementation

**File:** `cowrie/docker-compose.yml`, service `ssh-relay` only.

```diff
     entrypoint: ["/cowrie/cowrie-env/bin/twistd"]
-    command: ["-n", "--pidfile=", "portforward", "--port=tcp:2222", "--host=cowrie", "--dest_port=2222"]
+    command: ["-n", "--pidfile=", "portforward", "--port=tcp:2222:interface=172.21.0.2", "--host=cowrie", "--dest_port=2222"]
+    sysctls:
+      net.ipv4.ip_forward: "0"
+      net.ipv4.conf.all.forwarding: "0"
+      net.ipv4.conf.default.forwarding: "0"
     ports:
       - "127.0.0.1:2223:2222"
```

**Apply command** (after backup and approval):

```
docker compose -f cowrie/docker-compose.yml up -d --no-deps --force-recreate ssh-relay
```

**Files that must not change:**
- the `cowrie` service;
- the `networks:` section;
- `configs/threat_attribution_v1.json`, `configs/defence_policy*.json`;
- `behavioural_evidence/`, `threat_assessment/`.

**New artefacts at implementation:**
- `cowrie/backups/pre_relay_hardening_<UTC>/` (backup);
- an implementation report with V1–V14 results.

## 3. Deferred (separate approvals)

- Pin `relay_frontend` (`ipam` plus `ipv4_address: 172.21.0.2`). This recreates the relay-only network.
- The attributing relay with the demo listener and the per-listener policy table, and the local-address check.
- Creating the demo network (Task 25B plan).

## 4. Risks and limits (`limitations.md`)

- **Unverified until applied:** sysctl acceptance, bind timing, and IPAM reassignment of `.2`.
- **Container ID:** the relay's ID changes on recreation.
- **Residuals:** the weak-host-model residual, and the dependency on Docker-managed isolation rules.
- **One verification connection** must be approved at implementation time; its session will be excluded from all data, like `99732d516898`.

## 5. Files

| File | Content |
|---|---|
| `relay_configuration_design.md` | Current vs proposed service, rationale |
| `listener_binding_design.md` | Listener map, demo-exposure rules, fail-closed bind |
| `network_preservation.md` | Address preservation, why no pinning, abort rule |
| `rollback_plan.md` | Backup, triggers, procedure, limits |
| `verification_plan.md` | V1–V14 |
| `limitations.md` | Unverified items and residual risks |
| `evidence/readonly_inspection.txt` | Twisted portforward source and endpoint check, IPAM, mounts, versions |
