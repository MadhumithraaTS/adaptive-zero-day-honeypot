# Configuration changes

**Baseline check:** before editing, `cowrie/docker-compose.yml` matched the reviewed baseline, sha256 `cd84da489d29840d1f7c81465359b023caa139ad908e37b0c3e622f47f32e9f5`.

**Backup:** `cowrie/backups/pre_relay_hardening_20261111T165756Z/`. It contains:
- `docker-compose.yml` (the baseline);
- `relay_inspect.json`, `cowrie_inspect.json`, `networks_inspect.json`;
- `relay_mounts.txt`, `ports.txt`;
- `audit_before.txt` (routes, sysctls, listeners, capabilities, relay/Cowrie/VM firewall);
- `cowrie_log_before.txt` (21,852 lines, `28e1c576…`);
- `SHA256SUMS`.

**Change** (`evidence/docker-compose.diff`; service `ssh-relay` only):

```diff
     entrypoint: ["/cowrie/cowrie-env/bin/twistd"]
-    command: ["-n", "--pidfile=", "portforward", "--port=tcp:2222", "--host=cowrie", "--dest_port=2222"]
+    # Explicit bind: the forwarder listens only on the published-path address (was 0.0.0.0:2222; Task 25C-1/25C-3).
+    command: ["-n", "--pidfile=", "portforward", "--port=tcp:2222:interface=172.21.0.2", "--host=cowrie", "--dest_port=2222"]
+    # Application-level TCP proxy only: kernel IP forwarding is not needed (was 1; Task 25C-1/25C-3).
+    sysctls:
+      net.ipv4.ip_forward: "0"
+      net.ipv4.conf.all.forwarding: "0"
+      net.ipv4.conf.default.forwarding: "0"
     ports:
```

New file hash: `903f0b953112afd4…` (`evidence/file_hashes_after.txt`).

**Validation before apply:**
- `docker compose -f cowrie/docker-compose.yml config --quiet` gave **valid**.
- Rendering the baseline with the same project and directory (`-p cowrie --project-directory cowrie`) and diffing it with the new render (`evidence/compose_render.diff`) shows **only** the `--port` argument and the three `sysctls`. The `cowrie` service, networks, volumes and every other key render identically.

**Apply** (`evidence/apply_output.txt`; started `evidence/apply_started_utc.txt`):

```
$ docker compose -f cowrie/docker-compose.yml up -d --no-deps --force-recreate ssh-relay
 Container cowrie-ssh-relay  Recreate
 Container cowrie-ssh-relay  Recreated
 Container cowrie-ssh-relay  Starting
 Container cowrie-ssh-relay  Started
rc=0
```

No `docker compose down` and no `--renew-anon-volumes`; Cowrie was not recreated (`--no-deps`).
