# Relay configuration design (proposed; not applied)

## 1. Current relay service (`cowrie/docker-compose.yml`, sha256 `cd84da48…`)

```yaml
  ssh-relay:
    <<: *hardening                 # pull_policy never, cap_drop [ALL], no-new-privileges, read_only, tmpfs /tmp, restart unless-stopped
    image: *cowrie_image           # cowrie/cowrie@sha256:bf371c37…cc13a
    container_name: cowrie-ssh-relay
    pids_limit: 64
    mem_limit: 128m
    entrypoint: ["/cowrie/cowrie-env/bin/twistd"]
    command: ["-n", "--pidfile=", "portforward", "--port=tcp:2222", "--host=cowrie", "--dest_port=2222"]
    ports:
      - "127.0.0.1:2223:2222"
    networks: [cowrie_internal, relay_frontend]
    depends_on: [cowrie]
```

## 2. Proposed relay service (the only change in the file)

```yaml
  ssh-relay:
    <<: *hardening
    image: *cowrie_image
    container_name: cowrie-ssh-relay
    pids_limit: 64
    mem_limit: 128m
    entrypoint: ["/cowrie/cowrie-env/bin/twistd"]
    # Explicit bind: the generic forwarder listens only on the published-path address (Task 25C-1: was 0.0.0.0:2222).
    command: ["-n", "--pidfile=", "portforward", "--port=tcp:2222:interface=172.21.0.2", "--host=cowrie", "--dest_port=2222"]
    # The relay is an application-level TCP proxy; kernel IP forwarding is not needed (Task 25C-1: was 1).
    sysctls:
      net.ipv4.ip_forward: "0"
      net.ipv4.conf.all.forwarding: "0"
      net.ipv4.conf.default.forwarding: "0"
    ports:
      - "127.0.0.1:2223:2222"
    networks: [cowrie_internal, relay_frontend]
    depends_on: [cowrie]
```

Unchanged:
- the `cowrie` service;
- both network definitions;
- the hardening anchor;
- the image digest;
- the port mapping;
- network membership;
- limits.

## 3. Why each part is sufficient and safe

| Item | Basis |
|---|---|
| Forwarding off via `sysctls` | `net.ipv4.*` sysctls are network-namespaced. Docker applies them when it creates the container's namespace, before the process starts, so no capability is needed inside the container (`cap_drop: ALL` stays). `ip_forward` and `conf.all.forwarding` are the same switch; `conf.default.forwarding` covers interfaces created later. **To verify on recreation:** the engine accepts these keys (unverified; `limitations.md`) |
| Proxy function preserved | `twisted.protocols.portforward.ProxyFactory` is a userland TCP proxy (accept → connect → copy bytes). Kernel forwarding is not involved. The VM's DNAT `127.0.0.1:2223 → <relay frontend IP>:2222` is local delivery into the relay, not forwarding inside it. Docker's embedded DNS uses `OUTPUT` DNAT on loopback, which forwarding does not affect |
| Explicit bind | Twisted 25.5.0 `twisted/tap/portforward.py`: `makeService` → `strports.service(config["port"], ProxyFactory(host, dest_port))`. `--port` is a strports endpoint string, and the TCP endpoint parser accepts `interface=` (`evidence/readonly_inspection.txt`). The command change is therefore the minimum: no relay code and no new image |
| Backend mapping | Unchanged: `--host=cowrie --dest_port=2222`. `cowrie` resolves through Docker DNS on `cowrie_internal` to `172.22.0.1`. The kernel picks the source `172.22.0.2` (eth0) for that destination |
| Hardening preserved | The `*hardening` anchor, `pids_limit`, `mem_limit` and the image are untouched. The relay keeps user `cowrie` (image default) |

## 4. Not part of this change

- **The demo listener (`10.250.25.2`).** It must be served by the future attributing relay, never by the generic forwarder (`listener_binding_design.md`).
- **Address pinning (`ipv4_address`).** It would require `ipam:` blocks and therefore network recreation (`network_preservation.md`). It is deliberately excluded from the minimal plan.
