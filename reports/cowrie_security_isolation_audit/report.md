# Cowrie security and isolation audit

**Date:** 2026-11-10.
**Scope:** prepare the existing Cowrie lab for a controlled telemetry observability pilot.
**Not done:** no payloads, no attack simulation, no login, no downloads, no Dataset V2, no model or feature-extraction changes, no commits.

> **Correction (2026-11-10, Task 13B).** This audit said the internal network has "no gateway". That is wrong for the bridge.
>
> - `cowrie_cowrie_internal` has IPAM gateway **172.22.0.1**. Docker assigns that address to the bridge `br-72ab93e8020b` in the Docker Desktop VM. The container itself has no default gateway or route; `docker inspect` shows its `Gateway` as empty, which is probably what this audit relied on.
> - Cowrie can reach 172.22.0.1. In the Docker engine's network namespace, Docker Desktop's own NFS client services listen on all interfaces: **rpcbind on TCP/UDP 111** and **rpc.statd on TCP 32775 and UDP 51113**. These are not Cowrie services.
> - **Why it is reachable:** `internal=true` installs `DOCKER-INTERNAL` drops only in the FORWARD chain. Traffic to the bridge's own address is local delivery, and the VM's INPUT chain is `ACCEPT` with no rules.
> - **What still holds:** Cowrie has **no default route** (only 172.22.0.0/16), so the Internet, the Docker Desktop host (192.168.65.254), the other bridge addresses and the LAN stay unreachable.
> - **Cowrie's own controls:** its network commands (`nc`, `wget`, `curl`, `ftpget`) refuse 172.16.0.0/12 and the other private ranges (`core/network.py` `BLOCKED_IPS`). SSH `direct-tcpip` forwarding uses a fake, log-only channel (`forward_redirect` and `forward_tunnel` are false). So no attacker-facing Cowrie feature reaches 172.22.0.1.
> - **Residual risk:** code running with the container's real privileges, after a compromise of Cowrie, Twisted or Python, or via `docker exec`, could reach rpcbind and statd on the Docker Desktop VM. Other projects' containers also run on that VM.
> - **Status:** accepted as a documented residual risk under option **R1** (explicitly approved, 2026-11-10). No Docker or Cowrie configuration was changed.
> - Details: `reports/revised_profile_cowrie_smoke_test/gateway_port111_investigation.md`.
>
> **Address note:** the internal IPs in §3 were correct when this audit was written. Since the containers were re-created at 09:03:25 UTC, Cowrie is **172.22.0.3** and the relay **172.22.0.2**.

> **Update — gateway exposure remediated (2026-11-10, Tasks 14A/14A.1, option R2).** This supersedes the R1 acceptance above.
>
> - `cowrie_internal` now sets `driver_opts: com.docker.network.bridge.gateway_mode_ipv4: isolated` (the only change in `cowrie/docker-compose.yml`, now `cd84da48…`). Docker Engine 29.1.2 supports this mode for internal networks.
> - **Bridge:** the bridge (`br-8de3b00259f2`, network `8de3b00259f2`) has **no IPv4 address**. The Docker Desktop VM has no address or route in 172.22.0.0/16.
> - **Cowrie can no longer reach** rpcbind or rpc.statd on any VM address, the Docker Desktop host, or external networks. It still has no default route.
> - **Containers:** both were recreated with `--force-recreate` at 12:30 UTC, keeping their pinned images, hardening and **the same volumes** (logs unchanged).
> - **Final verified topology:**
>
>   ```
>   host 127.0.0.1:2223 ─► cowrie-ssh-relay (frontend 172.21.0.2 | internal 172.22.0.2) ─► cowrie-project (172.22.0.1, alias "cowrie")
>   cowrie_cowrie_internal: internal=true, gateway_mode_ipv4=isolated, no gateway, bridge without IPv4
>   ```
>
> - **Address change:** Cowrie is now **172.22.0.1** and the relay **172.22.0.2**.
> - **Verification:** all ten checks passed, including relay → `cowrie` resolution and connection and one loopback banner read. Details, rollback and limitations: `reports/cowrie_gateway_remediation/report.md`.

## 1. Original configuration findings

Recorded before any change; evidence is in `cowrie/backups/pre_isolation_20261110/`: `container_inspect.json`, `image_inspect.json`, `docker-compose.yml`.

| Item | Finding |
|---|---|
| Compose file | `cowrie/docker-compose.yml`: one service, `image: cowrie/cowrie:latest`, `ports: "2223:2222"`, `restart: unless-stopped`. It is the only Compose file in the repository. |
| Image | Floating tag `latest`; local image `sha256:bf371c37…cc13a`, created 2026-04-08T01:45:02Z, label `version: main`, revision `cd0770d3df5088553fec2d7ee9002eb03f5ac087`, base `gcr.io/distroless/python3-debian13` |
| Cowrie configuration | No `cowrie.cfg` override; only `cowrie.cfg.dist`, i.e. defaults. `userdb.txt` present in the config volume (SHA-256 `46d68fb5…0649`, identical to the repository's `cowrie/userdb.txt`), copied in manually as `dataset_builder/README.md` describes |
| Network | Default Compose bridge `cowrie_default` (172.19.0.0/16, `internal=false`) |
| Port exposure | Published on **0.0.0.0:2223 and [::]:2223**, i.e. reachable from every host interface, including the LAN |
| Privileges | Runs as `cowrie` (uid 999); not privileged; **no capabilities dropped, no `no-new-privileges`, writable root filesystem, no PID or memory limits** |
| Volumes | Two anonymous image volumes: `/cowrie/cowrie-git/etc` (`f51e84a3…`) and `/cowrie/cowrie-git/var` (`268411d7…`); no bind mounts |
| Host firewall | Not inspected or modified (out of scope; the isolation below doesn't depend on it) |
| **Measured egress (before)** | From inside the container: TCP connect **succeeded** to 1.1.1.1:443, 8.8.8.8:53 and 185.220.101.5:80; public DNS resolved (`example.com`); `host.docker.internal` resolved to 192.168.65.254. **The container was not isolated.** |
| Stored downloads | `var/lib/cowrie/downloads/` holds files fetched by Cowrie's emulated `wget`/`curl` during earlier runs (backed up, not opened) |
| Traffic profiles | `dataset_builder/profiles_v2.json`: real public IPs `185.220.101.5`, `193.27.228.11`, `45.154.255.85`, `103.145.13.92`; private LAN IPs `10.0.0.5`, `10.0.0.12`, `192.168.1.10`, `172.16.0.8` and `nmap -sn 10.0.0.0/24`; domains `example.com`, `files-mirror.org`, `pkg-repo.xyz`. `configs/attack_profiles.json`: `http://example.com/malware.sh`, `http://10.0.0.1/c2_payload` |

Disclosure: the "before" egress check opened one TCP connection (handshake only, no data) to each of 1.1.1.1:443, 8.8.8.8:53 and 185.220.101.5:80 from the container.

## 2. Image version and digest

- **Pinned reference:** `cowrie/cowrie@sha256:bf371c37638bf8b49efed87b66f5d0bf48432a499c6b3fa3c44c03ebf02cc13a`
  - This is the digest of the image the container was already running. It equals both the local `RepoDigests` entry and the image ID in Docker Desktop's containerd store.
  - **No pull or upgrade happened:** both services set `pull_policy: never`.
- **Version reported by Cowrie at start-up:** `Cowrie Version 2.9.17.dev1+gcd0770d3d`, Twisted 25.5.0, Python 3.13.5.
- **Caveat:** `2.9.17.dev1` is a development build of the `main` branch, not a tagged release.

## 3. Network architecture

```
host 127.0.0.1:2223 ──► cowrie-ssh-relay (172.21.0.2 frontend / 172.22.0.3 internal)
                        Twisted portforward, same pinned image
                                 │ tcp 2222
                                 ▼
                        cowrie-project (172.22.0.2), attached ONLY to
                        cowrie_cowrie_internal (internal=true, 172.22.0.0/16)
```

| Network | Driver | Internal | Subnet | Members |
|---|---|---|---|---|
| `cowrie_cowrie_internal` | bridge | **true** (no default route for containers, no outbound route; *corrected:* gateway address 172.22.0.1 exists on the bridge and is reachable, see the correction above) | 172.22.0.0/16 | cowrie-project, cowrie-ssh-relay |
| `cowrie_relay_frontend` | bridge | false (needed to publish a port) | 172.21.0.0/16 | cowrie-ssh-relay |

- **Why a relay:** Docker doesn't publish ports for a container attached only to an internal network. The relay runs `twistd -n --pidfile= portforward --port=tcp:2222 --host=cowrie --dest_port=2222` from the **same pinned image**, so no new image or dependency was introduced.
- **The old `cowrie_default` network** still exists but is unused.

## 4. Isolation and hardening controls

From `cowrie/docker-compose.yml` (SHA-256 `67aa9e6b…5f12`):

| Control | cowrie-project | cowrie-ssh-relay |
|---|---|---|
| Image | pinned digest, `pull_policy: never` | same |
| Networks | internal only | internal + frontend |
| Published port | none | `127.0.0.1:2223` only |
| `cap_drop: [ALL]` | yes | yes |
| `no-new-privileges` | yes | yes |
| Read-only root filesystem | yes (`/tmp` tmpfs; data volumes writable) | yes (`/tmp` tmpfs) |
| PID / memory limits | 256 / 512 MiB | 64 / 128 MiB |
| User | cowrie (999), image default | same |
| `userdb.txt` | bind-mounted **read-only** from `cowrie/userdb.txt` (survives container re-creation) | — |
| Restart | `unless-stopped` | same |

**Data continuity:** Compose re-created `cowrie-project` and re-attached the same anonymous `etc` and `var` volumes (`f51e84a3…`, `268411d7…`).

- At start-up, Cowrie rotated the old log to `var/log/cowrie/cowrie.json.2026-10-24`. It is byte-identical to the backup (SHA-256 `d88daba6…6974`, 19,465,252 bytes), and a new `cowrie.json` was started.

**Backup:** `cowrie/backups/pre_isolation_20261110/`

- Contents: the full `var` and `etc` trees (1,848 files, 31 MB, including tty logs and earlier downloads), the original Compose file, and container and image inspect output.
- Integrity: every file is listed in `SHA256SUMS`.

## 5. Traffic-profile destinations

New documentation-only versions were created next to the originals:

| New file | Version | Replacements |
|---|---|---|
| `dataset_builder/profiles_v2_isolated.json` (SHA-256 `385af936…f63`) | `2.1.0-docnet` | `ip` → 192.0.2.10, 198.51.100.20, 203.0.113.30, 192.0.2.40; `lan_ip` → 192.0.2.5, 192.0.2.12, 198.51.100.10, 203.0.113.8; `nmap -sn 10.0.0.0/24` → `192.0.2.0/24`; domains → `files.example`, `mirror.example`, `pkg-repo.example` |
| `configs/attack_profiles_isolated.json` (SHA-256 `cce96008…46e`) | — | `http://example.com/malware.sh` → `http://files.example/malware.sh`; `http://10.0.0.1/c2_payload` → `http://192.0.2.1/c2_payload` |

**Checks:**

- Both new files are valid JSON with the same profile set.
- A scan finds only RFC 5737 addresses and RFC 2606 `.example` names.
- The originals are byte-unchanged: `profiles_v2.json` `182afa5f…60e`, `attack_profiles.json` `f3cc54a9…4d0`.

**Why not in place:** the originals generated existing runs; `train_v1`/`eval_v1` record config version 2.0.0. `dataset_builder/package_release.py` (lines 171 and 195) ships `profiles_v2.json` as their generation profile, and earlier diagnostics hash both files as protected inputs. Editing them would misstate the provenance of existing data.

**Consequence:** the defaults still point at the originals: `DEFAULT_CONFIG` in `dataset_builder/generate_labelled_traffic.py` line 27, and `--config` default in `scripts/attack_generator.py` line 76. Any pilot must pass `--config dataset_builder/profiles_v2_isolated.json` explicitly. Even if it doesn't, Cowrie can no longer reach any of those destinations (section 6).

## 6. Verification results

### Probe method

`iso_check.py` was run inside each container via `docker exec -i … python3 -`. It makes TCP connects and DNS lookups only; no data is sent and nothing is downloaded.

| Check | cowrie-project | cowrie-ssh-relay |
|---|---|---|
| uid/gid | 999/999 | 999/999 |
| CapEff / CapBnd | 0 / 0 | 0 / 0 |
| NoNewPrivs / Seccomp | 1 / 2 (filter) | 1 / 2 |
| Write to root filesystem | **blocked** (OSError) | **blocked** |
| Write to /tmp | allowed (tmpfs) | allowed |
| TCP 1.1.1.1:443 | **Network is unreachable** | connected |
| TCP 8.8.8.8:53 | **unreachable** | connected |
| TCP 185.220.101.5:80 (profile IP) | **unreachable** | connected |
| TCP 192.168.65.254:80 (Docker Desktop host) | **unreachable** | refused |
| TCP 172.19.0.1:2223 (old gateway) | **unreachable** | refused |
| DNS `example.com` | **fails** | resolves |
| DNS `host.docker.internal` | **fails** | resolves |
| TCP cowrie:2222 | connected (itself) | connected (the intended path) |
| Routing table | only 172.22.0.0/16, **no default route** | default route via 172.21.0.1 |

### Host-side checks

These were banner reads only: TCP connect and read the SSH version string, with no authentication and nothing sent.

| Target | Result |
|---|---|
| 127.0.0.1:2223 | connected; banner `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3` (Cowrie's emulated banner) |
| 172.20.10.5:2223 (LAN interface) | refused |
| 192.168.56.1:2223, 172.27.0.1:2223 (virtual adapters) | refused |
| `docker port cowrie-ssh-relay` | `2222/tcp -> 127.0.0.1:2223` only |

Cowrie logged the three banner probes as `cowrie.session.connect`/`closed` with `src_ip` 172.22.0.3 (the relay).

### Conclusion

- **Cowrie:** cannot reach the internet, the Docker host, the old network or external DNS, so emulated `wget`/`curl` can no longer reach external hosts. *Corrected 2026-11-10:* Cowrie **can** reach its own bridge address 172.22.0.1 in the Docker Desktop VM, where rpcbind (TCP/UDP 111) and rpc.statd (TCP 32775, UDP 51113) listen. That address was not probed in this audit. The exposure is accepted under R1; see the correction at the top.
- **Local access:** works.
- **LAN access:** the port is no longer exposed.

## 7. Remaining security risks and telemetry effects

1. **Relay egress:** the relay has outbound internet access, because port publishing needs a non-internal network.
   - Mitigations: it runs only Twisted's port forwarder, has no capabilities, a read-only root filesystem and `no-new-privileges`, and only proxies bytes to `cowrie:2222`.
   - What would close the gap: host-firewall egress rules for the relay or frontend subnet, which were not changed.
2. **Development image:** the image is a `main`-branch development build (`2.9.17.dev1`). Pinning freezes it but doesn't make it a reviewed release.
3. **Shared kernel:** Docker Desktop's VM kernel is shared with other containers on the host. This is not a VM-level sandbox.
   - *Added 2026-11-10:* the VM's rpcbind and rpc.statd are reachable from Cowrie on 172.22.0.1 (see the correction at the top). Cowrie's command-level blocklist prevents attacker-facing use. The residual risk applies only if Cowrie itself is compromised or accessed via `docker exec`. It is accepted under R1.
   - Structural fix, not applied: recreate the internal network with no IPv4 address on the bridge (option R2).
   - *Resolved 2026-11-10 (R2 applied, Tasks 14A/14A.1):* the bridge has no IPv4 address, and Cowrie can no longer reach rpcbind or statd. The VM services still listen for containers on other, non-isolated bridges.
4. **Stored downloads:** earlier downloads remain inside the `var` volume (and in the backup). Don't open or execute them.
5. **Telemetry changes for future runs** (record these in the pilot's metadata):
   - `src_ip` is now the relay (172.22.0.3), not the gateway 172.19.0.1;
   - handshake timing (`tcprtt`) includes an extra proxy hop;
   - emulated downloads will fail, so `session.file_download` events should no longer appear and `wget` output changes;
   - profile strings changed (`.example` domains, different IPs), so command byte lengths differ from `profiles_v2.json` runs.

   Data from the isolated lab is therefore not directly comparable with `train_v1`/`eval_v1`.
6. **Log rotation:**
   - Cowrie rotates `cowrie.json` daily or on restart.
   - `scripts/collect_logs.py` copies only `cowrie.json`, so a run spanning a rotation would lose events. The builder's baseline check warns when the log is shorter than the baseline.
   - Keep pilot runs within one day and don't restart Cowrie mid-run.
7. **Documentation not updated:** `docs/setup_guide.md` and `dataset_builder/README.md` still describe the old `docker cp userdb.txt` step and port 2223 on all interfaces. Updating them is a separate documentation change.
8. **Unused network:** the old `cowrie_default` network remains; it can be removed with `docker network rm cowrie_default`, which wasn't done.

## 8. Files

- **Modified:**
  - `cowrie/docker-compose.yml` (isolated two-service configuration; original preserved in the backup folder and in git).
- **Created:**
  - `cowrie/backups/pre_isolation_20261110/`, containing the volume backup, original Compose file, inspect output and `SHA256SUMS`;
  - `dataset_builder/profiles_v2_isolated.json`;
  - `configs/attack_profiles_isolated.json`;
  - this report.
- **Docker state changed:**
  - `cowrie-project` re-created with the new configuration;
  - new container `cowrie-ssh-relay`;
  - new networks `cowrie_cowrie_internal` and `cowrie_relay_frontend`.
- **Unchanged:** models, datasets, feature extraction, source code, original profiles, host firewall.

The payload pilot has **not** been started and needs separate approval.
