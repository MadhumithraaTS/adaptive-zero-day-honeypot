# Connection observation (DIAGNOSTIC; not attribution evidence)

**Method:** `observe_once.py` (lock file `evidence/OBSERVATION_DONE.lock`; refuses a second run).
- One TCP connection to `127.0.0.1:2223`. **No bytes sent.** The server banner was read, the connection held about 3 s, then closed.
- The relay and Cowrie kernel TCP tables (`/proc/net/tcp`, `tcp6`) and the relay's forwarding sysctls were read with read-only `docker exec … python3` before, during (twice) and after.
- Raw data: `evidence/raw_observation.json`.

## Client

| Field | Value |
|---|---|
| connected | 2026-11-11T17:03:25.110247Z |
| local → peer | `127.0.0.1:49278` → `127.0.0.1:2223` |
| bytes sent | 0 |
| banner | `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3` |
| closed | 2026-11-11T17:03:28.269786Z |

## Relay TCP table

| Phase | Sockets |
|---|---|
| Before | LISTEN `172.21.0.2:2222`; LISTEN `127.0.0.11:34069` (Docker DNS) |
| During (2 identical samples) | LISTEN `172.21.0.2:2222`; LISTEN `127.0.0.11:34069`; **accepted** `172.21.0.2:2222 ← 172.21.0.1:43062` ESTABLISHED; **outbound** `172.22.0.2:56300 → 172.22.0.1:2222` ESTABLISHED |
| After | LISTEN `172.21.0.2:2222`; LISTEN `127.0.0.11:34069`; `172.22.0.2:56300 → 172.22.0.1:2222` TIME_WAIT (normal TCP close state) |

- **Listener:** bound exclusively to `172.21.0.2:2222` in all phases. No `0.0.0.0:2222` appeared.
- **Accepted-socket peer:** `172.21.0.1` (the Docker Desktop proxy, as in Task 25A). The originating client `127.0.0.1:49278` is not visible at the relay. That is expected for the published path and was not under test here.

## Relay forwarding sysctls (before and after, identical)

`/proc/sys/net/ipv4/ip_forward = 0`; `conf/{all,default,eth0,eth1,lo}/forwarding = 0`.
