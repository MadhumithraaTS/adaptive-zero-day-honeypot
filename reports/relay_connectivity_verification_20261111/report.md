# Hardened relay end-to-end connectivity verification (Task 25C-4)

**Date:** 2026-11-11.

**Result: PASS.** Exactly one controlled connection was made, with no retries and no bytes sent.

**Not done:**
- no configuration or code change;
- no container restart or recreation;
- no demo network;
- no Dataset V2 or sealed data;
- no evidence, assessment, policy or attribution change;
- nothing committed.

## Procedure

1. Recorded the relay and Cowrie state (`evidence/state_before.txt`):
   - **relay:** `54b551d98e1a…`, started 2026-11-11T16:59:16.172162889Z, 0 restarts, command `--port=tcp:2222:interface=172.21.0.2`, forwarding sysctls `"0"`, 172.22.0.2 / 172.21.0.2;
   - **Cowrie:** `0bec5a78b1cb…`, started 2026-11-10T12:30:30.630598884Z, 0 restarts, 172.22.0.1.
2. Ran `observe_once.py` (lock-file protected):
   - one connection to `127.0.0.1:2223`;
   - read the banner `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`;
   - held about 3 s, then closed cleanly.
3. Read the relay and Cowrie kernel TCP tables and the relay's forwarding sysctls (read-only `docker exec`) before, during and after.
4. Read the new Cowrie events.

## Results

| Verification | Observed | Result |
|---|---|---|
| Relay still forwards application-level TCP to Cowrie | The banner was received through `127.0.0.1:2223` → `172.21.0.2:2222` → `172.22.0.1:2222` | PASS |
| Cowrie source IP is `172.22.0.2` | `session.connect src_ip 172.22.0.2` | PASS |
| Cowrie `src_port` = relay outbound local port | `56300` = `56300` | PASS |
| Listener exclusively `172.21.0.2:2222` | Before, during and after; no wildcard listener | PASS |
| IP forwarding disabled | `ip_forward = 0`; all, default, eth0, eth1 and lo `forwarding = 0`, before and after | PASS |
| Exactly one diagnostic session | `b806554e19b9` only (log 21,852 → 21,854; connect + closed) | PASS |
| State unchanged | Relay and Cowrie IDs, start times, restarts, commands, addresses, port mapping and config hashes identical before and after (`evidence/state_after.txt`) | PASS |

The relay's accepted-socket peer was `172.21.0.1:43062`, the Docker Desktop proxy, as established in Task 25A. The published path still provides no client attribution.

**Diagnostic session `b806554e19b9`** is recorded in `diagnostic_exclusion.md` together with `99732d516898`. Both are excluded from every dataset and evaluation.

## Files

| File | Content |
|---|---|
| `connection_observation.md` | Client and relay socket observation, forwarding settings |
| `cowrie_correlation.md` | Cowrie events and the port match |
| `diagnostic_exclusion.md` | Exclusion register for both diagnostic sessions |
| `observe_once.py` | The one-shot script |
| `evidence/` | Raw observation, lock file, pre- and post-state |
