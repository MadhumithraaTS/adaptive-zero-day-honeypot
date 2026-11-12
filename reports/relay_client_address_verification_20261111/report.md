# Docker Desktop client address at relay ingress (Task 25A)

**Date:** 2026-11-11.

**One controlled connection; read-only observation.**

**Not done:**
- no instrumentation was added (none was needed), so nothing had to be removed;
- the relay and Cowrie were not replaced, restarted or reconfigured: container IDs, start times, restart counts, commands, port mapping and config hashes are identical before and after (`evidence/state_before.txt`, `evidence/state_after.txt`);
- no Docker network, port, firewall or Cowrie change;
- no enforcement;
- no attribution records (every file is labelled diagnostic);
- no Dataset V2 or sealed-test data used;
- nothing committed.

## Objective

Determine what source address the existing relay sees when a client connects through `127.0.0.1:2223`, and whether Cowrie records the relay's outbound source port.

## Procedure

1. **Inspected the relay.** It is `twistd -n portforward --port=tcp:2222 --host=cowrie --dest_port=2222`: Twisted's TCP listener on `0.0.0.0:2222` accepts the client and opens a new connection to `cowrie:2222`.
2. **Observation point.** This is the accepted socket of that listener. Its endpoints were read from the kernel TCP table inside the relay container (`/proc/net/tcp`) with a read-only `docker exec python3` parser while the connection was open. The kernel reports the same pair that `getpeername()` / `getsockname()` would return. No code was inserted into the relay.
3. **Exactly one connection** (`observe_once.py`, which refuses to run twice):
   - opened `127.0.0.1:2223` from the host;
   - sent **no bytes**;
   - read the server banner;
   - held the connection about 4 s while sampling the relay and Cowrie TCP tables twice;
   - closed it.
4. **Read the new Cowrie JSON events**, and correlated them with the relay's outbound socket.

## Observations (`relay_observation.txt`, `cowrie_correlation.txt`, `evidence/raw_observation.json`)

| Hop | Local endpoint | Peer endpoint |
|---|---|---|
| Client (host) | `127.0.0.1:57328` | `127.0.0.1:2223` |
| **Relay accepted socket** | `172.21.0.2:2222` | **`172.21.0.1:43452`** |
| Relay outbound socket | `172.22.0.2:53490` | `172.22.0.1:2222` |
| Cowrie accepted socket | `172.22.0.1:2222` | `172.22.0.2:53490` |
| Cowrie `session.connect` (session `99732d516898`) | `dst 172.22.0.1:2222` | **`src_ip 172.22.0.2`, `src_port 53490`** |

## Conclusion

1. **The relay sees a Docker Desktop gateway/proxy address, not the client.**
   - **Observed socket peer:** `172.21.0.1:43452`. `172.21.0.1` is the gateway of `cowrie_relay_frontend` (172.21.0.0/16).
   - **Actual originating client:** `127.0.0.1:57328`, which is **not visible** at the relay. The different port shows that Docker Desktop's proxy opened a new connection.
   - The real client address was **not** recovered, and cannot be recovered at the relay in this topology.
2. **Cowrie records the relay's outbound source port.**
   - This was observed, not assumed: `cowrie.session.connect.src_port = 53490` equals the relay's outbound local port, and `src_ip = 172.22.0.2` equals its outbound local IP.
   - `cowrie.session.closed` has no `src_port`.
   - The relay→Cowrie hop therefore supports exact 4-tuple correlation, as assumed by the Task 25 design.
3. **Consequence for the Task 25 design.**
   - An attributing relay on the current published-port path would sign mappings whose client is always the Docker gateway. Under the existing attribution rules that is `protected` (172.21.0.0/16), so it is never attributable.
   - Trustworthy client attribution therefore requires an ingress where the relay's socket peer is the client itself, such as the designed `demo_ingress` container network.
   - No workaround was attempted here.

## Side effect

The diagnostic session added 2 events (lines 21851–21852) to Cowrie's live log, after the sealed test run's last line (21850). They belong to no dataset and must stay excluded.

## Files

| File | Content |
|---|---|
| `report.md` | This report |
| `relay_observation.txt` | Exact relay socket observation |
| `cowrie_correlation.txt` | Cowrie events and port correlation |
| `limitations.md` | What is and is not established |
| `observe_once.py` | The one-shot observation script |
| `evidence/` | Raw observation JSON, the lock file, pre- and post-state |
| `SHA256SUMS` | Hashes |
