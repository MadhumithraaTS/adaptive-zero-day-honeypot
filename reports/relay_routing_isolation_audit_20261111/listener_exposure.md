# Listener exposure (read-only)

**Command:** `awk 'NR>1 && (FILENAME ~ /udp/ || $4=="0A")' /proc/<pid>/net/{tcp,tcp6,udp,udp6}` from the VM distribution, plus the Task 25C-pre `docker exec` read of the same tables.

## Relay (pid 2890)

| Proto | Local (decoded) | State | Inode | Exposed on |
|---|---|---|---|---|
| tcp | `0.0.0.0:2222` (`00000000:08AE`) | LISTEN | 278845 | **every relay interface**: eth0 172.22.0.2 (`cowrie_internal`), eth1 172.21.0.2 (`relay_frontend`), lo |
| tcp | `127.0.0.11:43835` (`0B00007F:AB3B`) | LISTEN | 280672 | loopback only (Docker DNS TCP) |
| udp | `127.0.0.11:33834` (`0B00007F:842A`) | — | 280671 | loopback only (Docker DNS UDP) |

**Interpretation:**
- **[O]** The Cowrie forwarder (`twistd portforward --port=tcp:2222`) is bound to the wildcard address.
- **[I]** It is reachable from:
  - the frontend network, as intended: the VM's DNAT `127.0.0.1:2223 → 172.21.0.2:2222`, accepted by the VM `DOCKER` chain only for dport 2222 to 172.21.0.2;
  - the **internal** network side as well: any host on `172.22.0.0/16`, i.e. Cowrie itself at 172.22.0.1.

  A connection from Cowrie to `172.22.0.2:2222` would be forwarded back to `cowrie:2222`.
- **[I]** Inside Cowrie only the honeypot process runs, and its emulated network commands refuse 172.16.0.0/12 (`communication_allowed` / `BLOCKED_IPS`, Task 13). That is an emulator control, not a network one.
- **[O]** If the relay joined any additional network (e.g. the demo network), this listener would be exposed there too (Task 25C-pre, check 5).

## Cowrie (pid 2837)

Cowrie listens on `0.0.0.0:2222` (its SSH service) and on Docker DNS on loopback, and is reachable only on `172.22.0.0/16` (`evidence/audit_readonly_output.txt`).
