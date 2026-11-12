# Expected attribution path (design; not experimentally verified)

## 1. Flow

```
test client 10.250.25.3:<eph C>
   |  TCP connect to 10.250.25.2:2222 (same user-defined bridge; no published-port proxy)
   v
attributing relay   accepted socket: local 10.250.25.2:2222, peer 10.250.25.3:<eph C>   <- getpeername() = client
   |  (1) mapping record opened: connection_id, client tuple, ingress listener, accepted_utc
   |  (2) restriction check (future enforcement; allowlist 10.250.25.3/32 only)
   |  (3) upstream connect 172.22.0.2:<P> -> 172.22.0.1:2222; getsockname() = 172.22.0.2:<P>
   |  (4) mapping record: upstream_local_ip/port, upstream_connected_utc
   v
Cowrie  cowrie.session.connect {src_ip 172.22.0.2, src_port P, dst 172.22.0.1:2222, session S, timestamp t}
        ... session events (no src_port) ... cowrie.session.closed {src_ip, session S, duration} (no src_port; Task 25A)
   ^
attributing relay   (5) on close: closed_utc, bytes; mapping record closed (hash-chained, signed)
```

**Task 25A basis.** For the relay→Cowrie hop, Cowrie's `session.connect` recorded `src_port` = the relay's outbound local port (53490 = 53490), and `src_ip` = the relay's `cowrie_internal` address. `session.closed` had no `src_port`. The client→relay hop on a container network is **expected** to expose the client container address as the socket peer. That is the standard behaviour of a user-defined bridge, but it has **not** been observed here.

## 2. Correlation rule (future implementation)

A Cowrie session `S` is attributed to a demo client **only if all** of the following hold:
1. **Exactly one** mapping record has `upstream_local_ip == S.connect.src_ip` and `upstream_local_port == S.connect.src_port`.
2. `|S.connect.timestamp − upstream_connected_utc| ≤ 2 s`, and `accepted_utc ≤ S.connect.timestamp`.
3. The mapping record's `ingress_listener` is `10.250.25.2:2222` (the demo listener).
4. The mapping's client IP is in the client registry. Its role (test or control) comes from the registry, never from client-supplied data.
5. The mapping record's signature and hash chain verify, and its checkpoint is current.
6. The mapping was open when `S` connected (`closed_utc` absent or later than the connect).
7. **Close consistency.** After the connect join, `S`'s `session.closed` (joined by session ID, since it has no port) must not precede the mapping's `accepted_utc`. The mapping's `closed_utc` should be within the skew budget of `S.closed`. A mismatch is flagged `close_inconsistent` and blocks attribution.

**Outcomes:**

| Case | Result |
|---|---|
| Exactly one valid match, consistent close | `attributable_via_proxy_mapping` (role: test or control) |
| No match | `unattributed:mapping_missing` |
| ≥ 2 matches (port reuse inside the window) | `unattributed:mapping_ambiguous` |
| Duplicate mapping records for one connection ID, or the same upstream tuple open twice | `unattributed:mapping_duplicate` |
| Signature, chain or checkpoint fails | `unattributed:mapping_untrusted` |
| Mapping log unavailable | `unattributed:mapping_unavailable` |
| Peer not in the registry, or published-path listener | `unattributed:unregistered_peer` / `trusted_proxy` |
| Close inconsistent | `unattributed:close_inconsistent` |

There is no nearest-time guessing, and no fallback to "probably the test client".

## 3. Exclusions

- **Diagnostic session `99732d516898`** (Task 25A, Cowrie live-log lines 21851–21852) is excluded from all datasets, evaluations and correlation tests.
- Demo traffic is also never added to Dataset V2 or the sealed test. Demo sessions would be written to a separate, labelled demo slice.
