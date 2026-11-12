# Limitations: Task 25A observation

**What this observation establishes:**
1. For a connection through the published endpoint `127.0.0.1:2223`, the relay's accepted socket peer is `172.21.0.1:<new port>`. That is the `cowrie_relay_frontend` gateway used by Docker Desktop's port proxy, not the originating client `127.0.0.1:57328`. The peer port differs from the client port, so the proxy creates a new connection and the client tuple is not passed through.
2. Cowrie's `cowrie.session.connect` records the relay's outbound source port (`src_port`), and it exactly equals the relay's outbound local port. An exact 4-tuple correlation between relay connections and Cowrie sessions is therefore technically possible for the relay→Cowrie hop.

**What it does not establish:**
1. **Behaviour for other client origins.** Only one connection was made, from the host's loopback. A client on the LAN or the internet reaching a non-loopback published port, a different Docker Desktop network mode (e.g. host networking or mirrored WSL networking), or Docker Engine on Linux with `userland-proxy` disabled might expose different addresses. None of these was tested, and nothing should be assumed about them.
2. **Whether the proxy always uses 172.21.0.1.** One sample cannot show whether this holds for every connection, or that the address is stable across Docker Desktop restarts or upgrades.
3. **That the original client can be recovered at the relay.** In this topology it cannot, which is the point of the finding. The Task 25 design's attributing relay would therefore see only `172.21.0.1` for published-port traffic. Trustworthy attribution needs a path where the relay's socket peer *is* the client, such as the designed `demo_ingress` container network. That remains to be approved and was not built.
4. **Whether correlation holds under concurrency.** Port uniqueness under concurrent connections, port reuse and clock skew were not tested.
5. **The full internal mechanism of Docker Desktop's proxy.** The observation is a TCP-table read rather than a capture: it shows endpoints, not how Docker Desktop forwards internally.
6. **Side effect.** The diagnostic session added 2 events to Cowrie's live log (session `99732d516898`). They are outside every dataset slice and must stay excluded.
