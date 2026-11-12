# Isolation results

**No isolation test was run.** The demo network and clients were not created (preflight stop), so client→Cowrie, client→host, client→unrelated-container and client→external reachability were **not** tested.

## Isolation-relevant findings from preflight (read-only)

1. **Relay forwarding is enabled.** `net.ipv4.ip_forward = 1` in the relay's network namespace.
   - **Design impact.** Task 25B relied on "the relay is not a router". With forwarding on, a host on a network the relay is attached to could, in principle, use `10.250.25.2` as a next hop towards `cowrie_internal` (172.22.0.0/16).
   - **Why not demonstrated.** In the proposed demo, clients with `cap_drop: ALL` cannot add such a route (no `NET_ADMIN`), so the path is not demonstrated. But the design's "not a router" premise is false as deployed, and a client with any routing capability would not be stopped by the relay.
2. **The existing deployment carries the same property** (finding for review; not tested).
   - The relay is already attached to `cowrie_relay_frontend` (172.21.0.0/16, not internal; gateway 172.21.0.1, the Docker VM side) and to `cowrie_internal`, with forwarding enabled.
   - Whether anything on the VM side could route to `172.22.0.1` through `172.21.0.2` was **not** tested. Earlier isolation audits (Tasks 13–14A) checked egress from Cowrie, not ingress routing through the relay.
   - This should be assessed in a separately approved, read-only or controlled check.
3. **The forwarder listens on every interface** (`0.0.0.0:2222`). Any network the relay joins can reach the Cowrie forwarder.
