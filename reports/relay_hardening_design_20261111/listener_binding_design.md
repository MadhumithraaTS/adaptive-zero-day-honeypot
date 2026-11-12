# Listener binding design

## 1. Listener map

| Phase | Listener | Bound by | Backend | Purpose | Attribution meaning |
|---|---|---|---|---|---|
| **Now (this hardening)** | `172.21.0.2:2222` | Generic `twistd portforward` (`--port=tcp:2222:interface=172.21.0.2`) | `cowrie:2222` → 172.22.0.1:2222 | Published path: `127.0.0.1:2223` → VM DNAT → `172.21.0.2:2222` | Peer is always the Docker proxy `172.21.0.1` (Task 25A), so never attributable |
| Future (attributing relay, separately approved) | `172.21.0.2:2222` | Attributing relay | `cowrie:2222` | Same published path | Mapping recorded with `ingress_listener = published`; never attributable |
| Future (attributing relay, separately approved) | `10.250.25.2:2222` | Attributing relay **only** | `cowrie:2222` | Demo ingress (Task 25B) | Mapping plus restriction check; attributable only through a verified mapping |

## 2. Rules that keep the demo listener from exposing the unrestricted forwarder

1. **The generic forwarder never binds `10.250.25.2` or `0.0.0.0`.** After this change, its only socket is `172.21.0.2:2222`.
2. **Ordering rule.** The relay is attached to `cowrie_demo_ingress` only in the same approved change that replaces the generic forwarder with the attributing relay. Never before.
   - Until then, the demo address does not exist on the relay.
   - Even if it existed, nothing listens on `10.250.25.2` (point 1).
3. **Weak host model (residual).** Linux accepts a packet for *any* local address on *any* interface. So a demo client that could send to `172.21.0.2` through `10.250.25.2` would reach the published-path listener, even with forwarding off. It needs a route to `172.21.0.0/16` via the relay, which demo clients do not have:
   - the internal network has no gateway or default route;
   - with `cap_drop: ALL`, clients have no `NET_ADMIN` to add one.

   The attributing relay must still check, per accepted socket, that the **local** address equals the listener it was accepted on, and reject a mismatch.
4. **One forwarder process per listener role.** The future attributing relay keeps a per-listener policy table: listener → backend, mode (`published` / `demo`), restriction check on or off. A listener with no entry is never opened.

## 3. Failure behaviour of the explicit bind

- If `172.21.0.2` is not assigned to the recreated relay at start, Twisted cannot bind and the service fails to start.
- That is **fail-closed**: the published path stops, and no other address is exposed.
- The verification plan detects it, and the rollback plan restores the previous command.
