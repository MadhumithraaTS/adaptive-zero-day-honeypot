# Cowrie correlation (DIAGNOSTIC)

**Cowrie TCP table during the connection:** `172.22.0.1:2222 ← 172.22.0.2:56300` ESTABLISHED.

**New Cowrie JSON events.** The live log went from 21,852 to 21,854 lines: exactly 2 new events, both for one session.

```json
{"eventid": "cowrie.session.connect", "src_ip": "172.22.0.2", "src_port": 56300, "dst_ip": "172.22.0.1", "dst_port": 2222, "session": "b806554e19b9", "protocol": "ssh", "message": "New connection: 172.22.0.2:56300 (172.22.0.1:2222) [session: b806554e19b9]", "sensor": "0bec5a78b1cb", "uuid": "bafc61de-32ec-11f1-a37e-46de337b5ff9", "timestamp": "2026-11-11T17:03:25.165789Z"}
{"eventid": "cowrie.session.closed", "duration": "3.1", "message": "Connection lost after 3.1 seconds", "sensor": "0bec5a78b1cb", "uuid": "bafc61de-32ec-11f1-a37e-46de337b5ff9", "timestamp": "2026-11-11T17:03:28.291911Z", "src_ip": "172.22.0.2", "session": "b806554e19b9", "protocol": "ssh"}
```

| Verification | Expected | Observed | Result |
|---|---|---|---|
| Cowrie source IP | `172.22.0.2` | `172.22.0.2` | PASS |
| Cowrie `src_port` = relay outbound local port | equal | `56300` = `56300` | PASS |
| Relay listener exclusively `172.21.0.2:2222` | yes | yes (before, during, after) | PASS |
| IP forwarding disabled | 0 | 0 (before and after) | PASS |
| Exactly one diagnostic session | 1 | 1 (`b806554e19b9`; 2 events: connect + closed) | PASS |

**Timing:** client connect 17:03:25.110 → Cowrie connect 17:03:25.166 (+0.056 s; Task 25A before hardening: +1.08 s). Close 17:03:28.270 (client) → 17:03:28.292 (Cowrie).

**Conclusion:** the hardened relay, with forwarding disabled and the listener bound to `172.21.0.2:2222` only, still forwards application-level TCP traffic to Cowrie end to end. Cowrie records the relay's outbound source port.
