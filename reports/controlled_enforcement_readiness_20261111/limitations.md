# Limitations: Task 25 enforcement readiness design

1. **Design only; not ready for enforcement.** Nothing was deployed, configured or tested live. Every mechanism here (attributing relay, demo network, approval tool, controller, signed checkpoints) is still to be built and tested.
2. **The client-address loss at Docker Desktop is unverified (H).** The claim that the relay sees a proxy or gateway address for `127.0.0.1:2223` comes from policy v1's note and Docker Desktop behaviour, not from a measurement in this task. One controlled connection is needed to verify it.
3. **This is a lab demonstration, not real attacker defence.** The demo restricts a dedicated container that we control, on an internal network. It proves the safety mechanics (attribution, approval, scope, inverse, expiry, audit), not effectiveness against real attackers. Real deployment would need an internet-facing path that preserves client addresses.
4. **Dataset V2 stays unattributable.** No historical session can ever be enforced against.
5. **Single-host key custody.** In the lab, all keys sit on one machine, which weakens separation of duties. That is acceptable only for a demonstration.
6. **Application-level enforcement.** The restriction acts at the relay's accept handler. It does not stop packets reaching the relay and is not a network firewall, which is intentional for safety and reversibility.
7. **Correlation relies on exact 4-tuple matching and a time window.** Heavy concurrency with fast port reuse could cause ambiguity, which the design handles by abstaining, not by guessing.
8. **Code changes would be required later, each needing approval:**
   - a new relay implementation;
   - `threat_assessment` 1.1 (mapping-based attribution states);
   - attribution config v2;
   - the approval tool and enforcement controller.

   The current components remain valid for existing data and were not changed.
9. **No claim of detection effectiveness or zero-day capability.**
