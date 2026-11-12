# Limitations (Task 25C-pre)

1. **The core question is unanswered.** Whether a demo client's connection reaches the relay with peer `10.250.25.3` was not tested, because the preflight stop prevented the experiment. Nothing about the container path is verified.
2. **Preflight findings are point-in-time reads.**
   - `ip_forward = 1` and the `0.0.0.0:2222` bind were read once, on 2026-11-11T16:45Z.
   - The Docker default for a container's `net.ipv4.ip_forward` was not determined. It could result from Docker Desktop's namespace setup rather than the image.
3. **The routing exposure is a hypothesis, not a demonstrated path.** In the existing deployment, the relay's forwarding between `relay_frontend` and `cowrie_internal` was not probed, and no attempt was made to route through it.
4. **The SSH client is not minimal.** It would be the pinned Cowrie image with Twisted Conch's `conch`. That avoids pulling images, but it is a full image. A minimal client image would need a pull, and that needs approval.
5. **Options to proceed** (each changes something this task prohibited, so each needs explicit approval):
   - **(a)** Accept that the existing forwarder is reachable on the demo interface, which is limited to the two controlled clients, and that `ip_forward = 1` stays. The isolation then relies on the clients' dropped capabilities. This relaxes two preflight conditions.
   - **(b)** Recreate the relay with `sysctls: net.ipv4.ip_forward: 0`. Optionally run a second forwarder bound only to the demo address (Twisted endpoint `tcp:2222:interface=10.250.25.2`) in place of the `0.0.0.0` bind. This modifies the relay deployment and its forwarder bind.
   - **(c)** Use the future attributing relay (Task 25 design), with explicit per-interface binds and forwarding disabled, and verify the peer address with it directly.
