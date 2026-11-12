# Limitations (Task 25C-2)

1. **Design only.** Nothing was changed, recreated or restarted. The only actions were read-only inspection: `docker inspect`, `docker network inspect`, a `docker exec` Python read of the installed Twisted source, and `docker compose version`.
2. **Unverified until applied:**
   - **Sysctls:** whether this engine (29.1.2, Compose v2.40.3) accepts `net.ipv4.ip_forward`, `net.ipv4.conf.all.forwarding` and `net.ipv4.conf.default.forwarding` for a container joined to two networks. These are namespaced and normally permitted, but this was not tested here.
   - **Bind timing:** whether `172.21.0.2` is present when Twisted binds at start. Docker attaches all of a service's networks before starting the process, so it is expected to be, but this was not tested.
   - **Address reassignment:** whether the recreated relay again receives `.2` on both networks. That is expected from IPAM and precedent (Task 14A.1), not guaranteed.
3. **The container ID changes.** Recreation is unavoidable for a sysctl or command change, so the relay's container ID changes on apply and on rollback.
4. **Weak host model.** With forwarding off, a host that can route to any of the relay's local addresses can still reach a listener bound to one of them, via another interface. This is mitigated, not removed, by explicit binding plus the absence of routes on demo clients (`listener_binding_design.md` §2.3).
5. **Docker-managed isolation remains a dependency.** `DOCKER-INTERNAL` and `bridge-nf-call-iptables` are not under project control. Disabling forwarding removes the relay as a potential router, but does not replace Docker's internal-bridge isolation (re-check after Docker Desktop upgrades).
6. **The demo listener is not designed into the generic forwarder,** by intention. It depends on the future attributing relay.
7. **Verification needs one new connection** (V12). That must be separately approved at implementation time, and its session excluded from all data, like `99732d516898`.
