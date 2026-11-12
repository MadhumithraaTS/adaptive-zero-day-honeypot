# Network and address preservation

## 1. Facts (read-only; `evidence/readonly_inspection.txt`)

- `cowrie_cowrie_internal`: subnet 172.22.0.0/16, no gateway (isolated). Members: Cowrie 172.22.0.1, relay 172.22.0.2.
- `cowrie_relay_frontend`: subnet 172.21.0.0/16, gateway 172.21.0.1. Member: relay 172.21.0.2.
- Both networks were created by Compose **without** `ipam:` blocks: the subnets came from Docker's default pool, and Compose's network config-hash labels reflect that.
- The relay's anonymous volumes are `4492a68c…` (`/cowrie/cowrie-git/etc`) and `fba87a59…` (`/cowrie/cowrie-git/var`).

## 2. Decision: no network change, no pinning

- **Pinning would require network recreation.** A fixed `ipv4_address` needs a user-configured subnet, i.e. an `ipam:` block in Compose. Adding one changes the network definition, so Compose would recreate the network.
  - **On `cowrie_internal`:** recreation would also detach and reattach Cowrie. That changes Cowrie's network, which this task forbids, and Task 14A showed it can drop service aliases.
  - **On `relay_frontend`:** only the relay is affected. It is still a second moving part, so it is deferred to an optional later step.
- **Minimal plan:** recreate **only the relay container**, with `docker compose up -d --no-deps --force-recreate ssh-relay`. No network definition changes, and Cowrie is not touched (`--no-deps`).

## 3. Why the relay should keep `172.22.0.2` and `172.21.0.2` (expected; verified after recreation)

- **Cowrie keeps `172.22.0.1`.** It is not recreated.
- **The relay's addresses are freed and reassigned.** When the old relay is removed, Docker's default IPAM allocates the first free address in each subnet:
  - `cowrie_internal`: `.1` is held by Cowrie and there is no gateway reservation in isolated mode, so the first free address is expected to be `.2`;
  - `relay_frontend`: `.1` is the gateway, so the first free address is expected to be `.2`.
- **Precedent:** in Task 14A.1 the relay was force-recreated and received `172.22.0.2` / `172.21.0.2` again.
- **Not guaranteed:** this is the expected IPAM behaviour, not a pinned guarantee. Hence the abort rule below.

## 4. Abort rule

If after recreation the relay's `cowrie_internal` address is not `172.22.0.2`, or its `relay_frontend` address is not `172.21.0.2`, **stop using the lab and roll back** (`rollback_plan.md`). The consequences would be:

| Wrong address | Consequence |
|---|---|
| `relay_frontend` ≠ 172.21.0.2 | The explicit bind fails: fail-closed, the published path is down |
| `cowrie_internal` ≠ 172.22.0.2 | `configs/threat_attribution_v1.json` (trusted proxy `172.22.0.2/32`) and the behavioural-evidence `relay_sources` would no longer describe the relay. The address would still sit inside the protected `172.22.0.0/16`, so no proposal could result, but evidence records (authentication status) would change meaning. The configs must not be "fixed" without approval |

## 5. Optional later step (separate approval)

Pin `relay_frontend`: add `ipam.config: [{subnet: 172.21.0.0/16, gateway: 172.21.0.1}]` and `ipv4_address: 172.21.0.2` on the relay. This recreates `relay_frontend`, which has only the relay as a member. `cowrie_internal` stays unpinned unless a Cowrie-affecting change is separately approved.
