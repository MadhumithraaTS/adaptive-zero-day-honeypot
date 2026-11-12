# Rollback and restoration plan

## 1. Before the change (backup; no state change)

1. Create `cowrie/backups/pre_relay_hardening_<UTC>/` containing:
   - `docker-compose.yml`;
   - `docker inspect cowrie-ssh-relay cowrie-project`;
   - `docker network inspect cowrie_cowrie_internal cowrie_relay_frontend`;
   - the relay's mount list (anonymous volume names `4492a68c…`, `fba87a59…`);
   - the relay's `/proc/net/tcp` listeners and forwarding sysctls (Task 25C-1 method);
   - the VM `iptables-nft-save` excerpt (`DOCKER-INTERNAL`, `DOCKER` chain, DNAT for 2223);
   - a Cowrie log line count and SHA-256 (via `docker cp`, as in Task 14B);
   - `SHA256SUMS`.
2. Record the expected post-change values (`verification_plan.md`).

## 2. Apply (for reference; not executed)

```
docker compose -f cowrie/docker-compose.yml up -d --no-deps --force-recreate ssh-relay
```

- **Never** `docker compose down`: anonymous volumes would be at risk (Task 14A).
- **No** `--renew-anon-volumes`.
- Cowrie is not recreated (`--no-deps`).

## 3. Rollback triggers

Roll back when any of these occurs:
- the engine rejects the `sysctls` keys;
- the relay does not reach `running`, or keeps restarting;
- an address differs from 172.22.0.2 / 172.21.0.2;
- the listener differs from exactly `172.21.0.2:2222` (plus Docker DNS on 127.0.0.11);
- `ip_forward` ≠ 0;
- an anonymous volume is missing or changed;
- the single verification connection fails to produce a Cowrie `session.connect` from `172.22.0.2`;
- Cowrie's container ID, start time or address changed;
- the VM rules `DOCKER-INTERNAL` / the 2223 DNAT are missing.

## 4. Rollback procedure

1. Restore `cowrie/docker-compose.yml` from the backup, and check its hash equals `cd84da48…`.
2. Run `docker compose -f cowrie/docker-compose.yml up -d --no-deps --force-recreate ssh-relay`.
3. Verify the restored state against the backup:
   - relay command `--port=tcp:2222`;
   - listener `0.0.0.0:2222`;
   - addresses 172.22.0.2 / 172.21.0.2;
   - the same anonymous volumes;
   - Cowrie unchanged;
   - published port `127.0.0.1:2223`.
4. Record a rollback report beside the backup, with every verification result.

## 5. Restoration limits

- **The relay's container ID changes** on any recreation, both apply and rollback. That cannot be avoided: Docker recreates the container. The old ID is recorded in the backup.
- **Addresses cannot be forced** on rollback without pinning (`network_preservation.md`). If rollback also yields a wrong address, the lab stays out of use, and an address-pinning change (separate approval) is required.
- **Diagnostic session `99732d516898`, and any verification-connection session, stay excluded** from all datasets and evaluations.
