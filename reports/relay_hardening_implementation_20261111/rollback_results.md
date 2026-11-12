# Rollback results

**Rollback was not needed and was not performed.** No trigger from the approved rollback plan (`reports/relay_hardening_design_20261111/rollback_plan.md` §3) occurred:

| Trigger | Observed |
|---|---|
| Engine rejects the sysctls | no: accepted and effective |
| Relay not running or restarting | no: running, 0 restarts |
| Address ≠ 172.22.0.2 / 172.21.0.2 | no: both retained |
| Listener ≠ exactly `172.21.0.2:2222` (+ DNS) | no |
| `ip_forward` ≠ 0 | no |
| Volume missing or changed | no |
| Cowrie ID, start time or address changed | no |
| VM `DOCKER-INTERNAL` or 2223 DNAT missing | no |

The connection-based trigger (V12) was not evaluated, because the connection is prohibited in this task.

**Rollback readiness** (unchanged and available):
- **Backup:** `cowrie/backups/pre_relay_hardening_20261111T165756Z/`, verified with `SHA256SUMS`.
- **Procedure:**
  1. Restore `docker-compose.yml` from the backup and check its hash equals `cd84da48…`.
  2. Run `docker compose -f cowrie/docker-compose.yml up -d --no-deps --force-recreate ssh-relay`.
  3. Verify against the backup inspections.
- **Container IDs:** the pre-change relay container (`8d3bafb35f38…`) no longer exists; Compose removed it on recreation. A rollback would create a third container ID.
