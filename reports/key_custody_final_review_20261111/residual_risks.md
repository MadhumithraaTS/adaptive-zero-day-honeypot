# Residual risks

## Host-account (`madhu`) compromise
`madhu` is the only enabled account, a member of Administrators (elevatable) and `docker-users`, and can browse `\\wsl.localhost\docker-desktop`. An attacker with this account can:

| Capability | Effect | Mitigated by current design? |
|---|---|---|
| Read P1 (NTFS read) and any Docker volume key (P2/P3 after migration) | Forge relay records, attribution results and checkpoints | **No** |
| Run `docker` (root-equivalent over the VM) | Exec into any container, mount anything, replace images | **No** |
| Edit configs and policy, re-pin keys consistently | Silent key replacement for **future** runs | **Partly.** Every assessment and audit entry records the config and policy digests, so a re-pin is visible afterwards, but nothing prevents it. Needs an off-host anchor (approved digests signed by a key the host never holds) |
| Delete or alter relay logs and checkpoint stores together | Erase history | **Partly**: only if an off-host checkpoint copy exists |
| Read or modify the Cowrie SSH host key backups (K-3) | Impersonate the honeypot's SSH identity | **No** (any local user, not just `madhu`) |
| Forge future human approvals | Approve proposals | **Not yet relevant**; the approval key must live off this host (next task) |

## Docker administrator compromise
- Any `docker-users` member, or any process with the Docker socket, has the same power as above inside the VM.
- Containers holding keys (relay; later signer and witness) can be exec'd into and their keys read.
- No current control prevents this. The assessment container's isolation protects against a compromised **assessment process**, not against a Docker administrator.

## Other residual risks
1. **K-1 (blocking for migration):** the same key can be pinned for two roles (verified: the relay key was accepted as the attribution-result key). If that ever happened, the relay key holder could sign attribution results directly and bypass correlation.
2. **K-2:** a corrupt result public key raises `ValueError` instead of `AssessmentConfigError`. It still fails closed.
3. **Self-asserted time:** relay and signer clocks set `written_utc` / `issued_utc`, so a key holder can backdate within key validity.
4. **The relay can influence, not approve:**
   - A compromised relay (or P1) can sign false mappings for real sessions. It is limited to registered clients, and only 10.250.25.3 can become a proposal subject: .4 is excluded and .2 is protected.
   - It cannot approve. No approval mechanism exists, proposals are `manual_approval: pending`, and the relay has no access to policy, configs, assessment code, outputs, work directories or the Docker socket (`evidence/isolation_recheck.txt`).
   - The approval design must bind approval keys to their role (K-1 rule) so relay, signer or witness keys can never sign approvals.
5. **Fail-closed batches** (Task 26C): an injected invalid document blocks proposals for the batch (a denial of service).
6. **Record expiry:** captured records age out after 24 h. Re-validation after 2026-11-12T17:19Z needs new sessions or a validation-only config.
7. **Third-party test keys** in the pinned image may confuse broad key scans.

## Recommended additional controls (not implemented)
- Run signers (and later the approver) under a separate account or host without `docker-users`, or use a non-exportable keystore (TPM / Windows CNG).
- Sign approved config and policy digests with an offline key; have verifiers require that signature.
- Copy checkpoints and audit-log heads off-host at each interval.
- Enforce distinct-role key pins (K-1) and typed key purposes in every signed format.
