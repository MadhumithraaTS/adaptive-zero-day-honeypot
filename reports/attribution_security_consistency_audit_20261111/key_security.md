# Signing-key security

## Storage and permissions (read-only inspection, 2026-11-11)

| Location | Observation |
|---|---|
| Host file `cowrie/attributing_relay/secrets/relay_mapping_ed25519.pem` | Ed25519 PKCS#8 PEM, **unencrypted**, inside the repository working tree. Git-ignored by `secrets/.gitignore` (`*`), confirmed with `git check-ignore`. It is the only private-key file found in the repository, the backups and the session scratchpad |
| NTFS ACL on the file and the `secrets/` folder (inherited) | Administrators: Full · SYSTEM: Full · **BUILTIN\Users: Read & Execute** · **Authenticated Users: Modify** |
| Inside the relay (`/run/relay/relay_mapping_ed25519.pem`) | bind mount, **read-only**; owner root:root, mode 0777 (Docker Desktop presentation of a Windows bind); readable by the relay uid 999; not writable |
| Other containers | Cowrie: not mounted · test client and control client: only `demo_client.py` mounted |
| Code | `client_attribution` and `threat_assessment` contain no private-key loading or signing code (enforced by a unit test). No approval-signing key exists |

### Finding F-3 (High): only the relay *should* need the key, but every local account *can* read it, and any authenticated user can replace it
- **Who needs it:** only the relay, to sign records.
- **Who actually has it:**
  - every process of every local user, including the assessment engine (same Windows account), editors and IDE extensions;
  - anything with Docker API access;
  - anyone with read access to the relay container's filesystem.
- **Consequences:**
  - Anyone holding the key can produce records that are indistinguishable from genuine ones.
  - *Modify* rights also allow the key to be swapped. A swapped key would be caught at verification (`key_id` / pinned SHA-256 mismatch), so every mapping becomes untrusted: fail-safe, but a denial of service.

## Public-key distribution and verification
- **Publication:** the public key `relay_mapping_ed25519.pub.pem` sits next to the relay code; it is not secret.
- **Pinning chain:**
  1. The public key's SHA-256 is `a52b8c52…d272bf`, pinned in `configs/threat_attribution_v2.json` together with its validity window (2026-11-11 → 2026-12-11).
  2. That config is pinned by canonical digest `612d6360…` in `configs/defence_policy_v2_1.json`.
  3. `correlate()` rejects any supplied public key whose SHA-256 differs from the pin.
  4. `verify_records` requires each record's `key_id` to match the pin and `relay_start.public_key_sha256` to equal it.
- **Root of trust:** the pins live in unsigned files that the same local users can edit. Whoever can change the config and policy together can re-pin a key of their choosing. Root of trust is therefore the integrity of the repository working tree.

## Rotation and compromise limitations
- **No rotation procedure:**
  - There is a single key and no successor or hand-over record.
  - The validity window exists only on the verifier side; the relay will keep signing after 2026-12-11. Records written after that date will be rejected as outside validity, which is fail-safe.
  - A new key needs a new config version and a new policy pin.
- **No revocation:** there is no revocation list and no compromise time. If the key leaks, every record it ever signed must be distrusted. No external checkpoint exists that could separate pre-compromise records from post-compromise ones (see `audit_integrity.md`).
- **Self-asserted time:** `written_utc` is set by the signer, so a key holder can backdate records anywhere inside the validity window.

## Does relay compromise permit false signed records? Yes (Finding F-5, Medium)
- **What an attacker can do:** an attacker controlling the relay process can read the key it uses and sign any record. Examples:
  - map the control client's session to 10.250.25.3;
  - invent tuples;
  - backdate records;
  - omit close records.
- **What bounds the damage today:**
  - Correlation needs a real Cowrie `session.connect` with the same tuple and time. The relay does make the upstream connection, so a compromised relay can satisfy this.
  - The client must be in the registry {.3, .4}.
  - The control client and protected addresses are never subjects.
  - Proposals are dry-run and need manual approval.
  - No enforcement controller exists.
- **What the relay runs:** it does not parse client bytes; it is a plain TCP copier. Its attack surface is Twisted's TCP handling and the container boundary.

## Minimum key-custody improvements (recommendations; not implemented)
1. **Move the key out of the repository tree and restrict its ACL.** Remove inheritance and grant read to only the identity that starts Docker Desktop. Remove *Authenticated Users* and *BUILTIN\Users*.
2. **Provide the key as a Docker secret or tmpfs-injected file** rather than a bind of a host path. Never mount it into anything except the relay; this is already true.
3. **Encrypt the key at rest** with a passphrase or DPAPI-protected wrapper, unlocked only at relay start. Better still, use hardware-backed or OS keystore signing.
4. **Pin trust outside the editable tree.** Sign the attribution config and policy with a separate offline key, or record their digests in the approval workflow, so re-pinning needs a second party.
5. **Define rotation:**
   - the relay refuses to start outside the validity window;
   - each new key is announced by a `key_rollover` record signed by the old key;
   - the verifier accepts a list of pinned keys with non-overlapping windows.
6. **Define a compromise response:** a revocation entry with a compromise timestamp, combined with external checkpoints (see `audit_integrity.md`) to bound which records stay trusted.
7. **Keep the future approval-signing key separate:** a different key, a different custodian, never present on the assessment host account (fixes the F-3 pattern before it repeats).
