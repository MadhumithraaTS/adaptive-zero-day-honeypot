# Task 26D-3 — Contain and Remove Exposed Cowrie Host-Key Backups (K-3)

Date: 2026-11-12 · Completed. No stop condition triggered. Live host keys not rotated, regenerated or modified. Nothing committed.

## 1. Identification
- **Scope of inspection:**
  - `cowrie/backups/pre_isolation_20261110/`;
  - the host-key settings in its `etc/cowrie.cfg.dist` and in the live container's `cowrie.cfg.dist` (no `cowrie.cfg` override exists);
  - the backup's own `container_inspect.json` and `docker-compose.yml`, for the old mounts.
- **Private-key scan:** the backup holds 1,849 files. A PEM/OpenSSH private-key header scan, which printed file names only, found exactly 3 files: `var/lib/cowrie/ssh_host_{rsa,ecdsa,ed25519}_key`.
- **Config:** Cowrie's `[ssh]` section names exactly these as `rsa_private_key`, `ecdsa_private_key` and `ed25519_private_key` under `state_path = var/lib/cowrie`. The `.pub` files are the matching public keys.
- **Confirmation for each private copy:**
  - it pairs with its `.pub`: the public key was derived in memory from the private key and compared; nothing was printed or kept;
  - its SHA-256 equals the backup's own `SHA256SUMS`, so it is unchanged since the backup;
  - it is **byte-identical to the live Cowrie private key** (SHA-256 compared inside the container).
- **Live-key relationship:** the live Cowrie container (`0bec5a78b1cb`) mounts `/cowrie/cowrie-git/var` from volume `268411d7…`, created 2026-10-24T17:05:49Z. That is the same volume the backup was copied from (per `container_inspect.json`). The old deployment used Docker volumes, not host bind mounts, so this backup left no second host directory.
- **Administrator account:** `MADHUMITHRAA\madhu`. It owns the files and the directory, it is the only enabled member of Administrators, and it is the account running this session.

## 2. Files removed (no private-key contents shown anywhere)

| File (`var/lib/cowrie/`) | Bytes | File SHA-256 | Public key | Public fingerprint (SHA256) | MD5 |
|---|---|---|---|---|---|
| `ssh_host_rsa_key` | 1675 | `0b3fec81ad7b2eca…` | ssh-rsa | `SHA256:29LQXC4gBIZ7kT/40ExyZ8b6ZFJcwwiHlwB0x6is+J4` | `ec:64:4b:06:a9:e3:96:35:2a:61:99:12:88:ac:26:ea` |
| `ssh_host_ecdsa_key` | 227 | `dd8e164b2bed64d3…` | ecdsa-sha2-nistp256 | `SHA256:gIf4j+uWxz/GZmvXt5E9Go5IR4ry7m7pibcHLb/uSds` | `e5:c5:a4:a5:7a:0a:52:b8:99:4e:b0:31:c7:cd:a1:eb` |
| `ssh_host_ed25519_key` | 387 | `fb5c3f08eab8d519…` | ssh-ed25519 | `SHA256:FH4+yAVLrevTYlx4SZbhbVoWfgg2SyZq3CuLs9pBL+A` | `3a:54:d6:aa:ca:d4:20:a1:58:c4:9d:5f:b3:44:7c:c2` |

The full hashes are in `evidence/inventory_before.json`. SHA-256 of a private key does not reveal it.

## 3. Permissions and ownership

| Stage | Owner | ACL on each of the 3 files |
|---|---|---|
| Before (`evidence/acl_before.txt`) | `MADHUMITHRAA\madhu` | inherited: Administrators F, SYSTEM F, **BUILTIN\Users RX**, **Authenticated Users M** |
| Restricted for removal (`evidence/acl_restricted.txt`) | `MADHUMITHRAA\madhu` | inheritance removed; **`MADHUMITHRAA\madhu:(R,D)` only** |
| After | — | files removed |

- **Timestamps:** created and modified 2026-10-24T17:05:51Z, i.e. when the volume was initialised. The copy preserved the original times.
- **Directory:** the `var/lib/cowrie/` ACL was not changed.

## 4. Verification (`evidence/verification_after.txt`)
- **Removed copies:** all three are gone.
- **No other key material:** no private-key header remains anywhere in the backup.
- **Preserved:** 1,846 files remain (1,849 − 3). Every non-key file is **present and byte-identical** to the pre-change manifest (`evidence/preserved_files_before.json`), with nothing missing or unexpected.
  - The three `.pub` files are kept as useful metadata, since the fingerprints are public anyway.
  - Also kept: the backup `SHA256SUMS`, `container_inspect.json`, `image_inspect.json`, `docker-compose.yml`, `etc/`, logs, `downloads/`, `tty/` and the rest.
- **The backup's own `SHA256SUMS` was not edited:** it is a historical record. It now reports three missing entries; that is expected and documented here.
- **No tracked files:** git tracks no file in this directory, and the git status of tracked files is unchanged.

## 5. Live Cowrie host keys

| Key | Live private SHA-256 | Mode / owner (in container) | Changed by this task |
|---|---|---|---|
| RSA | equal to the removed copy | 0644, uid 999 | no (same hash and mtime) |
| ECDSA | equal | 0644, uid 999 | no |
| Ed25519 | equal | 0644, uid 999 | no |

The Cowrie container is unchanged: started 2026-11-10T12:30:30Z, 0 restarts.

**Prior exposure (now removed):** the backup copies were readable by *BUILTIN\Users* and modifiable by *Authenticated Users* on this host.
- `madhu` is the only enabled account, so in practice the readers were processes of that account (IDE, extensions, scripts, any sync or backup client indexing the working tree).
- The path is git-ignored and **no commit on any ref ever contained these files**, so they never reached the GitHub remote.
- No evidence of any read or copy exists. NTFS access auditing was not enabled, so a read cannot be ruled out either.

**Remaining copies of the same keys:**
- the live volume, inside the Docker Desktop VM. It is reachable by `madhu` through `\\wsl.localhost` and the Docker API (Task 26C), and the keys are mode 0644 inside the Cowrie container.
- Whether other copies exist outside this backup was not searched; repository-wide searches are prohibited in this task.

**Operational implications of the prior exposure:**
- **What a copy enables:** the private host key is the honeypot's SSH server identity. A holder could impersonate this sensor (run another SSH server presenting the same host key) or actively man-in-the-middle connections to it.
- **What it does not enable:**
  - decrypting recorded sessions (SSH key exchange is ephemeral, so there is forward secrecy);
  - access to the host or the relay;
  - attribution forgery: these keys sign SSH handshakes only, not relay records or attribution results.
- **Fingerprints are public anyway:** every connecting client receives them.

## 6. Recommendation: live host-key rotation
**Rotation is not urgently necessary; plan it, don't do it now.**
- The exposure was local to a single-user host and never committed or pushed. The key's value is limited to impersonating a honeypot, which has no confidentiality or attribution role.
- Rotate **at the next planned Cowrie maintenance**, or immediately if any of these occur: evidence of host compromise, sharing or sync of the working tree, a public demonstration where sensor identity matters, or a requirement for strict sensor provenance.
- **How to rotate** (separate approved task): stop Cowrie, move the six `ssh_host_*` files in the live volume aside, and let Cowrie generate new keys at start. Record the new fingerprints, and update any `known_hosts` used by the demo clients (they currently accept the host key without pinning).
- Independently of rotation, the in-container mode 0644 could be tightened to 0600. That is a separate change to the live volume and was not done here.

## Confirmations
- Only the three confirmed plaintext private-key copies were removed. The backup directory and every other file remain.
- **Not touched:** Docker Compose, relay, assessment configs, policies, severity definitions, behavioural evidence, attribution or checkpoint keys, and live Cowrie keys. No keys were generated.
- No migration step was run.
- No Dataset V2, sealed evaluation output or protected report folder was accessed, and no repository-wide search was run.
- The backup's `downloads/` and `tty/` content was hashed for the preservation check only; nothing was opened, displayed or executed.

Stopped.
