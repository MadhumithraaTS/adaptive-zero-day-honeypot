# Key custody (F-3)

## Actual permissions found (inspected 2026-11-11, before any change)

| Layer | Finding |
|---|---|
| Windows (NTFS) | Key `secrets/relay_mapping_ed25519.pem` inherited *Authenticated Users: Modify*, *BUILTIN\Users: Read & Execute*, Administrators/SYSTEM: Full. The records folder had the same ACLs |
| Accounts | Only `madhu` is enabled (Administrator, Guest, DefaultAccount, WDAGUtilityAccount and WsiAccount are disabled). `madhu` is the only member of `docker-users`. The session is non-elevated: Administrators is *deny only* |
| WSL / Docker VM | `\\wsl.localhost\docker-desktop\…\docker\volumes` is **readable by the non-elevated `madhu` session** (listed 19 volumes and the relay's volume contents). Membership of `docker-users` gives Docker API access, which is root-equivalent over the VM |
| Relay container | Read-only bind of the key; earlier mode 0777 root:root (Docker Desktop presentation) |
| Other containers | Cowrie, test client and control client do not mount the key |

**Consequence:** any process of the `madhu` Windows account can reach the key whether it lives on NTFS or in a Docker volume. Moving the key into a Docker volume would **not** separate it from the assessment if the assessment ran as `madhu` on the host. The real boundary therefore has to be the **process execution environment**, not the file location.

## Changes applied (no key generated, rotated or moved)
1. **NTFS ACLs restricted.** Inheritance was removed and access granted to the single operator account only. The previous ACLs are saved in `cowrie/backups/pre_trust_boundary_20261111/acl_*.txt` for `icacls /restore`.

   | Path | ACL now |
   |---|---|
   | `secrets\` | `MADHUMITHRAA\madhu:(OI)(CI)(RX)` |
   | `secrets\relay_mapping_ed25519.pem` | `MADHUMITHRAA\madhu:(R)`, read-only, even for the operator |
   | `records\` | `MADHUMITHRAA\madhu:(OI)(CI)(M)` |
   | `records\relay_mapping.jsonl` | `MADHUMITHRAA\madhu:(M)` |

   *Authenticated Users* (previously Modify) and *Users* (previously Read) are removed (F-3 and F-9).
2. **Relay re-verified in its real environment.**
   - The relay still loads the key; the derived public key `a52b8c52…d272bf` is unchanged.
   - The key is now mode **0444** in the container and not writable.
   - Records are still appendable (opened for append and closed, 0 bytes written).
   - The relay was not restarted.
3. **Signing separated from verification.**
   - The assessment runs in the new **`threat-assessment`** compose service (profile `assessment`, never started by `up`).
   - It runs from the same pinned image as user 999, with: cap_drop ALL, no-new-privileges, read-only root filesystem, `network_mode: none`, pids 32, 256 MiB.
   - It mounts only `threat_assessment/`, `behavioural_evidence/` and `configs/` (all read-only) plus a work directory.
   - It mounts no relay key, no records, no Cowrie volume and no Docker socket.
4. **Runtime self-check** (`run_signed.isolation_report`). The runner refuses to run if:
   - any relay/secret/socket path exists;
   - any file under its inputs contains a PEM private-key header;
   - it runs as root;
   - it runs outside a container (unless `--allow-host`, which is for tests).

## Verified from the actual execution environment (`evidence/validation_summary.json`, `evidence/evidence_checks.json`)

| Test (inside `threat-assessment`) | Result |
|---|---|
| open `/run/relay/relay_mapping_ed25519.pem`, `/run/relay`, `/var/relay_records/…`, `/opt/relay` | FileNotFoundError |
| open `/var/run/docker.sock`, `/run/docker.sock` | FileNotFoundError |
| read Cowrie log path | FileNotFoundError |
| network (TCP to 172.22.0.1:2222); interfaces | OSError; `lo` only |
| write to the mounted code | OSError (read-only) |
| uid | 999 |
| mounts | `/opt/project/{threat_assessment,behavioural_evidence,configs}` ro, `/work/input` ro, `/work/output` rw |
| PEM private keys under `/opt/project`, `/work` | **none** |
| PEM private-key headers anywhere in the image | Only third-party **test fixtures** bundled in the pinned Cowrie image (Twisted `test/server.pem`, Twisted Conch test key data, and the PEM-header constants in `cryptography`'s and Conch's key parsers). They are publicly known keys, unrelated to this project, and are outside the runner's scan roots |
| runner isolation check, all 9 validation runs | `ok: true`, in container |

The first container run was refused by the self-check. A host-compiled `.pyc` contained the PEM-header literal, because Python constant-folds `b"PRIVATE" + b" KEY"`. The marker is now built at runtime and the refusal no longer happens. This shows the guard is effective.

**What is not achieved:** the Windows operator account `madhu` can still read the relay key and the Docker VM. Docker Desktop file sharing needs that access, and the account is root-equivalent through `docker-users`. Full separation from the operator needs the steps below.

## Migration plan — **documented; awaiting approval (no keys generated or rotated)**

### A. Attribution-result key (new; required before signed attribution works in deployment)
1. Generate the Ed25519 key **inside** a one-shot container whose only writable mount is a new named volume `attribution_signing_key`. Set the file to 0400, owned by uid 999, and export only the **public** key.
2. Pin the public key in a new attribution config (3.1.0): `attribution_result.status = provisioned`, its SHA-256, a 30-day `key_validity`, and `public_key_path`. Re-pin it in a new policy version. Leave the 3.0.0 / 2.2.0 files unchanged.
3. Add an `attribution-signer` compose service (profile `attribution`) using the same hardening and no network. Its mounts:
   - relay records, read-only;
   - the Cowrie log volume, read-only;
   - the relay public key;
   - the `attribution_signing_key` volume, read-only;
   - an output directory, writable, that the relay and the assessment cannot write.
4. The assessment mounts only the attribution **public** key and the signer's output, read-only.

### B. Relay key (existing; unchanged until approved)
- Option B1 (minimum): keep it in place with the restricted ACL. Rotate it into a named volume at the next planned rotation, using the same procedure as A.1.
- Option B2: move it to a named volume now. As shown above, this does **not** protect it from the operator account. It only removes it from the repository tree and IDE indexing.

### Rotation
- **Overlap:** the new key's validity starts before the old one ends, and the verifier accepts both during the overlap.
- **Hand-over:** a `key_rollover` record, signed by the **old** key, announces the new key's SHA-256. This is a relay record type for the relay key, and a signed result field for the attribution key.
- **Re-pin:** a new config/policy version pins the new key. Old versions remain for verifying historical results.

### Revocation and compromise recovery
1. Stop the affected signer.
2. Publish a revocation entry with the compromise time; it requires a new config/policy version.
3. Treat records/results signed after the last **witnessed checkpoint** before the compromise as untrusted.
4. Generate a new key per A.1, re-pin it, re-issue results for still-valid sessions, and record the incident in the audit chain.

### Backup
- **Private signing keys are deliberately not backed up.** A lost key means rotation, not recovery, so there is no backup copy to protect or leak.
- **Public keys, checkpoints, configs and signed results are backed up**: they are needed to verify history.
- The current relay private key has no copy outside `secrets/`; the Task 26A, 26B and 26C backups contain none.

### Operator separation (beyond this lab)
For the operator to be unable to read signing keys:
- run signers under a separate OS account or host without `docker-users` membership, **or**
- use a hardware/OS keystore with non-exportable keys.

Approval signing keys for the next task must follow the same separation and never be present in the assessment container.
