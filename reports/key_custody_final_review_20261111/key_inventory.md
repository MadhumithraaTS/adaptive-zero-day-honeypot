# Key inventory (as of 2026-11-12; read-only review)

The search covered every `*.pem` / `*.key` file name in the repository, plus PEM headers in code, config, key and Task 26A–26C report folders. Datasets were excluded; see `report.md` §Disclosure.

## Private keys

| # | Key | Location | Owner (uses it) | Custodian / who can read | Status |
|---|---|---|---|---|---|
| P1 | **Relay record signing key**: Ed25519, public SHA-256 `a52b8c52…d272bf`, key_id `a52b8c522a4bb091` | `cowrie/attributing_relay/secrets/relay_mapping_ed25519.pem` (plaintext PKCS#8, git-ignored) → bind-mounted read-only at `/run/relay/relay_mapping_ed25519.pem` (mode 0444, not writable) | `cowrie-ssh-relay` process (uid 999); loaded once at start | NTFS: `MADHUMITHRAA\madhu:(R)` only. Also any process of `madhu`, and anyone with Docker API access (via the relay container) | **Live**; validity window in config 2026-11-11 → 2026-12-11 (verifier side only) |
| P2 | **Attribution-result signing key** | — | planned `attribution-signer` | — | **Does not exist** (v3 `attribution_result.status = pending_provisioning`) |
| P3 | **Checkpoint witness key** | — | planned `log-witness` (see `checkpoint_procedure.md`) | — | **Does not exist** |
| P4 | Approval signing key (next task) | — | human approver | — | Out of scope; must be distinct from P1–P3 |
| P5 | **Cowrie SSH host keys** (ECDSA, Ed25519, RSA): honeypot SSH identity, not attribution keys | live: Cowrie var volume `/cowrie/cowrie-git/var/lib/cowrie/ssh_host_*_key`. **Copies:** `cowrie/backups/pre_isolation_20261110/var/lib/cowrie/ssh_host_*_key` | `cowrie-project` | Backup copies: inherited ACL *BUILTIN\Users: RX*, *Authenticated Users: **Modify***. Git-ignored | **Live, and the backup copies are identical**: public fingerprints match, ECDSA MD5 `e5:c5:a4:a5:…` = the key the demo clients saw. Finding K-3 |
| — | Ephemeral validation/test keys (Task 26C validation, unit tests) | memory only; never written | tests / validation script | — | Discarded. Validation result public key `a21a42cc…` is kept for re-verification only |
| — | Third-party test keys in the pinned Cowrie image (Twisted, `cryptography` fixtures) | image layers | none | public | Not project keys |

## Public keys and pins

| Public key | File(s) | Pinned in | Consumed by |
|---|---|---|---|
| Relay (P1) `a52b8c52…` | `cowrie/attributing_relay/relay_mapping_ed25519.pub.pem` (file SHA-256 `ec26c9fc…`) | `threat_attribution_v2.json` and `threat_attribution_v3.json` → `proxy_client_mapping.public_key_sha256`; announced in the relay's signed `relay_start` record | `client_attribution` correlator (`verify_records`) |
| Validation result key `a21a42cc…` (ephemeral, not live) | `reports/attribution_trust_boundary_remediation_20261111/evidence/validation_fixtures/attribution_result_validation.pub.pem`; scratch copy `cowrie/assessment_work/input/` | validation fixture config only (**not** in `configs/`) | 26C validation runs only |
| P2 (planned) | — | `threat_attribution_v3.x` → `attribution_result.public_key_sha256` (live value `null`) | `threat_assessment.signed_attribution` (assessment container) |
| P3 (planned) | — | new field (`checkpoint_witness.public_key_sha256`) in the next config version | correlator / attribution signer (`verify_checkpoints`) |

**Pin chain:**
1. The public-key SHA-256 is pinned in the attribution config.
2. The config's canonical digest is pinned in the policy.
3. The policy digest, attribution digest and evidence digest are recorded in every assessment's `versions` and in the hash-chained audit entry.

## Who can reach which private key (verified)

| Component | P1 relay key | P5 host keys | Evidence |
|---|---|---|---|
| `cowrie-ssh-relay` | **yes** (read-only) | no | mounts (`evidence/isolation_recheck.txt`) |
| `threat-assessment` container | **no**: path absent; no Docker socket, records, secrets or network (`lo` only); uid 999; no private key in its mounts | no | probe re-run 2026-11-11T18:29Z |
| Cowrie, demo clients | no | Cowrie only (its own) | Task 26A/26C mount inspection |
| Windows account `madhu` (host processes, IDE, Python) | **yes** (NTFS R; Docker API; `\\wsl.localhost`) | **yes** (and any local user can read/modify the backup copies) | `residual_risks.md` |
