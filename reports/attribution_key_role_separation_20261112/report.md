# Task 26D-1 — Attribution Key-Role Separation (K-1) and Configuration Error Handling (K-2)

Date: 2026-11-12 · Scope: the two approved code fixes only · No keys generated, rotated, replaced, exported or deleted · No migration step run · Nothing committed

## Root cause

| ID | Root cause (in `threat_assessment/config.py`, `AttributionConfig._from_v3`) |
|---|---|
| K-1 | The attribution-result pin (`attribution_result.public_key_sha256`) was checked only against the supplied PEM. It was **never compared with the relay record key pin** (`proxy_client_mapping.public_key_sha256`). The relay pin's format was never validated either, so a differently spelled digest of the same key (for example in upper case) would also have defeated a plain string comparison |
| K-2 | `serialization.load_pem_public_key(pem).public_bytes(Raw, Raw)` was called unwrapped, so malformed input raised a raw `ValueError`. **Found during the fix:** the key **type** was never checked. An X25519 PEM whose hash matched the pin was accepted, and would have crashed at verification with an `AttributeError` |

## Files changed
- `threat_assessment/config.py`
  - **New `_pin(value, role)`:** a pin must be exactly 64 lowercase hex characters, the SHA-256 of the raw Ed25519 public key. Any other spelling is rejected (upper case, whitespace, prefixes, wrong length).
  - **New `ed25519_public_key_identity(pem, role)`:** returns the raw-key SHA-256. Every failure raises `AssessmentConfigError`: missing, empty, non-bytes, malformed PEM, a private-key PEM, unsupported algorithm, or not Ed25519.
  - **`_from_v3` enforces key-role separation (below).** The relay pin is validated even while the result key is `pending_provisioning`.
  - **New field `AttributionConfig.relay_key_sha256`**, set for v3.
- `threat_assessment/signed_attribution.py` (`verify_result`): it enforces the same rule again at verification time (defence in depth), and converts an unusable configured key into `SignedResultError` (fail closed).
- `tests/test_key_role_separation.py` (new, 30 tests).
- `tests/test_trust_boundary.py`: one expectation widened. `test_result_public_key_must_match_pin` supplies the relay PEM as the result key, which is now caught by the earlier, more specific key-role check.

Not changed: policy thresholds, severity definitions, proposal gates, behavioural evidence, configs, keys, Cowrie host keys and backups.

## Key-role separation rule enforced by the code
Key identity = SHA-256 of the raw 32-byte Ed25519 public key, written as 64 lowercase hex characters. It is independent of PEM encoding: CRLF line endings, missing trailing newline, and extra blank lines all give the same identity.

**At config load (`_from_v3`)**, all of these hold or `AssessmentConfigError` is raised:
1. The relay record key pin is a canonical pin (always, including while the result key is pending).
2. If the result key is provisioned, its pin is canonical **and ≠ the relay pin**.
3. The supplied result public key is a valid Ed25519 public key, its identity **≠ the relay pin**, and its identity equals the result pin.

**At verification (`verify_result`)**, all of these hold or `SignedResultError` is raised:
1. The config's relay pin is present, and the result pin ≠ the relay pin. This also covers a config object built around the loader.
2. `signer.public_key_sha256` ≠ the relay pin.
3. The configured result key loads as Ed25519, its identity ≠ the relay pin, and it equals the result pin.

Consequence: an attribution result signed with the relay key is rejected even if a config pins the relay key as the result key, and the session stays unattributed.

## Tests and exact results
- **New suite** `tests/test_key_role_separation.py`: **30 passed**.

  | Requirement | Tests |
  |---|---|
  | relay public key used for result verification → rejected | `test_relay_key_as_result_key_is_rejected`; reproduction below |
  | distinct, correct keys accepted | `test_distinct_correct_keys_are_accepted` |
  | missing / malformed / invalid keys → standard config error | 8 parametrised cases (None, empty, junk, truncated, corrupted header, corrupted body, private-key PEM, str instead of bytes); non-Ed25519 (X25519) key; no raw `ValueError` escapes; wrong-but-valid key fails the pin; verifier turns an unusable configured key into `SignedResultError` |
  | substitution and equivalent encodings cannot bypass | 4 PEM re-encodings of the relay key, each rejected whether pinned as itself or as another key; 6 alternative pin spellings, each rejected for both the result and the relay pin; relay pin validated while the result key is pending; verifier rejects a forged config object and a relay-signed result; a relay-signed result never proposes |
  | existing valid signature verification works | genuine signed result verifies and the S4-style session still proposes (subject 10.250.25.3, all gates true); a re-encoded genuine result key still verifies |
  | no private key exposed to the assessment | no private-key loading, signing or signer import in `threat_assessment` (test); the Task 26C isolation tests still pass |

- **Security suites** (`test_results_security.txt`): `test_key_role_separation`, `test_trust_boundary`, `test_client_attribution` and `test_threat_assessment`: **237 passed**.
- **Full suite** (`test_results_full.txt`): **623 passed** (Task 26C: 593).
- **Reproduction of the Task 26D finding** (`reproduction_after_fix.txt`):
  - K-1, relay key pinned as the attribution-result key → `AssessmentConfigError: key-role separation: the attribution_result key must not be the relay record key` (it was **ACCEPTED** in Task 26D).
  - K-2, corrupt result public key → `AssessmentConfigError: attribution_result public key is malformed or not a PEM public key` (it was a raw `ValueError`).
  - The live v3 config still loads: result key `pending_provisioning`, relay pin `a52b8c522a4bb091`.

## Confirmations
- **No keys were generated, rotated, replaced, exported or deleted** (`unchanged_checks.txt`).
  - Relay private key: metadata only checked, contents not read. Size 119 bytes, mtime 2026-11-11 22:42:34 +0530, unchanged since creation in Task 26A.
  - Relay public key: SHA-256 `ec26c9fc…`, unchanged.
  - Relay code, relay config, v3 config, policy 2.2.0 and address-safety config all match the Task 26D manifest.
  - Tests use only the existing ephemeral in-memory fixture keys. The non-Ed25519 case uses the fixed X25519 base point, a public constant.
- **Unchanged:** severity definitions (`severity.py` matches the Task 24 manifest), behavioural evidence (9/9 files match the Task 22 manifest), Cowrie host keys and backups (not touched).
- **No protected datasets or sealed evaluation outputs were intentionally accessed.**
  - Inspection was limited to `threat_assessment/config.py`, `threat_assessment/signed_attribution.py`, the named tests, `configs/`, the relay public key, and the hash manifests of the Task 22, 24 and 26D reports.
  - No repository-wide content search was run.
  - The full test suite consists of synthetic-data tests; this was checked in Task 26C, when no test referenced sealed or Dataset V2 paths.

## Remaining limitations
1. **Only the roles that exist today are covered:** relay record key vs. attribution-result key. The planned checkpoint-witness key (P3) and approval key (P4) have no pins yet. When they are added, they must join the same distinct-role rule. The helpers are reusable, but no rule exists for those roles yet.
2. **Separation is by key identity, not by usage.** An operator who controls both the relay key and the configs could still provision a *different* key they also hold. That is the host-account residual risk from Task 26D, not a code defect.
3. **The relay side (client_attribution) does not apply the canonical-pin check.** A non-canonical relay pin there simply fails to match, so the relay log is untrusted: still fail-closed. The v3 loader now rejects such configs before they are used.
4. **v2 configs (withdrawn)** do not set `relay_key_sha256`. The verifier treats that as a separation failure, so v2 cannot verify any result, which is already the Task 26C behaviour.

Stopped. Scratch-file transfer, backup cleanup and migration were not started.
