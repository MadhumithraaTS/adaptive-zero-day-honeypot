# Limitations

1. **No deployment attribution-result key exists.**
   - Key generation awaits approval of the migration plan (`key_custody.md`), so the deployed v3 config is `pending_provisioning` and every relay session is unattributed. This is fail-closed.
   - Real-data validation used an ephemeral in-memory key and validation-only copies of the configs (`evidence/validation_fixtures/`). Its signed results cannot be re-signed later; they can only be re-verified with the saved public key.
2. **The operator account is not separated from signing keys.**
   - `madhu` can read the relay key (Docker Desktop file sharing needs that) and can reach every Docker volume through `\\wsl.localhost` and `docker-users`.
   - The separation achieved is process-level: the assessment runs in a container without keys, socket or network. OS-level separation needs a second account, a second host or a keystore.
3. **The relay key is unchanged.** It is still a plaintext PKCS#8 file in the repository tree; it is git-ignored and now ACL-restricted. No rotation, revocation or backup procedure is in force yet; they are designed, not implemented.
4. **Tail deletion is detectable only against a checkpoint.**
   - No checkpoint store is deployed yet; it needs the attribution key.
   - Without one, deleting the newest records is still undetectable; it is reported as `tail: unattested`.
   - Even when deployed, checkpoints are independent of the relay but not of the operator unless copied off-host.
5. **Gap handling is conservative.** A session whose open-record window touches a relay-log gap is withheld, even when its own records verify. A damaged line can therefore cost attribution for neighbouring sessions.
6. **Fail-closed batches.** One invalid document among the supplied results fails gate 7 for the whole batch, so an attacker who can inject a bad document can prevent proposals (a denial of service). It cannot create a proposal.
7. **Time is self-asserted.** Relay `written_utc` and signer `issued_utc` come from the signers' clocks, so a compromised signer can backdate within key validity.
8. **Authentication evidence for relay sessions depends on Cowrie session IDs.** `login.success` has no `src_port`. Correlation rests on the session ID plus source, sensor and time checks; ambiguity stays indeterminate.
9. **Direct-source sessions under policy 2.1 need an evidence success status.** `below_threshold` and `repeated_failures` (without `+success`) never satisfy gate 4, even if a login occurred. This is stricter than before, and intentional.
10. **The pinned image contains third-party test keys** (Twisted and `cryptography` test fixtures). They are public and unrelated to this project, but a broad key scan will flag them. The runner scans only its own mounts.
11. **Exclusions cover data preparation, not the ML notebooks.** They are wired into the dataset builder and the V2 feature extractor. The frozen ML notebooks were not modified (they refuse to re-split), and the legacy V1 extractor (`scripts/extract_features.py`, which has your own uncommitted changes) was not touched.
12. **Leftover validation scratch files.** `cowrie/assessment_work/{input,output}` still holds copies of the validation inputs and outputs (no secrets). A recursive delete was blocked by a safety check and left for the operator; the authoritative copies are in `evidence/`.
13. **Test files changed on purpose.** Task 26A tests were updated where the remediation deliberately changes semantics (F-1 and F-6); see `security_test_results.md`.
