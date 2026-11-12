# Limitations: Task 23 threat-assessment design

1. **Design only.**
   - No threat scoring, policy loader or enforcement exists.
   - `dry_run_mapping.py` is a read-only illustration of the proposed mapping on existing records, not an implementation.
2. **Severity is judgement, not measurement.** S0–S3 encode potential impact on a real host, justified per interpretation. They are not validated against incident outcomes and must be reviewed by the project owner.
3. **The lab cannot exercise attribution.** Every session arrives through the relay, so the design's attributable path, and therefore any proposal, cannot be demonstrated on V2. It needs either a real deployment or a relay that logs an integrity-protected client mapping (not available; PROXY-protocol support in this Cowrie build is unverified).
4. **Severity inherits indicator limits.** Severity only describes the indicators the package matched: generalisation limits, unvalidated indicators (uploads, archives, persistence) and parsing limits all carry over (Task 22 `limitations.md`).
5. **Honeypot semantics.**
   - A "successful login" is configured acceptance (`userdb`), so E3 from AUTH-2 is emulator-dependent.
   - Severity describes what the attempt would mean on a real system; the honeypot itself was not harmed.
6. **Contract gaps** (G1–G9 in `integration_contract.md`) must be handled by the assessment layer: event IDs are absent from matches, network scope is visible only through the config digest, and default internal networks apply silently.
7. **The policy file is stale.** `configs/defence_policy.json` lists the former Docker network. It was not modified (out of scope).
8. **Interpretation coverage.** Of 11 interpretations, 5 never occur on V2 train/validation in the deployable configuration: repeated failures, guessing then login, upload, archive-and-upload, persistence. Their tiers are validated only by fixtures.
9. **No zero-day or detection-accuracy claim.** Tiers describe evidence handling, not attack-detection performance.
