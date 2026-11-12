# Limitations and operational requirements (Task 24)

## Limitations

1. **The proposal path is demonstrated only synthetically.**
   - Every Dataset V2 session arrives through the relay (`172.22.0.2`, a trusted proxy with no client mapping), so the lab result is **0 proposals** by design.
   - The `propose` tier is exercised only by unit tests and scenario checks that use RFC 5737 documentation addresses as stand-in clients. No lab session was given a manufactured identity.
2. **Severity is a judgement table.**
   - S0–S3 encode potential impact on a real host and are not validated against incidents.
   - Shell history (`.bash_history`) is in the approved secret-file list. That produces 42 validation S3 findings (lateral movement, `cat ~/.bash_history`), so this choice should be confirmed by the project owner.
3. **The successful-login gate is partly inferred.**
   - For relay sessions, `authentication_status` is `indeterminate:shared_source`.
   - Gate 4 then relies on recorded command input, which Cowrie records only after login. On a honeypot, acceptance is configured (`userdb`) and is not a real compromise.
4. **The assessment inherits evidence limits** (Task 22): indicator generalisation is not demonstrated; uploads, archives, persistence and the authentication rules never fire on V2 in the deployable configuration; and parsing has limits.
5. **No proxy mapping support.** Sessions behind a relay stay unattributable until an integrity-protected relay→client mapping exists. `proxy_client_mapping` must be null in this version.
6. **The network configuration is lab-specific.** The protected and internal CIDRs reflect the current Docker Desktop deployment on 2026-11-11. Any topology change requires a new attribution config version and a new policy pin.
7. **Audit timestamps.** The validation run uses a fixed timestamp so that outputs are byte-reproducible. A live run uses the UTC clock, so hashes then differ between runs by design.
8. **Nothing is executed.** There is no enforcement code, no firewall connector, and no approval workflow beyond the `pending` status.

## Secure checkpoint and log-preservation requirements (before any enforcement work)

1. **Append-only storage.** Audit logs are written once per run (the module refuses to reopen an existing file) and must live on storage where the assessment process cannot rewrite earlier bytes (e.g. WORM or object lock, or a separate log host).
2. **External checkpoints.**
   - After each run, `AuditLog.checkpoint()` (entry count and last hash) must be stored **outside** the log's storage domain: a signed message, a separate host, or a printed or notarised digest.
   - Without an external checkpoint, deleting the tail of a log cannot be detected (`verify_chain` without a checkpoint verifies only internal consistency).
3. **Signing.** In production, checkpoints should be signed with a key the assessment host cannot use to rewrite history (separation of duties).
4. **Verification schedule.** `verify_chain(entries, checkpoint)` runs before any approval decision and on a fixed schedule; a failure freezes all proposals.
5. **Retention.**
   - Logs, checkpoints, the attribution config, the policy and the evidence-config digest are retained together for every run.
   - Each proposal must stay reconstructible: session refs, line indices and tokens resolve against the preserved raw Cowrie log (integration contract G1).
6. **Rollback evidence.** Approval, execution and rollback, when they exist in future, must be appended as new entries referencing the original `record_id`. They must never be edits to existing entries.
