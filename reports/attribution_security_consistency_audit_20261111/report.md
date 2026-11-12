# Task 26B — Attribution Security and Threat Proposal Consistency Audit

Date: 2026-11-11 · Type: read-only audit · No source, config, key or policy changes · No new sessions · No defensive actions · Nothing committed

## Verdict

- **S4 proposal: eligible.** Each policy condition was evaluated independently and all are satisfied, including the stricter Task 23 wording of the login condition. No eligibility defect was found for S4.
- **Two high-severity weaknesses were found.** Neither has been exploited and neither changes the S4 result. Both must be fixed before any enforcement controller is built:
  - **F-1:** the assessor trusts an unsigned correlation result.
  - **F-3:** the relay signing key is readable and modifiable by every local Windows user.

## Findings

| ID | Severity | Area | Finding |
|---|---|---|---|
| F-1 | **High** | Attribution trust boundary | `ThreatAssessor.assess()` accepts the correlation result as a plain dict. It checks only that the dict carries the attribution config digest, which is public. `attribute()` does not re-check the client registry, the relay record hash or the enforcement allowlist. A forged result (in memory, never written) produced: S5 (control client) → **propose against 10.250.25.3**, and S4 → **propose against unregistered 203.0.113.9**. Forging the control client's own address is still blocked (`enforcement_excluded`), as is forging a protected address |
| F-3 | **High** | Key custody | The private key file inherits NTFS ACLs: *Authenticated Users: Modify* and *BUILTIN\Users: Read & Execute*. Any local account or process can read it, including the assessment engine, which runs as the same user. The "assessment has no signing key" property holds only at code level |
| F-2 | Medium | Eligibility consistency | Gate 4 (successful login) is satisfied by recorded command input; it does not depend on `authentication_status`. Relay sessions are always `indeterminate:shared_source`. An indeterminate status on its own never satisfies gate 4 (verified). The Task 23 design wording was "has `cowrie.login.success`"; Task 24 documented the input basis. S4 satisfies both |
| F-4 | Medium | Record integrity | Deleting the newest records cleanly cannot be detected; every truncated prefix still verifies. The effect is fail-safe (sessions lose attribution), but the deletion is silent |
| F-5 | Medium | Key / relay | A compromised relay can sign arbitrary valid records. `written_utc` is self-asserted, and there is no rotation, revocation or external witness |
| F-6 | Medium | Availability | Verification is all-or-nothing: one corrupted line removes attribution for every session in the log. This fails safe, but anyone who can write to the log can trigger it |
| F-7 | Low–Medium | Regression / exclusions | Exclusion of the diagnostic and demo sessions is documentary only. No code in `dataset_builder/`, `ml_pipeline/` or `scripts/` filters them. The live Cowrie log contains all of them, so a future dataset build would include them unless filtered by hand |
| F-8 | Low | Config consistency | The `protected_networks` and `enforcement_excluded_sources` fields in policy 2.1.0 are not read by any code. The authoritative lists are in the attribution config, which the policy pins by digest. The two copies could silently diverge |
| F-9 | Low | Record storage | The records directory is writable by any authenticated host user and by the relay. This enables F-4 and F-6; modification and insertion are still detected |
| F-10 | Info | Reproducibility | The reference-sequence component of the evidence config digest cannot be recomputed without Dataset V2. Reproduction relied on hash identity plus a self-consistent re-run |

## Area summaries
- **Authentication and eligibility:** `proposal_eligibility.md`, `authentication_analysis.md`.
  - Verified client attribution cannot influence authentication status. The evidence engine sets that status before assessment and depends only on `src_ip`. Records are deep-copied and unchanged after assessment.
  - S4 was reproduced:
    - the correlation is byte-identical;
    - the evidence re-run is identical except for the digest;
    - the self-consistent re-assessment gives propose with no failed gate, subject 10.250.25.3, and findings identical to the stored ones.
- **Key security:** `key_security.md`. Covers F-3 and F-5, with minimum custody improvements (recommended only, not implemented).
- **Record integrity:** `audit_integrity.md`.
  - Rejected: altered records, altered records with the hash recomputed, reordered, replayed, duplicate-appended, expired-age and outside-key-validity.
  - Tail truncation is undetected (F-4); the external signed-checkpoint requirement is documented there.
- **Regression:** `regression_results.md`.
  - The `behavioural_evidence` package (9/9 files) and `severity.py` are unchanged.
  - All 50 Task 26A artefacts still match.
  - V1 reproducibility (4,447/4,447) still holds by hash identity; it was not re-executed, because that would read Dataset V2-derived inputs.
  - Diagnostic sessions are excluded from attribution.
  - The control client is never a subject.
  - No enforcement has occurred: no firewall rules for the demo clients, and audit entries show `not_executed`.
  - Synthetic tests: 193 passed.
- **Limitations:** `limitations.md`.

## Method
- `audit_checks.py` reads only:
  - the Task 26A captured evidence and outputs (hash-checked against the Task 26A manifest: 50/50);
  - configs;
  - the Task 22 calibration file;
  - earlier SHA256SUMS manifests.
- All tampering, forging and gate probes act on in-memory copies only.
- Outputs: `audit_results.json`, `test_results.txt`, `live_state.txt`.
- Live checks were read-only: `icacls`; `docker inspect`; `stat` inside the relay; `iptables -S` / `nft list` through `nsenter`.

Stopped after the audit. Awaiting review before human approval and dynamic response.
