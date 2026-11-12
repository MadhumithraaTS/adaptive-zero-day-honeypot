# Defence-policy mapping (design only; nothing connected or activated)

## 1. Current `configs/defence_policy.json` (read by no code; unchanged)

| Key | Value | Mapping to the new assessment |
|---|---|---|
| `schema_version` | `1.0` | A v2 policy schema is needed (§2); v1 stays as a historical draft |
| `require_successful_login_for_block` | true | Kept: the subject session must have `cowrie.login.success` (a logged-in session with input) |
| `min_distinct_indicators_for_block` | 2 | Kept and made precise: ≥ 2 **distinct action indicator IDs** across the subject's E2+ findings. Context and caveat IDs never count |
| `flag_potentially_novel_for_review` | true | The legacy "Potentially Novel" class no longer exists. Re-mapped: a statistical novelty flag may **annotate** an assessment for review but never creates, raises or triggers anything |
| `protected_networks` | loopback, link-local, `172.19.0.0/16` | **Stale**: must add `172.22.0.0/16` (current lab network) and the sensor's own addresses |

## 2. Proposed handling tiers (v2 draft)

| Tier | Condition (all must hold) | Effect |
|---|---|---|
| `abstain` | `behavioural_status` ∈ {indeterminate, insufficient_evidence} | Stored with its reason; no severity |
| `record` | Only S0/S1 findings, or context only | Logged |
| `review` | Any S2+ finding that does not meet the proposal gate | Analyst queue; novelty or caveats shown as annotations |
| `propose_for_manual_approval` | (a) a finding with severity ≥ S2 at evidence level ≥ E2; (b) ≥ 2 distinct action indicator IDs across S2+/E2+ findings; (c) the subject session has a successful login and input; (d) attribution = `attributable` (or via a configured proxy mapping); (e) not protected and not shared; (f) the evidence-config digest verified; (g) network scope confirmed if the only qualifying finding is NET-1; (h) no unresolved schema, parse or attribution errors | A **proposed** rule is written to a queue; nothing is enforced |

**Never sufficient, alone or in combination with each other:**
- a caveat (EMU-1, ART-1, SEQ-1, TIME-0);
- a statistical novelty score or flag;
- a single failed login (AUTH-0);
- below-threshold failures;
- context indicators.

**Manual approval is always required in this design.** There is no automatic enforcement tier.

## 3. Reversibility, audit and rollback (required before any enforcement work)

- **Proposed action form:** time-limited (default TTL 24 h), subject = one attributable IP or prefix, scope = the sensor only, dry-run by default.
- **Audit log:** append-only JSONL, one entry per decision:
  - assessment ID;
  - session refs and the cited evidence: line indices, tokens, and raw event IDs resolved per contract G1;
  - catalogue version and evidence-config digest;
  - policy version and digest;
  - tier, gate results, approver, timestamps;
  - a hash chain to the previous entry.
- **Rollback:** every proposed rule carries its inverse operation. Expiry and manual revocation are logged. A "revoke all from policy version X" operation is required.
- **Fail-safe:** any error (schema, catalogue, digest mismatch, attribution exception) gives `abstain` with the reason, never a proposal.

## 4. Dry run of the tiers on V2 validation (`evidence/dry_run_summary.json`)

| Tier | Sessions | Breakdown |
|---|---:|---|
| abstain | 706 | |
| record | 313 | all 229 benign logins |
| review | 238 | botnet 71, lateral 77, PE 69, recon 21 |
| propose_for_manual_approval | 0 | |

**Why nothing reaches a proposal:** every session is `unattributed:trusted_proxy` (lab relay). This is the intended behaviour for the lab topology.

**Caveat and novelty checks:**
- The 4 novelty-flagged sessions fall in record (2) and review (2) purely through their behavioural findings.
- The 9 ART-1 (slow `find`) sessions are in review because of their PRIV-1/CRED-1 findings, not the caveat.
