# Threat-assessment architecture and integration design (Task 23)

**Date:** 2026-11-11.

**Design and integration-contract review only.**

**Unchanged:**
- `behavioural_evidence/` (SHA-256 identical before and after; `evidence/hashes_*.txt`);
- the catalogue `v2-evidence-1.1`, frozen models and novelty thresholds;
- Cowrie networking, `configs/defence_policy.json`.

**Not done:**
- no policy connected or activated;
- no TTY collection;
- the sealed test and exfiltration data were not accessed;
- nothing was committed.

**No attack probabilities and no zero-day claims.**

| File | Content |
|---|---|
| `integration_contract.md` | Every output field of the package (from code and 5,704 real records), with nine consumption gaps G1–G9 |
| `severity_model.md` | S0–S3, independent of the E1–E3 evidence levels; rationale per interpretation; observed vs inferred rendering |
| `source_attribution_policy.md` | Trusted proxies, relay/NAT exclusions, protected networks, explicit internal CIDRs, attribution states |
| `defence_policy_mapping.md` | Current policy keys → proposed v2 tiers, gates, never-sufficient conditions, manual approval, TTL, audit, rollback |
| `validation_strategy.md` | 19 tests and acceptance gates |
| `limitations.md` | Limitations |
| `dry_run_mapping.py`, `evidence/` | Read-only dry run of the proposed mapping on unchanged Task 22 records; field inventory; example record |

## 1. Integration contract (summary)

**Session record fields:**
- `session_ref`, `src_ip`;
- versions: `catalogue_version`, `telemetry_schema`, `config_digest`, `calibration`;
- `authentication_status` (6 values);
- `behavioural_status`: interpreted / system_discovery_only / insufficient_evidence / indeterminate;
- `abstention_reason`, `evidence_level`;
- `interpretations[]`, each with name, scope, required and supporting action IDs, per-interpretation level and per-indicator outcome;
- `indicators[]`, each with id, category, kind, class, telemetry, limitations, outcome, same-line caveats, and matches (line index, line, command, token, detail, file);
- the indicator-ID lists by kind, `caveats[]`, `timing_context`;
- `statistical_novelty`: separate, passed through unchanged.

**Result-level fields:** `authentication_windows`, `unknown_event_types`.

**Errors:** `SchemaError`, `CatalogueError`, `AttributionError` (raised, never partial output).

**Gaps the assessment must handle** (the package is not changed):

| Gap | Handling |
|---|---|
| G1: no event IDs or timestamps in matches | Resolve against the raw log for audit |
| G2/G3: network scope only via a digest; silent default internal networks | Recompute the digest; NET-1 is `scope unconfirmed` unless an explicit CIDR list is configured |
| G4: session level can be E1 without an interpretation | Use per-interpretation levels |
| G5: CRED-1 mixes secrets with `known_hosts` | Use `matches[].detail` |
| G8: commands through a relay are interpretable but not attributable | Attribution applies to all findings |

## 2. Assessment design

**Findings.** One finding per interpretation. Each finding has:
- observed evidence: lines, tokens, Cowrie outcome events;
- the rule-level interpretation;
- a hedged intent statement;
- evidence level E1–E3 (from the package);
- severity S0–S3 (this layer);
- outcome (`not_observed` unless a Cowrie outcome event exists);
- caveats (annotations only).

**What never contributes to findings, severity or tiers:**
- context indicators;
- caveats (EMU-1, ART-1, SEQ-1, TIME-0);
- novelty;
- timing.

**Abstentions** keep their reason and receive no severity.

## 3. Severity, independent of evidence

| Level | Interpretations |
|---|---|
| S0 | discovery only |
| S1 | repeated authentication failures |
| S2 | guessing then login; privilege reconnaissance; `.ssh`-path credential access; download; history tampering; network probing |
| S3 | credential files (`shadow`, keys, `authorized_keys`, history); download-and-execute; upload; archive-and-upload; persistence modification |

- A weakly supported S3 (E1) can only reach `review`.
- A well-supported attempted upload stays S3 although `not_observed`.

## 4. Attribution and policy

**Attribution.**
- **The lab relay is a trusted proxy with no client mapping**, so every V2 session is `unattributed:trusted_proxy`.
- **Internal networks must be an explicit CIDR list.**
- **Synthetic interaction IDs are never identities.**
- **Stale protected network:** `defence_policy.json` must add `172.22.0.0/16`.

**Policy tiers:** abstain / record / review / propose_for_manual_approval.
- A proposal needs:
  - an S2+ finding at E2+;
  - ≥ 2 distinct action-indicator IDs;
  - a successful login;
  - an attributable, non-protected, non-shared source;
  - a verified config digest;
  - a confirmed network scope where relevant;
  - no errors.
- Manual approval is always required.
- Proposed actions have a TTL, an audit hash chain and an inverse operation.
- A caveat, a novelty score or a single failed login never triggers anything.

## 5. Dry run on V2 validation (proposed mapping; unchanged records)

| Tier | Sessions |
|---|---:|
| abstain | 706 |
| record | 313 (all 229 benign logins) |
| review | 238 (botnet 71, lateral 77, PE 69, recon 21) |
| propose_for_manual_approval | **0** (the lab relay makes every session unattributed) |

Train: abstain 1,817 / record 754 / review 619.

**Checks on the dry run:**
- 0 benign sessions are above `record`.
- The 4 novelty-flagged sessions are placed by behaviour alone.
- The 9 ART-1 sessions are in review via PRIV-1/CRED-1, not the caveat.

**The dry run exposed one design correction**, now in the severity model. A fixed S3 for "credential-material access" would have rated 29 `known_hosts`-only lateral findings as high severity, so credential severity now uses the CRED-1 match `detail`.

## 6. Awaiting approval

Implementing the assessment layer needs approval of:
1. the S0–S3 table, including the CRED-1 refinement;
2. the attribution configuration schema, and correcting the protected networks in a v2 policy file (v1 stays unchanged);
3. the tier gates;
4. the audit and rollback format.

Enforcement stays out of scope until separately approved.
