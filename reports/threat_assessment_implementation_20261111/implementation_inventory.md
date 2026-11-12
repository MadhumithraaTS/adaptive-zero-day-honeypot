# Implementation inventory (Task 24)

## New module `threat_assessment/` (repository root, beside `behavioural_evidence/`)

| File | Responsibility |
|---|---|
| `__init__.py` | API: `ThreatAssessor`, `assess_sessions`, `AuditLog`, `verify_chain`, config loaders, errors; `ASSESSMENT_VERSION = "threat-assessment-1.0.0"` |
| `config.py` | `AttributionConfig` (schema `threat-attribution-config-1`) and `PolicyConfig` (schema 2.0). All lists are explicit. `internal_cidrs` must be non-empty. `source_field` must be `src_ip`. `proxy_client_mapping` must be null (unsupported). Policy conditions cannot be relaxed (thresholds ≥ S2 / E2 / 2 indicators, all `require_*` true), enforcement must be `disabled`, manual approval true, and the proposed action must be `dry_run` with a TTL and an inverse. `canonical_digest()` is SHA-256 of canonical JSON |
| `severity.py` | S0–S3 table per interpretation. `credential_severity()`: S3 only for a **content operation** (`cat`, `less`, `cp`, `scp`, `tar`, `base64`, …) on, or **`find -name`** of, a secret file (`shadow`, `gshadow`, private keys `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`, `authorized_keys`, `.bash_history`); otherwise S2 (`known_hosts`, `config`, `.pub`, `ls` of a path). It never reads the evidence level |
| `attribution.py` | `attribute()`: uses only the record's Cowrie-observed `src_ip`. States: `attributable`, `unattributed:no_source`, `unattributed:invalid_source`, `unattributed:trusted_proxy`, `protected`, `shared_source`. Forwarded-for style fields are listed in `ignored_untrusted_fields` and never used |
| `assessment.py` | `ThreatAssessor(attribution, policy, evidence_config)`. Checks: policy catalogue = installed `behavioural_evidence` catalogue; the policy pins the attribution digest; evidence relay list ⊇ attribution relays; evidence internal networks = explicit internal CIDRs; authentication rule = 3 / 300 s. `assess(record)` deep-copies the record, validates the contract (missing fields, catalogue, schema, levels), and builds one finding per interpretation: interpretation-specific level, severity and basis, `attempted`, per-indicator `outcome`, `success_observed` (only `observed_success`), cited lines and tokens, hedged intent, caveat annotations, and attribution (per finding). It then evaluates the 8 conjunctive gates and the tier, plus a proposed action (dry-run, inverse, `manual_approval: pending`, `execution: not_executed`), and records versions and digests |
| `audit.py` | `AuditLog`: append-only JSONL (refuses an existing file), hash chain (genesis = 64 zeros), injectable clock, `checkpoint()`. `verify_chain()` detects modification, deletion, insertion, reordering, sequence gaps, recorded execution, and (with a checkpoint) truncation or extension |
| `errors.py` | `AssessmentConfigError`, `AssessmentInputError` |

**Dependency:** imports `behavioural_evidence` only for `CATALOGUE_VERSION` and `SUPPORTED_TELEMETRY_SCHEMAS`. It does not modify it.

**Tests:** `tests/test_threat_assessment.py`, 61 tests. The full suite has 447 passed (`test_results.txt`).

## New configuration files (policy v1 preserved)

| File | Content |
|---|---|
| `configs/threat_attribution_v1.json` | Version 1.0.0, canonical digest `9353fbdd…6611ea0`. Verified by read-only `docker network inspect` (`evidence/deployment_network_inspection.txt`): trusted proxy and relay `172.22.0.2`; no proxy mapping; shared sources none; protected `127.0.0.0/8`, `::1/128`, `169.254.0.0/16`, `fe80::/10`, `172.19.0.0/16` (`cowrie_default`, legacy), `172.21.0.0/16` (`cowrie_relay_frontend`), `172.22.0.0/16` (`cowrie_cowrie_internal`); internal `172.21.0.0/16`, `172.22.0.0/16`. RFC 5737 generator "LAN" placeholders are deliberately not internal |
| `configs/defence_policy_v2.json` | Policy 2.0.0, canonical digest `92e33428…3680712`. Enforcement `disabled`; manual approval required; pins the attribution digest; the 8 proposal conditions; never-sufficient list; dry-run `block_source_ip` with TTL 86,400 s and inverse `unblock_source_ip`; corrected protected networks |
| `configs/defence_policy.json` (v1) | **Unchanged** (`evidence/hashes_before.txt` = `hashes_after.txt`); rejected by `PolicyConfig` (schema 1.0) |

## Gates (all must hold for `propose`)

| # | Gate | Implementation |
|---|---|---|
| 1 | S2 or higher | Any finding with severity ≥ `min_finding_severity` |
| 2 | Interpretation-specific E2+ | An S2+ finding whose **own** `evidence_level` ≥ E2 (the session level is only a reference field) |
| 3 | ≥ 2 distinct action indicators | Union of `supporting_action_indicators` over the qualifying (S2+ and E2+) findings |
| 4 | Successful login | `authentication_status` ∈ {`success_without_repeated_failures`, `repeated_failures+success`}, or recorded command input (Cowrie records input only after login). The basis is stored |
| 5 | Attributable source | Every qualifying finding's attribution is `attributable` |
| 6 | Not protected or shared | The session attribution is neither `protected` nor `shared_source` |
| 7 | Verified configuration digests | Record `config_digest` = recomputed `EvidenceConfig.digest()`, and all configuration checks true |
| 8 | No processing or validation errors | Any error gives `abstain` |

**Tier order:**
1. any error → `abstain`;
2. evidence `indeterminate` / `insufficient_evidence` → `abstain`;
3. no S2+ finding → `record`;
4. all gates → `propose`;
5. otherwise → `review`.

## Report-directory script

`validate_assessment.py` runs evidence generation (unchanged package, explicit configuration), assessment, audit logs and checks, tamper simulations, synthetic attribution scenarios and the CSV deliverables.
