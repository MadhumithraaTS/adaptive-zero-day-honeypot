# Existing architecture inventory (as implemented)

Source evidence: `reports/behavioural_signature_revalidation_v2_20261111/` (Task 20) and the code itself. No file listed here was changed.

| # | Component | Location | Behaviour | Status on Dataset V2 | Reuse decision |
|---|---|---|---|---|---|
| 1 | Stored signature catalogue | `reports/behaviour_signatures/behaviour_signatures.json` (2026-10-15; 3 signatures, 54 V1 sessions) | One signature per V1 DEC cluster; numeric profile on V1 UNSW-style features (`ackdat`, `ct_*`, `dbytes`, `dinpkt`) | 0 of 8 features exist in V2; all sessions "Insufficient Evidence" (Task 20 class 6) | **Retire** (keep as a historical artefact) |
| 2 | Keyword categories | `scripts/behaviour_pattern_analysis.py` `CATEGORY_KEYWORDS`, `classify_command` | 8 categories; substring match on the lower-cased line | Runs; non-specific (`w` in `/etc/passwd`, `ssh` in `~/.ssh`, `rm ` in `-perm`); up to 71% of a category's hits are substrings | **Redesign** (token matching). Keep the *idea* of command families as descriptive vocabulary |
| 3 | Ordered interpretation rules | same, `infer_session_interpretation` | First-match ladder: any failed login or `credential_attack` → Credential-attack; then persistence → transfer → privilege → reconnaissance; ≥ 2 categories → Mixed; none → Insufficient Evidence | One failed login → "Credential-attack" (126/126 benign failed guesses); "Persistence" 89% benign; "Reconnaissance" 53% benign | **Redesign** (indicator sets, no single-winner ladder). Keep the explicit "Insufficient Evidence" outcome |
| 4 | Signature definition | `scripts/behaviour_signature_generation.py` `build_signatures` | Per DEC cluster: majority label, ≤ 8 numeric features ranked by relative variability, command categories, auth success rate, heuristic "confidence" 0.25–1.0 | Inherits DEC cluster meaning (login outcome and activity volume, Task 17) | **Redesign**. DEC cluster IDs are not identities; the "confidence" is not a probability |
| 5 | Weighted similarity | `scripts/novelty_assessment.py` `compare_session_to_signature` | 0.70 × numeric similarity (raw value z-distance to cluster mean, clipped at 3 SD) + 0.20 × command-category Jaccard + 0.10 × auth agreement | Numeric part tracks Cowrie latency and pacing; all 9 slow-`find` sessions → novel | **Do not reuse for behavioural evidence.** Statistical novelty stays a separate channel (Task 18 baseline) |
| 6 | Outcome classes | same, `assess_session_against_signatures` | Known-like ≥ 0.70 and margin ≥ 0.05; Ambiguous (top two within 0.05, ≥ 0.60); Potentially Novel; Insufficient Evidence | 27% of known-category validation logins "Potentially Novel" | **Replace** with evidence outcomes (`matching_design.md`); novelty reported separately |
| 7 | Reference-only builder | same, `_reference_only_signatures` | Builds signatures from reference sessions only | Correct leakage control; output inherits item 4 | Reuse the **reference/evaluation separation principle** |
| 8 | Threat-scoring dependencies | — | No component converts signatures or novelty to a threat score or action. The novelty assessment outputs categories only | — | Nothing to reuse; any future scoring must consume the new evidence records |
| 9 | Response policy | `configs/defence_policy.json` | Draft: block only with behavioural evidence, ≥ 2 distinct indicators, successful login required, protected networks (incl. 172.19.0.0/16) | **Read by no code**; protected list lacks the current lab network 172.22.0.0/16 | Keep as a **requirements input** (≥ 2 distinct indicators; behaviour not cluster). Not implemented here |
| 10 | Cowrie telemetry actually available | Cowrie JSON log | connect, client version/kex/size, login.success/failed (username, password), session.params, command.input (line text), command.failed (unknown command), file_download / file_upload (when they occur), log.closed (TTY size only), session.closed (duration) | **No command output** in JSON; TTY content not collected; one source IP in the lab | Defines what can be "directly observed" (`evidence_semantics.md`) |

**Reusable as-is:**
- the Cowrie JSON telemetry and the V2 extractor's session reconstruction;
- the explicit "Insufficient Evidence" outcome;
- reference/evaluation separation;
- the policy principle "≥ 2 distinct behavioural indicators, never a cluster".

**Requires redesign:**
- keyword matching;
- interpretation rules;
- signature identity;
- similarity scoring;
- outcome classes.

**Retire:**
- the V1 catalogue.
