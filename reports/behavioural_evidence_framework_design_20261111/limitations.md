# Limitations: Task 21 behavioural evidence framework design

1. **Design only.** The framework is not implemented. `evaluate_indicator_design.py` is a prototype written to test the design against existing evidence, not production code. No signature, matcher, scoring logic, extractor, model or defence rule was changed.
2. **Synthetic lab data.** Dataset V2 comes from one generator with disjoint category profiles.
   - **High category specificity is a property of the profiles.** For example, PRIV-1 matches only privilege escalation and EXEC-1 only botnet. That shows the rule matched the commands it targets, not that it generalises to real attackers.
   - **Labels are post-hoc references only.**
3. **Indicators that cannot be validated on approved data:** XFER-2 (upload), STAGE-1 (archive), PERS-1 (persistence modification) and REDIR-1 fire **0** times in train/validation. Their semantics are specified but unvalidated. They are the indicators an exfiltration-like category would exercise, and that category is sealed.
4. **No outcome telemetry.**
   - Cowrie JSON has no command output, and TTY logs are not collected, so almost every outcome is `not_observed`.
   - Collecting TTY content would make more outcomes observable, but Cowrie's emulated output is itself emulator-dependent evidence.
5. **Authentication aggregation is not testable in the lab.**
   - Every lab session arrives from the relay IP 172.22.0.2, so AUTH-1/AUTH-2 were evaluated only with interaction IDs as an oracle source key.
   - In deployment, a source key must be chosen (src_ip, possibly with the client version or HASSH), and shared-IP cases must abstain.
   - The 3 / 300 s parameters are proposals, not calibrated values.
6. **Emulator latency calibration.**
   - ART-1 uses the commands measured as slow on the *training* split (one command).
   - Other slow emulated commands may exist; a deployment needs a per-sensor benchmark of emulated commands.
   - No sealed-test information was used to extend the list.
7. **Residual false positives.** `curl -I` reachability checks trigger NET-1 in 19.7% of benign validation logins. A proposed refinement is listed in `false_positive_requirements.md` (FP-4) and needs approval.
8. **Parsing limits.**
   - `shlex` tokenisation does not expand variables, aliases, subshells, `eval`, base64 or encoded payloads.
   - Obfuscated commands will be under-matched and flagged `parse_degraded` only when quoting fails.
   - Non-ASCII bytes are stripped by this Cowrie build.
9. **Statistical novelty is unchanged.** The design only separates it from behavioural evidence. Task 18–19B limitations of the novelty baseline still apply.
10. **No zero-day claim.** Nothing here measures detection of unseen attacks.
