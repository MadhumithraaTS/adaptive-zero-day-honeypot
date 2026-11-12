# Limitations: Task 22 behavioural evidence framework

1. **No generalisation is demonstrated.** Dataset V2 profiles use largely disjoint command families. Every action indicator fires in at most 2 of the 6 categories:
   - PRIV-1: privilege escalation only;
   - EXEC-1: botnet only;
   - NET-1: lateral movement only;
   - CRED-1: lateral movement and privilege escalation.

   This shows that the rules match the commands they target in this lab. It does not show they would recognise other tools, phrasings or real attackers.
2. **Nine entries never fire on train/validation** and are validated by unit tests only:
   - AUTH-1 and AUTH-2 in the deployable configuration;
   - XFER-1-OK, XFER-2, XFER-2-OK;
   - STAGE-1, PERS-1;
   - REDIR-1, PRIV-2.

   Upload and archive behaviour belongs to the held-out exfiltration profile, which was not accessed. No V2 training profile modifies persistence, writes output to files, wraps a command in `sudo`, or produces a Cowrie download/upload event.
3. **Authentication rules are untestable in the lab topology.**
   - Every session arrives from the relay 172.22.0.2, so the deployable rule returns `indeterminate:shared_source` for all 4,447 sessions.
   - The oracle diagnostic (synthetic per-interaction sources) checks only the rule mechanics: it fires exactly on brute force, the only profile configured with ≥ 3 failures.
   - The 3 / 300 s parameters are a policy choice, not calibrated values.
4. **NET-1 depends on network configuration.**
   - With default internal networks (RFC 1918 and similar), `ping` to the lab's documentation-range "LAN" hosts is NET-0. Only `nc -z` / `nmap` count, giving 49 lateral sessions.
   - The lab address-plan run, which uses internal hosts from the profile file, gives 66. That configuration is generator-derived and is reported as a sensitivity run only.
5. **Outcomes are mostly unobservable.**
   - Cowrie JSON has no command output, so almost every outcome is `not_observed`.
   - `observed_failure:emulator_rejected` describes Cowrie (for example, `./payload` is unknown to it), not the attacker.
   - TTY collection was not introduced.
6. **Calibration is training-derived and sensor-specific.**
   - The ART-1 list has one command (`find / -name id_rsa 2>/dev/null`), measured on the training split.
   - The TIME-0 reference uses the training inter-input gap p99.
   - Other slow emulated commands may exist; a deployment needs a sensor benchmark. Sealed-test information was not used.
7. **SEQ-1 on the training split is in-sample.** The reference store is the training split itself; validation (50 of 600 logins, 38 of them brute force) is the meaningful figure.
8. **Parsing limits.**
   - No expansion of variables, aliases, `$()`, backticks, `eval`, base64 or `sh -c '...'` payloads.
   - Obfuscated commands are under-matched. Quoting failures are flagged `parse_degraded`, and substitutions are flagged as caveats.
9. **Some reasonable forms are not matched** (false negatives by design of the catalogue): for example `ls -la /usr/bin | grep rws` (a SUID search via `ls`), or credential files with non-standard names.
10. **Evidence levels describe evidence counts, not risk.**
    - E1/E2 are not probabilities and must not be thresholded as attack likelihood without calibration on independent labelled data.
    - In the oracle diagnostic, brute-force logins reach E3 because AUTH-2 includes an observed `login.success`. That is a successful login, not a successful attack.
11. **Not connected to anything.** No threat scoring, defence policy or automated response consumes these records yet.
