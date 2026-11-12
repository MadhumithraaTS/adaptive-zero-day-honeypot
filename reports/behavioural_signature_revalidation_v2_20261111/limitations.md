# Limitations: Task 20 behavioural signature revalidation

## Limitations of the evaluation

1. **Labels are generation intent.** The six categories come from the synthetic generator: one client, one relay IP and category-independent pacing. Agreement with them is not attack-detection accuracy, and nothing here shows that an unseen attack would be detected.
2. **No real-attacker telemetry.** Every result describes Cowrie lab traffic. Keyword behaviour on real attackers (obfuscation, chained one-liners, other languages) is untested.
3. **The stored catalogue was not evaluated against behaviour.** It cannot be: its features do not exist in V2. Classification 6 describes this incompatibility, not the quality of the original signatures.
4. **E3 is a re-instantiation, not the deployed catalogue.**
   - It uses the existing builder and matcher unchanged, but with the Task 17 DEC K = 3 assignments.
   - Task 17 found those clusters encode login outcome and activity volume, so E3 inherits that limitation.
   - A different reference clustering would give different signatures.
5. **Substring-hit rates are diagnostic only.** The "not whole-word" rate comes from a heuristic token test. It measures how often a keyword fires inside another word or path; it does not change any match.
6. **Benign is only a proxy.** Benign sessions stand in for known non-attack behaviour when counting false positives. Benign admin commands (`service`, `systemctl`, `cat /etc/passwd`) are realistic, so some "persistence" or "reconnaissance" hits may be defensible descriptions of activity rather than errors. They are still not evidence of an attack.
7. **Fixed thresholds.** The matcher ran with its default thresholds (0.70 / 0.05 / 0.60). No tuning was done, as required, so the results describe the configured behaviour.
8. **Grouping.** Logged-in sessions are independent (one per interaction). Failed-guess sessions are reported as counts; they are not treated as independent behavioural observations.
9. **No sealed-test or exfiltration data.** Nothing here speaks to the held-out category.

## Limitations of the signatures (findings to address only with approval)

- **Substring keyword matching:** `w`, `ls`, `ps`, `su`, `ssh`, `rm ` and `id` match inside unrelated tokens and paths.
- **Login outcome alone is treated as a credential attack:** any failed login, including a single benign typo, becomes "Credential-attack behaviour". This conflates authentication failure with attack intent.
- **Signatures are defined per DEC cluster:** every signature therefore inherits the cluster's meaning, which on V2 is authentication outcome and activity volume.
- **Numeric matching uses raw feature values against cluster means:** this makes it sensitive to Cowrie execution latency (slow `find`) and generator pacing tails.
- **The catalogue is tied to the V1 feature schema** and has no version or compatibility check, so it fails silently on V2 (every session becomes "Insufficient Evidence").
- **"Download or payload retrieval" describes a command, not an outcome:** in the isolated Cowrie lab no retrieval ever succeeds.
- **No response actions are implemented,** so signature quality has had no downstream effect so far.
