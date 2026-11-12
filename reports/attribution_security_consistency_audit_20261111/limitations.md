# Audit limitations

1. **V1 reproducibility was not re-executed.** Re-running needs Dataset V2 reference sequences and Task 24 evidence derived from Dataset V2, both prohibited here. Reproducibility is argued from hash identity with the Task 26A regression run.
2. **The evidence config digest was not recomputed.** Its reference-sequence component depends on Dataset V2. S4 was reproduced with a self-consistent config without reference sequences; the records were identical apart from the digest. The stored digest was confirmed only against the value recorded at assessment time.
3. **Demo-session absence from Dataset V2** relies on the Task 26A post-session manifest verification, not on a fresh check.
4. **Forgery and tampering were demonstrated in memory only.** Nothing was written to the live log, the configs or the keys. Whether a real attacker can reach the correlation result depends on how a future pipeline passes it, which does not exist yet.
5. **Key exposure was assessed from ACLs and mounts.** No attempt was made to read the key from other accounts or containers. Docker Desktop VM-level access, backups and cloud-sync of the working tree were not examined.
6. **Relay compromise was assessed by design review.** The relay was not attacked, fuzzed or exec'd into beyond a read-only `stat`.
7. **The firewall check covers the Docker Desktop VM namespace only** (iptables/nft), not Windows Firewall. Enforcement was never implemented in any layer.
8. **The gate 4 analysis is limited to Cowrie's documented behaviour.** Input is recorded only after authentication. A different emulator or telemetry source could break that inference (F-2).
9. **The 193 synthetic tests ran; the full 499-test suite did not**, because some other suites may read dataset or model artefacts.
