# Limitations (Task 25C-3)

1. **End-to-end proxy function is not yet re-verified.** V12 (one controlled connection through `127.0.0.1:2223`) was not performed, as instructed. The listener on `172.21.0.2:2222`, the unchanged DNAT `127.0.0.1:2223 → 172.21.0.2:2222` and the `ProxyFactory` start-up log indicate the published path should work, but no session has proved it since recreation.
2. **Blocking conclusions are configuration-based.** No probe was sent, so "would not forward" and "refused on 172.22.0.2:2222" are inferred from sysctls and socket tables.
3. **The container ID changed** (`8d3bafb35f38` → `54b551d98e1a`), as expected for a command or sysctl change. Anything that referenced the old ID must use the new one. The addresses that the attribution config and evidence `relay_sources` depend on are unchanged.
4. **Not pinned.** Addresses were retained through IPAM reassignment, not pinning. A future recreation must be verified again (`reports/relay_hardening_design_20261111/network_preservation.md`).
5. **Dependencies remain:** Docker-managed isolation (`DOCKER-INTERNAL`, `bridge-nf-call-iptables`), the weak-host residual, and the absence of routes on other hosts.
6. **DNS ports re-randomised.** The Docker DNS loopback ports (`127.0.0.11:*`) changed on recreation, which is normal.
7. **The backup contains copies of configuration and inspections only.** Cowrie's log was not copied into it; only its line count and hash were recorded. Diagnostic session `99732d516898` stays excluded from all datasets and evaluations. Dataset V2 and sealed-test data were not accessed.
