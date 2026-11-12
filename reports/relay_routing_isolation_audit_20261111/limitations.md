# Limitations (Task 25C-1)

1. **No probes.** No packet was sent and no connection was made (prohibited). Every reachability statement is derived from routing tables, sysctls, firewall listings and counters: observed configuration, not a demonstrated path or a demonstrated block.
2. **The hop-3 drop is inferred for this packet type.** That a relay-forwarded frame with a 172.21.x source would hit `DOCKER-INTERNAL` is inferred from the rule order, from br_netfilter being active (`bridge-nf-call-iptables = 1`), and from the 192,466-packet counter on the adjacent bridge-accept rule. No such frame was generated, so the drop counter (0) cannot confirm it.
3. **Point in time.** Readings were taken on 2026-11-11 around 16:49 UTC (relay pid 2890, Cowrie pid 2837, engine pid 165). Docker Desktop restarts, upgrades or network recreation can change bridge names, rules and sysctls.
4. **Method.**
   - Inspection ran as root in the `docker-desktop` WSL distribution, using `nsenter` into the containers' network namespaces and the engine's mount namespace for the `iptables-nft-save` and `nft` binaries.
   - These were listing commands only, and nothing was written.
   - Reading the container namespaces from outside does not change them.
   - The engine-namespace view is Docker Desktop's internal VM. Other VM components (e.g. `services1`, 192.168.65.7) were not audited.
5. **Other senders.** Hop 1 lists the frontend network's members and the VM routes. It does not audit every process in the VM, or the Windows host, which could alter VM routes only with administrative control of Docker Desktop.
6. **The emulator control mentioned** (Cowrie's `BLOCKED_IPS`) is from Task 13 and was not re-inspected here.
7. **Excluded:** diagnostic session `99732d516898`, from everything. No Dataset V2 or sealed-test data was used.
