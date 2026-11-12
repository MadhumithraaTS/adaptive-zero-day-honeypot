# Post-recreation verification plan (to run only after the change is approved and applied)

Read-only checks use the Task 25C-1 method: `docker inspect`, `docker network inspect`, and `wsl -d docker-desktop -u root` + `nsenter` with listing commands only.

| # | Check | Command (read-only unless noted) | Pass condition |
|---|---|---|---|
| V1 | Container state | `docker inspect cowrie-ssh-relay -f '{{.State.Status}} {{.RestartCount}} {{json .Config.Cmd}}'` | `running`, 0 restarts, cmd contains `--port=tcp:2222:interface=172.21.0.2` |
| V2 | Sysctls declared | `docker inspect -f '{{json .HostConfig.Sysctls}}'` | the three `forwarding` keys = `"0"` |
| V3 | Forwarding effective | `nsenter --net=/proc/<relay pid>/ns/net cat /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/conf/{all,default,eth0,eth1}/forwarding` | all `0` |
| V4 | Addresses | `docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}={{$v.IPAddress}} {{end}}'` | `cowrie_cowrie_internal=172.22.0.2`, `cowrie_relay_frontend=172.21.0.2` |
| V5 | Listeners | `awk 'NR>1 && $4=="0A"' /proc/<relay pid>/net/tcp /proc/<relay pid>/net/tcp6` | exactly `172.21.0.2:2222` (`020015AC:08AE`) and `127.0.0.11:<dns>`; **no** `0.0.0.0:2222` |
| V6 | Hardening | `docker inspect -f '{{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} {{.HostConfig.ReadonlyRootfs}} {{.Config.User}} {{.HostConfig.PidsLimit}} {{.HostConfig.Memory}}'`; `/proc/<pid>/status` CapEff | `[ALL]`, `no-new-privileges:true`, `true`, `cowrie`, 64, 134217728; CapEff = 0 |
| V7 | Volumes | `docker inspect -f '{{range .Mounts}}{{.Name}} {{end}}'` | `4492a68c…` and `fba87a59…` still mounted |
| V8 | Cowrie unchanged | `docker inspect cowrie-project` | same ID `0bec5a78b1cb`, StartedAt, RestartCount, `172.22.0.1` |
| V9 | Networks unchanged | `docker network inspect` | same IDs (`8de3b00259f2`, `c94e904b8861`), same options, members {Cowrie, relay} / {relay} |
| V10 | VM isolation intact | `nsenter … iptables-nft-save` (VM) | `DOCKER-INTERNAL` drop rules present; DNAT `127.0.0.1:2223 → 172.21.0.2:2222`; raw `PREROUTING` 2223 drop present |
| V11 | Routes | `nsenter --net=… ip route show` (relay) | unchanged (routes exist; forwarding now off) |
| V12 | Cowrie connectivity (**one** connection; needs explicit approval at that time) | Single TCP connection to `127.0.0.1:2223`: read the banner, send nothing, close (Task 25A method) | Banner `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`; Cowrie `session.connect` from `src_ip 172.22.0.2`; `src_port` = the relay's outbound local port; the session is recorded for exclusion |
| V13 | Config files | `sha256sum` | Only `cowrie/docker-compose.yml` changed (expected new hash recorded). Attribution config `46109a31…`, policies, `behavioural_evidence/` and `threat_assessment/` unchanged |
| V14 | Re-audit | Rerun `reports/relay_routing_isolation_audit_20261111/evidence/audit_readonly.sh` (with new PIDs) | Report diff: forwarding 0, explicit listener, everything else unchanged |

Any failure triggers `rollback_plan.md` §3.
