# Cleanup verification

## 1. What was created

**Nothing.** There was no network, container, endpoint, file inside a container, or connection. The only commands run inside containers were read-only `docker exec … python3` reads of `/proc` and directory listings in the relay (`evidence/preflight_inspection.txt`).

## 2. Cleanup and restoration plan (defined for a future, approved run; not executed)

1. `docker rm -f cowrie-demo-test-client cowrie-demo-control-client`.
2. `docker network disconnect cowrie_demo_ingress cowrie-ssh-relay`.
3. `docker network rm cowrie_demo_ingress`.
4. Verify the relay container ID (`8d3bafb35f38…`), `StartedAt` (`2026-11-10T12:30:31.406935186Z`), `RestartCount` (0), command, and endpoints (`cowrie_internal` 172.22.0.2 / `de:ee:4b:cd:e2:ad`; `relay_frontend` 172.21.0.2 / `62:7a:84:74:cf:15`) are unchanged.
5. Verify Cowrie (`0bec5a78b1cb…`, 172.22.0.1) and the network list and IDs are unchanged, and that the published port is still `127.0.0.1:2223`.
6. Verify the hashes of `cowrie/docker-compose.yml`, `configs/threat_attribution_v1.json` and `configs/defence_policy_v2.json` are unchanged.
7. Exclude the demo's Cowrie session(s) from all datasets, as for `99732d516898`.

## 3. Verification performed now (`evidence/state_after_preflight.txt`)

| Item | Before (Task 25B / preflight) | After | Unchanged |
|---|---|---|---|
| Relay ID / start / restarts | `8d3bafb35f38` / 2026-11-10T12:30:31.406935186Z / 0 | same | yes |
| Relay addresses | 172.22.0.2 (`cowrie_internal`), 172.21.0.2 (`relay_frontend`) | same | yes |
| Cowrie ID / start / restarts / address | `0bec5a78b1cb` / 2026-11-10T12:30:30.630598884Z / 0 / 172.22.0.1 | same | yes |
| Docker networks | bridge, cowrie_cowrie_internal `8de3b00259f2`, cowrie_default, cowrie_relay_frontend `c94e904b8861`, et-ai_default, host, none, rezumy_default | same; no `cowrie_demo_ingress` | yes |
| Containers | 10 (2 running) | same 10 | yes |
| Config hashes | compose `cd84da48…`, attribution `46109a31…`, policy v2 `24fd8cf4…` | same | yes |
