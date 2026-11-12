# Demo session exclusion register (Task 26A)

The Cowrie sessions below were generated deliberately to validate client attribution on 2026-11-11, between 17:19:01Z and 17:19:54Z, after Cowrie log line 21,854. They must be excluded from:
- every dataset build;
- novelty or clustering training and evaluation;
- any statistic about attacker behaviour.

| Cowrie session | Label | Source as seen by Cowrie | Client (verified mapping) |
|---|---|---|---|
| 9441bcce555c | S1 published-path banner (host) | 172.22.0.2:41994 | none (published listener; proxy 172.21.0.1) |
| acc2bad4a442 | S2 test client banner | 172.22.0.2:44200 | 10.250.25.3:38204 |
| d588636ce120 | S3 control client banner | 172.22.0.2:34936 | 10.250.25.4:52586 |
| 3eede5e19e25 | S4 test client shell | 172.22.0.2:59090 | 10.250.25.3:42370 |
| 4542a85f37ec | S5 control client shell | 172.22.0.2:34988 | 10.250.25.4:46198 |

The diagnostic sessions `99732d516898` and `b806554e19b9` remain excluded; see `reports/relay_connectivity_verification_20261111/diagnostic_exclusion.md`.

These IDs were not added to `configs/threat_attribution_v2.json`. That config is pinned by digest in policy 2.1.0, and its `excluded_diagnostic_sessions` list keeps only the two registered diagnostic sessions.
