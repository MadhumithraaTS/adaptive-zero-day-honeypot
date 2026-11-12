# Source attribution and network-scope policy (proposed)

## 1. What Cowrie actually records

- `src_ip` / `src_port` on Cowrie events is the **TCP peer of the Cowrie process**.
- **In this lab**, every client connects to `127.0.0.1:2223` on the host, and the `cowrie-ssh-relay` container (Twisted port-forward) opens a new connection to Cowrie. Every event therefore shows `src_ip = 172.22.0.2`:
  - 4,447 of 4,447 V2 train/validation sessions;
  - `authentication_status = indeterminate:shared_source` for all of them in the Task 22 primary run.
- **No original-client address reaches Cowrie.** SSH has no forwarding header, and the relay does not log a mapping. Whether this Cowrie build supports a PROXY-protocol listener was **not verified** and must not be assumed.

## 2. Configuration (assessment-side; supplied with the `EvidenceConfig`)

| Setting | Required | Meaning | Lab value |
|---|---|---|---|
| `trusted_proxies` | yes (may be empty) | Addresses whose connections are relayed. Their `src_ip` is **never** an attacker identity | `["172.22.0.2"]` |
| `attribution_source_for_trusted_proxies` | yes | How the true client is recovered for a trusted proxy: `none`, or a named, integrity-protected mapping (e.g. a relay connection log keyed by relay-side `src_port` and time) | `none` |
| `shared_sources` (relay/NAT exclusions) | yes (may be empty) | Known carrier-NAT, corporate egress, VPN or scanner-farm addresses: attributable as a *network*, never as one actor | `[]` |
| `protected_networks` | yes | Addresses that must never be the subject of an action (sensor, Docker networks, management, loopback) | `127.0.0.0/8, ::1/128, 169.254.0.0/16, fe80::/10, 172.19.0.0/16, 172.22.0.0/16` |
| `internal_networks` | yes, **explicit** | CIDR allowlist that makes a probe target "internal" for NET-1 | Deployment-specific. The lab's documentation-range "LAN" addresses are generator placeholders, not a real network |
| `evidence_config_digest` | yes | Must equal `EvidenceConfig.digest()` of the configuration that produced the records | recomputed |

The current `configs/defence_policy.json` lists `172.19.0.0/16`, but the lab network is now `172.22.0.0/16` (Task 14A). Its protected list is stale and must be corrected before any use.

## 3. Attribution states (assessment output)

| State | Condition | Consequence |
|---|---|---|
| `attributable` | `src_ip` present, not a trusted proxy, not shared, not protected | May be a policy subject (subject to all other gates) |
| `attributable_via_proxy_mapping` | Trusted proxy **and** a configured mapping yields the client address | Treated as `attributable`; the mapping evidence is recorded |
| `unattributed:trusted_proxy` | Trusted proxy without a mapping | Review only; **no action subject exists** |
| `shared_source` | In `shared_sources` | Review only; at most network-level observation |
| `protected` | In `protected_networks` | Never a subject; alert the operator if severity ≥ S2 |
| `unattributed:no_source` | `src_ip` null | Review only |

These states apply to **every** finding, not only authentication rules: commands typed through the relay are behaviourally interpretable but not attributable.

## 4. Authentication rules

- AUTH-1/AUTH-2 are computed by `behavioural_evidence` from `src_ip` with its own `relay_sources`. The assessment must pass the same addresses as `relay_sources` that it lists in `trusted_proxies` ∪ `shared_sources`, and it verifies this through the config digest.
- **Never** substitute synthetic identities. The Task 22 "oracle" interaction-ID run was a mechanics diagnostic and must not feed assessment or policy.
- A single failed login (AUTH-0) is context, and below-threshold failures are `record` only.

## 5. Network scope

- If `internal_networks` is not explicitly configured (the package default is in use), every NET-1 finding is marked `network_scope: unconfirmed`. It is reported at its severity, but it is **not policy-eligible**.
- A NET-1 finding whose target is in `protected_networks` remains a finding: probing the sensor's own infrastructure is notable. It still never makes the protected address a subject.
- `curl -I` and probes to non-qualifying targets are NET-0 (context) in the package and receive no severity.
