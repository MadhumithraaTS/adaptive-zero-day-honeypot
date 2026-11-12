# Safety test plan (to run only after implementation is approved)

**Environment:** the `demo_ingress` network with the dedicated test client and the control client. Synthetic unit fixtures cover components without containers.

**Data:** no sealed test or exfiltration data, and no historical dataset modification. Dataset V2 records are used only to prove that they are **never** attributable or enforceable.

| # | Test | Setup | Expected result |
|---|---|---|---|
| S1 | Benign traffic | Control and test clients run benign sessions (`w`, `uptime`, `service ssh status`) | Tier `record`; no proposal; no rule |
| S2 | Unattributable relay sessions | (a) Dataset V2 records; (b) a live connection via `127.0.0.1:2223` | (a) `unattributed:trusted_proxy`, 0 proposals; (b) no correlated mapping to a client identity, no proposal |
| S3 | Missing or ambiguous mapping | Delete one mapping record; duplicate an upstream port inside the window | `mapping_missing` / `mapping_ambiguous`; gate 5 fails |
| S4 | Spoofed identity | The client sends `X-Forwarded-For`-like text as SSH payload; a forged unsigned mapping record | Identity unchanged (socket peer only); forged record → `mapping_untrusted` |
| S5 | Shared NAT source | Test client address added to `shared_source_cidrs` in a test config | `shared_source`; no proposal |
| S6 | Protected addresses | Proposal or rule targeting 172.22.0.1, 172.21.0.1, 127.0.0.1 | Assessment `protected`; the relay refuses the rule even if signed |
| S7 | Target outside the allowlist | Signed, approved rule for the control client | Relay refuses (`rule_rejected:allowlist`); no restriction |
| S8 | Expired proposal | Approval after `proposal_expires_utc` | `approval_invalid:expired`; no rule |
| S9 | Duplicate or conflicting approval | Second approve, or reject after approve, for one `proposal_id` | `approval_duplicate`; exactly one decision effective |
| S10 | Invalid approval identity | Unknown key, revoked key, the assessment identity, bad signature | `approval_invalid:<reason>`; no rule |
| S11 | Broader-than-proposed approval | Approval with a longer TTL or a wider target | Rejected |
| S12 | Incorrect configuration digest | Change attribution/policy/allowlist after the proposal | Gate 7 fails or `approval_invalid:config_changed`; no rule |
| S13 | Failed rule deployment | Corrupt rule signature; unwritable restriction volume | `deployment_failed`; no restriction; no retry without new approval |
| S14 | Positive enforcement (the demonstration) | Approved proposal for the test client | Test client is closed at accept with no Cowrie session; control client is unaffected; audit `rule_deployed`, `rule_verified` |
| S15 | Rollback | Operator revoke | Test client connects again; `rule_rolled_back`; rollback verified |
| S16 | Failed rollback | Make the rule file undeletable | `rollback_failed`; rule lapses at TTL; `rule_expired` and `expiry_verified` |
| S17 | Expiry | Wait past TTL | Relay ignores the rule; test client connects; no automatic renewal |
| S18 | Audit tampering | Edit, delete, reorder or truncate controller, mapping or assessment logs; forge a checkpoint | Detected; all approvals and deployments frozen |
| S19 | Crash recovery | Kill the controller and relay during an active rule | Restart, reconcile, `orphan_rule_removed` if applicable; no rule outlives TTL |
| S20 | Novelty, caveat or single failed login | Fixtures with high novelty, ART-1/EMU-1, a single AUTH-0 | Never a proposal or rule |

**Acceptance:**
- S1–S20 pass.
- No rule ever affects an address outside the allowlist.
- No Cowrie or `cowrie_internal` configuration differs from its pre-test hash.
- Every state change is in a verified chain.
