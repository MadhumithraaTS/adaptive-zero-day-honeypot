# False-positive requirements and evaluation of the proposed design

Each requirement is checked against Dataset V2 train/validation using `evaluate_indicator_design.py` (a design prototype; `evidence/`). Benign sessions are used as the known non-attack reference, not as ground truth for novelty.

| # | Requirement | Old behaviour (Task 20) | Proposed design on V2 (validation unless stated) | Met? |
|---|---|---|---|---|
| FP-1 | One failed login must not be "credential-attack behaviour" | 126/126 benign failed guesses (train 302/302) labelled credential attack | AUTH-0 is context only. AUTH-1 (≥ 3 failures/source/300 s) fires on **0 of 126** benign failed sessions (0/302 train); the maximum per benign interaction is 1 failure | **Yes**, with qualification: AUTH-1 is only evaluable with an oracle source key (lab has one source IP). Its clean separation reflects the generator's `failed_attempts` settings, so it is generator-dependent evidence |
| FP-2 | No substring matches inside paths or unrelated words | `w`, `ps`, `su`, `ssh`, `rm ` fire inside other tokens; up to 71% of a category's hits | Token, flag and path-component matching. 240 validation lines (551 train) previously "credential_attack" match no credential indicator (e.g. `service ssh status`, `cat /etc/passwd \| grep sh`) | **Yes** (by construction; verified on the same lines) |
| FP-3 | No interpretation from one context indicator | "Reconnaissance" 53% benign; "Persistence" 89% benign | DISC-1 (100% of benign logins) and PERS-0 (63% benign) are context. "Persistence modification attempt" fires **0** times (no write commands exist in V2); benign gets only "system discovery only" (184) | **Yes** |
| FP-4 | Benign sessions must not receive attack-implying interpretations | 79/229 (34.5%) benign logins | **45/229 (19.7%)** benign logins get "network probing attempt", all from `curl -I http://<mirror>/` (HTTP HEAD reachability checks). 0 benign in every other action interpretation | **Partially.** Residual false-positive condition documented. Proposed fix for approval: restrict NET-1 to internal or scan targets and scanning tools, and treat `curl -I` as a context "HTTP reachability check". Not applied, to avoid tuning on labels |
| FP-5 | No dependence on generator command templates for identity | Signatures per DEC cluster; template keywords | Indicators are generic command semantics. The *lab rates* still follow templates: PRIV-1 = 100% PE and 0% elsewhere; EXEC-1 = 100% botnet; SEQ-1 48% brute force | **Partially.** The rules aren't templates, but V2 can't show they generalise: every action indicator fires in at most 2 categories because profiles are disjoint by design |
| FP-6 | No interpretation from Cowrie execution time | Matcher: 9/9 slow-`find` sessions "Potentially Novel" | No indicator or rule uses timing. ART-1 marks the 9 sessions (train 30) as a caveat. PE indicator rates are identical with and without ART-1 for PRIV-1 and DISC-1 (1.0 / 1.0); CRED-1 and FILE-1 differ only because `find -name id_rsa` itself is the slow command | **Yes** |
| FP-7 | No false novelty from slow `find` | As above | Novelty is a separate field; ART-1 is displayed beside any novelty flag as "explained by known emulator latency" | **Yes** (design rule). The novelty model itself is unchanged |
| FP-8 | No unsupported claims of successful download/upload | "Download or payload retrieval" for 99 validation logins with 0 download events | XFER-1 = attempt; outcome `not_observed` for all 347 attempts (train + validation); XFER-1-OK = 0; XFER-2 = 0 | **Yes** |
| FP-9 | Emulator failures are not attacker behaviour | Not distinguished | EMU-1 (benign 31%: `systemctl`, `journalctl` unknown to Cowrie) is a caveat, never an indicator of intent | **Yes** |
| FP-10 | Explicit abstention | "Insufficient Evidence" only when no numeric overlap | "Insufficient evidence" for 49 validation logins (all brute force with 0–1 trivial command); "indeterminate" whenever the AUTH source key is shared (the whole lab) | **Yes** |

**Residual false-positive conditions** (documented in `indicator_catalogue.csv`):
- `curl -I` connectivity checks (NET-1);
- IP-echo fetches (`curl -s http://…/ip`), counted as download attempts (recon 21 validation sessions);
- users reading their own `~/.ssh/known_hosts` (CRED-1);
- admins auditing sudo or SUID files (PRIV-1);
- shared egress IPs (AUTH-1).
