# Evidence and confidence semantics

## 1. Evidence classes (every indicator and every interpretation carries exactly one)

| Class | Definition | Example | May support an interpretation? |
|---|---|---|---|
| **Directly observed** | A Cowrie event or recorded input line, read literally | `cowrie.login.failed`; input line `sudo -l`; `cowrie.session.file_download` | Yes |
| **Inferred** | A relation between ≥ 2 directly observed items, stated explicitly | EXEC-1: the session ran `./payload` after attempting to download `payload` | Yes, if every component is cited |
| **Emulator-dependent** | Depends on how Cowrie implements or times a command, not on the client | EMU-1 (`systemctl` unknown to Cowrie); ART-1 (`find / -name id_rsa` takes ~11.6 s); any "outcome" of tar/curl/sudo | **No.** Attached as a caveat |
| **Generator-dependent** | Its value in lab data is set by the traffic generator | Failure counts per interaction (profile `failed_attempts`), exact command sequences (SEQ-1), think-time pacing | **No** in lab evaluation. In deployment the same indicator may be behavioural, but lab results cannot show that |
| **Unknown / insufficient** | The telemetry needed is absent, or the indicator never fired | Outcome of any command without an event; upload behaviour (0 V2 occurrences) | Produces an explicit abstention |

## 2. Attempt vs outcome

Every action-type indicator has two separate fields: `attempted` and `outcome`.

- **`outcome` values:** `observed_success`, `observed_failure`, `not_observed`.
- **`observed_success` requires an outcome event:**
  - `cowrie.session.file_download` for downloads;
  - `cowrie.session.file_upload` for uploads;
  - `cowrie.login.success` for logins.
- **`observed_failure`:** `cowrie.command.failed` (the emulator rejected the command), or `cowrie.login.failed`.
- **`not_observed` is the default** for everything else: tar, curl -T, sudo, crontab, find results.
  - Cowrie JSON contains no command output, so the framework **must not** infer success from the command, the absence of an error, or session duration.
  - A Cowrie emulation failure is reported as an *emulator* fact (EMU-1), not as attacker failure.

**Consequences on Dataset V2:**
- 347 validation and train download attempts, with **0** `observed_success`;
- 0 upload attempts;
- no claim of downloaded, exfiltrated, persisted or escalated state is possible.

## 3. "Confidence"

**No probability is reported.** The framework reports:
1. which indicators fired, with the exact matching line(s) and event IDs;
2. the evidence class of each;
3. which interpretation rules were satisfied, and the indicator IDs that satisfied them;
4. caveat flags (ART-1, EMU-1, generator-dependent, telemetry gaps).

**An ordinal "evidence level" may be shown, defined by counts, not weights:**

| Level | Condition |
|---|---|
| E0 | No action indicator; descriptive context only |
| E1 | One directly observed action indicator |
| E2 | ≥ 2 distinct directly observed or inferred action indicators belonging to one interpretation |
| E3 | E2 plus an `observed_success` outcome event |

On Dataset V2 no session reaches E3. The level is a description of the evidence available, not a likelihood of attack. Any future numeric score must be calibrated on held-out labelled data before it is called a probability.

## 4. Abstention

The framework returns `insufficient_evidence` when:
- the session has no input lines;
- only context indicators fired (DISC-1, SHELL-1, CHAIN-1, PERS-0, FILE-2, TIME-0); or
- every fired indicator is emulator- or generator-dependent.

It returns `indeterminate` when:
- required telemetry is missing (no `session.closed`, a malformed log), or
- the source key needed by AUTH-1/2 is shared (a known relay/NAT address; in the lab, every session).

Abstentions are reported with their reason. They are never mapped to "known" or "novel".

## 5. Separation from statistical novelty

The behavioural evidence record and the Task 18 novelty score are **two independent fields**:
- A novelty flag never creates or strengthens a behavioural interpretation.
- A behavioural interpretation never suppresses a novelty flag.
- When both are present, ART-1 or EMU-1 caveats are shown next to the novelty score. Example: a novelty flag on an ART-1 session is displayed as "statistically unusual timing, explained by known emulator latency".
