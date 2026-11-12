# Matching design (proposed; not implemented)

## 1. Parsing (replaces substring keywords)

1. **Input:** the session's `cowrie.command.input` lines in (timestamp, log order), excluding exactly `exit`/`logout`. This is the V2 extractor convention.
2. **Split into simple commands:** each line is split at unquoted `|`, `;`, `&&`, `||`. Redirection tokens (`>`, `>>`, `<`, `2>`) are stripped into a separate `redirections` list.
3. **Tokenise:** `shlex` (POSIX). On a quoting error, fall back to whitespace split and flag the line `parse_degraded`.
4. **Command name:** the basename of `argv[0]`.
   - A leading `sudo` (with its own options) is recorded as a `wrapper`, and the wrapped command is analysed.
   - `./x` is recorded as `local_exec`.
5. **Matching:** an indicator matches on **command name**, **specific flags** and **argument values or path components**, never on a substring of the whole line.
   - Path rules match path components or exact paths. For example, `shadow` must be the final component, so `/etc/shadow.bak` doesn't match, and neither does the word `shadowsocks`.
   - Every rule is a pure function of the tokens, so it is reproducible and testable.

**Measured effect on the Task 20 failure modes** (validation, same lines):
- 240 lines that the old substring rules called `credential_attack` match no credential indicator under token rules. Examples: `service ssh status`, `ps aux | grep sshd`, `cat /etc/passwd | grep sh`.
- `w`, `ps`, `su` and `rm ` no longer fire inside other words.

## 2. Indicators

The 25 indicators are defined in `indicator_catalogue.csv`, each with its required telemetry, exact semantics, what it establishes, what it cannot establish, false-positive conditions and V2 support. `TIME-0` is listed with them but is context only, not an indicator.

They fall into three groups:
- **Action indicators** (can contribute to interpretations): AUTH-1, AUTH-2, PRIV-1, CRED-1, XFER-1, XFER-2, EXEC-1, STAGE-1, EVADE-1, PERS-1, NET-1.
- **Context indicators** (never sufficient alone): AUTH-0, SHELL-1, DISC-1, PRIV-2, FILE-1, FILE-2, PERS-0, CHAIN-1, REDIR-1.
- **Caveat flags** (never behavioural): EMU-1, ART-1, SEQ-1, TIME-0.

## 3. Interpretation rules (multi-label; no first-match ladder)

Each rule lists the **required indicators**. Every satisfied rule is reported, and several may coexist in one session. Wording is fixed to *attempt* language.

| Interpretation | Rule | Unit |
|---|---|---|
| repeated authentication failures | AUTH-1 | source-window (needs a non-shared source key) |
| credential guessing followed by login | AUTH-2 | source-window |
| privilege-context reconnaissance | PRIV-1 and at least one of {CRED-1, FILE-1, DISC-1} | session |
| credential-material access attempt | CRED-1 (directly observed path argument) | session |
| download attempt | XFER-1 | session |
| download-and-execute attempt | XFER-1 and EXEC-1 on the same file name | session |
| upload attempt | XFER-2 | session |
| archive-and-upload attempt | STAGE-1 and XFER-2 | session |
| history tampering | EVADE-1 | session |
| persistence modification attempt | PERS-1 (never PERS-0) | session |
| network probing attempt | NET-1 | session |
| system discovery only | DISC-1 and no action indicator | session (descriptive) |
| insufficient evidence | no input, or only context and caveat flags | session |

**Rules that removed old false positives:**
- **One failed login is never an interpretation.** AUTH-0 is context. AUTH-1 needs ≥ 3 failures from one source in 300 s; these parameters are fixed in advance and must be set from deployment policy, not tuned on lab labels.
- **A single context indicator never produces an attack interpretation.** Interpretations need an action indicator, and policy (`defence_policy.json`) additionally requires ≥ 2 distinct indicators before any proposed response.
- **Reading is not modifying.** `crontab -l`, `cat /etc/crontab` and `service ssh status` are PERS-0 (read), never persistence.
- **Download language means a command, not an outcome.** Interpretations describe the attempt, and the outcome is shown separately (`evidence_semantics.md` §2).

## 4. Identity and versioning

- **Indicator and rule IDs are stable names** (e.g. `PRIV-1@1.0`). DEC cluster IDs are never identities, and clusters are not used.
- **The indicator set is versioned.** Each evidence record stores the indicator-set version and the telemetry schema version.
- **Schema check:** the matcher refuses to run, rather than silently returning "Insufficient Evidence", if a required telemetry field is missing. This addresses the Task 20 V1 catalogue failure.

## 5. Emulator and generator caveats

- **EMU-1** (`cowrie.command.failed`) and **ART-1** (a sensor-calibrated slow-command list) are attached to the record.
  - They never change an interpretation.
  - They must be shown next to any statistical novelty result.
- **ART-1 calibration** uses the training split only (here: `find / -name id_rsa 2>/dev/null`). In deployment, it is set by **benchmarking the sensor's emulated commands**, not by attacker data or evaluation data.
- **SEQ-1** (exact sequence repeat) and all timing statistics are reported as context. In lab data they are generator properties.

## 6. Output record (per session; per source-window for AUTH-1/2)

```json
{
  "session_ref": "...", "indicator_set": "v2-evidence-1.0", "telemetry_schema": "cowrie-json-2.9",
  "indicators": [{"id": "XFER-1", "class": "directly_observed", "lines": ["wget -q http://... -O payload"],
                   "attempted": true, "outcome": "not_observed"}],
  "interpretations": [{"name": "download-and-execute attempt", "requires": ["XFER-1", "EXEC-1"], "evidence_level": "E2"}],
  "caveats": ["EMU-1: ./payload unknown to emulator"],
  "abstention": null,
  "statistical_novelty": {"source": "Task 18 baseline C", "flag": false, "note": "independent field"}
}
```
