# Diagnostic session exclusion register

These Cowrie sessions were created by controlled infrastructure checks. They are **not** attack or benign data, and must be excluded from every dataset, label file, feature extraction, model training, validation, test, novelty evaluation, behavioural-evidence run and threat assessment.

| Session ID | Task | Created (UTC) | Live-log lines | Events | Purpose |
|---|---|---|---|---|---|
| `99732d516898` | 25A | 2026-11-11T16:37:34Z | 21851–21852 | `session.connect`, `session.closed` | Relay peer-address observation |
| **`b806554e19b9`** | **25C-4** | **2026-11-11T17:03:25Z** | **21853–21854** | `session.connect`, `session.closed` | Hardened-relay end-to-end connectivity check |

**Exclusion rules for any future slice of Cowrie's live log:**
1. **Session IDs:** exclude both sessions by ID.
2. **Line ranges:** these sessions lie after the sealed test run's last line (21850). No existing slice contains them:
   - Dataset V2 train/validation slices end at their own baselines (Task 14B);
   - the sealed test slice ends at line 21850 (Task 19B).
3. **Recording:** any new slice must record its line range and assert that neither session ID appears in it.

Neither session sent credentials or commands: no `login.*`, `command.*` or `client.version` events.
