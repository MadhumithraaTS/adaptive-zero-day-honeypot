# Cowrie session feature specification, version 2.0.0 (draft.3)

**Machine-readable form:** `configs/feature_spec_v2.json` (`spec_version` `2.0.0-draft.3`).
**Evidence and audit:** `reports/common_feature_specification_v2/report.md`.

**Status:** design only. No extractor implements this yet, no Dataset V2 exists, and the V1 extractor (`scripts/extract_features.py`) and every existing model are unchanged.

## Amendment log

| Revision | Date | Change |
|---|---|---|
| draft.1 (`2.0.0-draft`) | 2026-11-10 | Initial specification |
| draft.2 | 2026-11-10 | Final review (task 5A); see the list below |
| draft.3 | 2026-11-10 | Descriptive event coverage (task 8); see below. **No model feature changed** |

draft.3 changes:

1. **New provenance class `file_event_network_download_failed`.** It covers `cowrie.session.file_download.failed`: an emulated `wget`/`curl` attempted a URL and failed, so no file was obtained. It was first seen in the 2026-11-10 smoke test and is emitted by the error handlers in Cowrie's `wget.py` and `curl.py`.
2. **New descriptive field `download_failed_events`** (count). It is lab-specific, because it depends on blocked egress and on Cowrie's per-command error handling, and it is not a model feature.
3. **`url_download_events` clarified:** it counts **successful** downloads only (`file_download` with `url`). Failed attempts (`file_download.failed`) and local redirect writes (`file_download` with `destfile`) are separate.
4. **`forbidden_inputs` extended:** the generator's diagnostic terminal output and per-command manifest fields can never be feature inputs.

draft.2 changes:

1. **Conditional count clarified:** draft.1 marked 5 individual features as conditional or leakage-checked; earlier summaries said "four", which was a miscount. draft.2 has **7 conditional features in 4 groups** and 6 core features.
2. **`time_to_first_input_s` added to the generator leakage review** (group C2).
3. **`session_duration_s` added to the generator leakage review** (group C3).
4. **Inter-input features redefined:** `inter_input_mean_s` and `inter_input_std_s` are now explicitly intervals between **recorded** `command.input` events, not client typing intervals.
5. **Names unchanged:** the recorded-input naming is kept as it was.
6. **Conditional rules added:** each conditional group now states the risk tested, the evidence needed to keep the feature, the action on failure and how exclusion works.
7. **Four dimensions recorded separately for every feature:** event provenance, availability, statistical leakage risk and deployment-domain compatibility.

## Why a new specification

The V1 features (24 UNSW-NB15-style columns, 15 or 17 of them used by the models) were designed as network-flow features. Cowrie records application-level events, not packets, and the audits found that several V1 columns:

- **are artefacts of the synthetic generator:** `dbytes`, `rate` and `dload` came from a per-category random range;
- **are formulas rather than measurements:** `synack` = 0.45 × `tcprtt`;
- **measure the lab, not the attacker:** `tcprtt`, `ct_*`, `proto`, `ttl`;
- **mean different things in synthetic and real telemetry:** `spkts`, `dpkts` and failed-command handling.

Version 2 keeps only quantities that can be computed **the same way from any Cowrie JSON log**, for generated training data and for live inference alike. Each one is named after what it actually measures.

## Design rules

1. **One source:** the Cowrie JSON log. Features never read the generation manifest, TTY recordings, labels or identifiers; the manifest is used only for validation.
2. **Unit:** one Cowrie session (one session ID).
3. **Honest names:** `input_line_count`, not `spkts`; `tty_output_bytes`, not `dbytes`. Names starting with `input_` or `inter_input_` refer to **recorded** command lines, and no name implies verified client provenance.
4. **No injected values:** a feature must come from an event Cowrie emits in response to real interaction. A generator may not write feature-bearing values.
5. **Missing is not zero:** the extractor writes NaN when a quantity is undefined, and 0 only when it provably cannot occur (a structural zero). It never imputes; imputation belongs in the modelling pipeline and is fitted on training data only.
6. **Version everything:** every output row carries `feature_spec_version`. See "Versioning" below.

## Four separate assessment dimensions

Each feature records these four separately, because a feature can be good on one and poor on another:

| Dimension | Question | Example |
|---|---|---|
| Event provenance | Who produced the events? | `time_to_first_input_s`: reliable (the first line is client-sent) |
| Availability | Do the source events exist in this telemetry? | Every model feature: yes in real Cowrie; none in synthetic V1 |
| Statistical leakage risk | Could generated values reveal the profile for non-behavioural reasons? | `time_to_first_input_s`: medium, even with reliable provenance, because the generator's fixed wait sets the value |
| Deployment-domain compatibility | Will the lab distribution resemble real deployment? | `time_to_first_input_s`: low, because lab timing is set by the generator and `--speed` |

## Event provenance

| Class | Cowrie events | What can be said |
|---|---|---|
| Connection | `session.connect`, `client.version`, `client.kex`, `session.closed` | Lifecycle and duration; both client and server timing. Termination cause is not distinguishable |
| Authentication | `login.success`, `login.failed` | Client credentials as judged by Cowrie. The lab generator opens one connection per attempt; real clients may retry within one |
| Recorded command lines | `command.input` | **Mixed provenance** (see below) |
| First recorded command line | the first `command.input` | **Client-originated.** Cowrie executes nothing before the client's first line; all 1,498 manifest-aligned live sessions agree |
| Server emulation | `command.failed`, `session.params`, `client.size` | Reflect Cowrie's emulation (command coverage, one event per `;` part), not attacker intent |
| Server terminal output | `log.closed.size` | Bytes Cowrie wrote to the terminal, **including the echo of typed input** (pilot, 2026-11-10) |
| File events | `session.file_download`, `session.file_download.failed` | `session.file_download` covers three different things, distinguished by fields: a completed network download (`url`), a local redirect write (`destfile`, no `url`), and client lines swallowed by emulated `scp` (`realm: scp`). `session.file_download.failed` is a **failed** download attempt (`url`, no file) (draft.3) |

**Why `command.input` is not client-specific.**

- **Extra lines.** Cowrie logs lines it executes itself (from `sh script`, or from downloaded files) as `command.input`, milliseconds after the triggering command (pilot test C; a 5,605-character HTML line in train_v1).
- **Missing lines.** Client lines can be absent:
  - 771 manifest lines in 262 of 1,498 aligned train_v1 sessions never appeared, because the client disconnected while an emulated download was blocking the shell;
  - after `scp`, typed lines are logged only as `scp` file events (32 of 32 in eval_v1).
- **Timing can't separate them.** 36 genuine client gaps were under 10 ms, so client and Cowrie-generated lines overlap in timing.

Without TTY collection, which is deferred, there is no reliable per-line provenance. Input features are therefore defined and named as **recorded** lines, and must not be interpreted as client typing.

## Features (model candidates)

| # | Feature | Status | Formula (see JSON for full rules) | Missing / zero policy |
|---|---|---|---|---|
| 1 | `login_success` | core | 1 if any `login.success` | never missing |
| 2 | `login_failed_count` | conditional (C1) | count `login.failed` | never missing |
| 3 | `session_duration_s` | conditional (C3) | `session.closed.duration` | NaN if no `session.closed` |
| 4 | `input_line_count` | core | count of recorded input lines* | true count |
| 5 | `input_bytes_total` | core | Σ UTF-8 bytes of recorded input lines | true count |
| 6 | `input_line_max_bytes` | core | max UTF-8 bytes of a recorded input line | NaN if no lines |
| 7 | `unique_command_names` | core | distinct first tokens | true count |
| 8 | `shell_operator_lines` | conditional (C4) | lines containing `\|`, `;`, `&&`, `>`, `<`, `` ` ``, `$(` | true count |
| 9 | `download_command_lines` | conditional (C4) | lines whose first token is wget/curl/tftp/ftp/ftpget/scp | true count |
| 10 | `time_to_first_input_s` | conditional (C2) | first recorded input − `login.success` | NaN if no login or no input |
| 11 | `inter_input_mean_s` | conditional (C2) | mean interval between consecutive **recorded** `command.input` events | NaN if < 2 lines |
| 12 | `inter_input_std_s` | conditional (C2) | population standard deviation of those recorded-event intervals | NaN if < 3 lines |
| 13 | `tty_output_bytes` | core | Σ `log.closed.size` | 0 if no login (no terminal exists); NaN if logged in but no `log.closed` |

\* Recorded input lines are `command.input` events, sorted by (timestamp, log order), excluding lines that are exactly `exit` or `logout`. Those are termination, not behaviour; the generator always sends `exit`, and in 230 aligned sessions it never reached Cowrie.

**Counts:** 13 model features = **6 core** + **7 conditional** in **4 groups**. Core features still go through the general leakage checks L1–L7. "Conditional" marks features with a specific identified risk, which need explicit evidence to be kept.

**Interpreting the timing features.** `inter_input_mean_s` and `inter_input_std_s` measure intervals between **recorded** events. A Cowrie-executed script line adds a gap of a few milliseconds, and a lost client line merges two gaps into one. They describe recorded command cadence, **not** how fast the client typed.

**Descriptive and quality fields,** written but not model inputs: `unknown_command_events`, `url_download_events` (successful downloads only), `download_failed_events` (draft.3), `redirect_write_events`, `scp_stdin_events`, `event_count`, `session_closed_observed`, `timestamp_order_mismatch`.

## Conditional features: tests, retention evidence and failure handling

| Group | Features | Leakage risk tested | Evidence required to keep | On failure | How exclusion works |
|---|---|---|---|---|---|
| C1 authentication collinearity | `login_failed_count` | The generator opens one connection per attempt, so the value is 0/1 and ≈ 1 − `login_success` | \|Spearman ρ\| with `login_success` < 0.95; L1/L2 pass; a non-lab or pilot sample shows within-session retries | Mark inactive | Deactivate (patch revision); no re-extraction |
| C2 generator timing | `time_to_first_input_s`, `inter_input_mean_s`, `inter_input_std_s` | Per-profile `delay_range`; fixed post-shell wait of 0.5/`--speed` (`dataset_builder/generate_labelled_traffic.py:160`); `--speed` scaling. `time_to_first_input_s` has reliable provenance but can still be a generator constant. The inter-input features include Cowrie-executed lines and gaps across lost lines | Generation metadata shows one category-independent pacing distribution, a fixed `--speed` and wait-for-prompt; L1/L2 pass (proposed η² < 0.8); `time_to_first_input_s` not near-constant (coefficient of variation reported); L6 contamination not category-dependent | Generator at fault → fix it and regenerate. Otherwise → mark the failing feature inactive | Deactivate, or regenerate data; the specification is not regenerated |
| C3 session lifecycle | `session_duration_s` | Command count × pacing; blocking emulated commands (curl/wget/scp) whose run time depends on the lab network; Cowrie `authentication_timeout` 120 s and `idle_timeout` 180 s; pre-fix ~120 s failed logins | No pre-fix generated sessions; L1/L2 pass; share of sessions within 1 s of 120 s or 180 s reported per category and not category-dependent; duration not mostly explained by category after accounting for `input_line_count` | Generator or timeout artefact → fix and regenerate. Otherwise → inactive | Deactivate, or regenerate data |
| C4 profile-template content | `shell_operator_lines`, `download_command_lines` | Fixed command templates (for example, download commands only in botnet/exfiltration profiles) | L2 η² and exact-value lookup below thresholds; non-zero values in ≥ 2 categories, including a benign one where realistic; values vary within categories | Broaden and overlap vocabularies and regenerate; if still failing → inactive | Deactivate, or regenerate data |

## Versioning

- **Deactivating a feature:** set `"active": false` with a dated reason and bump the revision. Formulas and the output columns are unchanged and the extractor still writes the column, so no re-extraction is needed. Only the model input list (active features) changes.
- **Changing a formula or adding a feature:** minor version (2.1.0), and re-extract all datasets.
- **Changing a source event, unit or provenance class:** major version (3.0.0); results are not comparable across major versions.
- **Generator-caused failure:** the specification is unchanged. Fix the generator, regenerate the data and repeat the check.

## Conditions on the generator (for Dataset V2 to be valid)

The specification only removes leakage if the data that feeds it is generated fairly:

1. **Pacing:** command delays drawn from **one category-independent distribution**, sending each line only **after the shell prompt returns**. Otherwise timing features (C2) and duration (C3) encode the profile's `delay_range`, and lines are lost while emulated commands block.
2. **Post-login wait:** the wait before the first command must be the same for every profile and recorded. It currently is (a fixed 0.5/`--speed`), which is exactly why `time_to_first_input_s` may carry no behavioural information in generated data.
3. **Connection handling:** failed-login connections closed immediately (fixed 2026-11-10; `reports/generator_encoding_fixes/report.md`).
4. **Destinations:** documentation-only addresses (`dataset_builder/profiles_v2_isolated.json`) in the isolated lab. Confirmed downloads are therefore impossible, which is why only download *attempts* (`download_command_lines`) are a model feature.
5. **Content:** no category-specific fixed values in anything that reaches a feature (no constant byte ranges, no fixed markers), and overlapping command vocabularies across categories.

## Limitations

- **Provenance:** input features mix client and Cowrie-executed lines. Client-specific interpretation needs TTY collection (deferred).
- **Non-ASCII:** this Cowrie build strips non-ASCII bytes before logging, so binary payloads are invisible and out of scope.
- **Cross-session behaviour:** brute-force guessing appears as many short sessions, which per-session features can't link. All lab sessions share one source IP (the relay), and the source IP is never a feature.
- **Synthetic V1:** none of these features can be computed for the synthetic V1 data, because its raw events weren't kept. V1 and V2 results are not comparable.
- **Low lab-to-deployment compatibility:** several features have low deployment-domain compatibility (`login_failed_count`, `session_duration_s`, all C2 timing features). Even if they pass the leakage checks, a model trained on lab data may not transfer to real attackers.
