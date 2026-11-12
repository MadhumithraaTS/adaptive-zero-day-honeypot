# Common feature specification for Dataset V2: design audit

**Date:** 2026-11-10.
**Type:** specification and design. Nothing was generated, trained or extracted. The existing extractor, models and datasets are unchanged, and the held-out test split was not accessed.

**Deliverables:**

- `configs/feature_spec_v2.json` (the machine-readable specification; version `2.0.0-draft`, amended to `2.0.0-draft.2` in Amendment A1)
- `docs/feature_specification_v2.md` (design rationale)
- this report
- `evidence/`: `fs_provenance.py` and `fs_provenance.json`, the manifest-alignment provenance measurement

**Inputs reviewed:**

- `reports/research_integrity_audit_20261110/`
- `reports/buffer_overflow_telemetry_audit/`
- `reports/cowrie_security_isolation_audit/report.md`
- `reports/cowrie_payload_observability_pilot/report.md`
- `reports/generator_encoding_fixes/report.md`
- `scripts/{extract_features,parse_logs,collect_logs}.py`
- `dataset_builder/{generate_labelled_traffic,build_labelled_dataset,labelling}.py`
- model configurations: `ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/artifacts/config.json` (17 features) and `models/dec_15_feature_v2_deterministic/config.json` (15 features)

**New measurements in this task** (read-only; live logs `dataset_builder/runs/{train_v1,eval_v1}/raw/cowrie_thisrun.json`, the pilot slice, and labelling-v2 assignments in `dataset_builder/runs/train_v2_corrected/label_assignments.csv`):

- an event and field inventory;
- `command.input` provenance against the manifests;
- duplicate-session checks;
- structural invariants.

**Labels:** **[C]** confirmed by data, **[S]** source code, **[U]** unverified, **[Rec]** recommendation.

---

## Amendment A2: descriptive download-failure coverage (task 8, 2026-11-10; specification `2.0.0-draft.3`)

The smoke test (`reports/generator_cowrie_smoke_test/report.md` section 5) observed `cowrie.session.file_download.failed`, which section 2's event inventory did not contain. It comes from the error handlers in Cowrie's `wget.py` and `curl.py`, and means a failed URL attempt with no file obtained. draft.3:

- adds provenance class `file_event_network_download_failed` and descriptive field `download_failed_events`;
- clarifies that `url_download_events` counts only successful downloads;
- forbids the generator's terminal output and per-command manifest fields as inputs.

**No model feature, status or conditional group changed** (verified: the `features`, `feature_counts` and `conditional_groups` objects are identical to draft.2). Details: `reports/cowrie_profile_compatibility_v2/report.md`.

## Amendment A1: final review (task 5A, 2026-11-10; specification `2.0.0-draft.2`)

**Scope.** Documentation and configuration only. No extractor, generator, data, model or evidence changed. The provenance evidence (section 2 and `evidence/`) is unchanged. The pre-amendment files are kept, with their hashes, in the hand-off message.

| # | Amendment | Where |
|---|---|---|
| A1.1 | **Conditional count clarified (correction).** draft.1 marked **5** individual features as conditional or leakage-checked: `login_failed_count`, `shell_operator_lines`, `download_command_lines`, `inter_input_mean_s`, `inter_input_std_s`. Section 11 and the task 5 hand-off said "four"; that was a miscount. After A1.2 and A1.3, draft.2 has **7 conditional features in 4 groups** (C1–C4) and **6 core features** | JSON `feature_counts`, `conditional_groups`; doc; sections 4, 11 |
| A1.2 | **`time_to_first_input_s` added to the generator leakage review (C2).** Its event provenance is reliable, but its value can be a generator constant: a fixed 0.5/`--speed` wait after the shell opens (`dataset_builder/generate_labelled_traffic.py:160`) [S]. It can also be a profile parameter | JSON feature and C2; doc |
| A1.3 | **`session_duration_s` added to the generator leakage review (C3).** Risks: command count × pacing; blocking emulated commands; Cowrie `authentication_timeout` 120 s and `idle_timeout` 180 s (`cowrie.cfg.dist`, read in the pilot task); pre-fix ~120 s failed logins | JSON feature and C3; doc |
| A1.4 | **Inter-input features redefined:** `inter_input_mean_s` and `inter_input_std_s` are explicitly intervals between **recorded** `command.input` events, not necessarily client typing intervals | JSON definitions and `event_provenance`; doc |
| A1.5 | **Recorded-input names kept**; nothing renamed. A `conventions.naming` rule was added | JSON; doc |
| A1.6 | **Conditional rules:** each group now states the leakage risk tested, the evidence required to keep the feature, the failure action, and whether exclusion means deactivation (no specification regeneration) or data regeneration. A `versioning_policy` was added | JSON `conditional_groups`, `versioning_policy`; doc |
| A1.7 | **Four dimensions recorded separately for every feature:** `event_provenance`, `availability`, `statistical_leakage_risk` (level and note), `deployment_domain_compatibility` (level and note). `role` became `status` / `conditional_group` / `active`, and `provenance` became `event_provenance` | JSON; doc |

**Unresolved ambiguities (need your decision):**

1. **Thresholds are proposals, not agreed values:** η² < 0.8; |ρ| < 0.95 for C1; an exact-value-lookup limit for C4 that isn't yet numeric.
2. **"Not category-dependent" in C2(d) and C3(c) lacks an operational test.** A test (for example a χ² test of independence at a stated α) must be chosen before use.
3. **Core vs conditional is a judgement.** Core features (for example `input_bytes_total`) also carry template risk and must pass the general L1–L7 checks. "Conditional" marks features with a *specific* identified risk that needs explicit retention evidence. If you prefer that every feature with any non-low leakage risk be conditional, the core set would shrink to `login_success` and `tty_output_bytes`.
4. **Low deployment-domain compatibility is recorded but doesn't on its own deactivate a feature.** Deciding whether low compatibility should exclude a feature is a policy choice.

---

## 1. Existing feature audit

Code references are to `scripts/extract_features.py` at HEAD. Its feature logic is unchanged since commit c1678cf.

- "Synthetic" means `scripts/generate_dataset.py` (V1).
- "Real" means Cowrie logs processed by the same extractor.
- V1 missing-value policy for **every** feature: absent events produce 0 (never NaN); ±inf→NaN and median imputation happen only in model preprocessing.

| Feature | Calculation (lines) | Source event | Unit | Client / server | Synthetic | Real | Known limitations and contamination |
|---|---|---|---|---|---|---|---|
| `dur` | `session.closed.duration_ms`, else first–last event span (234–240, 304–311) | session.closed | s | both | generated delays (per-category `cmd_delay_range`) [S] | real duration; failed logins ~120 s from the generator's unclosed connection (fixed 2026-11-10) [C] | Generator artefacts in both sources |
| `spkts` | count of `command.input` (261) | command.input | lines | **mixed** | omits failed commands [S] | includes `exit` and Cowrie-executed lines; misses swallowed lines [C] | Not a packet count; semantics differ between sources |
| `dpkts` | count of `DPKT_EVENT_IDS` events (19–29, 291) | version, kex, login.*, client.size, session.params, command.success, command.failed, log.closed | events | **server/protocol** | baselines 4/5 + failed commands [C] | baselines 3/6 (`session.params`) + failed [C] | `command.success` is never emitted by Cowrie; not packets |
| `sbytes` | Σ UTF-8 bytes of `command.input` (262) | command.input | bytes | **mixed** | fixed per-category strings; failed commands missing [S] | after Cowrie's non-ASCII stripping [C] | Includes Cowrie-executed lines (5,605-byte HTML) |
| `dbytes` | Σ `log.closed.size` (242–248, 315) | log.closed | bytes | **server output** [C, pilot] | **random per-category `tty_size_range`** [S][C] | real terminal output, including echo [C] | Injected in V1 |
| `rate` | (`sbytes` + `dbytes`)/`dur` (316) | derived | B/s | mixed | inherits injection [C] | mixes input, output and duration | Not a meaningful rate |
| `sload` | 8·`sbytes`/`dur` (319) | derived | bit/s | mixed | derived | derived | Denominator includes auth and idle time |
| `dload` | 8·`dbytes`/`dur` (320) | derived | bit/s | server | inherits injection [C] | derived | — |
| `sinpkt` | mean gap of `command.input` (322–330); 0 if < 2 | command.input | s | mixed | per-category delay range [S] | recorded cadence, including ms gaps from Cowrie-executed lines [C] | 0 conflates "undefined" with "instant" |
| `sjit` | standard deviation of those gaps (343) | command.input | s | mixed | same | same | same |
| `dinpkt` | mean gap of `DPKT` events (332–340) | protocol/server events | s | server/protocol | generated offsets | real | Mixed event types |
| `djit` | standard deviation of `DPKT` gaps (344) | same | s | same | same | same | same |
| `tcprtt` | first `client.kex` − first event (346–349) | connect, kex | s | lab path | category-independent offsets (η² 0.003) [C] | loopback plus relay hop; median 0.010 s vs 0.073 s synthetic [C] | Measures the lab |
| `synack` | 0.45·`tcprtt` (352) | — | s | none | formula [C] | formula [C] | Not a measurement |
| `ackdat` | first `command.input` − first login event (354–357) | login, command.input | s | client | generated offset + delay [S] | real | 0 when no input |
| `ct_srv_src`, `ct_src_ltm` | sessions per `src_ip`(:service) in the processed file (359–364) | connect | count | none | per-category IPs → **label leakage** [C] | file size (single source IP) [C] | In the 17-feature DEC only |
| `ct_dst_ltm`, `ct_srv_dst` | per `dst_ip` (361–364) | connect | count | none | constant | file size | Unused |
| `proto`, `service`, `sttl`, `dttl`, `ct_state_ttl` | constants (312–317, 365) | — | — | none | constant | constant | Unused |

The 17-feature DEC uses `dur … ackdat` plus `ct_srv_src` and `ct_src_ltm`; the 15-feature models drop the two `ct_*`. No other feature exists in either configuration [C].

## 2. Event provenance findings

**Event inventory** (4,357 unique live sessions, plus 5 pilot sessions) [C]:

| Event | Fields used | Notes |
|---|---|---|
| `session.connect` | `dst_ip`, `dst_port`, `src_port` | — |
| `client.version`, `client.kex` | `version`, `hassh`, … | Client fingerprint; never a feature |
| `login.success`, `login.failed` | `username`, `password` | Exactly one login event per live session (generator: one attempt per connection) |
| `session.params`, `client.size` | `arch`, `width`/`height` | Emitted on every successful login |
| `command.input`, `command.failed` | `input` | — |
| `log.closed` | `size`, `duration`, `ttylog`, `shasum` | Present for all but 4 logged-in sessions |
| `session.closed` | `duration` | Present for 4,357/4,357 unique sessions |
| `session.file_download` | variant-dependent | Three variants (below) |

**Provenance categories:**

1. **Client-originated, reliably:**
   - the authentication outcome;
   - the **first** `command.input`: 1,498/1,498 manifest-aligned train_v1 sessions [C], and Cowrie executes nothing before the first client line [S, consistent with pilot test C].
2. **Recorded command lines, mixed provenance** (`command.input` after the first) [C]:
   - **extra:** lines Cowrie executes itself (pilot test C; the downloaded HTML file in train_v1);
   - **missing:** 771 manifest lines in 262 of 1,498 aligned sessions never appeared. The client disconnected while an emulated `curl`/`wget` blocked the shell; the most common missing commands were `exit` 230, `chmod` 153, `rm` 78 and `sh` 68. Separately, all 32 lines typed after `scp` in eval_v1 were logged only as `file_download` events with `realm: scp`;
   - **timing can't separate them:** 36 genuine client gaps were under 10 ms;
   - **order:** 2 sessions have `command.input` timestamps out of log order.
3. **Authentication events:** `login.*` as above.
4. **Server terminal output:** `log.closed.size` equals the TTY output bytes and includes the echo of typed input (pilot). Output < input in only 2 live sessions, both where Cowrie executed a downloaded file [C].
5. **File events:** `session.file_download` has three variants [C]:
   - **network download:** `url`, `outfile`, `shasum`; 13 events;
   - **local redirect:** `destfile`, `outfile`, `shasum`, message "Saved redir contents"; 1 event (pilot);
   - **scp stdin:** `realm: scp`, `input`; 33 events.
6. **Connection events:** `session.connect` / `session.closed`. The closing message is "Connection lost after N seconds" for both a client close and Cowrie's authentication timeout (pilot D1 and D2) [C], so **termination status can't be derived**.

**Manifest:** usable only to **validate** generated runs (measure contamination), never as a feature, because live inference has no manifest.

**TTY:** deferred. Without it, per-line client provenance is unavailable, so every input feature after the first line is marked "recorded, mixed provenance" in the specification [Rec].

**Duplicate sessions:** train_v1's raw slice contains 74 sessions from eval_v1, because it was collected after eval_v1 began. The builder's time-window filter dropped them (`out_of_window_dropped: 74`), and the labelled train and eval sets share 0 sessions [C]. This safeguard is necessary and must stay.

## 3. Candidate feature assessment

| Group | Candidate | Source and formula | Decision | Reason |
|---|---|---|---|---|
| Session | Session duration | `session.closed.duration` | **Keep, conditional (C3)** (`session_duration_s`) | Always present; pre-fix generator artefact documented. A1.3: generator leakage review for pacing, blocking commands and timeouts |
| Session | Total event count | count all events | Descriptive only | Dominated by fixed protocol events |
| Session | Termination status | `session.closed` message | **Reject** | Identical message for client close and timeout [C] |
| Input | Observable line count | count `command.input` (excluding exit/logout) | **Keep** (`input_line_count`) | Mixed provenance, named as "recorded" |
| Input | Total input bytes | Σ UTF-8 bytes | **Keep** (`input_bytes_total`) | As above |
| Input | Max line length | max UTF-8 bytes | **Keep** (`input_line_max_bytes`) | Printable payload length; can be a Cowrie-executed line |
| Input | Printable share / non-ASCII share | — | **Reject** | Cowrie strips non-ASCII, so the value is constant [C, pilot] |
| Input | Shell-operator lines | count of lines with `\| ; && > < `` ` `` $(` | **Keep, subject to leakage check** | Observable printable structure |
| Command | Unique command names | distinct first tokens | **Keep** | — |
| Command | Command sequence characteristics (n-grams, order) | — | **Reject for v2.0** | Mixed provenance, missing lines, and fixed profile templates make sequences a profile fingerprint |
| Command | Unknown-command events | count `command.failed` | Descriptive only | One per `;` part; reflects Cowrie's command coverage |
| Auth | Login success | indicator | **Keep** | — |
| Auth | Failed attempts | count `login.failed` | **Keep, conditional** | Nearly collinear with success in generated data |
| Auth | Login attempts | success + failed | **Reject** | Redundant |
| Timing | Time to first input | first input − `login.success` | **Keep, conditional (C2)** (`time_to_first_input_s`) | Only client-guaranteed timing (provenance). A1.2: its value can still be a generator constant or profile parameter |
| Timing | Mean inter-input interval | mean interval between recorded `command.input` events | **Keep, conditional (C2)** | Needs category-independent pacing in V2. A1.4: recorded-event intervals, not client typing |
| Timing | Variability | population standard deviation of the recorded-event intervals | **Keep, conditional (C2)** | Same |
| Timing | Inter-input interval (raw list) | — | **Reject** | Not a fixed-length feature |
| Server | Terminal output bytes | Σ `log.closed.size` | **Keep** (`tty_output_bytes`) | Real measurement; includes echo |
| Server | Server-generated event count | `command.failed` + `session.params` + … | **Reject** | Emulation detail; constant per login |
| Server | Output rate (`dload`-like) | bytes / duration | **Reject** | Duration includes auth and idle time; redundant |
| File | Download attempts | count of lines starting wget/curl/tftp/ftp/ftpget/scp | **Keep, subject to leakage check** (`download_command_lines`) | Observable regardless of network |
| File | Confirmed downloads | `file_download` with `url` | Descriptive only | Constant 0 in the isolated lab |
| File | Local redirect writes | `file_download` with `destfile`, no `url` | Descriptive only | Bookkeeping; overlaps shell-operator lines |
| File | scp stdin lines | `file_download` with `realm: scp` | Descriptive only | Quantifies input loss |

## 4. Final recommended feature list (v2.0.0-draft.2; amended A1)

**Model candidates (13 = 6 core + 7 conditional in 4 groups):**

1. `login_success` (core)
2. `login_failed_count` (conditional, C1)
3. `session_duration_s` (conditional, C3; **A1.3**: was core in draft.1)
4. `input_line_count` (core)
5. `input_bytes_total` (core)
6. `input_line_max_bytes` (core)
7. `unique_command_names` (core)
8. `shell_operator_lines` (conditional, C4)
9. `download_command_lines` (conditional, C4)
10. `time_to_first_input_s` (conditional, C2; **A1.2**: was core in draft.1)
11. `inter_input_mean_s` (conditional, C2): interval between **recorded** input events
12. `inter_input_std_s` (conditional, C2): interval between **recorded** input events
13. `tty_output_bytes` (core)

**Descriptive and quality fields (7):** `unknown_command_events`, `url_download_events`, `redirect_write_events`, `scp_stdin_events`, `event_count`, `session_closed_observed`, `timestamp_order_mismatch`.

**Excluded from V1:** all 24 V1 columns, each with a reason in `configs/feature_spec_v2.json` → `excluded_v1_features`. Six are replaced by renamed, re-defined equivalents:

| V1 | V2 replacement |
|---|---|
| `spkts` | `input_line_count` |
| `sbytes` | `input_bytes_total` |
| `dbytes` | `tty_output_bytes` |
| `sinpkt` | `inter_input_mean_s` |
| `sjit` | `inter_input_std_s` |
| `ackdat` | `time_to_first_input_s` |

## 5. Feature formulas

Definitions are exact in `configs/feature_spec_v2.json`. Shared conventions:

- **Input lines** = `command.input` events sorted by (timestamp, log order), excluding lines that are exactly `exit` or `logout`.
- **Line bytes** = `len(input.encode("utf-8"))` of the logged text.
- **Command name** = first whitespace-separated token.

```
login_success          = 1[any login.success]
login_failed_count     = #login.failed
session_duration_s     = session.closed.duration
input_line_count       = #input_lines
input_bytes_total      = Σ line_bytes
input_line_max_bytes   = max line_bytes                         (NaN if no lines)
unique_command_names   = |{command_name(l)}|
shell_operator_lines   = #{l : l contains | ; && > < ` $( }
download_command_lines = #{l : command_name(l) ∈ {wget, curl, tftp, ftp, ftpget, scp}}
time_to_first_input_s  = t(first input) − t(first login.success)   (NaN if no login/input)
inter_input_mean_s     = mean(Δt between consecutive RECORDED input events)  (NaN if < 2 lines)
inter_input_std_s      = pstdev(Δt between consecutive RECORDED input events) (NaN if < 3 lines)
                         (A1.4: recorded-event intervals, not necessarily client typing intervals)
tty_output_bytes       = Σ log.closed.size   (0 if no login; NaN if login but no log.closed)
```

**Ratios:** no rate or load ratio is defined. The V1 `rate`/`sload`/`dload` divide by a duration that includes authentication and idle time, and `rate` and `dload` inherited the injected `dbytes`.

## 6. Synthetic versus live availability

| Feature | Synthetic V1 | Real Cowrie | Common definition possible | Recommended |
|---|---|---|---|---|
| `login_success` | No (raw events not retained) | Yes | Yes | Yes |
| `login_failed_count` | No | Yes | Yes | Conditional |
| `session_duration_s` | No | Yes (4,357/4,357) | Yes | Conditional (C3; A1.3) |
| `input_line_count` | No | Yes | Yes (as "recorded lines") | Yes |
| `input_bytes_total` | No | Yes | Yes | Yes |
| `input_line_max_bytes` | No | Yes | Yes | Yes |
| `unique_command_names` | No | Yes | Yes | Yes |
| `shell_operator_lines` | No | Yes | Yes | Yes, leakage-checked |
| `download_command_lines` | No | Yes | Yes | Yes, leakage-checked |
| `time_to_first_input_s` | No | Yes | Yes | Conditional (C2; A1.2) |
| `inter_input_mean_s` | No | Yes | Yes, if generation pacing is fair | Conditional |
| `inter_input_std_s` | No | Yes | Same | Conditional |
| `tty_output_bytes` | No (V1 value injected) | Yes | Yes (real Cowrie only) | Yes |
| Confirmed downloads | No | Yes (0 in isolated lab) | Yes | Descriptive |
| Non-ASCII / binary content | No | **No** (stripped) | No | No (out of scope) |
| Per-line client provenance | — | **No** without TTY | No | No (deferred) |

**V1 cannot supply any V2 feature.** Its raw events are gone, and its CSV columns have different semantics. V2 must be generated from real Cowrie.

## 7. Leakage risks

1. **Generator pacing** [S]: `dataset_builder/profiles_v2.json` and `profiles_v2_isolated.json` give each profile its own `delay_range`. Timing features would then encode the profile, which is V1's `cmd_delay_range` problem again. Needs a generator change (category-independent pacing, wait for prompt) before V2.
   - **A1.2:** `time_to_first_input_s` is included in this review. Its provenance is reliable, but its generated value is set by a fixed 0.5/`--speed` wait (`generate_labelled_traffic.py:160`), so it may carry only generator information.
   - **A1.3:** `session_duration_s` is included too, because command count × pacing, blocking emulated commands and Cowrie's 120 s / 180 s timeouts can each produce category-dependent durations. See conditional groups C2 and C3 in `configs/feature_spec_v2.json`.
2. **Profile templates:** fixed command vocabularies can make content features (`input_bytes_total`, `unique_command_names`, `shell_operator_lines`, `download_command_lines`) reveal the profile. Mitigations: overlapping vocabularies and the checks in section 8.
3. **Collinearity in generated data:** `login_failed_count` and `login_success`.
4. **Identifiers:** source IP, ports, usernames, passwords, `hassh` and client version are forbidden inputs. Credentials differ by profile in `profiles_v2*.json`.
5. **Test markers:** lines with reserved markers (for example `PILOT_`) are a direct label. Exclude such sessions from datasets.
6. **Lab constants:** `--speed`, the relay hop and blocked egress. Keep them constant across V2 runs and record them in metadata.

## 8. Missing-value policy, and leakage validation design

**Missing-value policy:**

- **NaN** when a quantity is undefined: no lines, too few gaps, no closing event.
- **0** only for true counts, and for `tty_output_bytes` without a login (no terminal exists).
- **No imputation** in the extractor.
- The modelling pipeline decides imputation (fitted on training data only) and may add missingness indicators.
- `session_closed_observed` and `timestamp_order_mismatch` expose data-quality causes.

**Leakage checks.** All run on **training data only**, before any fitting:

| ID | Check | Method | Action on failure |
|---|---|---|---|
| L1 | Category-specific constants | Per feature: within-category variance = 0, or category ranges disjoint | Block the feature; fix the generator |
| L2 | Single-feature category reveal | η² per feature; train-range rule (as in `reports/buffer_overflow_telemetry_audit_20261110/trace_check.py`); exact-value lookup | Flag above an agreed threshold (proposal: η² > 0.8 or lookup accuracy > 50%); investigate before Gate A |
| L3 | Label-derived features | Static check that the extractor never reads `attack_cat`, `label`, manifest or identifier fields; a test that output is identical when those fields are removed from events | Block the build |
| L4 | Duplicate session aggregation | Session IDs unique; every event in exactly one session; Σ per-session events = total events; no session ID shared between runs or splits | Block the build |
| L5 | Generation-profile fingerprints | Reserved markers absent; duplicate command sequences across train/val/test below an agreed rate; profile-specific strings not present in held-out profiles | Exclude sessions or regenerate |
| L6 | Client/server contamination | Generated runs: share of `command.input` lines not in the manifest, and share of manifest lines missing from `command.input`, per category (train_v1 baseline: 9.2% of manifest lines missing, 771 of 8,375, in the 1,498 assigned sessions; 0 extra lines among assigned sessions, while the 2 sessions with Cowrie-executed HTML lines are exactly the 2 that labelling v2 marked `inconsistent`) | Report; if category-dependent, fix pacing |
| L7 | Training/live semantic mismatch | Invariants on every run: each `command.failed` follows a `command.input`; `session.params` present for logins; `tty_output_bytes` ≥ `input_bytes_total` except flagged cases. Compare per-feature distributions between generated train runs and a held-aside live or pilot sample | Report; block features that change meaning |

## 9. Extractor design (proposal; not implemented)

**Module:** `scripts/extract_features_v2.py`. It is new and leaves `scripts/extract_features.py` untouched.

1. **Ingestion:**
   - read Cowrie JSON lines in binary and decode strictly as UTF-8, reusing the `scripts/parse_logs.py` behaviour (line-numbered errors, no replacement);
   - accept a raw log or `parsed/sessions.json`;
   - keep each event's log line number for ordering.
2. **Spec binding:** load `configs/feature_spec_v2.json`; refuse to run if `spec_version` doesn't match the module's implemented version.
3. **Session aggregation:**
   - group by `session`;
   - reject duplicate events (same `uuid` + `timestamp` + `eventid`) with a count reported;
   - sort by (timestamp, line number) and set `timestamp_order_mismatch`.
4. **Provenance tagging:** tag each event with its class from `provenance_classes`, and split `session.file_download` into `url` / `redirect` / `scp` variants. No heuristic re-classification of `command.input` in v2.0.
5. **Feature computation:** one pure function per feature, implementing the JSON formula exactly, with NaN and structural-zero rules applied explicitly.
6. **Output:**
   - CSV `behavior_features_v2.csv` with columns `session_id`, `feature_spec_version`, the 13 model features, then the 7 descriptive fields;
   - no label columns; labels are joined separately by the dataset builder;
   - JSON `extraction_report.json` with counts of sessions, NaNs per feature, invariant violations and rejected duplicates.
7. **Validation:**
   - each feature's `validation` rule from the JSON;
   - L3 and L4 at extraction time;
   - a non-zero exit on schema or invariant failure.
8. **Tests:**
   - one fixture per provenance case (pilot A/B/C/D slices, an scp session, a download session, a failed login);
   - golden outputs;
   - the forbidden-input test (L3).
9. **Builder integration:** a new `--feature-spec v2` path in a future builder version, with no change to V1 outputs.

## 10. Limitations

- **[U]** Cowrie's behaviour is verified only for this pinned development build and for interactive shell input. `exec` requests, SFTP and credential fields with unusual content were not tested.
- **Provenance:** there is no per-line provenance without TTY; input features after the first line are mixed.
- **Lab environment:** lab sessions share one source IP, so cross-session behaviour (brute force across connections) can't be represented per session.
- **Timing:** timing features are valid only with fair generator pacing, which needs a generator change not yet made.
- **Untested:** the thresholds in L2 and L5 are proposals. The specification itself is untested against data, because no extractor exists yet.
- **V1 comparability:** V1 synthetic results are not comparable with any future V2 result.

## 11. Recommendations (each needs approval)

1. **Review and approve** `configs/feature_spec_v2.json` (or amend it), especially the conditional features.
   - **A1.1 correction:** draft.1 had five conditional or leakage-checked features, not four.
   - draft.2 has **seven**, in groups C1–C4, together with the thresholds still to be agreed (Amendment A1, unresolved ambiguities).
2. **Generator change before V2:** category-independent pacing drawn from one distribution, and wait-for-prompt before each line, so lines aren't lost and timing doesn't encode the profile.
3. **Implement** `scripts/extract_features_v2.py` with the tests in section 9, against the existing live logs only (no new traffic).
4. **Run L1–L7** on the existing labelled live run `train_v2_corrected`, as a dry run of the leakage checks, before any V2 generation.
5. **Revisit later:** TTY collection, if client-specific input features or binary payloads become a goal.

## Integrity

- **Created:**
  - `configs/feature_spec_v2.json`
  - `docs/feature_specification_v2.md`
  - `reports/common_feature_specification_v2/` (this report and `evidence/`)
- **Modified:** none.
- **Not touched:** Docker, Cowrie, the test split; nothing committed. Details are in the hand-off message.
