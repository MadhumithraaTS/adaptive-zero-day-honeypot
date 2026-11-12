# Dataset V2 experimental protocol (proposal; nothing here has been run)

Dataset V1 (the 1,800 synthetic sessions, its frozen 270-session test split, and every model and
report built on it) stays exactly as it is. V2 is a separate experiment with its own directories,
split and final test.

## 0. Principles

1. **Source:** every V2 session comes from a real Cowrie instance. No event is written by a generator.
2. **Features:** only from Cowrie events, using the common specification in `synthetic_vs_cowrie_comparison.md` section 4.
3. **Labels:** record generation intent (the manifest), not anything inferred from features.
4. **Splits:** separate before any fitting, grouped by generated interaction. Generate the test data last and score it once.
5. **Scope of claims:** a payload-like string typed into Cowrie's emulated shell is **a payload-delivery observation, not an exploit**. Cowrie does not execute binaries or have memory-corruption bugs. Section 3 separates the two.

## 1. Infrastructure and reproducibility record

Record each item in a run's `run_meta.json`, extending what `dataset_builder/generate_labelled_traffic.py` already writes:

- Cowrie image digest, Cowrie config hash and `userdb.txt` hash (`cowrie/userdb.txt`, see `dataset_builder/README.md`);
- `log_baseline_lines` (already implemented) and SHA-256 of the raw slice;
- profile file version and SHA-256, `--seed`, `--speed`, and the git commit of generator, builder and extractor;
- the feature-specification version;
- the Python environment lock (`pip freeze`) for both interpreters.

Keep one container per run, or one container with the existing baseline isolation, and never parallelise sessions (the matcher depends on order; `dataset_builder/README.md`).

## 2. Session generation

Use `dataset_builder/generate_labelled_traffic.py` (paramiko interactive shell, `channel.send(cmd + "\n")`), extended with profiles rather than a new path:

- **Legitimate:**
  - `benign_admin` (exists);
  - add at least two more benign styles, such as a developer session (git, editor, build commands) and monitoring scripts (short, regular);
  - give benign profiles a mix of failed first passwords so a failed login is not an attack marker.
- **Malicious, known:** reconnaissance, brute_force, botnet, privilege_escalation, lateral_movement (exist).
- **Held out for novelty:**
  - data_exfiltration (exists, `held_out: true`);
  - the payload-delivery profile below, also held out so it plays the "unseen" role honestly.
- **Behaviour variation inside a category:** keep the optional steps, alternative commands, placeholders and noise already in `profiles_v2.json`, and widen them so command sets overlap across categories (for example `uname -a` appears in several).
- **Avoiding artificial fingerprints:**
  - Don't attach any per-category constant to a feature-bearing quantity. Nothing equivalent to `tty_size_range` may exist; server output comes from Cowrie.
  - Draw pacing from one global distribution, then scale it by a per-session random factor shared by all categories, rather than fixing a `delay_range` per category. Document any category-specific pacing that is deliberate behaviour.
  - Draw credentials from one shared pool for all categories, except for brute-force guess lists. Credentials are never features.
  - The single source IP (Docker gateway) and constant fields are never features.

## 3. Buffer-overflow-style cases: two strictly separated levels

### Level 1: payload-delivery observation (in scope)

- **What it is:** an interactive session that, after login, types one long line containing a payload-like string. For example:
  - a printable NOP-like marker (`A` × N, or a `\x90`-escaped hex text);
  - a variant with raw non-ASCII bytes, to test how Cowrie logs them.

  Each payload's exact bytes and SHA-256 go into the manifest.
- **Claim allowed:** "a payload-like string was delivered to the honeypot and is visible in the features".
- **Claims not allowed:** "a buffer overflow occurred", "an exploit was executed", "a zero-day was detected".
- **Verify it reaches Cowrie as input:** for every Level 1 session, the raw log must contain a `cowrie.command.input` event whose `input` text matches the manifest payload, either byte for byte or under a documented normalisation. A `cowrie.command.failed` may follow. Record:
  - the normalisation Cowrie applies to non-ASCII bytes (unknown today; see the `\x90` limitation in `reports/buffer_overflow_telemetry_audit_20261110/report.md` section 8);
  - Cowrie's maximum line length, if it truncates.

  Abort the run if any Level 1 session lacks a matching input event.
- **Verify it is visible in features:** a unit test on the extractor, using that run's raw events, asserts:
  - `input_bytes` ≥ the payload length after normalisation;
  - `max_line_bytes` equals the payload line length;
  - `nonprintable_byte_share` > 0 for the raw-byte variant.

  Also report how the payload sessions differ from the matched profile without the payload (same commands minus the payload line), to isolate the payload's effect.

### Level 2: validated exploit (out of scope for Cowrie; only on separate approval)

A real buffer-overflow demonstration needs a deliberately vulnerable service in an isolated testbed, for example a lab binary built without stack protection, in a separate container with no network egress. Success would need its own evidence: a crash or a controlled return, captured by that service's own logging. Cowrie can't provide this, and Level 1 results must never be described as Level 2. This protocol does not recommend Level 2 for the current project.

## 4. Ground-truth labels

- **Primary label:** `intended_profile` / `attack_cat` from the manifest entry that produced the session, attached by the existing alignment in `dataset_builder/labelling.py` (credential-sequence alignment, `min_block`, clock tolerance).
- **Behaviour label (labelling v2):**
  - `failed_login`, `login_no_commands`, the profile category, `ambiguous`, `unassigned`;
  - training and evaluation use only confidently aligned sessions;
  - `ambiguous` and `unassigned` are reported but excluded from metrics.
- **For Level 1 payload sessions:** `payload_delivered = 1` only when the input-event check in section 3 passes for that session.
- **Label-quality gate:** `label_report.json` must show `out_of_window_dropped` = 0 and an inconsistent count of 0; otherwise the run is rejected, not patched.

## 5. Splits without session leakage

- **Group unit:** the manifest entry (`source_entry`). All Cowrie sessions from one entry (failed attempts plus the logged-in session) stay in one split.
- **Separate runs per split:**
  - train and validation from runs generated with seeds A and B;
  - the final test from a **later run with seed C and a disjoint placeholder pool** (different IPs, domains, file names in `profiles_v2.json` placeholders), so near-duplicate command strings can't cross splits;
  - held-out profiles (exfiltration, payload delivery) appear **only** in the test run.
- **Within train/validation:** if one run supplies both, use a grouped split on `source_entry` (`ml_pipeline/guard.py` `split(..., group_col=...)`), stratified on `attack_cat` as far as grouping allows.
- **Leakage checks before any fitting, on train only:**
  - single-feature category association (η²);
  - a range rule like the one in `reports/buffer_overflow_telemetry_audit_20261110/trace_check.py`;
  - duplicate command-sequence overlap between splits.

  Report the results and investigate any feature that alone identifies a category.

## 6. Preserving the untouched final test set

1. Generate the test run last, after model selection on train and validation is frozen.
2. Immediately after building it, record SHA-256 of `raw/`, `labelled/behavior_features.csv` and the manifest in a sealed file, and register its fingerprint with `guard.split`/`guard.final_test` (`ml_pipeline/guard.py`).
3. Don't open the test features until the final evaluation. Score once through `guard.final_test`. Any second evaluation needs a recorded override (`ml_pipeline/PIPELINE.md` convention).

## 7. Evaluation (pre-registered)

- **Clustering:** internal metrics on validation, for the baselines (K-Means on inputs, AE+K-Means) and DEC as a comparison. Bootstrap intervals over sessions grouped by `source_entry`.
- **Category alignment:** ARI and NMI against manifest labels, described as agreement with generation intent.
- **Novelty:** on the test run, the share of held-out sessions flagged and the share of known-profile sessions flagged (a false-positive proxy), with the novelty threshold fixed beforehand on validation.
- **Level 1 payload:** the share of payload sessions with `payload_delivered = 1`, and whether payload sessions are flagged or separated, compared with their payload-free twins.

## 8. Acceptance criteria before any V2 training

- Every `command.failed` has a matching `command.input` (section 4.8 of the comparison file).
- No feature depends on manifest or profile fields.
- The label-quality gate passes.
- Leakage checks are reported.
- All Level 1 sessions pass the input-event check.
- V1 hashes are unchanged.
