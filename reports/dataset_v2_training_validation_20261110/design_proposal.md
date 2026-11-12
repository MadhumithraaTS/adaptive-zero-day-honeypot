# Dataset V2 training/validation — design proposal (Task 14B, Phase 2)

**Status:** proposal for approval. **No traffic has been generated.** Phase 1 (pre-generation audit) will run
immediately before generation, so its evidence is current when traffic starts.

## 1. What the approved project design defines

| Item | Source | Defined? |
|---|---|---|
| Separate runs per split: train with seed A, validation with seed B | `reports/research_integrity_audit_20261110/dataset_v2_experimental_protocol.md` §5 | **Yes** |
| Group unit = generated interaction (manifest entry); all its Cowrie sessions (failed attempts + logged-in) in one split | same, §5 | **Yes** |
| Held-out profiles (data_exfiltration) appear **only** in the later, sealed test run | same, §5 | **Yes**, but conflicts with Task 14B "Preserve all seven categories" |
| Label = generation intent from the manifest; label-quality gate | same, §4 | **Yes** |
| Generate the test run last, with a disjoint placeholder pool | same, §5–6 | Yes (not part of this task) |
| **Number of interactions per split** | — | **No.** The V2 protocol gives no size |
| **`--speed`** (pacing compression; must be equal across all V2 runs) | — | **No** |
| Precedent (V1, generator 2.0, not V2) | `docs/dataset_and_evaluation_methodology.md` §3.2; `dataset_builder/runs/*/run_meta.json` | `train_v1` 1,500 interactions (seed 1, held-out excluded); `eval_v1` 600 (seed 2, held-out included); both `--speed 8` |

Because the sample size and speed are not defined, and the held-out treatment conflicts with the task, these
three items need a decision before generation.

## 2. Facts that bound the choice

- **Run time** at `--speed 1`, measured from the Task 13B smoke test: about **16.0 s per interaction** (failed
  attempts, think time, prompt waits and the 0.8 s inter-session gap included; mix weighted as the generator
  draws it).
  - 1,500 interactions ≈ 6.7 h; 600 ≈ 2.7 h; 1,200 ≈ 5.3 h; 900 ≈ 4.0 h.
  - Higher speed divides think time but not connection, authentication or Cowrie execution time.
- **Log rotation:** Cowrie rotates `cowrie.json` at 00:00 UTC. A run that crosses midnight breaks the
  line-count baseline, so **each run must start and end within one UTC day**. Separate runs may fall on
  different days.
- **Category mix:** `weighted_profile_order` draws profiles randomly with benign weighted 3 (others 1). With six
  training profiles, that gives about 37.5% benign and about 12.5% for each attack category. Counts per
  category are random, not fixed. The generator must not be changed, so exact equal counts would need
  one run per profile (as in the smoke test), which departs from the "one run per split" protocol.
- **Speed and timing features:** at `--speed 8`, think times shrink about 8×, but the 11.7 s Cowrie `find /`
  execution does not. That would make the find delay dominate privilege-escalation durations even more than at
  speed 1. Task 11 found that generator-2.0 timing (speed 8) drove C2/C3. Speed must be identical for train,
  validation and the later test.

## 3. Proposed design (recommended values marked)

| Item | Proposal |
|---|---|
| Profiles | `dataset_builder/profiles_v2_revised.json` (`79d47ac4…`), passed explicitly via `--config` |
| Generator | `dataset_builder/generate_labelled_traffic.py` 2.1 (`f8c55f9d…`), unchanged; prompt-gated; default readiness policy (20 s prompt timeout) |
| **Train run** | **1,500 interactions** (V1 precedent), planning seed **A = 14101**, pacing seed **9401** |
| **Validation run** | **600 interactions** (V1 precedent), planning seed **B = 14102**, pacing seed **9402** |
| **Held-out exfiltration** | **Recommended: excluded from both** (protocol §5; it stays for the sealed test run), giving 6 categories in train/validation. Alternative: include in validation only (as `eval_v1` did) |
| **Speed** | **Recommended: `--speed 1`** (realistic pacing; same as the smoke test). Total about 9.3 h: train ≈ 6.7 h and validation ≈ 2.7 h, each within one UTC day. Alternative: `--speed 8` (V1 precedent, about 2–3 h total) at the cost of stronger relative timing artefacts |
| Seeds check | All seeds verified unused (`find_pacing_seed_reuse` over `dataset_builder/runs` and `reports/`) before connecting |
| Output | `reports/dataset_v2_training_validation_20261110/runs/{train,validation}/` (manifest, terminal_output, run_meta), plus a raw Cowrie slice per run taken from the recorded baseline |
| Labels / reconciliation | Exact pairing of Cowrie sessions (connect order) with manifest authentication attempts, checked by credentials and outcome (as in Task 13B). Every Cowrie session gets its interaction ID (`split`, `index`) as metadata only |
| Features | `scripts/extract_features_v2.py --input <run slice>` per split; outputs `model_features.csv`, `session_metadata.csv`, `extraction_summary.json`; repeated twice to prove determinism |
| Split independence | Separate runs and seeds; interaction IDs are disjoint by construction. Command-sequence overlap between splits is reported (identical sequences across runs are expected from shared templates and are not leakage of the same interaction) |
| Failures | No silent regeneration. Failed or incomplete sessions stay in the data with their recorded termination. Replacements only with approval, labelled as such |

**Stopped for approval of: sample size, speed, and held-out handling.**

## 4. Decision (user, 2026-11-10, ~12:55 UTC)

| Item | Approved |
|---|---|
| Sample size | **Train 1,500 + validation 600 interactions** |
| Speed | **`--speed 1`** (for train, validation and the later test) |
| Held-out `data_exfiltration` | **Excluded from both splits** (protocol §5); reserved for the sealed test run |

Seeds as proposed: train planning 14101 / pacing 9401; validation planning 14102 / pacing 9402.
