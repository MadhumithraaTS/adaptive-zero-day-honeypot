# Task 26D-2 — Preserve Unique Task 26C Evidence and Clean Scratch Contents

Date: 2026-11-12 · Completed. No stop condition was triggered. Both scratch directories remain. Nothing committed.

## 1. Identification (before any change)
- **Scope of inspection:** only `cowrie/assessment_work/input`, `cowrie/assessment_work/output` and the Task 26C evidence directory. The 26D inventory and the two named source files for the copy check were also read.
- **Scratch contents:** 58 files, unchanged since the Task 26D review (same paths and SHA-256 values as `reports/key_custody_final_review_20261111/evidence/scratch_inventory.json`).
- **Unique files:** recomputed independently as files with no byte-identical copy in the Task 26C evidence package, the Task 26A captured events or the Task 22 calibration config. Result: **exactly six files, five unique contents**, identical to the Task 26D list. Identification was unambiguous.
- **Private keys:** a PEM private-key header scan of all 58 files found **none**.
- **Destination:** `reports/attribution_trust_boundary_remediation_20261111/evidence/attack_inputs/` did not exist. It was created as a new subdirectory, with creation set to fail if it already existed, so no existing evidence could be overwritten.

## 2. Preserved files

| File | Bytes | SHA-256 |
|---|---|---|
| `attackA_resigned_with_attacker_key_0.json` | 10265 | `5f479c09bd361db816eba0bd66d96c34926dc43dc6b6787add7d021c3ad2be27` |
| `attackA_signed_then_altered_0.json` | 10265 | `318af8367db131eb47592136a855a7bdb59f931294982734e603372df546d051` |
| `attackA_unsigned_S5_to_test_client_0.json` | 6944 | `13902d7bcada9aae4a8cee412e864d012e28338ebd7952a19047e4289a264b9b` |
| `attackB_signed_then_altered_0.json` | 10268 | `274751589194142f97c4ae82f12363f72bf0f381390dae02d37bd18ce5e1a6ff` |
| `attackB_unsigned_S4_to_unregistered_0.json` | 6942 | `e802e9ad663161c13963a69508e87c96de2e9b66f87d5b3c689e7c72248f2f74` |
| `genuine_plus_forged_1.json` | 6944 | `13902d7bcada9aae4a8cee412e864d012e28338ebd7952a19047e4289a264b9b` (same content as attack A unsigned) |

- **Source:** `cowrie/assessment_work/input/<file>`.
- **Destination:** `reports/attribution_trust_boundary_remediation_20261111/evidence/attack_inputs/<file>`.

## 3. Copy verification
- **Per file** (`copy_verification.json`): source and destination SHA-256 equal, sizes equal, and the destination parses as JSON (complete and readable). **6/6 verified.**
- **Manifest:** `evidence/attack_inputs/SHA256SUMS` was added. `sha256sum -c` gives **6/6 OK**, both before cleanup and after it.
  - The first version of this manifest had CRLF line endings, written by Python on Windows, so `sha256sum -c` could not find the files.
  - That was a formatting fault, not a hash mismatch; the per-file verification had already passed.
  - The manifest was rewritten with LF endings before any cleanup.
- **Existing Task 26C manifest:** 103 of its 106 entries still verify, including **every evidence file**. The 3 that differ are `threat_assessment/config.py`, `threat_assessment/signed_attribution.py` and `tests/test_trust_boundary.py`, which were changed on purpose in Task 26D-1; they match the Task 26D-1 manifest. The Task 26C report and its manifest were not edited. The only addition is the new `attack_inputs/` subdirectory.

## 4. Cleanup
- **Order:** cleanup started only after the six copies were verified.
- **Removed:**
  - the 13 files in `input/`;
  - the 9 case subdirectories in `output/` (45 files).
- **Method:** each entry was named by its explicit absolute path; no glob and no change of directory. Neither `input/` nor `output/` was removed.
- **Result** (`post_cleanup_checks.txt`):

| Check | Result |
|---|---|
| `input/` and `output/` exist | yes, both empty |
| NTFS ACLs before vs. after (`acl_before.txt`, `acl_after.txt`) | identical (inherited ACLs unchanged) |
| Compose config | valid; `threat-assessment` still binds `cowrie/assessment_work/input` → `/work/input` (read-only) and `cowrie/assessment_work/output` → `/work/output` |
| Inside the assessment container | `/work/input` exists, empty, read-only; `/work/output` exists, empty, writable |
| `cowrie/docker-compose.yml` | unchanged (`5d94ba5f…`, as in the Task 26D manifest) |

## 5. Confirmations
- **Only the two scratch directories were emptied.** No other file was deleted or modified. Additions are the six evidence copies with their manifest, and this report.
- **Not changed:** code, configs, policies, tests or Docker Compose. No key was generated, rotated, replaced, exported or deleted.
- **Not touched:** `cowrie/backups/pre_isolation_20261110/` (K-3). No migration step was run.
- **No protected data accessed.** No Dataset V2 raw files, sealed evaluation outputs or protected report folders were accessed, and no repository-wide search was run.

Stopped.
