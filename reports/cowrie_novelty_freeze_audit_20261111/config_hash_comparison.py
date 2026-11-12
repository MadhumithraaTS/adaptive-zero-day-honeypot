"""Task 19A: configuration hash comparison (before / after Task 19A) and which configuration applies to which experiment.

    .venv/Scripts/python.exe reports/cowrie_novelty_freeze_audit_20261111/config_hash_comparison.py
Reads evidence/hashes_before.txt (captured before any Task 19A change). Writes configuration_hash_comparison.json.
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
ROWS = [
    ("configs/model_features_v2_frozen.json", "clustering feature configuration 1.0.0 (canonical path, restored)",
     "Task 16 freeze; Task 17 AE+K-Means/DEC revalidation (asserted by revalidate_v2.py, recorded in models/dataset_v2_revalidation_20261111/*/config.json); spec draft.4 'authoritative' pointer"),
    ("configs/model_features_v2_frozen_v1.1.0.json", "clustering feature configuration 1.1.0 (versioned revision)",
     "Task 18 novelty baseline (hash recorded in configs/cowrie_novelty_baseline_v1.json); input_bytes_total inactive; same 8 inputs"),
    ("reports/dataset_v2_feature_freeze_20261111/model_features_v2_frozen.json", "archived 1.0.0 (Task 16 copy)", "restore source"),
    ("reports/cowrie_novelty_baseline_20261111/config/model_features_v2_frozen_v1.1.0.json", "archived 1.1.0 (Task 18 copy)", "reference copy"),
    ("configs/cowrie_novelty_baseline_v1.json", "novelty configuration (provisional, separate from both)", "Task 18; unchanged by Task 19A"),
    ("configs/feature_spec_v2.json", "feature specification 2.0.0-draft.3", "extractor contract; unchanged"),
    ("configs/feature_spec_v2_draft4.json", "feature specification 2.0.0-draft.4", "eligibility revision; unchanged"),
    ("scripts/extract_features_v2.py", "feature extractor", "unchanged"),
]


def sha(p):
    return hashlib.sha256((REPO / p).read_bytes()).hexdigest()


before = {}
for line in (HERE / "evidence" / "hashes_before.txt").read_text().splitlines()[1:]:
    h, p = line.split(maxsplit=1)
    before[p.lstrip("*")] = h
files = []
for p, what, applies in ROWS:
    row = {"path": p, "what": what, "applies_to": applies, "sha256_before_task19a": before.get(p), "sha256_after": sha(p)}
    if p.endswith(".json"):
        j = json.loads((REPO / p).read_text(encoding="utf-8"))
        row["version"] = j.get("config_version") or j.get("spec_version")
        if "model_input_features" in j:
            row["model_input_features"] = j["model_input_features"]
        elif j.get("config_name") == "cowrie_novelty_baseline":
            row["novelty_features"] = j["features"]
    files.append(row)
v100 = json.loads((REPO / ROWS[0][0]).read_text(encoding="utf-8"))
v110 = json.loads((REPO / ROWS[1][0]).read_text(encoding="utf-8"))
out = {"files": files,
       "v1_0_0_vs_v1_1_0": {"model_inputs_identical_and_same_order": v100["model_input_features"] == v110["model_input_features"],
                            "status_differences": {f["name"]: [f["final_status"], g["final_status"]] for f, g in zip(v100["features"], v110["features"])
                                                   if f["final_status"] != g["final_status"]},
                            "extracted_features_13": len(v100["specification"]["extracted_features_in_order"]) == 13},
       "canonical_now_equals_archived_1_0_0": sha(ROWS[0][0]) == sha(ROWS[2][0]),
       "versioned_1_1_0_equals_task18_copy": sha(ROWS[1][0]) == sha(ROWS[3][0]),
       "unchanged_by_task19a": [r["path"] for r in files if r["sha256_before_task19a"] == r["sha256_after"]],
       "changed_by_task19a": [r["path"] for r in files if r["sha256_before_task19a"] not in (None, r["sha256_after"])],
       "created_by_task19a": [r["path"] for r in files if r["sha256_before_task19a"] is None]}
(HERE / "configuration_hash_comparison.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
for r in files:
    print(f"{r['path'][:78]:80s} {(r['sha256_before_task19a'] or '-')[:12]:12s} -> {r['sha256_after'][:12]}  {r.get('version', '')}")
print({k: out[k] for k in ("v1_0_0_vs_v1_1_0", "canonical_now_equals_archived_1_0_0", "versioned_1_1_0_equals_task18_copy", "changed_by_task19a", "created_by_task19a")})
