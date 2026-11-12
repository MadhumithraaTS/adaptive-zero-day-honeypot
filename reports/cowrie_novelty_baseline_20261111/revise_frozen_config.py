"""Task 18 Phase 1: build revision 1.1.0 of the frozen model-feature configuration (input_bytes_total -> inactive).

Task 19A: 1.1.0 lives at configs/model_features_v2_frozen_v1.1.0.json; configs/model_features_v2_frozen.json is the
original 1.0.0 and is never written by this script (asserted). The original Task 18 run wrote 1.1.0 over the canonical
path; Task 19A restored 1.0.0 there from the archive below.

    .venv/Scripts/python.exe reports/cowrie_novelty_baseline_20261111/revise_frozen_config.py

Only input_bytes_total's status changes (conditional -> inactive, user decision 2026-11-11). The 8 model inputs, their
order and all 13 extracted features are unchanged. 1.0.0 stays archived byte-identically in
reports/dataset_v2_feature_freeze_20261111/model_features_v2_frozen.json (verified here). The draft.3 specification
(extractor contract) and the draft.4 revision are read, never written. Refuses to run unless the input is exactly 1.0.0.
"""
import copy
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CFG = REPO / "configs" / "model_features_v2_frozen_v1.1.0.json"
CANONICAL_V100 = REPO / "configs" / "model_features_v2_frozen.json"
ARCHIVE = REPO / "reports" / "dataset_v2_feature_freeze_20261111" / "model_features_v2_frozen.json"
DRAFT3 = REPO / "configs" / "feature_spec_v2.json"
DRAFT4 = REPO / "configs" / "feature_spec_v2_draft4.json"
EXTRACTOR = REPO / "scripts" / "extract_features_v2.py"
V100 = "8ae17612eabbbc46240aa1011aff8d6e3617df85380b3daa523201675fc3c288"
EXPECTED = {"draft3": "9401b355a1bfc48a14da32efba9ad4d5992f55233da3437a0715690d76f8fb1a",
            "draft4": "7f444dd1b335865ee37c0ecc25905e474c39c71aeba04e6931d4af51380aeadf",
            "extractor": "c0fdc684483e9953db2b6240994daa2b712d9782275eeebff9a38d57344cd5f2"}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def build(v1):
    c = copy.deepcopy(v1)
    c["config_version"] = "1.1.0"
    c["freeze_date"] = "2026-11-11"
    c["revisions"] = [
        {"config_version": "1.1.0", "date": "2026-11-11", "task": "Task 18 Phase 1",
         "change": "input_bytes_total: conditional -> inactive (user decision with the Task 17 approval). model_input_features, "
                   "their order and the 13 extracted features unchanged.",
         "previous_sha256": V100,
         "previous_archive": "reports/dataset_v2_feature_freeze_20261111/model_features_v2_frozen.json"},
        {"config_version": "1.0.0", "date": "2026-11-11", "task": "Task 16 freeze", "sha256": V100},
    ]
    for f in c["features"]:
        if f["name"] == "input_bytes_total":
            f["final_status"] = "inactive"
            f["model_input"] = False
            f["status_history"] = [{"config_version": "1.0.0", "status": "conditional"},
                                   {"config_version": "1.1.0", "status": "inactive", "date": "2026-11-11"}]
            f["reason"] = ("Inactive by user decision (2026-11-11). Task 16 evidence: with input_line_count retained, its additional "
                           "information is command length (residual eps2 0.419; mean bytes per line eps2 0.520), the same template-length "
                           "mechanism that made input_line_max_bytes inactive. Previously conditional: " + f["reason"])
    c["inactive_features"] = [f["name"] for f in c["features"] if f["final_status"] == "inactive"]
    c["conditional_features"] = [f["name"] for f in c["features"] if f["final_status"] == "conditional"]
    for p in c["correlated_pairs"]:
        if "input_bytes_total" in p["pair"]:
            p["deactivated"] = ["input_line_max_bytes", "input_bytes_total"]
            p.pop("unresolved", None)
            p["resolution"] = "input_line_max_bytes inactive at 1.0.0; input_bytes_total inactive at 1.1.0 (user decision)"
    c["extracted_features"] = {"count": 13, "names_in_order": c["specification"]["extracted_features_in_order"],
                               "note": "All 13 are still extracted (scripts/extract_features_v2.py, unchanged); only model_input_features are model inputs."}
    c["specification"]["revisions"] = {
        "extractor_contract": {"path": "configs/feature_spec_v2.json", "spec_version": "2.0.0-draft.3", "sha256": sha(DRAFT3)},
        "eligibility_revision": {"path": "configs/feature_spec_v2_draft4.json", "spec_version": "2.0.0-draft.4", "sha256": sha(DRAFT4),
                                 "note": "draft.4 records the 1.0.0 hash of this file; it is preserved unchanged as a separate revision."},
    }
    c["superseded_reproduction_note"] = ("Scripts that assert the 1.0.0 hash (Task 16 build_freeze.py would rewrite 1.0.0; Task 17 "
                                         "revalidate_v2.py asserts 8ae17612...) reproduce against the archived 1.0.0 copy; the model "
                                         "inputs are identical.")
    return json.dumps(c, indent=2, ensure_ascii=False) + "\n", c


def validate(text, c):
    d3 = json.loads(DRAFT3.read_text(encoding="utf-8"))
    d4 = json.loads(DRAFT4.read_text(encoding="utf-8"))
    names = [f["name"] for f in d3["features"]]
    p = json.loads(text)
    st = {f["name"]: f["final_status"] for f in p["features"]}
    inp = p["model_input_features"]
    return {
        "all_13_accounted": sorted(st) == sorted(names) and len(p["features"]) == 13,
        "extracted_list_equals_spec_order": p["extracted_features"]["names_in_order"] == names,
        "model_inputs_unchanged_from_1_0_0": inp == json.loads(ARCHIVE.read_text(encoding="utf-8"))["model_input_features"],
        "model_inputs_in_spec_order": inp == [n for n in names if n in inp],
        "no_inactive_or_conditional_in_inputs": not (set(inp) & (set(p["inactive_features"]) | set(p["conditional_features"]))),
        "input_bytes_total_inactive": st["input_bytes_total"] == "inactive",
        "no_conditional_left": p["conditional_features"] == [],
        "inputs_equal_draft4_active": inp == [f["name"] for f in d4["features"] if f["active"]],
        "draft3_unchanged": sha(DRAFT3) == EXPECTED["draft3"],
        "draft4_unchanged": sha(DRAFT4) == EXPECTED["draft4"],
        "extractor_unchanged": sha(EXTRACTOR) == EXPECTED["extractor"],
        "archive_is_1_0_0": sha(ARCHIVE) == V100,
        "valid_json_roundtrip": json.loads(json.dumps(p)) == p,
        "deterministic_rebuild": build(json.loads(ARCHIVE.read_text(encoding="utf-8")))[0] == text,
    }


if __name__ == "__main__":
    if sha(CANONICAL_V100) != V100:
        sys.exit(f"{CANONICAL_V100} is not the original 1.0.0; refusing (it must never be overwritten)")
    v1 = json.loads(ARCHIVE.read_text(encoding="utf-8"))
    text, c = build(v1)
    if not CFG.exists():
        CFG.write_text(text, encoding="utf-8", newline="\n")
    elif CFG.read_text(encoding="utf-8") != text:
        sys.exit(f"{CFG} differs from the deterministic 1.1.0 build; refusing")
    (HERE / "config").mkdir(exist_ok=True)
    (HERE / "config" / "model_features_v2_frozen_v1.1.0.json").write_text(text, encoding="utf-8", newline="\n")
    checks = validate(text, c)
    out = {"checks": checks, "all_pass": all(checks.values()), "sha256_1_1_0": sha(CFG), "sha256_1_0_0_archive": sha(ARCHIVE),
           "model_input_features": c["model_input_features"], "inactive_features": c["inactive_features"]}
    (HERE / "config" / "frozen_config_revision_checks.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(out, indent=1))
    sys.exit(0 if out["all_pass"] else 1)
