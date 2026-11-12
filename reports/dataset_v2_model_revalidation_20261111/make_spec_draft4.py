"""Task 17: write feature specification revision 2.0.0-draft.4 as a NEW file (deterministic; refuses to overwrite).

    .venv/Scripts/python.exe reports/dataset_v2_model_revalidation_20261111/make_spec_draft4.py

configs/feature_spec_v2.json (draft.3) is read and left byte-identical: scripts/extract_features_v2.py checks
spec_version == '2.0.0-draft.3' at load time, and neither the extractor nor its tests may change. draft.4 changes only
eligibility metadata ('active' flags with dated reasons, model-input pointer); all 13 definitions and formulas are copied
unchanged, so extraction under draft.3 is valid for draft.4 (versioning policy: deactivation needs no re-extraction).
"""
import copy
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "configs" / "feature_spec_v2.json"
DST = REPO / "configs" / "feature_spec_v2_draft4.json"
FROZEN = REPO / "configs" / "model_features_v2_frozen.json"
DATE = "2026-11-11"

INACTIVE = {
    "login_failed_count": "C1 fails: equals 1 - login_success in every Dataset V2 row (Spearman -1.0); no within-session retries (Task 15, Task 16).",
    "download_command_lines": "L1/C4 fail after the Task 12 vocabulary redesign: constant 1 in every botnet session; C4 handling 'if still failing -> inactive' (Task 15, Task 16).",
    "unique_command_names": "Deactivated member of the redundant pair with input_line_count (Spearman 0.91); its additional information is template repetition structure (Task 16).",
    "input_line_max_bytes": "Strongest command-length template fingerprint: L1 (botnet outside every other range 53%) and L2 lookup 0.71 fail (Task 15, Task 16).",
    "input_bytes_total": "Conditional at the Task 16 freeze; user decision 2026-11-11 (Task 17 approval): inactive. Its information beyond input_line_count is command length, the same template-length mechanism as input_line_max_bytes.",
}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


if DST.exists():
    sys.exit(f"{DST} exists; refusing to overwrite")
src_hash = sha(SRC)
spec = json.loads(SRC.read_text(encoding="utf-8"))
assert spec["spec_version"] == "2.0.0-draft.3"
frozen = json.loads(FROZEN.read_text(encoding="utf-8"))
new = copy.deepcopy(spec)
new["spec_version"] = "2.0.0-draft.4"
new["status"] = ("draft - eligibility revision; formulas identical to 2.0.0-draft.3, which scripts/extract_features_v2.py "
                 "implements and loads from configs/feature_spec_v2.json")
for f in new["features"]:
    if f["name"] in INACTIVE:
        f["active"] = False
        f["inactive_since"] = {"revision": "2.0.0-draft.4", "date": DATE, "reason": INACTIVE[f["name"]]}
active = [f["name"] for f in new["features"] if f["active"]]
assert active == frozen["model_input_features"], (active, frozen["model_input_features"])
new["model_input_configuration"] = {
    "authoritative": "configs/model_features_v2_frozen.json",
    "sha256": sha(FROZEN),
    "model_input_features": frozen["model_input_features"],
    "note": ("The frozen configuration is the authoritative model-input list and order. Its record still shows "
             "input_bytes_total as 'conditional' (its state at the Task 16 freeze; the file is frozen and was not edited); "
             "the approved 2026-11-11 decision makes it inactive here. The model-input list is identical either way."),
}
new["extraction_compatibility"] = {
    "extractor": "scripts/extract_features_v2.py implements 2.0.0-draft.3 and loads configs/feature_spec_v2.json",
    "draft3_file_sha256": src_hash,
    "consequence": "All 13 columns are still extracted; datasets extracted under draft.3 are valid under draft.4 without re-extraction.",
}
new["amendments"].insert(0, {
    "revision": "2.0.0-draft.4", "date": DATE, "task": "17 (eligibility decisions from Tasks 15-16)",
    "changes": [
        "active=false (with inactive_since reason) for login_failed_count, download_command_lines, unique_command_names, "
        "input_line_max_bytes, input_bytes_total. Definitions, formulas, dtypes and output columns unchanged.",
        "Active (model input) features, in specification order: " + ", ".join(active) + ".",
        "model_input_configuration added: configs/model_features_v2_frozen.json is authoritative.",
        "Written as a new file (configs/feature_spec_v2_draft4.json) because the unchanged extractor requires draft.3 at "
        "configs/feature_spec_v2.json; that file is kept byte-identical.",
    ],
})
new["feature_counts"]["active_model_inputs"] = len(active)
new["feature_counts"]["inactive"] = sorted(INACTIVE)
DST.write_text(json.dumps(new, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
assert sha(SRC) == src_hash
check = json.loads(DST.read_text(encoding="utf-8"))
old_defs = {f["name"]: {k: v for k, v in f.items() if k not in ("active", "inactive_since")} for f in spec["features"]}
new_defs = {f["name"]: {k: v for k, v in f.items() if k not in ("active", "inactive_since")} for f in check["features"]}
print(json.dumps({"written": str(DST.relative_to(REPO)), "sha256": sha(DST), "draft3_unchanged": sha(SRC) == src_hash,
                  "definitions_identical": old_defs == new_defs, "feature_count": len(check["features"]),
                  "historical_revisions_kept": [a["revision"] for a in check["amendments"]], "active": active}, indent=1))
