"""Task 16: build, validate and freeze the Dataset V2 model-input feature configuration.

    .venv/Scripts/python.exe reports/dataset_v2_feature_freeze_20261111/build_freeze.py

Deterministic: decisions are fixed in DECISIONS below (evidence: Task 15 + evidence/correlated_pairs.json); the
feature order is the specification order; no timestamps are written. Reads (never writes) configs/feature_spec_v2.json
and scripts/extract_features_v2.py. Writes:
  configs/model_features_v2_frozen.json            (the frozen model-input configuration)
  <this dir>/model_features_v2_frozen.json         (byte-identical copy)
  <this dir>/feature_eligibility_final.csv
  <this dir>/feature_list_before_after.csv
  <this dir>/evidence/validation_checks.json
No model is trained, no score is computed, no test data is read.
"""
import csv
import hashlib
import io
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
SPEC_PATH = REPO / "configs" / "feature_spec_v2.json"
EXTRACTOR = REPO / "scripts" / "extract_features_v2.py"
T15 = REPO / "reports" / "dataset_v2_leakage_validation_20261111"
DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
PAIRS = HERE / "evidence" / "correlated_pairs.json"
FROZEN = REPO / "configs" / "model_features_v2_frozen.json"
EXPECTED = {"spec": "9401b355a1bfc48a14da32efba9ad4d5992f55233da3437a0715690d76f8fb1a",
            "extractor": "c0fdc684483e9953db2b6240994daa2b712d9782275eeebff9a38d57344cd5f2"}
STATUSES = ("eligible", "eligible_with_limitations", "conditional", "inactive")


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


# --- decisions (one per specification feature) ----------------------------------------------------------------------
# status in STATUSES; model_input is True only for eligible / eligible_with_limitations.
DECISIONS = {
    "login_success": dict(
        status="eligible_with_limitations",
        reason="Authentication outcome; behavioural and observable in deployment. Constant within logged-in sessions; across all sessions its category information is the designed failed-guess mix, not an artefact.",
        evidence="T15: logged-in constant (BA 0.167); all sessions eps2 0.159 [0.145, 0.171], BA 0.243; train/validation 0.159/0.159.",
        leakage_risks="Brute force contributes 32% of rows (5.1 rows per interaction); row-level metrics are dominated by its failed-guess rows.",
        deployment="High availability (Cowrie login events). Becomes a constant if a downstream model is trained on logged-in sessions only."),
    "login_failed_count": dict(
        status="inactive",
        reason="C1 fails: exactly 1 - login_success in every row (Spearman -1.0) and no within-session retries; no independent information.",
        evidence="T15 C1: 3,190/3,190 train and 1,257/1,257 validation rows equal 1 - login_success; 0 sessions with > 1 failed login.",
        leakage_risks="Pure duplicate of login_success; would double-weight authentication outcome.",
        deployment="Spec: low deployment compatibility (one connection per attempt in the lab)."),
    "session_duration_s": dict(
        status="eligible_with_limitations",
        reason="Passes C3 retention evidence on generator 2.1: no pre-fix 120/180 s sessions, L2 below the spec proposal, not mostly explained by category after line count. Category dependence comes from command count and from brute force.",
        evidence="T15: eps2 0.393 [0.354, 0.428] (val 0.380); without brute force 0.095, BA 0.209 (chance 0.20); residual after line count 0.066 (T11 0.64); failed sessions 1.1 s in all categories.",
        leakage_risks="Cowrie `find / -name id_rsa` executes ~11.6 s only in privilege_escalation (30 train / 9 validation sessions): a PE-only tail (21/30 above the non-PE p95). Category-level effect negligible (eps2 0.393 -> 0.385). Report a with/without-find sensitivity check in evaluation.",
        deployment="Low (spec): lab think time is the generator's pacing policy, not attacker behaviour."),
    "input_line_count": dict(
        status="eligible_with_limitations",
        reason="Retained member of the input_line_count / unique_command_names pair (Spearman 0.91): simplest provenance (count of recorded command.input lines, no tokenisation), most interpretable (activity volume), and lower category-leakage evidence than its partner.",
        evidence="T15: eps2 0.516 [0.478, 0.554] (val 0.517); without brute force 0.251; lookup 0.533. Pair analysis: eps2 0.404 vs 0.493 (sessions with input), 0.251 vs 0.364 without brute force.",
        leakage_risks="Brute force runs 0-1 commands (100% outside other categories' range); remaining signal is profile length. Mixes client and Cowrie-executed lines (spec limitation).",
        deployment="Medium: observable for real attackers; lab counts come from templates."),
    "input_bytes_total": dict(
        status="conditional",
        reason="Not resolved. With input_line_count retained, the information it adds is command length (bytes per line), the same template-length mechanism as input_line_max_bytes. It fails only the L2 lookup proposal (0.54 > 0.50), not L1, and command length can be behavioural in deployment. The evidence does not justify a clear choice, so it is excluded from model input pending review.",
        evidence="T15: eps2 0.588 [0.554, 0.622] (rose from T11 0.483); lookup 0.540; Spearman 0.83 with max bytes. Pair analysis (train): residual after line count eps2 0.419 [0.380, 0.457]; mean bytes per line eps2 0.520; residual after max bytes 0.047 without brute force (adds almost nothing beyond max bytes).",
        leakage_risks="Template string lengths (botnet and lateral download/URL lines ~15.6 bytes per line vs benign 10.8).",
        deployment="Medium: available in deployment; meaning in the lab is dominated by fixed templates."),
    "input_line_max_bytes": dict(
        status="inactive",
        reason="Strongest command-length fingerprint, failing L1 (botnet outside every other category's range in 53% of train / 58% of validation sessions) and the L2 lookup proposal (0.71), and the signal does not depend on brute force. It is the length-heavy member of the 0.83 pair and adds information beyond input_bytes_total (residual eps2 0.179).",
        evidence="T15: BA 0.569 (0.574 without brute force; chance 0.20), lookup 0.708, eps2 0.530 [0.496, 0.568]. Pair analysis: residual after bytes total eps2 0.179 [0.143, 0.221].",
        leakage_risks="Template line lengths (botnet median 39 bytes, PE 37, reconnaissance 20) identify categories directly.",
        deployment="Medium in principle; in lab data it measures template strings."),
    "unique_command_names": dict(
        status="inactive",
        reason="Deactivated member of the 0.91 pair: what it adds beyond input_line_count is template vocabulary structure (repeated command names per session: PE 1.29, reconnaissance 0.80, lateral 0.75, benign 0.11, botnet 0.07), and it carries more category information than its partner on both splits. Depends on first-token tokenisation.",
        evidence="T15: eps2 0.587 [0.551, 0.622] (val 0.594); lookup 0.554. Pair analysis: residual after line count eps2 0.467 [0.426, 0.511] (val 0.480); lines-minus-unique eps2 0.391.",
        leakage_risks="Profile vocabulary breadth and repetition per template.",
        deployment="Medium; would need consistent tokenisation of real attacker input."),
    "shell_operator_lines": dict(
        status="eligible_with_limitations",
        reason="Passes C4 retention evidence after the Task 12 redesign: non-zero in 5 of 6 categories including benign, varies within categories, single-feature BA at chance, lookup below 50%.",
        evidence="T15: eps2 0.215 [0.185, 0.247] (val 0.202); BA 0.167; lookup 0.374; non-zero benign 47%, botnet 47%, lateral 44%, reconnaissance 25%, PE 87%; flags 6/12 (T11 12/12).",
        leakage_risks="PE enrichment (87%, `2>/dev/null` on find).",
        deployment="Medium-high: pipes and redirections are common in real shells."),
    "download_command_lines": dict(
        status="inactive",
        reason="Fails L1 (constant 1 in 100% of botnet sessions) and C4 'values vary within categories' after the vocabulary redesign; the spec's C4 handling is 'if still failing -> inactive'.",
        evidence="T15: botnet modal 1 share 1.00 (unique to botnet); eps2 0.583 [0.544, 0.627]; 0.564 without brute force; non-zero benign 14%, reconnaissance 34%.",
        leakage_risks="Botnet fingerprint.",
        deployment="Download attempts are observable; completion impossible in the isolated lab."),
    "time_to_first_input_s": dict(
        status="eligible_with_limitations",
        reason="Passes C2 retention evidence: category-independent pacing, fixed speed, prompt-gated, not near-constant, L6 clean. Values carry no category information; flags come only from structural missingness.",
        evidence="T15: eps2 0.007 [0.002, 0.018] (val 0.005); CV 0.81; medians 1.56-1.80 s in all categories; manifest think-time eps2 0.006 (p 0.13); missingness V 0.68.",
        leakage_risks="NaN when there is no login or no input (50% of brute-force logins); missingness is a deterministic function of login_success and input_line_count and must not be re-encoded by imputation or indicators.",
        deployment="Low (spec): in lab data the value is a generator pacing draw."),
    "inter_input_mean_s": dict(
        status="eligible_with_limitations",
        reason="Passes C2 on values after the generator-2.1 pacing fix (eps2 0.786 -> 0.009).",
        evidence="T15: eps2 0.009 [0.003, 0.026] (val 0.016); 0.004 without find sessions; missingness V 1.00 (logged-in, brute force only).",
        leakage_risks="NaN for < 2 lines (all brute-force logins) - same imputation constraint. Cowrie find delay raises PE find sessions (median 3.9 s vs 1.83 s; ranges overlap). Spearman 0.79 with inter_input_std_s (below the 0.8 redundancy flag).",
        deployment="Low (spec)."),
    "inter_input_std_s": dict(
        status="eligible_with_limitations",
        reason="Passes C2 on values (eps2 0.405 -> 0.016). Kept: its correlation with inter_input_mean_s (0.79) is below the 0.8 redundancy flag used in Tasks 11/15, so dropping it would be a discretionary choice not supported by a stated criterion.",
        evidence="T15: eps2 0.016 [0.007, 0.035] (val 0.011); missingness V 0.97; NaN in 59.5% of all rows.",
        leakage_risks="NaN for < 3 lines - same imputation constraint; find delay adds variance in PE find sessions.",
        deployment="Low (spec)."),
    "tty_output_bytes": dict(
        status="eligible_with_limitations",
        reason="Output-volume leakage fell substantially (residual beyond input 0.42 -> 0.18); remaining information is mostly 'no commands -> tiny output' (brute force). Cowrie output is also what a deployed Cowrie produces.",
        evidence="T15: eps2 0.443 [0.403, 0.481] (val 0.451); without brute force 0.152; residual after input bytes 0.176; KS train vs validation p 0.50.",
        leakage_risks="Cowrie-emulation dependent (per-command emulated output size; 'command not found' text from emulation gaps).",
        deployment="Medium: in deployment it reflects Cowrie's emulation of real attacker commands."),
}


def build():
    spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    names = [f["name"] for f in spec["features"]]
    t15 = {r["feature"]: r for r in csv.DictReader(io.StringIO((T15 / "feature_eligibility.csv").read_text(encoding="utf-8")))}
    pairs = json.loads(PAIRS.read_text(encoding="utf-8"))
    pt = pairs["splits"]["train"]["spearman"]
    pv = pairs["splits"]["validation"]["spearman"]
    feats = []
    for i, f in enumerate(spec["features"], 1):
        d = DECISIONS[f["name"]]
        feats.append({"spec_index": i, "name": f["name"], "spec_status": f["status"], "spec_group": f.get("conditional_group"),
                      "spec_active": f["active"], "dtype": f["dtype"], "task15_status": t15[f["name"]]["recommended_status"],
                      "final_status": d["status"], "model_input": d["status"] in ("eligible", "eligible_with_limitations"),
                      "reason": d["reason"], "evidence": d["evidence"], "leakage_risks": d["leakage_risks"],
                      "deployment_limitations": d["deployment"]})
    model_inputs = [f["name"] for f in feats if f["model_input"]]
    cfg = {
        "config_name": "model_features_v2_frozen",
        "config_version": "1.0.0",
        "frozen": True,
        "freeze_date": "2026-11-11",
        "task": "Task 16 - finalise and freeze the Dataset V2 model feature set",
        "purpose": "Model-input selection layer over the unchanged V2 feature specification. The extractor still computes and writes all 13 features; only the columns listed in model_input_features, in this order, are model inputs.",
        "specification": {"path": "configs/feature_spec_v2.json", "spec_name": spec["spec_name"], "spec_version": spec["spec_version"],
                          "sha256": sha(SPEC_PATH), "extracted_feature_count": len(names), "extracted_features_in_order": names,
                          "note": "The specification's own 'active' flags are unchanged (all true). Its versioning policy implements deactivation by editing the spec; Task 16 forbids that, so deactivation is recorded here instead. Mirroring it into the spec (patch revision) needs separate approval."},
        "extractor": {"path": "scripts/extract_features_v2.py", "sha256": sha(EXTRACTOR)},
        "evidence": {
            "task15_report": "reports/dataset_v2_leakage_validation_20261111/report.md",
            "task15_feature_eligibility": {"path": "reports/dataset_v2_leakage_validation_20261111/feature_eligibility.csv",
                                           "sha256": sha(T15 / "feature_eligibility.csv")},
            "task15_results": {"path": "reports/dataset_v2_leakage_validation_20261111/tables/leakage_results.json",
                               "sha256": sha(T15 / "tables" / "leakage_results.json")},
            "correlated_pairs": {"path": "reports/dataset_v2_feature_freeze_20261111/evidence/correlated_pairs.json", "sha256": sha(PAIRS)},
            "dataset": {"path": "reports/dataset_v2_training_validation_20261110/", "SHA256SUMS_sha256": sha(DS / "SHA256SUMS")},
            "freeze_report": "reports/dataset_v2_feature_freeze_20261111/report.md",
        },
        "status_definitions": {
            "eligible": "Passes all checks with no material concern. Model input.",
            "eligible_with_limitations": "Passes the specification's retention evidence; remaining category information is behavioural design; limitations listed. Model input.",
            "conditional": "Unresolved; excluded from model input until a reviewed decision.",
            "inactive": "Fails a criterion whose specification handling is deactivation, or is the deactivated member of a redundant pair. Excluded from model input; still extracted.",
        },
        "selection_rules": [
            "Statuses follow the Task 15 evidence and the specification's C1-C4 retention criteria; no validation score was used to select features.",
            "Redundant pair (Spearman >= 0.8 on both splits): retain the member with simpler provenance and interpretability and lower training-split category-leakage evidence, provided the partner's additional information is template-specific; if criteria disagree, mark conditional.",
            "A conditional feature is never in model_input_features.",
            "Feature order = specification order.",
        ],
        "correlated_pairs": [
            {"pair": ["input_line_count", "unique_command_names"], "spearman_train": round(pt["input_line_count~unique_command_names"], 4),
             "spearman_validation": round(pv["input_line_count~unique_command_names"], 4), "retained": "input_line_count", "deactivated": "unique_command_names"},
            {"pair": ["input_bytes_total", "input_line_max_bytes"], "spearman_train": round(pt["input_bytes_total~input_line_max_bytes"], 4),
             "spearman_validation": round(pv["input_bytes_total~input_line_max_bytes"], 4), "retained": None,
             "deactivated": "input_line_max_bytes", "unresolved": "input_bytes_total (conditional, excluded pending review)"},
        ],
        "model_input_features": model_inputs,
        "model_input_count": len(model_inputs),
        "inactive_features": [f["name"] for f in feats if f["final_status"] == "inactive"],
        "conditional_features": [f["name"] for f in feats if f["final_status"] == "conditional"],
        "missing_value_constraints": [
            "NaN in time_to_first_input_s, inter_input_mean_s, inter_input_std_s and session-level undefined values are structural (Task 15: 0 unexplained).",
            "Missingness is a deterministic function of login_success and input_line_count; do not add missing-value indicator features and do not use an imputation that encodes 'no input' as a distinctive constant without review.",
            "The imputation method itself is a Task 17 preprocessing decision, fitted on training data only.",
        ],
        "evaluation_constraints": [
            "Report interaction-grouped and balanced metrics; brute force contributes 32% of rows.",
            "Report a sensitivity check with and without the 39 sessions containing the Cowrie `find / -name id_rsa` delay.",
            "data_exfiltration is absent from train/validation; the sealed test set is untouched.",
        ],
        "features": feats,
    }
    return json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", cfg


def csv_text(rows, cols):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({c: r[c] for c in cols})
    return buf.getvalue()


def validate(text, cfg):
    spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
    names = [f["name"] for f in spec["features"]]
    parsed = json.loads(text)
    statuses = {f["name"]: f["final_status"] for f in parsed["features"]}
    inputs = parsed["model_input_features"]
    second, _ = build()
    from scripts import extract_features_v2 as x2
    checks = {
        "1_all_13_features_accounted_for": sorted(statuses) == sorted(names) and len(parsed["features"]) == 13
                                            and all(s in STATUSES for s in statuses.values()),
        "2_no_inactive_in_model_inputs": not (set(inputs) & set(parsed["inactive_features"])),
        "3_no_conditional_in_model_inputs": not (set(inputs) & set(parsed["conditional_features"])),
        "3b_model_inputs_are_exactly_eligible": set(inputs) == {n for n, s in statuses.items() if s in ("eligible", "eligible_with_limitations")},
        "4_order_is_specification_order": inputs == [n for n in names if n in inputs],
        "4b_no_duplicates": len(inputs) == len(set(inputs)),
        "5_valid_json_roundtrip": json.loads(json.dumps(parsed)) == parsed,
        "6_reproducible_rebuild_identical": second == text,
        "6b_file_on_disk_identical": FROZEN.read_text(encoding="utf-8") == text,
        "7_spec_unchanged": sha(SPEC_PATH) == EXPECTED["spec"],
        "7b_extractor_unchanged": sha(EXTRACTOR) == EXPECTED["extractor"],
        "7c_extractor_still_outputs_13": list(x2.MODEL_FEATURES) == names,
        "8_model_inputs_subset_of_extracted_columns": set(inputs) <= set(names),
        "9_count_matches": parsed["model_input_count"] == len(inputs),
    }
    return checks


if __name__ == "__main__":
    text, cfg = build()
    FROZEN.write_text(text, encoding="utf-8", newline="\n")
    (HERE / "model_features_v2_frozen.json").write_text(text, encoding="utf-8", newline="\n")
    cols = ["spec_index", "name", "spec_status", "spec_group", "task15_status", "final_status", "model_input",
            "reason", "evidence", "leakage_risks", "deployment_limitations"]
    (HERE / "feature_eligibility_final.csv").write_text(csv_text(cfg["features"], cols), encoding="utf-8", newline="")
    ba = [{"spec_index": f["spec_index"], "name": f["name"], "extracted_before": True, "extracted_after": True,
           "spec_active_flag": f["spec_active"], "task11_decision": None, "task15_status": f["task15_status"],
           "final_status": f["final_status"], "model_input_after": f["model_input"],
           "model_input_position": cfg["model_input_features"].index(f["name"]) + 1 if f["model_input"] else ""} for f in cfg["features"]]
    t15 = {r["feature"]: r["task11_decision"] for r in csv.DictReader(io.StringIO((T15 / "feature_eligibility.csv").read_text(encoding="utf-8")))}
    for r in ba:
        r["task11_decision"] = t15[r["name"]]
    (HERE / "feature_list_before_after.csv").write_text(csv_text(ba, list(ba[0])), encoding="utf-8", newline="")
    checks = validate(text, cfg)
    out = {"checks": checks, "all_pass": all(checks.values()),
           "sha256": {"configs/model_features_v2_frozen.json": sha(FROZEN), "copy": sha(HERE / "model_features_v2_frozen.json"),
                      "feature_spec_v2.json": sha(SPEC_PATH), "extract_features_v2.py": sha(EXTRACTOR)},
           "model_input_features": cfg["model_input_features"]}
    (HERE / "evidence").mkdir(exist_ok=True)
    (HERE / "evidence" / "validation_checks.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(out, indent=1))
    sys.exit(0 if out["all_pass"] else 1)
