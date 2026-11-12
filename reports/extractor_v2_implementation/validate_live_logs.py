"""Validate scripts/extract_features_v2.py on existing live Cowrie logs (no new traffic).

    .venv/Scripts/python.exe reports/extractor_v2_implementation/validate_live_logs.py

For each log: extract twice into validation/<name>/ (byte-identical check), record every file opened during
extraction (sys.addaudithook), and check session coverage, missing-value rules and output separation.
Writes validation/validation_results.json.
"""
import csv
import hashlib
import json
import math
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
from scripts import extract_features_v2 as x2  # noqa: E402

LOGS = {
    "train_v1": "dataset_builder/runs/train_v1/raw/cowrie_thisrun.json",
    "eval_v1": "dataset_builder/runs/eval_v1/raw/cowrie_thisrun.json",
    "payload_pilot": "reports/cowrie_payload_observability_pilot/evidence/cowrie_pilot_slice.json",
    "smoke_test_task7": "reports/generator_cowrie_smoke_test/evidence/cowrie_smoke_slice.json",
    "confirmation_task9": "reports/cowrie_compatibility_confirmation/evidence/cowrie_confirmation_slice.json",
    "verification_task10a": "reports/diagnostic_redaction_utf8_fix/evidence/cowrie_verification_slice.json",
}
OPENED = []
sys.addaudithook(lambda event, args: OPENED.append(str(args[0])) if event == "open" and args and isinstance(args[0], str) else None)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def is_nan(value):
    return value == "NaN"


results = {}
for name, rel in LOGS.items():
    src = REPO / rel
    out_a, out_b = HERE / "validation" / name, HERE / "validation" / (name + "_rerun")
    for d in (out_a, out_b):
        shutil.rmtree(d, ignore_errors=True)
    OPENED.clear()
    summary = x2.extract([str(src)], str(out_a))
    opened_files = sorted({Path(p).name for p in OPENED if Path(p).suffix in (".json", ".jsonl", ".csv")})
    x2.extract([str(src)], str(out_b))
    deterministic = all(digest(out_a / f) == digest(out_b / f) for f in ("model_features.csv", "session_metadata.csv"))
    shutil.rmtree(out_b)

    input_sessions = set()
    for line in src.read_text(encoding="utf-8").splitlines():
        if line.strip():
            sid = json.loads(line).get("session")
            if sid:
                input_sessions.add(sid)
    feats = list(csv.DictReader(open(out_a / "model_features.csv", encoding="utf-8")))
    meta = list(csv.DictReader(open(out_a / "session_metadata.csv", encoding="utf-8")))
    header = list(feats[0].keys())
    violations = []
    for f, m in zip(feats, meta):
        n = int(f["input_line_count"])
        rules = [
            (f["login_success"] in ("0", "1"), "login_success_binary"),
            (f["login_success"] == "1" or (f["tty_output_bytes"] == "0.0" and is_nan(f["time_to_first_input_s"])),
             "no_login_implies_zero_tty_and_nan_first_input"),
            (n >= 1 or (is_nan(f["input_line_max_bytes"]) and f["unique_command_names"] == "0"
                        and f["input_bytes_total"] == "0"), "no_input_implies_nan_max_and_zero_counts"),
            (n >= 2 or is_nan(f["inter_input_mean_s"]), "lt2_inputs_implies_nan_mean"),
            (n >= 3 or is_nan(f["inter_input_std_s"]), "lt3_inputs_implies_nan_std"),
            (m["session_closed_observed"] == "1" or is_nan(f["session_duration_s"]), "no_close_implies_nan_duration"),
            (not is_nan(f["login_failed_count"]) and not is_nan(f["input_line_count"]), "never_missing_counts"),
        ]
        violations += [(m["session_ref"], rule) for ok, rule in rules if not ok]
    results[name] = {
        "input": rel, "input_sha256": digest(src), "events_read": summary["events_read"],
        "input_sessions": len(input_sessions), "output_sessions": len(meta),
        "all_sessions_present_once": sorted(input_sessions) == sorted(m["session_ref"] for m in meta),
        "model_matrix_columns": header, "model_matrix_is_13_features": header == x2.MODEL_FEATURES,
        "deterministic": deterministic, "files_opened": opened_files,
        "only_log_and_spec_read": set(opened_files) <= {src.name, "feature_spec_v2.json", "model_features.csv",
                                                        "session_metadata.csv", "extraction_summary.json"},
        "missing_value_rule_violations": violations,
        "sessions_with_warnings": summary["sessions_with_warnings"],
        "session_warning_counts": summary["session_warning_counts"],
        "file_level_warnings": len(summary["file_level_warnings"]),
        "duplicate_records_removed": summary["duplicate_records_removed"],
        "nan_counts": summary["nan_counts"],
    }
    r = results[name]
    print(f"{name:22s} events={r['events_read']:6d} sessions in={r['input_sessions']:5d} out={r['output_sessions']:5d} "
          f"all_present={r['all_sessions_present_once']} 13cols={r['model_matrix_is_13_features']} "
          f"deterministic={r['deterministic']} only_log+spec={r['only_log_and_spec_read']} "
          f"rule_violations={len(violations)} warned={r['sessions_with_warnings']} warnings={r['session_warning_counts']}")
(HERE / "validation" / "validation_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
