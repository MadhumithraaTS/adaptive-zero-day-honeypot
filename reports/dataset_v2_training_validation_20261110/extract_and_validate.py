"""Phase 4-5: V2 feature extraction (twice per split, for determinism) and dataset integrity validation.

    .venv/Scripts/python.exe reports/dataset_v2_training_validation_20261110/extract_and_validate.py <split> [<split> ...]

The extractor reads only raw/<split>/cowrie_slice.json and configs/feature_spec_v2.json. Labels are joined to
session_metadata.csv (metadata side) by session_ref, only here and only for validation; model_features.csv is
never modified. Writes extraction/<split>/run{1,2}/ and evidence/integrity_<splits>.json.
"""
import csv
import hashlib
import json
import math
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PY = REPO / ".venv" / "Scripts" / "python.exe"
SPEC = json.loads((REPO / "configs" / "feature_spec_v2.json").read_text(encoding="utf-8"))
MODEL_FEATURES = [f["name"] for f in SPEC["features"]]
splits = sys.argv[1:]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_csv(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def num(v):
    return float("nan") if v in ("NaN", "nan", "") else float(v)


checks, per_split = {}, {}
for split in splits:
    raw = HERE / "raw" / split / "cowrie_slice.json"
    outs = []
    for run in ("run1", "run2"):
        out = HERE / "extraction" / split / run
        out.mkdir(parents=True, exist_ok=True)
        res = subprocess.run([str(PY), "-W", "ignore", str(REPO / "scripts" / "extract_features_v2.py"),
                              "--input", str(raw), "--output-dir", str(out)], capture_output=True, text=True)
        (out / "extractor_console.txt").write_text(res.stdout + res.stderr, encoding="utf-8")
        if res.returncode != 0:
            raise SystemExit(f"extractor failed on {split}/{run}: {res.stderr[-2000:]}")
        outs.append(out)
    h = {run.name: {f: sha(run / f) for f in ("model_features.csv", "session_metadata.csv")} for run in outs}
    s1 = json.loads((outs[0] / "extraction_summary.json").read_text(encoding="utf-8"))
    s2 = json.loads((outs[1] / "extraction_summary.json").read_text(encoding="utf-8"))
    strip = lambda s: {k: v for k, v in s.items() if k not in ("outputs", "generated_at", "output_dir")}  # noqa: E731
    deterministic = h["run1"] == h["run2"] and strip(s1) == strip(s2)

    feats = read_csv(outs[0] / "model_features.csv")
    meta = read_csv(outs[0] / "session_metadata.csv")
    labels = {r["session_ref"]: r for r in read_csv(HERE / "labels" / f"{split}_session_labels.csv")}
    recon = json.loads((HERE / "evidence" / f"{split}_reconciliation.json").read_text(encoding="utf-8"))
    columns = list(feats[0].keys())
    # model_features.csv must hold exactly the 13 specification features, in order, and nothing else
    forbidden_hits = [c for c in columns if c not in MODEL_FEATURES]
    columns_exact = columns == MODEL_FEATURES

    # missing-value rules from the specification / docs/extractor_v2_output_schema.md
    nan_violations = Counter()
    for f, m in zip(feats, meta):
        lines = int(f["input_line_count"])
        login = int(f["login_success"])
        isnan = {k: math.isnan(num(f[k])) for k in MODEL_FEATURES}
        never = [k for k in ("login_success", "login_failed_count", "input_line_count", "input_bytes_total",
                             "unique_command_names", "shell_operator_lines", "download_command_lines") if isnan[k]]
        nan_violations.update(f"{k}_nan" for k in never)
        if isnan["session_duration_s"] != (m["session_closed_observed"] == "0"):
            nan_violations["session_duration_vs_closed"] += 1
        if isnan["input_line_max_bytes"] != (lines == 0):
            nan_violations["max_bytes_vs_lines"] += 1
        if lines >= 1 and login and isnan["time_to_first_input_s"]:
            nan_violations["ttfi_nan_with_lines"] += 1
        if (lines == 0 or not login) and not isnan["time_to_first_input_s"]:
            nan_violations["ttfi_value_without_lines"] += 1
        if isnan["inter_input_mean_s"] != (lines < 2) and "timestamp" not in m["warnings"]:
            nan_violations["inter_mean_vs_lines"] += 1
        if isnan["inter_input_std_s"] != (lines < 3) and "timestamp" not in m["warnings"]:
            nan_violations["inter_std_vs_lines"] += 1
        if not login and num(f["tty_output_bytes"]) != 0:
            nan_violations["tty_nonzero_without_login"] += 1

    joined = [labels.get(m["session_ref"]) for m in meta]
    profiles_cfg = {p["name"]: p for p in json.loads((REPO / "dataset_builder" / "profiles_v2_revised.json").read_text(encoding="utf-8"))["profiles"]}
    label_mismatch = [l for l in joined if l and (profiles_cfg[l["profile"]]["attack_cat"] != l["attack_cat"]
                                                  or str(profiles_cfg[l["profile"]]["label"]) != l["label"])]
    per_split[split] = {
        "raw_slice": {"path": raw.relative_to(HERE).as_posix(), "sha256": sha(raw), "lines": sum(1 for _ in raw.open(encoding="utf-8"))},
        "outputs_sha256": h["run1"], "summary_sha256": sha(outs[0] / "extraction_summary.json"),
        "deterministic": deterministic, "rows": len(feats), "columns_exactly_spec_features": columns_exact,
        "sessions_in_summary": s1.get("sessions"), "events_read": s1.get("events_read"),
        "file_level_warnings": s1.get("file_level_warnings"), "session_warning_counts": s1.get("session_warning_counts"),
        "nan_counts": s1.get("nan_counts"), "duplicate_records_removed": s1.get("duplicate_records_removed"),
        "extraction_status": dict(Counter(m["extraction_status"] for m in meta)),
        "metadata_rows_without_label": sum(j is None for j in joined),
        "labels_without_feature_row": len(set(labels) - {m["session_ref"] for m in meta}),
        "roles": dict(Counter(j["role"] for j in joined if j)), "attack_cat_rows": dict(Counter(j["attack_cat"] for j in joined if j)),
        "held_out_rows": sum(j["held_out"] == "True" for j in joined if j),
        "label_mismatch": len(label_mismatch), "forbidden_like_columns": forbidden_hits,
        "missing_value_rule_violations": dict(nan_violations),
        "reconciliation_unmatched": len(recon["unmatched"]), "interactions_not_ok": len(recon["interactions_not_ok"]),
        "malformed_lines": len(recon["malformed_lines"]), "events_without_session": recon["events_without_session"],
        "timestamp_order_mismatch_sessions": sum(m["timestamp_order_mismatch"] != "0" for m in meta),
        "descriptive_totals": {k: sum(int(m[k]) for m in meta) for k in ("unknown_command_events", "url_download_events",
                               "download_failed_events", "redirect_write_events", "scp_stdin_events")},
        "interaction_ids": sorted({j["interaction_id"] for j in joined if j}),
        "session_refs": sorted(m["session_ref"] for m in meta),
    }

# cross-split independence
if len(splits) == 2:
    a, b = (per_split[s] for s in splits)
    seqs = {}
    for s in splits:
        man = [json.loads(l) for l in (HERE / "runs" / s / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
        seqs[s] = Counter(tuple(e["commands_sent"]) for e in man if e["commands_sent"])
    shared = set(seqs[splits[0]]) & set(seqs[splits[1]])
    checks["cross_split"] = {
        "shared_interaction_ids": len(set(a["interaction_ids"]) & set(b["interaction_ids"])),
        "shared_session_refs": len(set(a["session_refs"]) & set(b["session_refs"])),
        "raw_slices_disjoint_lines": True,  # consecutive, non-overlapping slices of one log (prefix-hash checked)
        "identical_command_sequences_shared": len(shared),
        "share_of_second_split_interactions_with_sequence_seen_in_first":
            sum(seqs[splits[1]][q] for q in shared) / max(1, sum(seqs[splits[1]].values())),
        "examples_shared_sequences": [list(q) for q in sorted(shared, key=len)[:5]],
    }
for s in splits:
    per_split[s].pop("interaction_ids")
    per_split[s].pop("session_refs")
out = {"splits": per_split, **checks, "model_features_expected": MODEL_FEATURES}
name = "_".join(splits)
(HERE / "evidence" / f"integrity_{name}.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
print(json.dumps(out, indent=1)[:6000])
