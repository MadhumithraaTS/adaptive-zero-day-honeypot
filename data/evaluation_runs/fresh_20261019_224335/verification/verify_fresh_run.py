"""Read-only verification of a fresh evaluation run. Writes only verification.json in the run directory."""
import csv
import json
import math
import subprocess
import sys
from pathlib import Path

REPO = Path(r"C:\AMRITA\Final_Year_Project_zero_day_27\adaptive-zero-day-honeypot")
RUN = Path(sys.argv[1])
T0 = sys.argv[2]            # UTC ISO timestamp taken just before generation
EXPECTED_NEW = int(sys.argv[3])
CATALOG = REPO / "reports/novelty_assessment/held_out/revised/reference_signatures/behaviour_signatures.json"

problems = []


def check(condition, message):
    if not condition:
        problems.append(message)
    return condition


def no_dup(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle, object_pairs_hook=no_dup)


def load_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def details_ids(path, name):
    data = load_json(path)
    check(isinstance(data, dict), f"{name} is not an object keyed by session ID")
    for key, rec in data.items():
        nested = rec.get("features", {}).get("session_id") if isinstance(rec, dict) else None
        check(type(nested) is str and nested == key, f"{name}: key {key!r} != features.session_id {nested!r}")
    return data


# --- Known session-ID sets ------------------------------------------------------------------------
head_text = subprocess.run(["git", "show", "HEAD:data/parsed/session_details.json"], cwd=REPO,
                           capture_output=True, text=True, encoding="utf-8", check=True).stdout
known = {
    "git_HEAD_baseline_54": set(json.loads(head_text)),
    "baseline_backup": set(details_ids(REPO / "data/baseline_backup_20261019_213122/data/parsed/session_details.json", "backup")),
    "working_tree_data_parsed": set(details_ids(REPO / "data/parsed/session_details.json", "working tree")),
    "demo_20261019_213439": set(details_ids(REPO / "data/demo_20261019_213439/parsed/session_details.json", "demo")),
    "fresh_20261019_210649_snapshot": set(details_ids(REPO / "data/fresh_evaluation/fresh_20261019_210649/features/snapshot_session_details.json", "previous fresh snapshot")),
}
catalog = load_json(CATALOG)
known["reference_catalogue"] = {str(i) for s in catalog["signatures"] for i in s.get("activity_profile", {}).get("session_ids", [])}
known_union = set().union(*known.values())
known_details_union = set(load_json(RUN / "inputs/known_sessions.json"))
check(known_union == known_details_union, "known_sessions.json does not cover every known session ID")

# --- Snapshot and fresh selection ----------------------------------------------------------------
snapshot = details_ids(RUN / "pipeline/parsed/session_details.json", "snapshot")
S = set(snapshot)
new_ids = S - known_union
fresh = details_ids(RUN / "fresh/fresh_session_details.json", "fresh")
D = set(fresh)
check(D == new_ids, "prepare_fresh_evaluation selection != snapshot minus all known IDs")
check(all(fresh[k] == snapshot[k] for k in D), "fresh records differ from snapshot records")
overlaps = {name: len(D & ids) for name, ids in known.items()}
check(all(v == 0 for v in overlaps.values()), f"fresh sessions overlap a known set: {overlaps}")

# --- Raw-log evidence that the new sessions were created by this run -------------------------------
events = {}
with open(RUN / "raw/cowrie.json", encoding="utf-8") as handle:
    for line in handle:
        if line.strip():
            event = json.loads(line)
            if isinstance(event.get("session"), str):
                events.setdefault(event["session"], []).append(event)
per_session = {}
for sid in sorted(D):
    ev = events.get(sid, [])
    ids = [e.get("eventid") for e in ev]
    start = min(e["timestamp"] for e in ev)
    per_session[sid] = {
        "start_utc": start,
        "end_utc": max(e["timestamp"] for e in ev),
        "login_success": "cowrie.login.success" in ids,
        "commands": [e.get("input") for e in ev if e.get("eventid") == "cowrie.command.input"],
        "closed": "cowrie.session.closed" in ids,
    }
    check(start >= T0, f"session {sid} started before this run ({start} < {T0})")
check(len(D) == EXPECTED_NEW, f"expected {EXPECTED_NEW} new sessions, found {len(D)}")
old_in_snapshot = sorted(S - D)

# --- Fresh features / DEC / novelty consistency ----------------------------------------------------
cfg = load_json(REPO / "ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/artifacts/config.json")
features = cfg["features"]
prep = load_json(RUN / "fresh/preparation_summary.json")
check(prep.get("required_dec_features") == features, "preparation feature order != config.json")
check(prep.get("new_session_count") == len(D), "preparation new_session_count mismatch")

feat_h, feat_rows = load_csv(RUN / "fresh/fresh_behavior_features.csv")
dec_h, dec_rows = load_csv(RUN / "dec/dec_results.csv")
nov_h, nov_rows = load_csv(RUN / "novelty/novelty_assessment_results.csv")
for name, rows in (("features", feat_rows), ("dec", dec_rows), ("novelty", nov_rows)):
    ids = [r["session_id"] for r in rows]
    check(len(ids) == len(set(ids)) and set(ids) == D, f"{name} CSV session IDs != fresh set")
prob_cols = ["cluster_0_prob", "cluster_1_prob", "cluster_2_prob"]
check(dec_h == feat_h + ["dec_cluster", "dec_confidence"] + prob_cols, "unexpected DEC column layout")

feat_by_id = {r["session_id"]: r for r in feat_rows}
cluster_counts, confidences = {}, []
for row in dec_rows:
    sid = row["session_id"]
    for f in features:
        check(math.isclose(float(row[f]), float(feat_by_id[sid][f]), rel_tol=1e-12, abs_tol=1e-12), f"DEC {sid} {f} mismatch")
    probs = [float(row[c]) for c in prob_cols]
    conf = float(row["dec_confidence"])
    check(abs(sum(probs) - 1) < 1e-4, f"DEC {sid} probabilities do not sum to 1")
    check(probs.index(max(probs)) == int(row["dec_cluster"]), f"DEC {sid} cluster != argmax")
    check(abs(max(probs) - conf) < 1e-6, f"DEC {sid} confidence != max prob")
    cluster_counts[row["dec_cluster"]] = cluster_counts.get(row["dec_cluster"], 0) + 1
    confidences.append(conf)

# Pipeline (full snapshot) DEC rows for the same sessions must match the fresh DEC rows.
_, snap_dec = load_csv(RUN / "pipeline/processed/dec_results.csv")
snap_by_id = {r["session_id"]: r for r in snap_dec}
check(set(snap_by_id) == S, "pipeline DEC IDs != snapshot IDs")
for row in dec_rows:
    other = snap_by_id[row["session_id"]]
    check(all(row[c] == other[c] for c in ["dec_cluster", "dec_confidence"] + prob_cols),
          f"fresh DEC row for {row['session_id']} differs from pipeline DEC row")
snapshot_cluster_counts = {}
for r in snap_dec:
    snapshot_cluster_counts[r["dec_cluster"]] = snapshot_cluster_counts.get(r["dec_cluster"], 0) + 1

nov_summary = load_json(RUN / "novelty/novelty_assessment_summary.json")
category_counts = {}
for r in nov_rows:
    category_counts[r["assessment_category"]] = category_counts.get(r["assessment_category"], 0) + 1
check(nov_summary.get("processed_session_count") == len(D), "novelty processed count mismatch")
check(nov_summary.get("category_counts") == category_counts, "novelty summary counts != CSV counts")

result = {
    "t0_utc": T0,
    "known_set_sizes": {k: len(v) for k, v in known.items()},
    "known_union_size": len(known_union),
    "snapshot_session_count": len(S),
    "snapshot_previously_known_count": len(old_in_snapshot),
    "new_session_count": len(D),
    "new_session_ids": sorted(D),
    "new_session_overlap_with_known_sets": overlaps,
    "new_sessions": per_session,
    "dec_cluster_counts_new": dict(sorted(cluster_counts.items())),
    "dec_confidence_new": {"min": min(confidences), "mean": sum(confidences) / len(confidences), "max": max(confidences)} if confidences else None,
    "dec_per_session": {r["session_id"]: {"cluster": r["dec_cluster"], "confidence": r["dec_confidence"],
                                          "probs": [r[c] for c in prob_cols]} for r in dec_rows},
    "dec_cluster_counts_full_snapshot": dict(sorted(snapshot_cluster_counts.items())),
    "novelty_category_counts": category_counts,
    "novelty_per_session": {r["session_id"]: {"category": r["assessment_category"], "closest": r["closest_signature_id"],
                                              "score": r["score"], "second": r["second_score"]} for r in nov_rows},
    "novelty_evaluation_mode": nov_summary.get("evaluation_mode"),
    "novelty_reference_session_id_count": nov_summary.get("reference_session_id_count"),
    "novelty_overlapping_session_count": nov_summary.get("overlapping_session_count"),
    "novelty_warnings": nov_summary.get("warnings"),
    "problems": problems,
    "verdict": "PASS" if not problems else "FAIL",
}
(RUN / "verification").mkdir(exist_ok=True)
(RUN / "verification/verification.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
print(json.dumps(result, indent=2))
sys.exit(0 if not problems else 1)
