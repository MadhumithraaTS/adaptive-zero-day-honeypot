"""Task 19B: assemble run_manifest.json (freeze checks, approved design, generation, sealing, scoring, output hashes).

    .venv/Scripts/python.exe reports/cowrie_sealed_exfiltration_evaluation_20261111/make_manifest.py
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def j(p):
    return json.loads((HERE / p).read_text(encoding="utf-8"))


console = (HERE / "logs" / "generator_console_test.txt").read_text(encoding="utf-8").splitlines()
run_meta = json.loads((HERE / "runs" / "test" / "run_meta.json").read_text(encoding="utf-8"))
sealed_raw = {}
for line in (HERE / "evidence" / "sealed_raw_hashes.txt").read_text().splitlines()[1:]:
    h, p = line.split(maxsplit=1)
    sealed_raw[p.lstrip("*")] = h
scoring = j("evidence/scoring_record.json")
manifest = {
    "task": "Task 19B - one-time sealed test evaluation of the frozen Cowrie novelty baseline",
    "single_approved_evaluation": True,
    "statement": ("This was the single approved evaluation of the sealed data_exfiltration test run. The test run was generated "
                  "once, sealed by hash before extraction, extracted once (plus one identical determinism repeat), scored once "
                  "(lock file evidence/SCORING_DONE.lock), and not rerun."),
    "freeze_verification": j("evidence/freeze_verification.json"),
    "approved_design": {"decided": "2026-11-11 (user answers)", "interactions": 600, "composition": "data_exfiltration only (single-profile config)",
                        "placeholders": "disjoint documentation-only IPs and .example domains; {dir} unchanged",
                        "planning_seed": 14103, "pacing_seed": 9403, "speed": 1, "generator": "2.1 (unchanged)",
                        "config": {"path": "reports/cowrie_sealed_exfiltration_evaluation_20261111/config/profiles_v2_sealed_exfiltration.json",
                                   "sha256": sha(HERE / "config" / "profiles_v2_sealed_exfiltration.json"),
                                   "derivation": j("evidence/test_config_derivation.json")}},
    "preflight": {p.name: p.read_text(encoding="utf-8") for p in sorted((HERE / "preflight").iterdir()) if p.is_file()},
    "generation": {"command": next((l[2:] for l in console if l.startswith("$ ")), None), "console_head": console[0], "console_tail": console[-3:],
                   "run_meta": run_meta},
    "sealed_raw_hashes": sealed_raw,
    "reconciliation": {k: v for k, v in j("evidence/test_reconciliation.json").items() if k not in ("eventid_counts",)},
    "sealed_extraction": j("evidence/sealed_extraction_hashes.json"),
    "preregistered_classification_rules": {"path": "evidence/preregistered_classification_rules.json",
                                           "sha256": sha(HERE / "evidence" / "preregistered_classification_rules.json"),
                                           "hashed_at": (HERE / "evidence" / "preregistered_rules_sha256.txt").read_text().strip().splitlines()[-1]},
    "scoring": scoring,
    "deliverable_sha256": {p: sha(HERE / p) for p in ("test_feature_summary.csv", "test_scores.csv", "flagged_session_analysis.csv", "method_comparison.csv")},
    "figures_sha256": {p.name: sha(p) for p in sorted((HERE / "figures").glob("*.png"))},
}
(HERE / "run_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
print("run_manifest.json written;", len(manifest["sealed_raw_hashes"]), "sealed raw files;", "scored", scoring["scored_logged_in"])
