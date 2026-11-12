"""Task 19B: reconcile the sealed test run, extract V2 features twice (determinism) and seal the extraction.

    .venv/Scripts/python.exe reports/cowrie_sealed_exfiltration_evaluation_20261111/postprocess_test.py

Reconciliation is the Task 14B reconcile_split.py logic (Cowrie sessions in connect order <-> manifest auth attempts,
checked by username, password and outcome; mismatches recorded, never dropped). Features come only from the raw Cowrie
slice through the unchanged scripts/extract_features_v2.py. This script does not read or summarise feature values; it
only checks structure and records hashes (evidence/sealed_extraction_hashes.json). Scoring is a separate one-time step.
"""
import csv
import hashlib
import json
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PY = REPO / ".venv" / "Scripts" / "python.exe"
RAW = HERE / "raw" / "test" / "cowrie_slice.json"
MAN = HERE / "runs" / "test" / "manifest.jsonl"
EXIT = ("exit", "logout")


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


# ---- verify the sealed raw evidence is unchanged since generation
sealed = {}
for line in (HERE / "evidence" / "sealed_raw_hashes.txt").read_text().splitlines()[1:]:
    h, p = line.split(maxsplit=1)
    sealed[p.lstrip("*")] = h
raw_ok = {p: sha(REPO / p) == h for p, h in sealed.items()}
if not all(raw_ok.values()):
    sys.exit(f"sealed raw evidence changed: {raw_ok}")

# ---- reconciliation (Task 14B logic)
events, malformed = [], []
for n, line in enumerate(RAW.read_text(encoding="utf-8").splitlines(), 1):
    if line.strip():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            malformed.append({"line": n, "error": str(exc)})
by_session = defaultdict(list)
for e in events:
    if "session" in e:
        by_session[e["session"]].append(e)
connect = {s: min(ts(e["timestamp"]) for e in evs if e["eventid"] == "cowrie.session.connect")
           for s, evs in by_session.items() if any(e["eventid"] == "cowrie.session.connect" for e in evs)}
sessions = sorted(connect, key=connect.get)
manifest = [json.loads(l) for l in MAN.read_text(encoding="utf-8").splitlines()]
expected = [(entry, k, u, p, k == len(entry["auth_attempts"]) - 1) for entry in manifest for k, (u, p) in enumerate(entry["auth_attempts"])]
unmatched, labels, not_ok = [], [], []
for i in range(max(len(sessions), len(expected))):
    sid = sessions[i] if i < len(sessions) else None
    if i >= len(expected) or sid is None:
        unmatched.append({"position": i, "cowrie_session": sid})
        continue
    entry, k, user, pw, final = expected[i]
    evs = sorted(by_session[sid], key=lambda e: ts(e["timestamp"]))
    logins = [e for e in evs if e["eventid"] in ("cowrie.login.success", "cowrie.login.failed")]
    m_out = entry["auth_log"][k]["outcome"] if k < len(entry["auth_log"]) else "missing"
    c_out = logins[0]["eventid"].split(".")[-1] if len(logins) == 1 else f"{len(logins)}_login_events"
    cred_ok = len(logins) == 1 and logins[0]["username"] == user and logins[0]["password"] == pw
    out_ok = (m_out == "accepted") == (c_out == "success")
    if not (cred_ok and out_ok):
        unmatched.append({"position": i, "cowrie_session": sid, "manifest": [entry["index"], k + 1]})
    role = "logged_in" if final and m_out == "accepted" else ("final_attempt_rejected" if final else "failed_guess")
    labels.append({"session_ref": sid, "split": "test", "interaction_id": f"test:{entry['index']}", "attempt": k + 1,
                   "profile": entry["profile"], "attack_cat": entry["attack_cat"], "label": entry["label"],
                   "held_out": entry["held_out"], "role": role, "manifest_termination": entry["termination"] if final else "",
                   "pairing_ok": cred_ok and out_ok})
    if final and entry["auth_success"]:
        rec = [e["input"] for e in evs if e["eventid"] == "cowrie.command.input" and e["input"].strip() not in EXIT]
        if not (rec == entry["commands_sent"] and entry["termination"] == "clean_exit"
                and not any(c["readiness_reason"] == "timeout" for c in entry["command_log"])):
            not_ok.append({"interaction": entry["index"], "termination": entry["termination"],
                           "order_matches": rec == entry["commands_sent"]})
(HERE / "labels").mkdir(exist_ok=True)
with open(HERE / "labels" / "test_session_labels.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(labels[0]))
    w.writeheader()
    w.writerows(labels)
recon = {"cowrie_events": len(events), "malformed_lines": malformed, "events_without_session": sum("session" not in e for e in events),
         "cowrie_sessions": len(sessions), "manifest_attempts": len(expected), "interactions": len(manifest),
         "unmatched": unmatched, "interactions_not_clean": not_ok,
         "terminations": dict(Counter(e["termination"] for e in manifest)), "profiles": dict(Counter(e["profile"] for e in manifest)),
         "roles": dict(Counter(l["role"] for l in labels)), "src_ips": dict(Counter(e.get("src_ip") for e in events)),
         "eventid_counts": dict(Counter(e["eventid"] for e in events)),
         "download_or_upload_events": sum("file_download" in e["eventid"] or "file_upload" in e["eventid"] for e in events),
         "time_range": [min(e["timestamp"] for e in events), max(e["timestamp"] for e in events)]}
(HERE / "evidence" / "test_reconciliation.json").write_text(json.dumps(recon, indent=2), encoding="utf-8")

# ---- extraction twice (unchanged extractor), structural checks only
outs = []
for run in ("run1", "run2"):
    out = HERE / "extraction" / "test" / run
    out.mkdir(parents=True, exist_ok=True)
    res = subprocess.run([str(PY), "-W", "ignore", str(REPO / "scripts" / "extract_features_v2.py"), "--input", str(RAW), "--output-dir", str(out)],
                         capture_output=True, text=True)
    (out / "extractor_console.txt").write_text(res.stdout + res.stderr, encoding="utf-8")
    if res.returncode != 0:
        sys.exit(f"extractor failed: {res.stderr[-2000:]}")
    outs.append(out)
h = {o.name: {f: sha(o / f) for f in ("model_features.csv", "session_metadata.csv")} for o in outs}
spec = json.loads((REPO / "configs" / "feature_spec_v2.json").read_text(encoding="utf-8"))
with open(outs[0] / "model_features.csv", encoding="utf-8", newline="") as f:
    header = next(csv.reader(f))
with open(outs[0] / "session_metadata.csv", encoding="utf-8", newline="") as f:
    meta_refs = [r["session_ref"] for r in csv.DictReader(f)]
summary = json.loads((outs[0] / "extraction_summary.json").read_text(encoding="utf-8"))
seal = {"sealed_utc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "raw_evidence_unchanged_since_generation": raw_ok,
        "deterministic_two_runs": h["run1"] == h["run2"], "outputs_sha256": h["run1"],
        "extraction_summary_sha256": sha(outs[0] / "extraction_summary.json"),
        "labels_sha256": sha(HERE / "labels" / "test_session_labels.csv"),
        "reconciliation_sha256": sha(HERE / "evidence" / "test_reconciliation.json"),
        "columns_exactly_spec_13": header == [f["name"] for f in spec["features"]],
        "rows": len(meta_refs), "sessions_in_summary": summary.get("sessions"), "file_level_warnings": summary.get("file_level_warnings"),
        "every_feature_row_labelled": set(meta_refs) == {l["session_ref"] for l in labels},
        "note": "feature values were not read or summarised before the one-time scoring step"}
(HERE / "evidence" / "sealed_extraction_hashes.json").write_text(json.dumps(seal, indent=2) + "\n", encoding="utf-8")
print(json.dumps({k: recon[k] for k in ("cowrie_events", "cowrie_sessions", "manifest_attempts", "interactions", "terminations", "roles", "src_ips", "download_or_upload_events")}, indent=1))
print("unmatched", len(unmatched), "not_clean", len(not_ok), "malformed", len(malformed))
print(json.dumps({k: seal[k] for k in ("deterministic_two_runs", "columns_exactly_spec_13", "rows", "every_feature_row_labelled")}, indent=1))
