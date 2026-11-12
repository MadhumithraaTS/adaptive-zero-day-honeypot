"""Manual source-event comparisons for selected live sessions.

For each session: list its raw Cowrie events (time offset, event type, key field) and recompute the features
with a deliberately simple, independent implementation written directly from the specification text, then
compare with the extractor output in validation/<log>/. Writes validation/manual_comparisons.json and .md.
"""
import csv
import json
import statistics
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CASES = [
    ("confirmation_task9", "reports/cowrie_compatibility_confirmation/evidence/cowrie_confirmation_slice.json",
     "e209f8a07f2f", "botnet #2: wget to .example (DNS failure), chmod, ./malware.sh, exit"),
    ("payload_pilot", "reports/cowrie_payload_observability_pilot/evidence/cowrie_pilot_slice.json",
     "852266ae5622", "pilot C: Cowrie-executed script line recorded as command.input; redirect write"),
    ("train_v1", "dataset_builder/runs/train_v1/raw/cowrie_thisrun.json",
     "db3846f69175", "downloaded HTML executed by Cowrie's sh; many command.failed; url download"),
    ("eval_v1", "dataset_builder/runs/eval_v1/raw/cowrie_thisrun.json", None, "first session with scp stdin events"),
    ("smoke_test_task7", "reports/generator_cowrie_smoke_test/evidence/cowrie_smoke_slice.json",
     "fa31b41fec41", "task 7 botnet #2: wget to IP hung; download failed; no exit"),
    ("confirmation_task9", "reports/cowrie_compatibility_confirmation/evidence/cowrie_confirmation_slice.json",
     None, "first failed-login-only session"),
]


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def independent(events):
    """Straight from the spec text; no shared code with the extractor."""
    evs = sorted(enumerate(events), key=lambda p: (ts(p[1]["timestamp"]), p[0]))
    evs = [e for _, e in evs]
    kind = lambda k: [e for e in evs if e["eventid"] == k]  # noqa: E731
    succ, fail = kind("cowrie.login.success"), kind("cowrie.login.failed")
    lines = [e for e in kind("cowrie.command.input") if e["input"].strip() not in ("exit", "logout")]
    texts = [e["input"] for e in lines]
    nb = [len(t.encode("utf-8")) for t in texts]
    names = {t.split()[0] for t in texts if t.split()}
    t_lines = [ts(e["timestamp"]) for e in lines]
    gaps = [(b - a).total_seconds() for a, b in zip(t_lines, t_lines[1:])]
    closed, logc = kind("cowrie.session.closed"), kind("cowrie.log.closed")
    dl = kind("cowrie.session.file_download")
    nan = "NaN"
    return {
        "login_success": 1 if succ else 0, "login_failed_count": len(fail),
        "session_duration_s": float(closed[0]["duration"]) if closed else nan,
        "input_line_count": len(lines), "input_bytes_total": sum(nb),
        "input_line_max_bytes": float(max(nb)) if nb else nan, "unique_command_names": len(names),
        "shell_operator_lines": sum(any(op in t for op in ("|", ";", "&&", ">", "<", "`", "$(")) for t in texts),
        "download_command_lines": sum(bool(t.split()) and t.split()[0] in ("wget", "curl", "tftp", "ftp", "ftpget", "scp") for t in texts),
        "time_to_first_input_s": (t_lines[0] - ts(succ[0]["timestamp"])).total_seconds() if succ and lines else nan,
        "inter_input_mean_s": sum(gaps) / len(gaps) if len(lines) >= 2 else nan,
        "inter_input_std_s": statistics.pstdev(gaps) if len(lines) >= 3 else nan,
        "tty_output_bytes": (float(sum(int(e["size"]) for e in logc)) if logc else nan) if succ else 0.0,
        "unknown_command_events": len(kind("cowrie.command.failed")),
        "url_download_events": sum("url" in e for e in dl),
        "download_failed_events": len(kind("cowrie.session.file_download.failed")),
        "redirect_write_events": sum("destfile" in e and "url" not in e for e in dl),
        "scp_stdin_events": sum(e.get("realm") == "scp" for e in dl),
        "event_count": len(evs), "session_closed_observed": 1 if closed else 0,
    }


def same(a, b):
    if a == "NaN" or b == "NaN":
        return a == b
    return abs(float(a) - float(b)) < 1e-6


report, md = [], ["# Manual source-event comparisons", ""]
for log, rel, sid, purpose in CASES:
    events = [json.loads(line) for line in (REPO / rel).read_text(encoding="utf-8").splitlines() if line.strip()]
    if sid is None:
        if log == "eval_v1":
            sid = next(e["session"] for e in events if e.get("realm") == "scp")
        else:
            sids = {e["session"] for e in events}
            sid = sorted(s for s in sids if not any(e["session"] == s and e["eventid"] == "cowrie.login.success" for e in events))[0]
    session = [e for e in events if e["session"] == sid]
    meta = list(csv.DictReader(open(HERE / "validation" / log / "session_metadata.csv", encoding="utf-8")))
    feats = list(csv.DictReader(open(HERE / "validation" / log / "model_features.csv", encoding="utf-8")))
    row = next(i for i, m in enumerate(meta) if m["session_ref"] == sid)
    extracted = {**feats[row], **{k: v for k, v in meta[row].items() if k not in ("row", "session_ref", "feature_spec_version")}}
    expected = independent(session)
    diffs = {k: (expected[k], extracted[k]) for k in expected if not same(expected[k], extracted[k])}
    t0 = ts(min(session, key=lambda e: ts(e["timestamp"]))["timestamp"])
    listing = [f"{(ts(e['timestamp']) - t0).total_seconds():8.3f}s  {e['eventid']:38s} "
               f"{(e.get('input') or e.get('url') or e.get('destfile') or e.get('realm') or e.get('size') or e.get('duration') or '')!s:.60}"
               for e in sorted(session, key=lambda e: ts(e["timestamp"]))]
    report.append({"log": log, "session": sid, "purpose": purpose, "events": len(session), "extracted": extracted,
                   "independent": expected, "differences": diffs, "warnings": meta[row]["warnings"]})
    md += [f"## {log} / {sid}: {purpose}", "", "```"] + (listing if len(listing) <= 40 else listing[:20] + [f"... {len(listing) - 30} more ..."] + listing[-10:]) + ["```", "",
           "| feature | extracted | independent |", "|---|---|---|"]
    md += [f"| {k} | {extracted[k]} | {expected[k]} |" for k in expected]
    md += ["", f"Warnings: `{meta[row]['warnings'] or 'none'}`. Differences: **{len(diffs)}**.", ""]
    print(f"{log:20s} {sid} events={len(session):3d} differences={diffs or 0} warnings={meta[row]['warnings'] or '-'}")
(HERE / "validation" / "manual_comparisons.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
(HERE / "validation" / "manual_comparisons.md").write_text("\n".join(md) + "\n", encoding="utf-8")
