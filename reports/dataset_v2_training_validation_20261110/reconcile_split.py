"""Reconcile one generated split: manifest <-> Cowrie events; write per-session labels as metadata only.

    .venv/Scripts/python.exe reports/dataset_v2_training_validation_20261110/reconcile_split.py <split>

Inputs: runs/<split>/manifest.jsonl and raw/<split>/cowrie_slice.json (the Cowrie lines after the run's baseline).
Sessions are generated strictly sequentially, so Cowrie sessions in connect order pair one-to-one with the
manifest's authentication attempts in execution order; each pair is checked by username, password and outcome.
Mismatches are recorded, never dropped. Outputs (never model inputs):
  labels/<split>_session_labels.csv   session_ref -> split, interaction_id, attempt, profile, attack_cat, label, role
  evidence/<split>_reconciliation.json, evidence/<split>_profile_table.json
"""
import csv
import json
import statistics as st
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
split = sys.argv[1]
EXIT = ("exit", "logout")


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


events, malformed = [], []
for n, line in enumerate((HERE / "raw" / split / "cowrie_slice.json").read_text(encoding="utf-8").splitlines(), 1):
    if not line.strip():
        continue
    try:
        events.append(json.loads(line))
    except json.JSONDecodeError as exc:
        malformed.append({"line": n, "error": str(exc)})
by_session = defaultdict(list)
no_session = [e for e in events if "session" not in e]
for e in events:
    if "session" in e:
        by_session[e["session"]].append(e)
connect = {s: min(ts(e["timestamp"]) for e in evs if e["eventid"] == "cowrie.session.connect")
           for s, evs in by_session.items() if any(e["eventid"] == "cowrie.session.connect" for e in evs)}
sessions = sorted(connect, key=connect.get)
orphans = sorted(set(by_session) - set(connect))

manifest = [json.loads(l) for l in (HERE / "runs" / split / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
expected = [(entry, k, u, p, k == len(entry["auth_attempts"]) - 1)
            for entry in manifest for k, (u, p) in enumerate(entry["auth_attempts"])]

unmatched, labels, logged_in, per_cmd_rows = [], [], [], []
for i in range(max(len(sessions), len(expected))):
    sid = sessions[i] if i < len(sessions) else None
    if i >= len(expected) or sid is None:
        unmatched.append({"position": i, "cowrie_session": sid,
                          "manifest": None if i >= len(expected) else [expected[i][0]["index"], expected[i][1] + 1]})
        continue
    entry, k, user, pw, final = expected[i]
    evs = sorted(by_session[sid], key=lambda e: ts(e["timestamp"]))
    logins = [e for e in evs if e["eventid"] in ("cowrie.login.success", "cowrie.login.failed")]
    m_out = entry["auth_log"][k]["outcome"] if k < len(entry["auth_log"]) else "missing"
    c_out = logins[0]["eventid"].split(".")[-1] if len(logins) == 1 else f"{len(logins)}_login_events"
    cred_ok = len(logins) == 1 and logins[0]["username"] == user and logins[0]["password"] == pw
    out_ok = (m_out == "accepted") == (c_out == "success")
    if not (cred_ok and out_ok):
        unmatched.append({"position": i, "cowrie_session": sid, "manifest": [entry["index"], k + 1],
                          "manifest_outcome": m_out, "cowrie_outcome": c_out, "credentials_match": cred_ok})
    role = "logged_in" if final and m_out == "accepted" else ("final_attempt_rejected" if final else "failed_guess")
    labels.append({"session_ref": sid, "split": split, "interaction_id": f"{split}:{entry['index']}",
                   "attempt": k + 1, "profile": entry["profile"], "attack_cat": entry["attack_cat"],
                   "label": entry["label"], "held_out": entry["held_out"], "role": role,
                   "manifest_termination": entry["termination"] if final else "", "pairing_ok": cred_ok and out_ok})
    if not final:
        continue
    recorded = [e["input"] for e in evs if e["eventid"] == "cowrie.command.input"]
    rec_cmds = [c for c in recorded if c.strip() not in EXIT]
    sent = entry["commands_sent"]
    closed = [e for e in evs if e["eventid"] == "cowrie.session.closed"]
    rec = {
        "session_ref": sid, "interaction_id": f"{split}:{entry['index']}", "profile": entry["profile"],
        "status": entry["status"], "termination": entry["termination"], "error": entry["error"],
        "auth_success": entry["auth_success"], "shell_ready_initial": entry["shell_ready_initial"],
        "exit_sent": entry["exit_sent"], "exit_confirmed": entry["exit_confirmed"],
        "exit_in_cowrie": any(c.strip() == "exit" for c in recorded),
        "planned": len(entry["commands_planned"]), "sent": len(sent), "recorded": len(rec_cmds),
        "not_sent": [c["command"] for c in entry["command_log"] if not c["sent"]],
        "timeouts": [c["command"] for c in entry["command_log"] if c["readiness_reason"] == "timeout"],
        "order_matches": rec_cmds == sent,
        "sent_not_recorded": [c for c in sent if c not in rec_cmds],
        "recorded_not_sent": [c for c in rec_cmds if c not in sent],
        "closed": bool(closed), "cowrie_duration_s": float(closed[0]["duration"]) if closed else None,
        "download_events": [e["eventid"] for e in evs if "file_download" in e["eventid"] or "file_upload" in e["eventid"]],
        "command_failed": sum(e["eventid"] == "cowrie.command.failed" for e in evs),
    }
    rec["ok"] = (rec["order_matches"] and rec["termination"] == "clean_exit" and rec["exit_confirmed"]
                 and rec["exit_in_cowrie"] and rec["closed"] and not rec["timeouts"] and not rec["not_sent"]
                 and cred_ok and out_ok) if entry["auth_success"] else (cred_ok and out_ok)
    logged_in.append(rec)
    for c in entry["command_log"]:
        per_cmd_rows.append({"interaction_id": rec["interaction_id"], "profile": entry["profile"], "seq": c["seq"],
                             "command": c["command"], "sent": c["sent"], "prompt_returned": c["prompt_returned"],
                             "readiness_reason": c["readiness_reason"], "think_time_s": c["think_time_s"],
                             "wait_s": c["wait_s"], "output_chars": c["output_chars"]})

(HERE / "labels").mkdir(exist_ok=True)
(HERE / "evidence").mkdir(exist_ok=True)
with open(HERE / "labels" / f"{split}_session_labels.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(labels[0]))
    w.writeheader()
    w.writerows(labels)
with open(HERE / "evidence" / f"{split}_command_log.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(per_cmd_rows[0]))
    w.writeheader()
    w.writerows(per_cmd_rows)

table = []
for prof in sorted({e["profile"] for e in manifest}):
    rows = [r for r in logged_in if r["profile"] == prof]
    labs = [l for l in labels if l["profile"] == prof]
    table.append({
        "profile": prof, "interactions": len(rows),
        "cowrie_sessions": len(labs), "login_success": sum(l["role"] == "logged_in" for l in labs),
        "login_failed": sum(l["role"] != "logged_in" for l in labs),
        "interactions_without_login": sum(not r["auth_success"] for r in rows),
        "commands_planned": sum(r["planned"] for r in rows), "commands_sent": sum(r["sent"] for r in rows),
        "commands_recorded": sum(r["recorded"] for r in rows),
        "timeouts": sum(len(r["timeouts"]) for r in rows), "not_sent": sum(len(r["not_sent"]) for r in rows),
        "clean_exit": sum(r["termination"] == "clean_exit" for r in rows),
        "terminations": dict(Counter(r["termination"] for r in rows)),
        "order_mismatches": sum(not r["order_matches"] for r in rows if r["auth_success"]),
        "download_events": sum(len(r["download_events"]) for r in rows),
        "command_failed_events": sum(r["command_failed"] for r in rows),
        "duration_median_s": st.median([r["cowrie_duration_s"] for r in rows if r["cowrie_duration_s"] is not None] or [0]),
    })
result = {
    "split": split, "cowrie_events": len(events), "malformed_lines": malformed, "events_without_session": len(no_session),
    "sessions_without_connect": orphans, "cowrie_sessions": len(sessions), "manifest_attempts": len(expected),
    "interactions": len(manifest), "unmatched": unmatched,
    "src_ips": dict(Counter(e.get("src_ip") for e in events)),
    "interactions_not_ok": [r for r in logged_in if not r["ok"]],
    "eventid_counts": dict(Counter(e["eventid"] for e in events)),
    "time_range": [min(e["timestamp"] for e in events), max(e["timestamp"] for e in events)],
}
(HERE / "evidence" / f"{split}_reconciliation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
(HERE / "evidence" / f"{split}_profile_table.json").write_text(json.dumps(table, indent=2), encoding="utf-8")
print(f"{split}: events={len(events)} malformed={len(malformed)} no_session={len(no_session)} orphans={len(orphans)} "
      f"cowrie_sessions={len(sessions)} manifest_attempts={len(expected)} interactions={len(manifest)} "
      f"unmatched={len(unmatched)} not_ok={len(result['interactions_not_ok'])}")
for row in table:
    print(row)
