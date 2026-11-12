"""Reconcile manifests, terminal_output.jsonl and Cowrie events for the revised-profile smoke test (task 13B).

    .venv/Scripts/python.exe reports/revised_profile_cowrie_smoke_test/analyze_smoke.py

Input: evidence/cowrie_smoke_slice.json (Cowrie lines after the recorded baseline) and runs/<profile>/.
Cowrie sessions in connect order are paired one-to-one with the manifests' authentication attempts in execution
order and checked by username, password and outcome. Mismatches are recorded, never dropped.
Writes evidence/reconciliation.json, evidence/profile_table.json, evidence/command_results.json.
"""
import json
import statistics as st
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from dataset_builder.generate_labelled_traffic import PROMPT_RE  # noqa: E402

ORDER = ["benign_admin", "reconnaissance", "brute_force", "botnet", "privilege_escalation", "lateral_movement",
         "data_exfiltration"]
FOCUS = ["wget -qO-", "curl -I", "curl -s", "cd /tmp || cd /var/tmp", "groups"]
EXIT = ("exit", "logout")


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


events = [json.loads(l) for l in (HERE / "evidence" / "cowrie_smoke_slice.json").read_text(encoding="utf-8").splitlines() if l.strip()]
by_session = defaultdict(list)
for e in events:
    by_session[e["session"]].append(e)
sessions = sorted(by_session, key=lambda s: min(ts(e["timestamp"]) for e in by_session[s]))
non_ssh = [e for e in events if e.get("src_ip") != "172.22.0.2"]

expected, terminal, manifests = [], {}, {}
for profile in ORDER:
    run = HERE / "runs" / profile
    for line in (run / "terminal_output.jsonl").read_text(encoding="utf-8").splitlines():
        t = json.loads(line)
        terminal.setdefault((profile, t["index"]), []).append(t)
    manifests[profile] = [json.loads(l) for l in (run / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    for entry in manifests[profile]:
        for k, (user, pw) in enumerate(entry["auth_attempts"]):
            expected.append((profile, entry, k, user, pw, k == len(entry["auth_attempts"]) - 1))

unmatched, logged_in, guesses = [], [], []
for i in range(max(len(sessions), len(expected))):
    sid = sessions[i] if i < len(sessions) else None
    exp = expected[i] if i < len(expected) else None
    if sid is None or exp is None:
        unmatched.append({"position": i, "cowrie_session": sid, "manifest_attempt": exp and exp[:1] + exp[2:5]})
        continue
    profile, entry, k, user, pw, final = exp
    evs = sorted(by_session[sid], key=lambda e: ts(e["timestamp"]))
    logins = [e for e in evs if e["eventid"] in ("cowrie.login.success", "cowrie.login.failed")]
    manifest_outcome = entry["auth_log"][k]["outcome"]
    cowrie_outcome = logins[0]["eventid"].split(".")[-1] if len(logins) == 1 else f"{len(logins)} login events"
    cred_ok = len(logins) == 1 and logins[0]["username"] == user and logins[0]["password"] == pw
    outcome_ok = (manifest_outcome == "accepted") == (cowrie_outcome == "success")
    if not (cred_ok and outcome_ok):
        unmatched.append({"position": i, "cowrie_session": sid, "profile": profile, "index": entry["index"], "attempt": k + 1,
                          "expected": [user, "<pw>"], "cowrie_logins": [(e["eventid"], e["username"]) for e in logins],
                          "manifest_outcome": manifest_outcome})
    closed = [e for e in evs if e["eventid"] == "cowrie.session.closed"]
    base = {"session": sid, "profile": profile, "manifest_index": entry["index"], "attempt": k + 1,
            "manifest_outcome": manifest_outcome, "cowrie_login": cowrie_outcome, "credentials_match": cred_ok,
            "cowrie_duration_s": float(closed[0]["duration"]) if closed else None, "closed": bool(closed),
            "final_event": evs[-1]["eventid"]}
    if not final:
        guesses.append(base)
        continue

    recorded = [e["input"] for e in evs if e["eventid"] == "cowrie.command.input"]
    recorded_cmds = [c for c in recorded if c.strip() not in EXIT]
    sent = entry["commands_sent"]
    term = {t["step"]: t for t in terminal.get((profile, entry["index"]), [])}
    per_cmd = []
    for c in entry["command_log"]:
        t = term.get(c["seq"], {})
        per_cmd.append({"seq": c["seq"], "command": c["command"], "sent": c["sent"], "prompt_returned": c["prompt_returned"],
                        "readiness_reason": c["readiness_reason"], "wait_s": c["wait_s"], "output_chars": c["output_chars"],
                        "recorded_by_cowrie": c["command"] in recorded_cmds, "output_head": (t.get("output") or "")[:300]})
    prompt_evidence_ok = all(
        (t["readiness_reason"] == "prompt" and t["prompt_match"] is not None and PROMPT_RE.fullmatch(t["prompt_match"]) is not None)
        or (t["readiness_reason"] != "prompt" and t["prompt_match"] is None) for t in term.values())
    rec = dict(base, **{
        "manifest_status": entry["status"], "termination": entry["termination"], "error": entry["error"],
        "shell_ready_initial": entry["shell_ready_initial"], "exit_sent": entry["exit_sent"],
        "exit_confirmed": entry["exit_confirmed"], "exit_in_cowrie": any(c.strip() == "exit" for c in recorded),
        "commands_planned": entry["commands_planned"], "commands_sent": sent,
        "commands_not_sent": [c["command"] for c in entry["command_log"] if not c["sent"]],
        "cowrie_command_input": recorded, "order_matches": recorded_cmds == sent,
        "sent_but_not_recorded": [c for c in sent if c not in recorded_cmds],
        "recorded_but_not_sent": [c for c in recorded_cmds if c not in sent],
        "cowrie_command_failed": [e["input"] for e in evs if e["eventid"] == "cowrie.command.failed"],
        "cowrie_download_events": [{k2: e.get(k2) for k2 in ("eventid", "url", "destfile", "outfile", "shasum", "message")}
                                   for e in evs if "file_download" in e["eventid"] or "file_upload" in e["eventid"]],
        "eventids": sorted({e["eventid"] for e in evs}),
        "tty_output_bytes": sum(int(e["size"]) for e in evs if e["eventid"] == "cowrie.log.closed"),
        "timeouts": [c["command"] for c in entry["command_log"] if c["readiness_reason"] == "timeout"],
        "prompt_evidence_consistent": prompt_evidence_ok, "per_command": per_cmd,
    })
    rec["ok"] = (rec["order_matches"] and rec["termination"] == "clean_exit" and rec["exit_confirmed"] and rec["exit_in_cowrie"]
                 and rec["shell_ready_initial"] and not rec["timeouts"] and not rec["commands_not_sent"] and prompt_evidence_ok
                 and cred_ok and outcome_ok and rec["closed"])
    logged_in.append(rec)

table = []
for profile in ORDER:
    rows = [r for r in logged_in if r["profile"] == profile]
    g = [x for x in guesses if x["profile"] == profile]
    rec_n = lambda r: len([c for c in r["cowrie_command_input"] if c.strip() not in EXIT])  # noqa: E731
    table.append({
        "profile": profile, "sessions_planned": len(manifests[profile]), "sessions_logged_in": len(rows),
        "login_attempts": len(rows) + len(g), "login_success": sum(r["cowrie_login"] == "success" for r in rows + g),
        "login_failed": sum(r["cowrie_login"] == "failed" for r in rows + g),
        "commands_planned": sum(len(r["commands_planned"]) for r in rows),
        "commands_sent": sum(len(r["commands_sent"]) for r in rows),
        "commands_recorded": sum(rec_n(r) for r in rows),
        "prompt_returned": sum(c["prompt_returned"] for r in rows for c in r["per_command"] if c["sent"]),
        "timeouts": sum(len(r["timeouts"]) for r in rows), "commands_not_sent": sum(len(r["commands_not_sent"]) for r in rows),
        "clean_exits": sum(r["termination"] == "clean_exit" and r["exit_confirmed"] for r in rows),
        "unexpected_disconnects": sum(r["termination"] not in ("clean_exit",) for r in rows),
        "duration_s": [r["cowrie_duration_s"] for r in rows], "guess_duration_s": [x["cowrie_duration_s"] for x in g],
        "tty_output_bytes": [r["tty_output_bytes"] for r in rows],
        "download_events": [d["eventid"] for r in rows for d in r["cowrie_download_events"]],
        "command_failed_events": sum(len(r["cowrie_command_failed"]) for r in rows),
    })

commands = defaultdict(lambda: {"n": 0, "prompt_returned": 0, "recorded": 0, "wait_s": [], "output_chars": [], "profiles": set(), "example_output": ""})
for r in logged_in:
    for c in r["per_command"]:
        if not c["sent"]:
            continue
        d = commands[c["command"]]
        d["n"] += 1
        d["prompt_returned"] += c["prompt_returned"]
        d["recorded"] += c["recorded_by_cowrie"]
        d["wait_s"].append(c["wait_s"])
        d["output_chars"].append(c["output_chars"])
        d["profiles"].add(r["profile"])
        d["example_output"] = d["example_output"] or c["output_head"]
cmd_out = {k: {**v, "profiles": sorted(v["profiles"]), "median_output_chars": st.median(v["output_chars"]),
               "max_wait_s": max(v["wait_s"])} for k, v in sorted(commands.items())}
focus = {f: {k: {x: v[x] for x in ("n", "prompt_returned", "recorded", "max_wait_s", "median_output_chars", "profiles", "example_output")}
             for k, v in cmd_out.items() if k.startswith(f) and (f != "groups" or k == "groups")} for f in FOCUS}

result = {"cowrie_events": len(events), "cowrie_sessions": len(sessions), "manifest_attempts": len(expected),
          "events_not_from_relay": len(non_ssh), "unmatched": unmatched,
          "sessions_with_problems": [r["session"] for r in logged_in if not r["ok"]],
          "logged_in_sessions": logged_in, "wrong_guess_sessions": guesses, "focus_commands": focus}
(HERE / "evidence" / "reconciliation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
(HERE / "evidence" / "profile_table.json").write_text(json.dumps(table, indent=2), encoding="utf-8")
(HERE / "evidence" / "command_results.json").write_text(json.dumps(cmd_out, indent=2), encoding="utf-8")

print(f"events={len(events)} cowrie_sessions={len(sessions)} manifest_attempts={len(expected)} non-relay events={len(non_ssh)}")
print("unmatched:", unmatched)
print("problem sessions:", result["sessions_with_problems"])
for r in logged_in:
    print(f"[{r['profile']} #{r['manifest_index']}] {r['session']} {r['termination']} exit={r['exit_confirmed']}/{r['exit_in_cowrie']} "
          f"order={r['order_matches']} sent={len(r['commands_sent'])}/{len(r['commands_planned'])} rec_extra={r['recorded_but_not_sent']} "
          f"missing={r['sent_but_not_recorded']} dur={r['cowrie_duration_s']} tty={r['tty_output_bytes']} dl={[d['eventid'] for d in r['cowrie_download_events']]} "
          f"failed={r['cowrie_command_failed']}")
print("guesses:", [(g["profile"], g["manifest_outcome"], g["cowrie_login"], g["cowrie_duration_s"]) for g in guesses])
for row in table:
    print(row)
for f, v in focus.items():
    for k, d in v.items():
        print(f"FOCUS {k!r}: n={d['n']} prompt={d['prompt_returned']} recorded={d['recorded']} max_wait={d['max_wait_s']} "
              f"chars={d['median_output_chars']} out={d['example_output'][:160]!r}")
