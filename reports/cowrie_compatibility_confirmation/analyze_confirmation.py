"""Compare manifests, terminal_output.jsonl and Cowrie events for the confirmation smoke test.

    .venv/Scripts/python.exe reports/cowrie_compatibility_confirmation/analyze_confirmation.py

Input: evidence/cowrie_confirmation_slice.json (Cowrie lines after the recorded baseline) and runs/<profile>/.
Cowrie sessions in connect order are paired one-to-one with the manifests' authentication attempts in
execution order and checked by username and password. Writes evidence/comparison.json and evidence/profile_table.json.
"""
import json
import re
import statistics as st
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from dataset_builder.generate_labelled_traffic import OUTPUT_CAPTURE_CHARS, PROMPT_RE, REDACT_MIN_LENGTH  # noqa: E402

ORDER = ["benign_admin", "reconnaissance", "brute_force", "botnet", "privilege_escalation", "lateral_movement",
         "data_exfiltration"]
MARKER = "\n[...truncated...]\n"


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


events = [json.loads(line) for line in (HERE / "evidence" / "cowrie_confirmation_slice.json").read_text(encoding="utf-8").splitlines() if line.strip()]
by_session = defaultdict(list)
for e in events:
    by_session[e["session"]].append(e)
sessions = sorted(by_session, key=lambda s: min(ts(e["timestamp"]) for e in by_session[s] if e["eventid"] == "cowrie.session.connect"))

expected, terminal = [], {}
for profile in ORDER:
    run = HERE / "runs" / profile
    for line in (run / "terminal_output.jsonl").read_text(encoding="utf-8").splitlines():
        t = json.loads(line)
        terminal.setdefault((profile, t["index"]), []).append(t)
    for line in (run / "manifest.jsonl").read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        for k, (user, pw) in enumerate(entry["auth_attempts"]):
            expected.append((profile, entry, k, user, pw, k == len(entry["auth_attempts"]) - 1))
assert len(sessions) == len(expected), (len(sessions), len(expected))

problems, logged_in, guesses = [], [], []
for sid, (profile, entry, k, user, pw, final) in zip(sessions, expected):
    evs = by_session[sid]
    logins = [e for e in evs if e["eventid"] in ("cowrie.login.success", "cowrie.login.failed")]
    assert len(logins) == 1 and logins[0]["username"] == user and logins[0]["password"] == pw, (sid, user, logins)
    closed = [e for e in evs if e["eventid"] == "cowrie.session.closed"]
    last = max(evs, key=lambda e: ts(e["timestamp"]))
    base = {"session": sid, "profile": profile, "manifest_index": entry["index"], "attempt": k + 1,
            "cowrie_login": logins[0]["eventid"].split(".")[-1],
            "cowrie_duration_s": float(closed[0]["duration"]) if closed else None,
            "final_event": last["eventid"]}
    if not final:
        base["manifest_outcome"] = entry["auth_log"][k]["outcome"]
        guesses.append(base)
        continue

    recorded = [e["input"] for e in evs if e["eventid"] == "cowrie.command.input"]
    recorded_cmds = [c for c in recorded if c.strip() not in ("exit", "logout")]
    sent = entry["commands_sent"]
    tty_bytes = sum(int(e["size"]) for e in evs if e["eventid"] == "cowrie.log.closed")

    # terminal-output evidence vs readiness decisions
    term = terminal.get((profile, entry["index"]), [])
    term_checks = []
    for t in term:
        ok_prompt = (t["readiness_reason"] == "prompt" and t["prompt_match"] is not None
                     and PROMPT_RE.fullmatch(t["prompt_match"]) is not None and t["output"].endswith(t["prompt_match"]))
        ok_other = t["readiness_reason"] != "prompt" and t["prompt_match"] is None and PROMPT_RE.search(t["output"]) is None
        bound_ok = len(t["output"]) <= OUTPUT_CAPTURE_CHARS + len(MARKER)
        trunc_ok = t["output_truncated"] == (t["output_chars"] > OUTPUT_CAPTURE_CHARS) or "[REDACTED]" in t["output"]
        leaked = [p for _, p in entry["auth_attempts"] if len(p) >= REDACT_MIN_LENGTH and p in t["output"]]
        term_checks.append({"step": t["step"], "reason": t["readiness_reason"], "evidence_consistent": ok_prompt or ok_other,
                            "bound_ok": bound_ok, "truncation_flag_ok": trunc_ok, "truncated": t["output_truncated"],
                            "output_chars": t["output_chars"], "password_leaks": leaked,
                            "redacted_markers": t["output"].count("[REDACTED]")})
    manifest_vs_term = all(c["output_chars"] == next(t["output_chars"] for t in term if t["step"] == c["seq"])
                           for c in entry["command_log"] if c["sent"])

    rec = dict(base, **{
        "manifest_status": entry["status"], "termination": entry["termination"],
        "shell_ready_initial": entry["shell_ready_initial"], "exit_sent": entry["exit_sent"],
        "exit_confirmed": entry["exit_confirmed"], "exit_in_cowrie": any(c.strip() == "exit" for c in recorded),
        "commands_planned": entry["commands_planned"], "commands_sent": sent, "cowrie_command_input": recorded,
        "order_matches": recorded_cmds == sent,
        "sent_but_not_recorded": [c for c in sent if c not in recorded_cmds],
        "recorded_but_not_sent": [c for c in recorded_cmds if c not in sent],
        "cowrie_command_failed": [e["input"] for e in evs if e["eventid"] == "cowrie.command.failed"],
        "cowrie_download_events": [{"eventid": e["eventid"], "url": e.get("url"), "destfile": e.get("destfile")}
                                   for e in evs if e["eventid"].startswith("cowrie.session.file_download")],
        "per_command": [{k2: c[k2] for k2 in ("seq", "command", "sent", "prompt_returned", "wait_s", "readiness_reason",
                                              "prompt_match", "output_chars", "output_truncated", "status")}
                        for c in entry["command_log"]],
        "terminal_checks": term_checks, "manifest_output_chars_match_terminal_file": manifest_vs_term,
        "tty_output_bytes": tty_bytes,
    })
    logged_in.append(rec)
    if not (rec["order_matches"] and rec["termination"] == "clean_exit" and rec["exit_confirmed"] and rec["exit_in_cowrie"]
            and all(c["evidence_consistent"] and c["bound_ok"] and c["truncation_flag_ok"] and not c["password_leaks"]
                    for c in term_checks) and manifest_vs_term and rec["shell_ready_initial"]):
        problems.append(sid)

table = []
for profile in ORDER:
    rows = [r for r in logged_in if r["profile"] == profile]
    table.append({
        "profile": profile, "sessions_attempted": len(rows),
        "sessions_completed": sum(r["termination"] == "clean_exit" for r in rows),
        "early_terminations": sum(r["termination"] != "clean_exit" for r in rows),
        "commands_planned": sum(len(r["commands_planned"]) for r in rows),
        "commands_sent": sum(len(r["commands_sent"]) for r in rows),
        "commands_recorded": sum(len([c for c in r["cowrie_command_input"] if c.strip() not in ("exit", "logout")]) for r in rows),
        "mean_session_duration_s": round(st.mean(r["cowrie_duration_s"] for r in rows), 1),
        "mean_recorded_inputs": round(st.mean(len([c for c in r["cowrie_command_input"] if c.strip() not in ("exit", "logout")]) for r in rows), 1),
        "mean_tty_output_bytes": round(st.mean(r["tty_output_bytes"] for r in rows), 1),
        "timeouts": sum(1 for r in rows for c in r["per_command"] if c["readiness_reason"] == "timeout"),
        "wrong_guess_sessions": sum(1 for g in guesses if g["profile"] == profile),
    })

result = {"cowrie_sessions": len(sessions), "manifest_attempts": len(expected), "pairing": "all usernames/passwords matched",
          "sessions_with_problems": problems, "logged_in_sessions": logged_in, "wrong_guess_sessions": guesses}
(HERE / "evidence" / "comparison.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
(HERE / "evidence" / "profile_table.json").write_text(json.dumps(table, indent=2), encoding="utf-8")

print(f"Cowrie sessions {len(sessions)} = manifest attempts {len(expected)}; paired by credentials. Problems: {problems}")
for r in logged_in:
    tc = r["terminal_checks"]
    print(f"[{r['profile']} #{r['manifest_index']}] {r['session']} term={r['termination']} exit_conf={r['exit_confirmed']} "
          f"order={r['order_matches']} sent={len(r['commands_sent'])}/{len(r['commands_planned'])} dur={r['cowrie_duration_s']} "
          f"tty={r['tty_output_bytes']} waits={len(tc)} consistent={all(c['evidence_consistent'] for c in tc)} "
          f"truncated={sum(c['truncated'] for c in tc)} redacted={sum(c['redacted_markers'] for c in tc)} final={r['final_event']}")
print("wrong guesses:", [(g["profile"], g["manifest_outcome"], g["cowrie_login"], g["cowrie_duration_s"]) for g in guesses])
for row in table:
    print(row)
