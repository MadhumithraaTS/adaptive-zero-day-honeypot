"""Compare generator manifests with Cowrie's JSON events for the smoke test.

    .venv/Scripts/python.exe reports/generator_cowrie_smoke_test/analyze_smoke.py

Reads evidence/cowrie_smoke_slice.json (Cowrie lines after the recorded baseline) and runs/<profile>/manifest.jsonl.
Every SSH connection is one Cowrie session and the runs were sequential, so Cowrie sessions in connect order
must pair one-to-one with the manifests' authentication attempts in execution order; each pair is checked
by username and password. Writes evidence/comparison.json.
"""
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORDER = ["benign_admin", "brute_force", "botnet", "data_exfiltration", "lateral_movement"]


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


events = [json.loads(line) for line in (HERE / "evidence" / "cowrie_smoke_slice.json").read_text(encoding="utf-8").splitlines() if line.strip()]
by_session = defaultdict(list)
for line_no, e in enumerate(events):
    e["_line"] = line_no
    by_session[e["session"]].append(e)
sessions = sorted(by_session, key=lambda s: min(ts(e["timestamp"]) for e in by_session[s] if e["eventid"] == "cowrie.session.connect"))

expected = []
for profile in ORDER:
    for line in (HERE / "runs" / profile / "manifest.jsonl").read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        for k, (user, pw) in enumerate(entry["auth_attempts"]):
            expected.append((profile, entry, k, user, pw, k == len(entry["auth_attempts"]) - 1))

assert len(sessions) == len(expected), (len(sessions), len(expected))
pairs, guesses = [], []
for sid, (profile, entry, k, user, pw, final) in zip(sessions, expected):
    evs = by_session[sid]
    logins = [e for e in evs if e["eventid"] in ("cowrie.login.success", "cowrie.login.failed")]
    assert len(logins) == 1 and logins[0]["username"] == user and logins[0]["password"] == pw, (sid, user, logins)
    closed = [e for e in evs if e["eventid"] == "cowrie.session.closed"]
    login_ok = logins[0]["eventid"] == "cowrie.login.success"
    base = {"session": sid, "profile": profile, "manifest_index": entry["index"], "attempt": k + 1,
            "cowrie_login": "success" if login_ok else "failed",
            "cowrie_duration_s": float(closed[0]["duration"]) if closed else None,
            "cowrie_closed_message": closed[0]["message"] if closed else None}
    if not final:
        base["manifest_outcome"] = entry["auth_log"][k]["outcome"]
        guesses.append(base)
        continue
    recorded = [e["input"] for e in evs if e["eventid"] == "cowrie.command.input"]
    recorded_cmds = [c for c in recorded if c.strip() not in ("exit", "logout")]
    sent = entry["commands_sent"]
    missing = [c for c in sent if c not in recorded_cmds]
    extra = [c for c in recorded_cmds if c not in sent]
    pairs.append(dict(base, **{
        "manifest_status": entry["status"], "manifest_termination": entry["termination"],
        "manifest_auth_success": entry["auth_success"],
        "shell_ready_initial": entry["shell_ready_initial"], "shell_initial_wait_s": entry["shell_initial_wait_s"],
        "commands_planned": entry["commands_planned"], "commands_sent": sent,
        "cowrie_command_input": recorded,
        "cowrie_command_failed": [e["input"] for e in evs if e["eventid"] == "cowrie.command.failed"],
        "cowrie_file_download": [{k2: e.get(k2) for k2 in ("url", "destfile", "realm", "input", "message")}
                                 for e in evs if e["eventid"] == "cowrie.session.file_download"],
        "per_command": [{k2: c[k2] for k2 in ("seq", "command", "blocking_expected", "sent", "think_time_s",
                                              "prompt_returned", "wait_s", "status", "action")} for c in entry["command_log"]],
        "exit_sent": entry["exit_sent"], "exit_confirmed": entry["exit_confirmed"],
        "exit_in_cowrie": any(c.strip() == "exit" for c in recorded),
        "sent_but_not_recorded": missing, "recorded_but_not_sent": extra,
        "order_matches": recorded_cmds[:len(sent)] == sent if not extra else None,
    }))

result = {"cowrie_sessions": len(sessions), "manifest_attempts": len(expected), "pairing": "all usernames/passwords matched",
          "logged_in_sessions": pairs, "wrong_guess_sessions": guesses}
(HERE / "evidence" / "comparison.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

print(f"Cowrie sessions {len(sessions)} = manifest attempts {len(expected)}; all paired by credentials")
for p in pairs:
    print(f"\n[{p['profile']} #{p['manifest_index']}] {p['session']} login={p['cowrie_login']} initial_prompt={p['shell_ready_initial']} "
          f"({p['shell_initial_wait_s']} s) termination={p['manifest_termination']} status={p['manifest_status']} "
          f"exit_sent={p['exit_sent']} exit_confirmed={p['exit_confirmed']} exit_in_cowrie={p['exit_in_cowrie']} "
          f"cowrie_duration={p['cowrie_duration_s']}")
    for c in p["per_command"]:
        print(f"   {c['seq']}. {c['command'][:48]:<48} sent={c['sent']!s:<5} prompt={c['prompt_returned']!s:<5} wait={c['wait_s']} {c['status']}")
    print(f"   missing={p['sent_but_not_recorded']} extra={p['recorded_but_not_sent']} failed={len(p['cowrie_command_failed'])} downloads={p['cowrie_file_download']}")
print("\nwrong-guess sessions:", [(g["profile"], g["manifest_outcome"], g["cowrie_login"], g["cowrie_duration_s"]) for g in guesses])
