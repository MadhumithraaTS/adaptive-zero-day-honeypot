"""Check the two verification sessions: manifest vs Cowrie, prompt evidence, redaction and Unicode."""
import json
from collections import defaultdict
from pathlib import Path
HERE = Path(__file__).resolve().parent
ev = [json.loads(l) for l in (HERE / "evidence" / "cowrie_verification_slice.json").read_text(encoding="utf-8").splitlines()]
by = defaultdict(list)
for e in ev:
    by[e["session"]].append(e)
out = {}
for prof in ("benign_admin", "botnet"):
    m = json.loads((HERE / "runs" / prof / "manifest.jsonl").read_text(encoding="utf-8").splitlines()[0])
    term = [json.loads(l) for l in (HERE / "runs" / prof / "terminal_output.jsonl").read_text(encoding="utf-8").splitlines()]
    user, pw = m["auth_attempts"][-1]
    sid = next(s for s, es in by.items() if any(e["eventid"] == "cowrie.login.success" and e["username"] == user and e["password"] == pw for e in es))
    es = by[sid]
    recorded = [e["input"] for e in es if e["eventid"] == "cowrie.command.input"]
    text = "".join(t["output"] for t in term)
    out[prof] = {
        "session": sid, "credentials": [user, pw], "termination": m["termination"], "exit_confirmed": m["exit_confirmed"],
        "commands_sent": m["commands_sent"], "cowrie_inputs": recorded,
        "sent_equals_recorded_in_order": [c for c in recorded if c != "exit"] == m["commands_sent"] and recorded[-1] == "exit",
        "final_event": max(es, key=lambda e: e["timestamp"])["eventid"],
        "cowrie_duration_s": float(next(e["duration"] for e in es if e["eventid"] == "cowrie.session.closed")),
        "waits": len(term),
        "prompt_evidence_matches_manifest": all(t["output"].endswith(t["prompt_match"]) for t in term)
            and [c["prompt_match"] for c in m["command_log"]] == [t["prompt_match"] for t in term[1:]],
        "prompts": sorted({t["prompt_match"] for t in term}),
        "redacted_markers": text.count("[REDACTED]"),
        "redaction_reasons": sorted({t["redaction"]["reason"] for t in term}),
        "password_text_in_output": pw in text,
        "password_occurrences_outside_prompts": sum(t["output"][:-len(t["prompt_match"])].count(pw) for t in term),
        "replacement_chars": text.count("�"), "invalid_utf8_bytes": sum(t["invalid_utf8_bytes"] for t in term),
        "non_ascii_chars": sorted({ch for ch in text if ord(ch) > 127}),
        "truncated_waits": sum(t["output_truncated"] for t in term),
        "wget_output": next((t["output"] for t in term if t["step"] != "initial"
                             and m["command_log"][t["step"] - 1]["command"].startswith("wget")), None),
    }
(HERE / "evidence" / "verification_checks.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps(out, indent=1, ensure_ascii=True))
