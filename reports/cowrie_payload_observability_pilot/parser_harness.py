"""Run the existing, unmodified parser, extractor and dataset builder on pilot-log variants in a temporary directory.

    .venv/Scripts/python.exe reports/cowrie_payload_observability_pilot/parser_harness.py <work_dir>

Variants of the pilot slice (only the PILOT_B command.input event differs):
  V0  as logged by Cowrie (pure ASCII; high bytes already stripped by Cowrie)
  V1  B's original input re-serialised with JSON \\u escapes (ensure_ascii=True)
  V2  B's original input re-serialised as raw UTF-8 (ensure_ascii=False)
  V3  an invalid raw 0x90 byte inside the JSON string
Each variant runs under the Windows default encoding and with PYTHONUTF8=1.
"""
import csv
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PY = sys.executable
work = Path(sys.argv[1])
work.mkdir(parents=True, exist_ok=False)
lines = (HERE / "evidence" / "cowrie_pilot_slice.json").read_bytes().splitlines()
rec = json.loads((HERE / "evidence" / "client_record.json").read_text())
b_sent = bytes.fromhex(rec["tests"]["B"]["sent"][0]["hex"])[:-1]
b_text_clean = b_sent.decode("latin-1")  # one code point per byte, for the JSON variants


def variant(kind):
    out = []
    for raw in lines:
        e = json.loads(raw)
        if e["eventid"] == "cowrie.command.input" and "PILOT_B" in e.get("input", ""):
            if kind == "V1":
                e["input"] = b_text_clean
                raw = json.dumps(e, ensure_ascii=True).encode("ascii")
            elif kind == "V2":
                e["input"] = b_text_clean
                raw = json.dumps(e, ensure_ascii=False).encode("utf-8")
            elif kind == "V3":
                raw = raw.replace(b"PILOT_B_", b"PILOT_B_\x90", 1)
        out.append(raw)
    return b"\n".join(out) + b"\n"


def run(args, env_utf8):
    env = dict(os.environ)
    env.pop("PYTHONUTF8", None)
    if env_utf8:
        env["PYTHONUTF8"] = "1"
    p = subprocess.run([PY, *args], cwd=REPO, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    tail = (p.stderr or p.stdout).strip().splitlines()[-1:] if p.returncode else []
    return p.returncode, tail


def b_session_value(sessions_path):
    sessions = json.loads(Path(sessions_path).read_text(encoding="utf-8", errors="replace"))
    for events in sessions.values():
        for e in events:
            if e.get("eventid") == "cowrie.command.input" and "PILOT_B" in e.get("input", ""):
                return e["input"]
    return None


def manifest(out):
    """Minimal manifest so the builder can run; one entry per pilot session (labels irrelevant here)."""
    entries = []
    for i, (t, user, cat) in enumerate((("A", "pilot_a", "pilot_printable"), ("B", "pilot_b", "pilot_highbyte"),
                                        ("C", "pilot_c", "pilot_provenance")), start=1):
        te = rec["tests"][t]
        entries.append({"index": i, "profile": cat, "attack_cat": cat, "label": 0, "held_out": False,
                        "username": user, "start_utc": te["start_utc"], "end_utc": te["end_utc"],
                        "auth_attempts": [[user, f"{user}-pw"]], "auth_success": True,
                        "commands_sent": [bytes.fromhex(s["hex"])[:-1].decode("latin-1") for s in te["sent"][:-1]],
                        "status": "ok", "error": None})
    (out / "manifest.jsonl").write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")


results = {"b_sent_hex": b_sent.hex()}
for kind in ("V0", "V1", "V2", "V3"):
    src = work / f"{kind}.json"
    src.write_bytes(variant(kind))
    for utf8 in (False, True):
        tag = f"{kind}_{'utf8' if utf8 else 'default'}"
        r = {}
        parsed, feats, details = work / f"{tag}_sessions.json", work / f"{tag}_features.csv", work / f"{tag}_details.json"
        r["parse_logs"] = run(["scripts/parse_logs.py", "--input", str(src), "--output", str(parsed)], utf8)
        if parsed.exists():
            val = b_session_value(parsed)
            r["parsed_B_input_codepoints"] = None if val is None else [hex(ord(c)) for c in val[16:]]
            r["extract_features"] = run(["scripts/extract_features.py", "--input", str(parsed), "--output", str(feats),
                                         "--details", str(details)], utf8)
            if feats.exists():
                rows = list(csv.DictReader(open(feats, encoding="utf-8", errors="replace")))
                r["sbytes_by_session"] = {row["session_id"]: int(float(row["sbytes"])) for row in rows
                                          if float(row["sbytes"]) > 0}
        bdir = work / f"{tag}_builder"
        bdir.mkdir()
        manifest(bdir)
        r["builder"] = run(["dataset_builder/build_labelled_dataset.py", "--output-dir", str(bdir), "--raw-input", str(src)], utf8)
        copied = bdir / "raw" / "cowrie.json"
        if copied.exists():
            data = copied.read_bytes()
            r["builder_raw_copy"] = {"bytes>127": sum(x > 127 for x in data), "contains_EF_BF_BD": b"\xef\xbf\xbd" in data,
                                     "contains_0x90": b"\x90" in data, "contains_3F_in_B": b"PILOT_B_?" in data}
        bparsed = bdir / "parsed" / "sessions.json"
        if bparsed.exists():
            val = b_session_value(bparsed)
            r["builder_B_input_codepoints"] = None if val is None else [hex(ord(c)) for c in val[16:]]
        results[tag] = r
        print(tag, json.dumps({k: (v if k != "parsed_B_input_codepoints" else (v[:6] if v else v)) for k, v in r.items()})[:400])
(HERE / "evidence" / "parser_harness_results.json").write_text(json.dumps(results, indent=2))
