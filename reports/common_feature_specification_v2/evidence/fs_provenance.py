"""Read-only: provenance of command.input in live train_v1, using labelling v2 source assignments + manifest."""
import csv, json, collections, statistics as st
from datetime import datetime
R = "dataset_builder/runs/"
man = {json.loads(l)["index"]: json.loads(l) for l in open(R + "train_v1/manifest.jsonl", encoding="utf-8")}
assign = {r["session_id"]: r for r in csv.DictReader(open(R + "train_v2_corrected/label_assignments.csv", encoding="utf-8"))}
ev = collections.defaultdict(list)
for l in open(R + "train_v1/raw/cowrie_thisrun.json", encoding="utf-8"):
    e = json.loads(l); ev[e["session"]].append(e)
t = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
out = collections.Counter(); gaps = {"client": [], "not_in_manifest": []}; first_is_client = collections.Counter()
missing_examples = collections.Counter(); scp_sessions = 0
for sid, a in assign.items():
    if a["source_status"] != "assigned" or a["assignment_method"] != "sequence_alignment" or a["auth_outcome"] != "success" or not a["source_index"]:
        continue
    sent = [c.strip() for c in man[int(a["source_index"])]["commands_sent"]] + ["exit"]
    inputs = [e for e in ev[sid] if e["eventid"] == "cowrie.command.input"]
    seen = [e["input"].strip() for e in inputs]
    out["sessions"] += 1
    remaining = list(sent)
    prev = None
    for i, e in enumerate(inputs):
        txt = e["input"].strip()
        cls = "client" if txt in remaining else "not_in_manifest"
        if cls == "client": remaining.remove(txt)
        out[cls + "_lines"] += 1
        if i == 0: first_is_client[cls] += 1
        if prev is not None: gaps[cls].append((t(e["timestamp"]) - t(prev)).total_seconds())
        prev = e["timestamp"]
    out["manifest_lines_missing_from_input"] += len(remaining)
    for r in remaining: missing_examples[r.split()[0] if r else ""] += 1
    if any(e["eventid"] == "cowrie.session.file_download" and e.get("realm") == "scp" for e in ev[sid]): scp_sessions += 1
    if remaining: out["sessions_with_missing_client_lines"] += 1
    if len(seen) - (len(sent) - len(remaining)) > 0: out["sessions_with_extra_lines"] += 1
q = lambda v: [round(x, 4) for x in (min(v), st.median(v), max(v))] if v else None
res = {"counts": dict(out), "first_input_class": dict(first_is_client), "scp_sessions": scp_sessions,
       "gap_s_min_median_max": {k: q(v) for k, v in gaps.items()},
       "client_gaps_below_0.01s": sum(g < 0.01 for g in gaps["client"]), "not_in_manifest_gaps_above_0.01s": sum(g >= 0.01 for g in gaps["not_in_manifest"]),
       "missing_by_first_token": missing_examples.most_common(8)}
print(json.dumps(res, indent=1))
json.dump(res, open(r"C:/Users/madhu/AppData/Local/Temp/claude/c--AMRITA-Final-Year-Project-zero-day-27-adaptive-zero-day-honeypot/601b0171-9524-480b-9fb8-d783f51bad37/scratchpad/fs_provenance.json", "w"), indent=1)
