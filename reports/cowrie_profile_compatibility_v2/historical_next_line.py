"""Read-only: for each command name sent in the historical live runs (train_v1, eval_v1; pre-isolation Cowrie,
timer-based generator 2.0), how often the NEXT planned line (or the final exit) was recorded by Cowrie.
A low rate means the command kept Cowrie's shell busy beyond the old generator's delays."""
import csv, json, collections
R = "dataset_builder/runs/"
stats = collections.defaultdict(lambda: collections.Counter())
for run, lab in (("train_v1", "train_v2_corrected"), ("eval_v1", "eval_v2_corrected")):
    man = {json.loads(l)["index"]: json.loads(l) for l in open(R + run + "/manifest.jsonl", encoding="utf-8")}
    ev = collections.defaultdict(list)
    for l in open(R + run + "/raw/cowrie_thisrun.json", encoding="utf-8"):
        e = json.loads(l); ev[e["session"]].append(e)
    for a in csv.DictReader(open(R + lab + "/label_assignments.csv", encoding="utf-8")):
        if a["auth_outcome"] != "success" or not a["source_index"]:
            continue
        sent = man[int(a["source_index"])]["commands_sent"] + ["exit"]
        got = [e["input"].strip() for e in ev[a["session_id"]] if e["eventid"] == "cowrie.command.input"]
        for c, nxt in zip(sent, sent[1:]):
            name = c.split()[0]
            stats[name]["n"] += 1
            stats[name]["next_recorded"] += nxt in got
out = {k: {"followed": v["n"], "next_recorded": v["next_recorded"], "rate": round(v["next_recorded"] / v["n"], 3)}
       for k, v in sorted(stats.items(), key=lambda kv: kv[1]["next_recorded"] / kv[1]["n"])}
json.dump(out, open("reports/cowrie_profile_compatibility_v2/evidence/historical_next_line.json", "w"), indent=1)
for k, v in out.items():
    print(f"{k:12s} followed={v['followed']:5d} next_recorded={v['next_recorded']:5d} rate={v['rate']}")
