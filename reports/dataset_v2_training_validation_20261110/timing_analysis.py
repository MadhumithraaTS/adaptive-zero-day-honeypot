"""Phase 6: timing and execution analysis (descriptive only; no models, no classifiers, no feature decisions).

    .venv/Scripts/python.exe reports/dataset_v2_training_validation_20261110/timing_analysis.py train [validation]

Category-level timing descriptives use the first split given (train). For further splits only command
execution delays are summarised, to confirm they are a property of Cowrie, not of the split.
Execution delay = manifest command_log wait_s (send -> prompt returned, measured by the client).
Think time      = manifest command_log think_time_s (drawn from the category-independent PacingPolicy).
Writes evidence/timing_analysis.json and evidence/timing_*.csv.
"""
import csv
import json
import math
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
splits = sys.argv[1:]
TIMING = ["session_duration_s", "time_to_first_input_s", "inter_input_mean_s", "inter_input_std_s"]
SLOW = 5.0  # seconds of execution delay counted as "slow"


def q(vals, ps=(0.05, 0.25, 0.5, 0.75, 0.95)):
    v = sorted(x for x in vals if x is not None and not (isinstance(x, float) and math.isnan(x)))
    if not v:
        return None
    pick = lambda p: v[min(len(v) - 1, int(round(p * (len(v) - 1))))]  # noqa: E731
    return {"n": len(v), **{f"p{int(p * 100)}": round(pick(p), 3) for p in ps}, "max": round(v[-1], 3)}


def read(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def num(x):
    return float("nan") if x in ("NaN", "") else float(x)


out = {"execution_delay_s_by_command": {}, "splits": {}}
for i, split in enumerate(splits):
    man = {f"{split}:{e['index']}": e for e in
           (json.loads(l) for l in (HERE / "runs" / split / "manifest.jsonl").read_text(encoding="utf-8").splitlines())}
    cmds = [c | {"interaction_id": iid, "profile": e["profile"]} for iid, e in man.items() for c in e["command_log"] if c["sent"]]
    by_cmd = defaultdict(list)
    for c in cmds:
        by_cmd[c["command"]].append(c["wait_s"])
    slow_cmds = {k: q(v) for k, v in by_cmd.items() if max(v) >= SLOW}
    think_by_profile = {p: q([c["think_time_s"] for c in cmds if c["profile"] == p]) for p in sorted({c["profile"] for c in cmds})}
    wait_by_profile = {p: q([c["wait_s"] for c in cmds if c["profile"] == p]) for p in sorted({c["profile"] for c in cmds})}
    out["splits"][split] = {
        "commands_sent": len(cmds),
        "commands_with_wait_ge_5s": sum(c["wait_s"] >= SLOW for c in cmds),
        "slow_commands": slow_cmds,
        "think_time_s_by_profile": think_by_profile,
        "execution_delay_s_by_profile": wait_by_profile,
        "execution_delay_s_all_except_slow": q([c["wait_s"] for c in cmds if c["command"] not in slow_cmds]),
    }
    if i == 0:
        with open(HERE / "evidence" / f"timing_command_delays_{split}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["command", "n", "median_wait_s", "max_wait_s", "profiles"])
            for k, v in sorted(by_cmd.items(), key=lambda kv: -st.median(kv[1])):
                w.writerow([k, len(v), round(st.median(v), 3), round(max(v), 3),
                            ";".join(sorted({c["profile"] for c in cmds if c["command"] == k}))])
        # session-level: join V2 features (metadata side) with labels and manifest decomposition
        feats = read(HERE / "extraction" / split / "run1" / "model_features.csv")
        meta = read(HERE / "extraction" / split / "run1" / "session_metadata.csv")
        labels = {r["session_ref"]: r for r in read(HERE / "labels" / f"{split}_session_labels.csv")}
        rows = []
        for f_, m in zip(feats, meta):
            lab = labels[m["session_ref"]]
            if lab["role"] != "logged_in":
                continue
            e = man[lab["interaction_id"]]
            sent = [c for c in e["command_log"] if c["sent"]]
            rows.append({"profile": lab["profile"], **{k: num(f_[k]) for k in TIMING},
                         "think_sum_s": sum(c["think_time_s"] for c in sent),
                         "exec_sum_s": sum(c["wait_s"] for c in sent),
                         "max_exec_s": max([c["wait_s"] for c in sent], default=0.0),
                         "has_slow_cmd": any(c["wait_s"] >= SLOW for c in sent),
                         "has_find_id_rsa": any(c["command"].startswith("find / -name id_rsa") for c in sent),
                         "n_cmds": len(sent)})
        profiles = sorted({r["profile"] for r in rows})
        per_prof = {}
        for p in profiles:
            rs = [r for r in rows if r["profile"] == p]
            per_prof[p] = {k: q([r[k] for r in rs]) for k in TIMING + ["think_sum_s", "exec_sum_s", "n_cmds"]}
            per_prof[p]["share_with_slow_cmd"] = round(sum(r["has_slow_cmd"] for r in rs) / len(rs), 3)
            per_prof[p]["share_with_find_id_rsa"] = round(sum(r["has_find_id_rsa"] for r in rs) / len(rs), 3)
            per_prof[p]["exec_share_of_duration_median"] = round(st.median(
                r["exec_sum_s"] / r["session_duration_s"] for r in rs if r["session_duration_s"] > 0), 3)
        slow = [r for r in rows if r["has_slow_cmd"]]
        others_dur = [r["session_duration_s"] for r in rows if r["profile"] != "privilege_escalation"]
        thr = q(others_dur, ps=(0.95, 0.99))
        above95 = [r for r in rows if r["session_duration_s"] > thr["p95"]]
        pe = [r for r in rows if r["profile"] == "privilege_escalation"]
        pe_find = [r for r in pe if r["has_find_id_rsa"]]
        pe_nofind = [r for r in pe if not r["has_find_id_rsa"]]
        out["splits"][split].update({
            "logged_in_sessions": len(rows),
            "per_profile": per_prof,
            "slow_command_sessions_by_profile": {p: sum(r["profile"] == p for r in slow) for p in profiles},
            "non_pe_duration_quantiles": thr,
            "sessions_above_non_pe_p95_by_profile": {p: sum(r["profile"] == p for r in above95) for p in profiles},
            "pe_duration_with_find_id_rsa": q([r["session_duration_s"] for r in pe_find]),
            "pe_duration_without_find_id_rsa": q([r["session_duration_s"] for r in pe_nofind]),
            "pe_duration_minus_find_exec": q([r["session_duration_s"] - r["max_exec_s"] for r in pe_find]),
            "duration_vs_components": {
                "median_abs_residual_s": round(st.median(abs(r["session_duration_s"] - r["think_sum_s"] - r["exec_sum_s"]) for r in rows), 3),
                "note": "duration minus (sum think + sum execution); the residual is login, initial prompt, exit and connection overhead",
            },
        })
        with open(HERE / "evidence" / f"timing_sessions_{split}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    for k, v in by_cmd.items():
        out["execution_delay_s_by_command"].setdefault(k, {})[split] = {"n": len(v), "median": round(st.median(v), 3), "max": round(max(v), 3)}

slowest = sorted(out["execution_delay_s_by_command"].items(), key=lambda kv: -max(x["max"] for x in kv[1].values()))[:15]
out["slowest_commands"] = dict(slowest)
(HERE / "evidence" / "timing_analysis.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
print(json.dumps({s: {k: v for k, v in d.items() if k not in ("per_profile",)} for s, d in out["splits"].items()}, indent=1)[:5000])
print(json.dumps(out["slowest_commands"], indent=1)[:2500])
