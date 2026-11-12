"""Read-only: check code-derived predictions on the train + validation rows (test pickle never opened)."""
import json, sys
import pandas as pd
REPO = r"C:\AMRITA\Final_Year_Project_zero_day_27\adaptive-zero-day-honeypot"
d = pd.concat([pd.read_pickle(REPO + r"\ml_pipeline\work\train.pkl").assign(split="train"),
               pd.read_pickle(REPO + r"\ml_pipeline\work\val.pkl").assign(split="validation")])
TTY = {"reconnaissance": (500, 3000), "botnet_malware_download": (200, 1500), "privilege_escalation": (800, 4000),
       "evasion_anti_forensics": (300, 2000), "brute_force_only": (0, 0), "zero_day_buffer_overflow": (0, 100),
       "zero_day_covert_tunnel": (100, 500), "zero_day_obfuscated_memory_attack": (1500, 5000)}
out = {"rows": int(len(d)), "by_split": d["split"].value_counts().to_dict(), "categories": {}}
for cat, g in d.groupby("attack_cat"):
    login_ok = g["dpkts"] >= 5 if cat != "brute_force_only" else g["dbytes"] > -1  # brute force has no client.size event
    failed = (g["dpkts"] - 5).clip(lower=0).where(g["dpkts"] >= 5, 0)
    lo, hi = TTY[cat]
    out["categories"][cat] = {
        "n": int(len(g)),
        "dpkts_values": {int(k): int(v) for k, v in g["dpkts"].value_counts().sort_index().items()},
        "spkts_zero": int((g["spkts"] == 0).sum()),
        "dpkts4_failed_login_like": int((g["dpkts"] == 4).sum()),
        "dpkts4_with_dbytes_0": int(((g["dpkts"] == 4) & (g["dbytes"] == 0)).sum()),
        "sessions_with_inferred_failed_commands": int((failed > 0).sum()),
        "inferred_failed_commands_total": int(failed.sum()),
        "logged_in_but_spkts_zero": int(((g["dpkts"] >= 6) & (g["spkts"] == 0)).sum()),
        "dbytes_min_max_when_dpkts_ge5": [float(g.loc[g.dpkts >= 5, "dbytes"].min()) if (g.dpkts >= 5).any() else None,
                                          float(g.loc[g.dpkts >= 5, "dbytes"].max()) if (g.dpkts >= 5).any() else None],
        "tty_size_range_in_generator": [lo, hi],
        "sinpkt_sjit_ackdat_all_zero_when_spkts_zero": bool((g.loc[g.spkts == 0, ["sinpkt", "sjit", "ackdat", "sbytes", "sload"]] == 0).all().all()),
    }
bo = d[d.attack_cat == "zero_day_buffer_overflow"]
out["buffer_overflow_dur_max_s"] = float(bo["dur"].max())
out["buffer_overflow_dbytes_le_100"] = bool((bo["dbytes"] <= 100).all())
print(json.dumps(out, indent=1))
