"""Two verification sessions from dataset_builder/profiles_v2_compat.json, chosen offline before any connection.

benign_admin: planning seed 1. botnet: smallest seed in 1..500 whose single session logs in as admin/admin
(username = password, the overlap case) and plans a wget to a .example name (Unicode quotes in Cowrie's message).
Pacing seeds 9201 and 9202 must be unused under dataset_builder/runs and reports/.
"""
import json, random, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from dataset_builder import generate_labelled_traffic as glt  # noqa: E402
HERE = Path(__file__).resolve().parent
full = json.loads((REPO / "dataset_builder" / "profiles_v2_compat.json").read_text(encoding="utf-8"))
RULES = {"benign_admin": (9201, lambda creds, cmds: True),
         "botnet": (9202, lambda creds, cmds: creds[-1] == ["admin", "admin"] and any(c.startswith("wget http://") and ".example/" in c for c in cmds))}
used = {s: [h for r in (REPO / "dataset_builder" / "runs", REPO / "reports") for h in glt.find_pacing_seed_reuse(str(r), s)] for s, _ in RULES.values()}
assert not any(used.values()), used
chosen = {}
for name, (pacing, ok) in RULES.items():
    cfg = dict(full, profiles=[p for p in full["profiles"] if p["name"] == name])
    (HERE / "configs" / f"{name}.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    for seed in range(1, 501):
        rng = random.Random(seed)
        profile = glt.weighted_profile_order(cfg["profiles"], 1, rng, False)[0]
        creds = glt.plan_credentials(profile, rng)
        cmds = glt.plan_commands(profile, cfg["placeholders"], rng)
        if ok(creds, cmds):
            chosen[name] = {"seed": seed, "pacing_seed": pacing, "credentials": creds, "planned_commands": cmds}
            break
(HERE / "configs" / "session_plan.json").write_text(json.dumps(chosen, indent=2), encoding="utf-8")
print(json.dumps(chosen, indent=1))
