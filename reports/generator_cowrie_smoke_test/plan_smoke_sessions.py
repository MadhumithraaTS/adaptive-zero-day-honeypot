"""Build single-profile configs from dataset_builder/profiles_v2_isolated.json and pick seeds offline.

Seed rule (fixed before any session ran): smallest seed in 1..200 whose planned commands meet the profile's
coverage requirement; seed 1 when there is no requirement. Planning replicates main() exactly
(weighted_profile_order, plan_credentials, plan_commands on one Random(seed)); it opens no connection.
"""
import json, random, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from dataset_builder import generate_labelled_traffic as glt  # noqa: E402

SESSIONS = 2
REQUIRE = {
    "benign_admin": lambda plans: True,
    "brute_force": lambda plans: True,
    "botnet": lambda plans: any(c.split()[0] in ("wget", "curl") for p in plans for c in p),
    "data_exfiltration": lambda plans: any(c.split()[0] == "scp" for p in plans for c in p),
    "lateral_movement": lambda plans: any(c.split()[0] == "ssh" for p in plans for c in p)
                                     and any(c.split()[0] in ("nc", "ping") for p in plans for c in p),
}
src = REPO / "dataset_builder" / "profiles_v2_isolated.json"
full = json.loads(src.read_text(encoding="utf-8"))
out_dir = Path(__file__).resolve().parent / "configs"
chosen = {}
for name, ok in REQUIRE.items():
    cfg = dict(full, profiles=[p for p in full["profiles"] if p["name"] == name])
    (out_dir / f"{name}.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    held_out = cfg["profiles"][0].get("held_out", False)
    for seed in range(1, 201):
        rng = random.Random(seed)
        order = glt.weighted_profile_order(cfg["profiles"], SESSIONS, rng, held_out)
        plans = []
        for profile in order:
            glt.plan_credentials(profile, rng)
            plans.append(glt.plan_commands(profile, cfg.get("placeholders", {}), rng))
        if ok(plans):
            chosen[name] = {"seed": seed, "include_held_out": held_out, "planned_commands": plans}
            break
print(json.dumps(chosen, indent=1))
(out_dir / "seed_selection.json").write_text(json.dumps({"source_profiles": str(src.relative_to(REPO)), "sessions_per_profile": SESSIONS, "chosen": chosen}, indent=2), encoding="utf-8")
