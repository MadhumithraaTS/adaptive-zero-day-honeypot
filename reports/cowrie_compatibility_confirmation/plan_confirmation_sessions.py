"""Single-profile configs from dataset_builder/profiles_v2_compat.json, pre-registered planning seeds, fresh pacing seeds.

Planning-seed rule (fixed before any session ran): seed 1, except the smallest seed in 1..200 whose two planned
sessions include the profile's critical compatibility command (botnet: wget; lateral_movement: the replacement
~/.ssh step; data_exfiltration: curl -T). Planning replicates main() and opens no connection.
Pacing seeds 9101..9107 (one per run) must be unused under every run root in the repository.
"""
import json, random, sys
from pathlib import Path
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from dataset_builder import generate_labelled_traffic as glt  # noqa: E402

HERE = Path(__file__).resolve().parent
SESSIONS = 2
ORDER = ["benign_admin", "reconnaissance", "brute_force", "botnet", "privilege_escalation", "lateral_movement", "data_exfiltration"]
REQUIRE = {
    "botnet": lambda plans: any(c.startswith("wget ") for p in plans for c in p),
    "lateral_movement": lambda plans: any(c in ("cat ~/.ssh/config", "ls -la ~/.ssh") for p in plans for c in p),
    "data_exfiltration": lambda plans: any(c.startswith("curl -T ") for p in plans for c in p),
}
PACING = {name: 9101 + i for i, name in enumerate(ORDER)}
full = json.loads((REPO / "dataset_builder" / "profiles_v2_compat.json").read_text(encoding="utf-8"))
roots = [REPO / "dataset_builder" / "runs", REPO / "reports"]
used = {seed: [h for r in roots for h in glt.find_pacing_seed_reuse(str(r), seed)] for seed in PACING.values()}
assert not any(used.values()), used
chosen = {}
for name in ORDER:
    cfg = dict(full, profiles=[p for p in full["profiles"] if p["name"] == name])
    (HERE / "configs" / f"{name}.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    held_out = cfg["profiles"][0].get("held_out", False)
    ok = REQUIRE.get(name, lambda plans: True)
    for seed in range(1, 201):
        rng = random.Random(seed)
        plans = []
        for profile in glt.weighted_profile_order(cfg["profiles"], SESSIONS, rng, held_out):
            glt.plan_credentials(profile, rng)
            plans.append(glt.plan_commands(profile, cfg.get("placeholders", {}), rng))
        if ok(plans):
            chosen[name] = {"seed": seed, "pacing_seed": PACING[name], "include_held_out": held_out, "planned_commands": plans}
            break
(HERE / "configs" / "session_plan.json").write_text(json.dumps({"source_profiles": "dataset_builder/profiles_v2_compat.json",
    "pacing_seeds_checked_unused_under": [str(r.relative_to(REPO)) for r in roots], "sessions_per_profile": SESSIONS,
    "chosen": chosen}, indent=2), encoding="utf-8")
for name, c in chosen.items():
    print(f"{name:22s} seed={c['seed']} pacing={c['pacing_seed']} plans={c['planned_commands']}")
