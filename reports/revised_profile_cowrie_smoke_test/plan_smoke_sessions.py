"""Single-profile configs copied from dataset_builder/profiles_v2_revised.json; pre-registered planning seeds; fresh pacing seeds.

    .venv/Scripts/python.exe reports/revised_profile_cowrie_smoke_test/plan_smoke_sessions.py

The generator has no profile filter, so each profile runs from a config holding only that profile (object copied
verbatim, same placeholders and version) - the approach of reports/cowrie_compatibility_confirmation.
Planning-seed rule (fixed before any session ran): the smallest seed in 1..5000 whose 3 planned sessions contain
every command named in REQUIRE for that profile (the task-13 focus commands and each profile's critical step);
profiles without a requirement use seed 1. Planning replicates main() exactly and opens no connection.
Pacing seeds 9301..9307 (one per run) must be unused under every run root in the repository.
"""
import copy
import hashlib
import json
import random
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from dataset_builder import generate_labelled_traffic as glt  # noqa: E402

HERE = Path(__file__).resolve().parent
SRC = REPO / "dataset_builder" / "profiles_v2_revised.json"
SESSIONS = 3
ORDER = ["benign_admin", "reconnaissance", "brute_force", "botnet", "privilege_escalation", "lateral_movement",
         "data_exfiltration"]


def has(prefix):
    return lambda plans: any(c.startswith(prefix) for p in plans for c in p)


REQUIRE = {
    "benign_admin": [has("curl -I ")],
    "reconnaissance": [has("wget -qO- "), has("curl -s "), has("groups")],
    "botnet": [has("cd /tmp || cd /var/tmp"), has("wget ")],
    "privilege_escalation": [has("groups")],
    "lateral_movement": [has("nc -zv "), has("ping -c ")],
    "data_exfiltration": [has("curl -T ")],
}
PACING = {name: 9301 + i for i, name in enumerate(ORDER)}

assert hashlib.sha256(SRC.read_bytes()).hexdigest() == "79d47ac48e1f4c242ffcb851c567da884df21d039cc11917dc5bf3dea761fe62"
full = json.loads(SRC.read_text(encoding="utf-8"))
roots = [REPO / "dataset_builder" / "runs", REPO / "reports"]
used = {seed: [h for r in roots for h in glt.find_pacing_seed_reuse(str(r), seed)] for seed in PACING.values()}
assert not any(used.values()), used
(HERE / "configs").mkdir(exist_ok=True)
chosen = {}
for name in ORDER:
    cfg = dict(copy.deepcopy(full), profiles=[copy.deepcopy(p) for p in full["profiles"] if p["name"] == name])
    assert cfg["profiles"][0] == next(p for p in full["profiles"] if p["name"] == name)
    (HERE / "configs" / f"{name}.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    held_out = cfg["profiles"][0].get("held_out", False)
    for seed in range(1, 5001):
        rng = random.Random(seed)
        plans, creds = [], []
        for profile in glt.weighted_profile_order(cfg["profiles"], SESSIONS, rng, held_out):
            creds.append(glt.plan_credentials(profile, rng))
            plans.append(glt.plan_commands(profile, cfg.get("placeholders", {}), rng))
        if all(check(plans) for check in REQUIRE.get(name, [])):
            chosen[name] = {"seed": seed, "pacing_seed": PACING[name], "include_held_out": held_out,
                            "auth_attempts_planned": [len(c) for c in creds], "planned_commands": plans}
            break
    else:
        raise SystemExit(f"no seed in 1..5000 satisfies the rule for {name}")
(HERE / "configs" / "session_plan.json").write_text(json.dumps({
    "source_profiles": "dataset_builder/profiles_v2_revised.json",
    "source_sha256": "79d47ac48e1f4c242ffcb851c567da884df21d039cc11917dc5bf3dea761fe62",
    "pacing_seeds_checked_unused_under": [str(r.relative_to(REPO)) for r in roots], "sessions_per_profile": SESSIONS,
    "planning_seed_rule": "smallest seed in 1..5000 whose 3 planned sessions contain every REQUIRE prefix; else 1",
    "require": {k: len(v) for k, v in REQUIRE.items()}, "chosen": chosen}, indent=2), encoding="utf-8")
for name, c in chosen.items():
    print(f"{name:22s} seed={c['seed']} pacing={c['pacing_seed']} auth={c['auth_attempts_planned']}")
    for p in c["planned_commands"]:
        print("     ", p)
