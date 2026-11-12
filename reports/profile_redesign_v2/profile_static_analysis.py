"""Static leakage and Cowrie-compatibility analysis of V2 profiles: compat (before) vs revised (after).

    .venv/Scripts/python.exe reports/profile_redesign_v2/profile_static_analysis.py

No traffic and no classifiers. Planned sessions come from the generator's own planner (plan_commands) run
offline; planned values are proxies - Cowrie may record more or fewer lines, and tty output is not modelled.
Writes evidence/*.json and evidence/*.csv.
"""
import csv
import itertools
import json
import random
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
from dataset_builder import generate_labelled_traffic as glt  # noqa: E402

EVID = HERE / "evidence"
FILES = {"compat": REPO / "dataset_builder/profiles_v2_compat.json", "revised": REPO / "dataset_builder/profiles_v2_revised.json"}
SHELL_OPERATORS = ('|', ';', '&&', '>', '<', '`', '$(')          # configs/feature_spec_v2.json shell_operator_lines
DOWNLOAD_COMMANDS = {'wget', 'curl', 'tftp', 'ftp', 'ftpget', 'scp'}  # download_command_lines
SAMPLES = 2000
URL_HOST = re.compile(r"https?://([^/\s]+)")
registry = json.loads((EVID / "cowrie_command_registry.json").read_text(encoding="utf-8"))
PY = registry["python_commands"]
TXT = {t.rsplit("/", 1)[-1] for t in registry["txtcmds"]}
INTERACTIVE_TXT = {"vi", "vim", "nano", "pico", "emacs", "vipw"}


def name(cmd):
    t = cmd.strip().split()
    return t[0] if t else ""


def segment_names(cmd):
    """Command names of every pipeline / ; / && / || segment (Cowrie executes each)."""
    return [name(s) for s in re.split(r"\|\||&&|\||;", cmd) if s.strip()]


def expand(config):
    pools = config["placeholders"]
    out = {}
    for p in config["profiles"]:
        templates = []
        for step in p["steps"]:
            opts = step["cmd"] if isinstance(step, dict) else step
            templates += opts if isinstance(opts, list) else [opts]
        templates += p.get("noise_pool", [])
        cmds = set()
        for t in templates:
            keys = [k for k in pools if "{" + k + "}" in t]
            for vals in itertools.product(*(pools[k] for k in keys)):
                c = t
                for k, v in zip(keys, vals):
                    c = c.replace("{" + k + "}", v)
                cmds.add(c)
        out[p["attack_cat"]] = cmds
    return out


def sample(config):
    """SAMPLES planned command lists per profile from the generator's planner (seeded, offline)."""
    out = {}
    for p in config["profiles"]:
        rng = random.Random(f"static:{p['name']}")
        out[p["attack_cat"]] = [glt.plan_commands(p, config["placeholders"], rng) for _ in range(SAMPLES)]
    return out


# --- evidence of observed behaviour (smoke tests and historical runs) --------------------------------------
observed_ok, observed_block = set(), set()
for run_root in ("reports/generator_cowrie_smoke_test/runs", "reports/cowrie_compatibility_confirmation/runs",
                 "reports/diagnostic_redaction_utf8_fix/runs"):
    for man in (REPO / run_root).glob("*/manifest.jsonl"):
        for line in man.read_text(encoding="utf-8").splitlines():
            for c in json.loads(line)["command_log"]:
                if c["sent"]:
                    (observed_ok if c["prompt_returned"] else observed_block).add(c["command"])
hist = json.loads((REPO / "reports/cowrie_profile_compatibility_v2/evidence/historical_next_line.json").read_text())
hist_ok = {k for k, v in hist.items() if v["rate"] == 1.0 and v["followed"] >= 20}
verbosity = defaultdict(list)
for run_root in ("reports/cowrie_compatibility_confirmation/runs", "reports/diagnostic_redaction_utf8_fix/runs"):
    for d in (REPO / run_root).iterdir():
        man = {json.loads(l)["index"]: json.loads(l) for l in (d / "manifest.jsonl").read_text(encoding="utf-8").splitlines()}
        for l in (d / "terminal_output.jsonl").read_text(encoding="utf-8").splitlines():
            t = json.loads(l)
            if t["step"] != "initial":
                cmd = man[t["index"]]["command_log"][t["step"] - 1]["command"]
                verbosity[cmd].append(t["output_chars"])


def classify(cmd):
    n, segs = name(cmd), segment_names(cmd)
    host = URL_HOST.search(cmd)
    if n in ("ssh", "scp", "sftp", "telnet") or n in INTERACTIVE_TXT:
        return "potentially_blocking", "interactive / stdin-consuming emulation"
    if n == "ping" and "-c" not in cmd.split():
        return "potentially_blocking", "ping without -c never stops in Cowrie"
    if n == "wget" and host and re.fullmatch(r"[0-9.]+", host.group(1)):
        return "potentially_blocking", "wget to an IP hangs (wget.py ConnectingDone bug)"
    if cmd in observed_block:
        return "potentially_blocking", "observed readiness timeout"
    if n in ("wget", "curl", "nc", "tftp", "ftpget", "ftp"):
        how = "observed prompt return" if cmd in observed_ok else "source: handled failure path, exits"
        if n == "curl" and "-T" in cmd.split():
            how += "; Cowrie curl has no -T option (getopt 'Lsho:IO'): option error, no upload emulated"
        return "network_dependent_fails_in_isolation", how
    if cmd in observed_ok:
        return "confirmed_returns", "observed prompt return (tasks 7/9/10A)"
    unknown = [s for s in segs if s not in PY and s not in TXT and not s.startswith(("./", "/"))]
    static = [s for s in segs if s in TXT and s not in PY]
    if unknown:
        return "unsupported_command_not_found", f"not implemented: {sorted(set(unknown))} -> 'command not found', returns"
    if static:
        return "static_output", f"txtcmd: {sorted(set(static))}"
    if all(s in hist_ok for s in segs if s):
        return "expected_returns", "implemented; historically returned (gen 2.0 next-line rate 1.0)"
    return "expected_returns", "implemented in Cowrie source; not yet observed"


def stats_for(samples):
    def proxies(cmds):
        b = [len(c.encode("utf-8")) for c in cmds]
        return {"input_line_count": len(cmds), "input_bytes_total": sum(b), "input_line_max_bytes": max(b) if b else None,
                "unique_command_names": len({name(c) for c in cmds if name(c)}),
                "shell_operator_lines": sum(any(op in c for op in SHELL_OPERATORS) for c in cmds),
                "download_command_lines": sum(name(c) in DOWNLOAD_COMMANDS for c in cmds)}
    out = {}
    for cat, plans in samples.items():
        rows = [proxies(p) for p in plans]
        out[cat] = {}
        for f in rows[0]:
            vals = [r[f] for r in rows if r[f] is not None]
            out[cat][f] = {"min": min(vals) if vals else None, "median": statistics.median(vals) if vals else None,
                           "max": max(vals) if vals else None, "share_nonzero": sum(v > 0 for v in vals) / len(rows),
                           "missing_share": sum(r[f] is None for r in rows) / len(rows)}
    return out


def overlap(samples, expanded):
    names = {c: {name(x) for x in cmds} for c, cmds in expanded.items()}
    cats = sorted(names)
    occ = defaultdict(set)
    for c, ns in names.items():
        for n in ns:
            occ[n].add(c)
    seq_cats, set_cats, first = defaultdict(set), defaultdict(set), defaultdict(Counter)
    for c, plans in samples.items():
        for p in plans:
            seq_cats[tuple(p)].add(c)
            set_cats[frozenset(name(x) for x in p)].add(c)
            first[name(p[0]) if p else "<none>"][c] += 1
    total = sum(len(v) for v in samples.values())
    seq_shared = sum(1 for c, plans in samples.items() for p in plans if len(seq_cats[tuple(p)]) > 1) / total
    set_shared = sum(1 for c, plans in samples.items() for p in plans if len(set_cats[frozenset(name(x) for x in p)]) > 1) / total
    first_purity = sum(cnt.most_common(1)[0][1] for cnt in first.values()) / total
    return {
        "command_names_per_category": {c: sorted(ns) for c, ns in names.items()},
        "unique_names_per_category": {c: sorted(n for n in ns if len(occ[n]) == 1) for c, ns in names.items()},
        "shared_names": sorted(n for n, cs in occ.items() if len(cs) > 1),
        "share_of_names_unique": {c: len([n for n in ns if len(occ[n]) == 1]) / len(ns) for c, ns in names.items()},
        "jaccard": {f"{a}|{b}": len(names[a] & names[b]) / len(names[a] | names[b]) for a, b in itertools.combinations(cats, 2)},
        "sampled_sequences_shared_across_categories": seq_shared,
        "sampled_name_sets_shared_across_categories": set_shared,
        "first_command_majority_category_share": first_purity,
        "first_command_by_category": {k: dict(v) for k, v in first.items()},
        "name_to_categories": {n: sorted(cs) for n, cs in sorted(occ.items())},
    }


results = {}
for label, path in FILES.items():
    config = json.loads(path.read_text(encoding="utf-8"))
    expanded, samples = expand(config), sample(config)
    compat_rows = []
    for cat, cmds in expanded.items():
        for cmd in sorted(cmds):
            cls, why = classify(cmd)
            compat_rows.append({"category": cat, "command": cmd, "class": cls, "evidence": why,
                                "observed_output_chars": statistics.median(verbosity[cmd]) if cmd in verbosity else ""})
    with open(EVID / f"compatibility_{label}.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(compat_rows[0]))
        w.writeheader()
        w.writerows(compat_rows)
    ov = overlap(samples, expanded)
    cats = sorted(expanded)
    with open(EVID / f"command_category_matrix_{label}.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["command_name"] + cats + ["n_categories"])
        for n, cs in ov["name_to_categories"].items():
            w.writerow([n] + [int(c in cs) for c in cats] + [len(cs)])
    results[label] = {"version": config["version"], "overlap": ov, "planned_feature_proxies": stats_for(samples),
                      "compatibility_class_counts": dict(Counter(r["class"] for r in compat_rows)),
                      "blocking_commands": sorted({r["command"] for r in compat_rows if r["class"] == "potentially_blocking"}),
                      "has_delay_range": any("delay_range" in p for p in config["profiles"])}
(EVID / "static_analysis.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
(EVID / "observed_output_chars_by_command.json").write_text(json.dumps(
    {k: {"n": len(v), "median_chars": statistics.median(v)} for k, v in sorted(verbosity.items())}, indent=1), encoding="utf-8")

for label, r in results.items():
    o = r["overlap"]
    print(f"\n=== {label} ({r['version']})  delay_range present={r['has_delay_range']}  blocking={r['blocking_commands']}")
    print("  classes:", r["compatibility_class_counts"])
    print("  sequences shared across categories:", round(o["sampled_sequences_shared_across_categories"], 3),
          "| name-sets shared:", round(o["sampled_name_sets_shared_across_categories"], 3),
          "| first-command majority share:", round(o["first_command_majority_category_share"], 3))
    print("  share of names unique to category:", {c: round(v, 2) for c, v in o["share_of_names_unique"].items()})
    for f in ("shell_operator_lines", "download_command_lines"):
        print(f"  {f} share_nonzero:", {c: round(v[f]["share_nonzero"], 2) for c, v in r["planned_feature_proxies"].items()})
    print("  input_line_count median [min,max]:", {c: (v["input_line_count"]["median"], v["input_line_count"]["min"], v["input_line_count"]["max"]) for c, v in r["planned_feature_proxies"].items()})
    print("  input_line_max_bytes median:", {c: v["input_line_max_bytes"]["median"] for c, v in r["planned_feature_proxies"].items()})
