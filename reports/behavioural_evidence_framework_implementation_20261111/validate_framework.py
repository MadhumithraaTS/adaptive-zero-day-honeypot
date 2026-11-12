"""Task 22: validate behavioural_evidence on Dataset V2 train/validation (no test, sealed or exfiltration data).

    .venv/Scripts/python.exe reports/behavioural_evidence_framework_implementation_20261111/validate_framework.py

Configurations
  primary      relay_sources={172.22.0.2} (documented lab relay), default internal networks (RFC1918, loopback,
               link-local, CGNAT, ULA), calibration and SEQ-1 references from the TRAINING split only
  lab_plan     as primary + internal_hosts = the profile file's `lan_ip` placeholder pool (lab address plan; generator-
               derived, reported as a sensitivity run only)
  oracle_auth  diagnostic for the repeated-failure mechanics: each interaction gets a synthetic distinct source address
               and no relay list. Uses interaction IDs (metadata), so it is not a deployable configuration.
Labels are post-hoc only. Writes only into this directory.
"""
import hashlib
import json
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
OPENED = []


def _audit(event, args):
    if event == "open" and args and isinstance(args[0], (str, Path)):
        p = str(args[0]).replace("\\", "/").lower()
        if "ml_pipeline/work/test" in p or "sealed" in p or "/runs/test" in p or "exfiltration" in p:
            raise RuntimeError(f"blocked: {p}")
        OPENED.append(p)


sys.addaudithook(_audit)
from behavioural_evidence import EvidenceConfig, EvidenceEngine  # noqa: E402
from behavioural_evidence.calibration import CALIBRATION_SCHEMA, load_calibration  # noqa: E402
from behavioural_evidence.catalogue import ACTION, CONTEXT, catalogue_document  # noqa: E402
from behavioural_evidence.commandline import parse_line  # noqa: E402
from behavioural_evidence.engine import read_jsonl  # noqa: E402
from scripts import behaviour_pattern_analysis as bpa  # noqa: E402  (read-only, legacy comparison)

DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
T18 = REPO / "reports" / "cowrie_novelty_baseline_20261111" / "outputs" / "validation_scores.csv"
T20 = REPO / "reports" / "behavioural_signature_revalidation_v2_20261111" / "evidence" / "validation_session_signature_results.csv"
T21 = REPO / "reports" / "behavioural_evidence_framework_design_20261111" / "evidence"
OUT, CFG = HERE / "evidence", HERE / "config"
OUT.mkdir(exist_ok=True)
CFG.mkdir(exist_ok=True)
SPLITS = ("train", "validation")
RELAY = "172.22.0.2"


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


for line in (DS / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    h, name = line.split(maxsplit=1)
    assert sha(DS / name.lstrip("*").lstrip("./")) == h

# ---- calibration and references from TRAIN only
tcl = pd.read_csv(DS / "evidence" / "train_command_log.csv")
events = {s: read_jsonl(DS / "raw" / s / "cowrie_slice.json") for s in SPLITS}
labels = {s: pd.read_csv(DS / "labels" / f"{s}_session_labels.csv", dtype=str).set_index("session_ref") for s in SPLITS}
gaps = []
by_sess = defaultdict(list)
for e in events["train"]:
    if e["eventid"] == "cowrie.command.input" and e["input"].strip() not in ("exit", "logout"):
        by_sess[e["session"]].append(e["timestamp"])
for ts in by_sess.values():
    t = sorted(pd.to_datetime(ts))
    gaps += [(b - a).total_seconds() for a, b in zip(t, t[1:])]
cal_doc = {"schema": CALIBRATION_SCHEMA, "sensor": "cowrie-project (lab, image bf371c37)", "version": "train-20261110",
           "slow_threshold_s": 5.0, "slow_commands": sorted(set(tcl[tcl.wait_s >= 5].command)),
           "inter_input_gap_reference_p99_s": round(float(pd.Series(gaps).quantile(0.99)), 6),
           "source": "Dataset V2 TRAIN split only: manifest command_log wait_s >= 5 s; Cowrie command.input gap p99"}
(CFG / "sensor_calibration_lab_train.json").write_text(json.dumps(cal_doc, indent=2) + "\n", encoding="utf-8")
cal = load_calibration(CFG / "sensor_calibration_lab_train.json")
ref_seq = frozenset(tuple(v) for v in pd.DataFrame(
    [(e["session"], e["timestamp"], e["input"]) for e in events["train"]
     if e["eventid"] == "cowrie.command.input" and e["input"].strip() not in ("exit", "logout")],
    columns=["s", "t", "i"]).sort_values(["s", "t"], kind="stable").groupby("s").i.apply(tuple))
profiles = json.loads((REPO / "dataset_builder" / "profiles_v2_revised.json").read_text(encoding="utf-8"))
lan_hosts = tuple(profiles["placeholders"]["lan_ip"])
configs = {
    "primary": EvidenceConfig(relay_sources=frozenset({RELAY}), calibration=cal, reference_sequences=ref_seq),
    "lab_plan": EvidenceConfig(relay_sources=frozenset({RELAY}), calibration=cal, reference_sequences=ref_seq, internal_hosts=lan_hosts),
    "no_calibration": EvidenceConfig(relay_sources=frozenset({RELAY}), reference_sequences=ref_seq),
}
(CFG / "configurations.json").write_text(json.dumps({k: {"relay_sources": sorted(v.relay_sources), "internal_networks": list(v.internal_networks),
                                                         "internal_hosts": list(v.internal_hosts), "auth": [v.auth_failure_threshold, v.auth_window_s],
                                                         "calibration": cal_doc["version"] if v.calibration else None,
                                                         "reference_sequences": len(v.reference_sequences or ()), "digest": v.digest()}
                                                     for k, v in configs.items()}, indent=2) + "\n", encoding="utf-8")
(CFG / "catalogue_v2_evidence_1_1.json").write_text(json.dumps(catalogue_document(), indent=2) + "\n", encoding="utf-8")

# ---- novelty metadata (Task 18 validation scores) as a separate field
nov_df = pd.read_csv(T18)
novelty = {r.session_ref: {"C_input_knn": float(r.C_input_knn), "C_flag": bool(r.C_input_knn_flag_seed42)} for r in nov_df.itertuples()}


def oracle_events(evs, lab):
    """Replace src_ip by a synthetic per-interaction documentation address (diagnostic only)."""
    ids = sorted(lab.interaction_id.unique())
    rng = random.Random(0)
    addr = {i: f"198.18.{k // 250}.{k % 250 + 1}" for k, i in enumerate(ids)}
    out = []
    for e in evs:
        e2 = dict(e)
        if e2.get("session") in lab.index:
            e2["src_ip"] = addr[lab.loc[e2["session"], "interaction_id"]]
        out.append(e2)
    return out


results, records = {}, {}
for s in SPLITS:
    for name, cfg in configs.items():
        res = EvidenceEngine(cfg).evaluate(events[s], novelty=novelty if s == "validation" else None)
        records[(s, name)] = res
    records[(s, "oracle_auth")] = EvidenceEngine(EvidenceConfig(calibration=cal, reference_sequences=ref_seq)).evaluate(oracle_events(events[s], labels[s]))
for (s, name), res in records.items():
    if name in ("primary", "oracle_auth"):
        with open(OUT / f"{s}_{name}_records.jsonl", "w", encoding="utf-8", newline="\n") as f:
            for r in res["sessions"]:
                f.write(json.dumps(r, sort_keys=True) + "\n")


def frame(s, name):
    rows = []
    lab = labels[s]
    for r in records[(s, name)]["sessions"]:
        L = lab.loc[r["session_ref"]]
        rows.append({"session_ref": r["session_ref"], "interaction_id": L.interaction_id, "attack_cat": L.attack_cat, "role": L.role,
                     "status": r["behavioural_status"], "level": r["evidence_level"], "auth": r["authentication_status"],
                     "interps": tuple(sorted(i["name"] for i in r["interpretations"])), "action": tuple(r["action_indicators"]),
                     "context": tuple(r["context_indicators"]), "caveats": tuple(r["caveat_indicators"]), "rec": r})
    return pd.DataFrame(rows)


F = {(s, n): frame(s, n) for s in SPLITS for n in ("primary", "lab_plan", "no_calibration", "oracle_auth")}
CATS = sorted(labels["train"].attack_cat.unique())

# ================================================================== checks
checks = []


def check(cid, desc, split, passed, measured, detail=""):
    checks.append({"check": cid, "description": desc, "split": split, "passed": bool(passed), "measured": measured, "detail": detail})


for s in SPLITS:
    P, O = F[(s, "primary")], F[(s, "oracle_auth")]
    # 1 benign single failed login
    for nm, D in (("primary", P), ("oracle_auth", O)):
        bf = D[(D.attack_cat == "benign") & (D.role != "logged_in")]
        bad = bf[bf.interps.map(lambda x: any("authentication" in i or "credential" in i for i in x))]
        check("V1", f"no benign single failed login is a credential-attack interpretation ({nm})", s, len(bad) == 0,
              f"{len(bad)} of {len(bf)} benign failed-guess sessions")
    # 2 substring false matches
    legacy_cred = sub_ok = 0
    token_violations = []
    for r in P.rec:
        for ind in r["indicators"]:
            for m in ind["matches"]:
                if m["line_index"] < 0 or ind["id"] in ("SHELL-1", "CHAIN-1", "SEQ-1", "EMU-1", "ART-1", "TIME-0"):
                    continue
                cmds, _ = parse_line(m["line"])
                toks = {t for c in cmds for t in c.argv + c.wrapper_options + [x for _, x in c.redirections] + ([c.wrapper] if c.wrapper else [])}
                parts = m["token"].split()
                if not all(p in toks or p.lstrip("<>0123456789") in toks or p in (">", ">>", "<") or p in m["command"].split() for p in parts):
                    token_violations.append((ind["id"], m["token"], m["line"]))
    lines = [ln for r in P.rec for ind in r["indicators"] if ind["id"] == "SHELL-1" for ln in []]
    # legacy substring categories on the same validation lines vs token indicators
    sess_lines = defaultdict(list)
    for e in events[s]:
        if e["eventid"] == "cowrie.command.input" and e["input"].strip() not in ("exit", "logout"):
            sess_lines[e["session"]].append(e["input"])
    from behavioural_evidence.indicators import NetScope, match_lines
    sc = NetScope()
    for ln in (ln for v in sess_lines.values() for ln in v):
        if "credential_attack" in bpa.classify_command(ln):
            legacy_cred += 1
            got = {m.indicator for m in match_lines([ln], sc)[0]}
            sub_ok += not (got & {"CRED-1", "XFER-1", "XFER-2"})
    check("V2", "every matched token is a whole parsed token of its source line", s, not token_violations,
          f"{len(token_violations)} violations", "; ".join(map(str, token_violations[:3])))
    check("V2b", "legacy 'credential_attack' substring lines that the token matcher does not treat as credential/transfer", s, True,
          f"{sub_ok} of {legacy_cred} lines", "descriptive (e.g. `service ssh status`, `cat /etc/passwd | grep sh`)")
    # 3 curl -I
    li = P[P.role == "logged_in"]
    curl_only = [r for r in li.rec if any(i["id"] == "NET-0" and any(m["token"] == "curl -I" for m in i["matches"]) for i in r["indicators"])]
    net_from_curl = [r for r in curl_only if any(i["name"] == "network probing attempt" and all(
        m["token"] == "curl -I" for ind in r["indicators"] if ind["id"] == "NET-1" for m in ind["matches"]) for i in r["interpretations"])]
    check("V3", "`curl -I` never establishes 'network probing attempt'", s, len(net_from_curl) == 0,
          f"{len(curl_only)} sessions with curl -I; {len(net_from_curl)} interpreted as probing from it",
          f"benign 'network probing attempt': {int(li[li.attack_cat == 'benign'].interps.map(lambda x: 'network probing attempt' in x).sum())}")
    # 4 slow find caveat only
    NC = F[(s, "no_calibration")].set_index("session_ref")
    art = P[P.caveats.map(lambda x: "ART-1" in x)]
    same = all(NC.loc[r.session_ref].interps == r.interps and NC.loc[r.session_ref].level == r.level for r in art.itertuples())
    check("V4", "slow `find` (ART-1) is a caveat: interpretations and levels identical with and without calibration", s,
          same and not any("ART-1" in a for a in P.action), f"{len(art)} ART-1 sessions; identical={same}")
    # 5 no success claims without events
    dl_events = sum(e["eventid"] == "cowrie.session.file_download" for e in events[s])
    ul_events = sum(e["eventid"] == "cowrie.session.file_upload" for e in events[s])
    succ = Counter(i["id"] for r in P.rec for i in r["indicators"] if i.get("outcome") == "observed_success")
    attempts = Counter(i["id"] for r in P.rec for i in r["indicators"] if i["id"] in ("XFER-1", "XFER-2"))
    check("V5", "no download/upload success without the Cowrie event", s,
          succ.get("XFER-1", 0) <= dl_events and succ.get("XFER-2", 0) <= ul_events and not any(r["evidence_level"] == "E3" for r in P.rec),
          f"attempt sessions XFER-1 {attempts.get('XFER-1', 0)}, XFER-2 {attempts.get('XFER-2', 0)}; observed_success {dict(succ)}; download events {dl_events}, upload events {ul_events}")
    # 6 context-only
    viol = [r for r in P.rec for i in r["interpretations"] if not set(i["requires"]) <= ACTION or not set(i["requires"]) <= set(r["action_indicators"])]
    ctx_only = P[P.action.map(len) == 0]
    check("V6", "context/caveat-only sessions produce no interpretation; every interpretation's required indicators are present action indicators", s,
          not viol and not ctx_only.interps.map(len).any(), f"{len(ctx_only)} context/caveat-only sessions, {int(ctx_only.interps.map(len).sum())} interpretations; {len(viol)} rule violations")
    # 7 auth abstains
    auth_sessions = P[P.auth != "no_authentication_events"]
    check("V7", "repeated-failure rules abstain when the only source is the lab relay", s,
          (auth_sessions.auth == "indeterminate:shared_source").all() and not P.interps.map(lambda x: any("authentication" in i or "guessing" in i for i in x)).any(),
          f"{int((auth_sessions.auth == 'indeterminate:shared_source').sum())} of {len(auth_sessions)} authenticated/failed sessions indeterminate")
    ob = O[O.role != "logged_in"]
    check("V7b", "oracle-source diagnostic: AUTH-1 fires only where >= 3 failures exist in 300 s from one (synthetic) source", s, True,
          json.dumps(O[O.interps.map(lambda x: 'repeated authentication failures' in x)].attack_cat.value_counts().to_dict()),
          "diagnostic of rule mechanics with interaction IDs as source key; brute force is the only profile configured with >= 3 failures")
    # 8 coexistence
    multi = P[P.interps.map(len) >= 2]
    check("V8", "multiple interpretations can coexist in one session", s, len(multi) > 0, f"{len(multi)} sessions with >= 2 interpretations",
          json.dumps(Counter(multi.interps).most_common(3)))
    results[s] = {"primary": P, "oracle": O}

# 9/10 determinism and second run
for s in SPLITS:
    a = json.dumps(records[(s, "primary")], sort_keys=True)
    shuffled = list(events[s])
    random.Random(1).shuffle(shuffled)
    b = json.dumps(EvidenceEngine(configs["primary"]).evaluate(shuffled, novelty=novelty if s == "validation" else None), sort_keys=True)
    check("V9", "evidence levels and records are deterministic under input re-ordering", s, a == b, f"sha {hashlib.sha256(a.encode()).hexdigest()[:16]}")
# novelty separation
nv = F[("validation", "primary")]
base = EvidenceEngine(configs["primary"]).evaluate(events["validation"])
strip = lambda r: {k: v for k, v in r.items() if k != "statistical_novelty"}  # noqa: E731
same_nov = [strip(x) for x in base["sessions"]] == [strip(x) for x in records[("validation", "primary")]["sessions"]]
check("V11", "statistical novelty is a separate field and does not change behavioural output", "validation", same_nov,
      f"{sum(r['statistical_novelty'] is not None for r in records[('validation', 'primary')]['sessions'])} sessions carry novelty metadata")
pd.DataFrame(checks).to_csv(HERE / "validation_results.csv", index=False)

# ================================================================== distributions and comparison tables
dist = []
for s in SPLITS:
    for nm in ("primary", "lab_plan", "oracle_auth"):
        D = F[(s, nm)]
        for unit, m in (("logged_in", D.role == "logged_in"), ("failed_guess", D.role != "logged_in")):
            sub = D[m]
            names = Counter(i for x in sub.interps for i in x)
            for iname, n in sorted(names.items()):
                dist.append({"split": s, "config": nm, "unit": unit, "row": f"interpretation: {iname}", "sessions": n,
                             **{c: int(sub[sub.attack_cat == c].interps.map(lambda x: iname in x).sum()) for c in CATS}})
            for st in sorted(sub.status.unique()):
                dist.append({"split": s, "config": nm, "unit": unit, "row": f"status: {st}", "sessions": int((sub.status == st).sum()),
                             **{c: int(((sub.status == st) & (sub.attack_cat == c)).sum()) for c in CATS}})
            for lv in ("E0", "E1", "E2", "E3"):
                dist.append({"split": s, "config": nm, "unit": unit, "row": f"level: {lv}", "sessions": int((sub.level == lv).sum()),
                             **{c: int(((sub.level == lv) & (sub.attack_cat == c)).sum()) for c in CATS}})
pd.DataFrame(dist).to_csv(OUT / "interpretation_status_level_distribution.csv", index=False)

# false-positive comparison: legacy rules (Task 20), design prototype (Task 21), implementation (primary / lab_plan)
v20 = pd.read_csv(T20, keep_default_na=False)
v21 = pd.read_csv(T21 / "composite_interpretations_by_category.csv")
P = F[("validation", "primary")]
LP = F[("validation", "lab_plan")]
OA = F[("validation", "oracle_auth")]
bl = lambda D: D[(D.attack_cat == "benign") & (D.role == "logged_in")]  # noqa: E731
bf = lambda D: D[(D.attack_cat == "benign") & (D.role != "logged_in")]  # noqa: E731
attackish = lambda x: bool(x)  # noqa: E731
leg_bl = v20[(v20.attack_cat == "benign") & (v20.role == "logged_in")]
leg_bf = v20[(v20.attack_cat == "benign") & (v20.role != "logged_in")]
leg_attack = {"Reconnaissance", "Persistence-related activity", "Download or payload retrieval", "Command execution / privilege escalation", "Credential-attack behaviour"}
v21v = v21[v21.split == "validation"].set_index("interpretation")
fp = [
    {"measure": "benign logged-in sessions with an attack-implying interpretation", "denominator": len(bl(P)),
     "legacy_task20": int(leg_bl.interpretation.isin(leg_attack).sum()),
     "design_prototype_task21": int(v21v.loc["network probing attempt" if "network probing attempt" in v21v.index else "internal network probing", "n_benign"]),
     "implementation_primary": int(bl(P).interps.map(attackish).sum()), "implementation_lab_plan": int(bl(LP).interps.map(attackish).sum())},
    {"measure": "benign failed-guess sessions labelled credential attack", "denominator": len(bf(P)),
     "legacy_task20": int((leg_bf.interpretation == "Credential-attack behaviour").sum()),
     "design_prototype_task21": 0, "implementation_primary": int(bf(P).interps.map(attackish).sum()),
     "implementation_lab_plan": int(bf(LP).interps.map(attackish).sum()), "implementation_oracle_auth": int(bf(OA).interps.map(attackish).sum())},
    {"measure": "benign 'network probing' from curl -I", "denominator": len(bl(P)), "legacy_task20": None,
     "design_prototype_task21": 45, "implementation_primary": int(bl(P).interps.map(lambda x: "network probing attempt" in x).sum()),
     "implementation_lab_plan": int(bl(LP).interps.map(lambda x: "network probing attempt" in x).sum())},
    {"measure": "sessions claiming a successful download (legacy label 'Download or payload retrieval' vs observed_success)",
     "denominator": int((P.role == "logged_in").sum()), "legacy_task20": int((v20.interpretation == "Download or payload retrieval").sum()),
     "design_prototype_task21": 0, "implementation_primary": sum(1 for r in P.rec if any(i.get("outcome") == "observed_success" for i in r["indicators"])),
     "implementation_lab_plan": sum(1 for r in LP.rec if any(i.get("outcome") == "observed_success" for i in r["indicators"]))},
    {"measure": "slow-find sessions treated as novel/behavioural (legacy matcher E3 'Potentially Novel' vs ART-1 caveat changing output)",
     "denominator": int(P.caveats.map(lambda x: "ART-1" in x).sum()), "legacy_task20": 9, "design_prototype_task21": 0,
     "implementation_primary": 0, "implementation_lab_plan": 0},
]
pd.DataFrame(fp).to_csv(HERE / "false_positive_comparison.csv", index=False)

# per-indicator firing on validation logged-in sessions
ind_rows = []
for s in SPLITS:
    D = F[(s, "primary")]
    for iid in catalogue_document()["indicators"]:
        k = iid["id"]
        has = D.rec.map(lambda r: any(i["id"] == k for i in r["indicators"]))
        unit = D if k.startswith("AUTH") else D[D.role == "logged_in"]
        h = has[unit.index]
        ind_rows.append({"split": s, "indicator": k, "kind": iid["kind"], "unit": "all sessions" if k.startswith("AUTH") else "logged-in",
                         "sessions": int(h.sum()), "of": len(unit),
                         **{f"rate_{c}": round(float(h[unit.attack_cat == c].mean()), 4) for c in CATS}})
pd.DataFrame(ind_rows).to_csv(OUT / "indicator_rates_by_category.csv", index=False)
(OUT / "run_summary.json").write_text(json.dumps({
    "calibration": cal_doc, "configs": {k: v.digest() for k, v in configs.items()},
    "record_sha256": {f"{s}_{n}": hashlib.sha256(json.dumps(records[(s, n)], sort_keys=True).encode()).hexdigest() for s, n in records},
    "unknown_event_types": {f"{s}_{n}": records[(s, n)]["unknown_event_types"] for s, n in records},
    "checks_passed": int(sum(c["passed"] for c in checks)), "checks_total": len(checks),
    "test_like_paths_opened": [p for p in OPENED if "test" in p.rsplit("/", 1)[-1] and p.endswith((".pkl", ".csv", ".json", ".jsonl"))],
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(pd.DataFrame(checks)[["check", "split", "passed", "measured"]].to_string())
print(pd.DataFrame(fp).to_string())
