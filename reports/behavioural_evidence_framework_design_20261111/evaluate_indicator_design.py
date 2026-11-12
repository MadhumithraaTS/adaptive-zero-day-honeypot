"""Task 21: evidence review of the PROPOSED behavioural indicators on Dataset V2 train/validation (design prototype only).

    .venv/Scripts/python.exe reports/behavioural_evidence_framework_design_20261111/evaluate_indicator_design.py

Not an implementation of the framework: nothing outside this directory is written or imported for production, the
existing signatures/matcher/scoring are untouched (only read for the old-vs-new substring comparison), no model is fitted.
Inputs: Cowrie JSON slices (the only deployable telemetry), labels and interaction IDs (post-hoc / oracle grouping only),
manifest command_log wait_s (artefact diagnosis only). Test/sealed/exfiltration paths are blocked by an audit hook.
"""
import hashlib
import json
import re
import shlex
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
from scripts import behaviour_pattern_analysis as bpa  # noqa: E402  (read-only, for the substring comparison)

DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
OUT = HERE / "evidence"
OUT.mkdir(exist_ok=True)
SPLITS = ("train", "validation")
EXIT = ("exit", "logout")


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


for line in (DS / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    h, name = line.split(maxsplit=1)
    assert sha(DS / name.lstrip("*").lstrip("./")) == h

# ---------------------------------------------------------------------------------------------------------------
# Proposed tokenisation: split each recorded line into simple commands at unquoted | ; && || ; argv by shlex;
# command name = basename of argv[0]; `sudo` (and `sudo -n/-u x`) is recorded as a wrapper, the wrapped argv analysed.
# ---------------------------------------------------------------------------------------------------------------
SPLIT_RE = re.compile(r"\s*(?:\|\||&&|\||;)\s*")


def simple_commands(line):
    out = []
    for part in SPLIT_RE.split(line.strip()):
        if not part:
            continue
        try:
            argv = shlex.split(part, posix=True)
        except ValueError:
            argv = part.split()
        redirs = [a for a in argv if re.match(r"^\d?>>?|^<", a)]
        argv = [a for a in argv if not re.match(r"^\d?>>?|^<", a)]
        wrapper = None
        if argv and argv[0] == "sudo":
            wrapper = "sudo"
            argv = argv[1:]
            while argv and argv[0].startswith("-") and argv[0] not in ("-l",):
                argv = argv[2:] if argv[0] in ("-u", "-g") else argv[1:]
        name = argv[0].rsplit("/", 1)[-1] if argv else ""
        out.append({"argv": argv, "name": name, "local_exec": bool(argv) and argv[0].startswith("./"), "wrapper": wrapper,
                    "redirections": redirs, "raw": part})
    return out


URL_RE = re.compile(r"^(https?|ftp|tftp)://", re.I)
DISCOVERY = {"whoami", "id", "groups", "w", "who", "uname", "hostname", "uptime", "lscpu", "nproc", "free", "df", "ps", "ip",
             "ifconfig", "ss", "netstat", "arp", "route", "last", "lastlog", "env", "printenv"}
CRED_PATHS = re.compile(r"(^|/)(shadow|gshadow)$|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$|/\.ssh(/|$)|(^|/)authorized_keys$|(^|/)\.bash_history$")
SENSITIVE_DIRS = re.compile(r"^(/root|~root)(/|$)")


def indicators_for(cmds_lines):
    """Return {indicator_id: [evidence strings]} for one session's recorded lines (client input only)."""
    hit = defaultdict(list)
    downloaded = set()
    sc_all = [(ln, c) for ln in cmds_lines for c in simple_commands(ln)]
    for ln, c in sc_all:
        a, n = c["argv"], c["name"]
        if not a:
            continue
        args = a[1:]
        if n in DISCOVERY:
            hit["DISC-1"].append(c["raw"])
        if (n == "sudo" and "-l" in args) or (c["wrapper"] == "sudo" and n == "-l") or (c["raw"].strip() == "sudo -l"):
            hit["PRIV-1"].append(c["raw"])
        if n in ("cat", "less", "more", "head", "tail") and any(x in ("/etc/sudoers",) or x.startswith("/etc/sudoers.d") for x in args):
            hit["PRIV-1"].append(c["raw"])
        if n == "find" and any(x in ("-perm",) for x in args) and any(x in ("-4000", "-u=s", "/4000", "-2000", "-g=s") for x in args):
            hit["PRIV-1"].append(c["raw"])
        if n in ("ls", "cd", "find") and any(SENSITIVE_DIRS.match(x) for x in args):
            hit["PRIV-1"].append(c["raw"])
        if c["wrapper"] == "sudo":
            hit["PRIV-2"].append(c["raw"])
        if any(CRED_PATHS.search(x) for x in args) or (n == "find" and "-name" in args and any(re.match(r"^id_(rsa|dsa|ecdsa|ed25519)$|^authorized_keys$|^shadow$", x) for x in args)):
            hit["CRED-1"].append(c["raw"])
        if n == "find" and any(x in ("-name", "-iname", "-path") for x in args):
            hit["FILE-1"].append(c["raw"])
        if n in ("du",) or (n == "ls" and any(x.startswith("-") and "R" in x for x in args)):
            hit["FILE-2"].append(c["raw"])
        urls = [x for x in args if URL_RE.match(x)]
        if n == "curl" and ("-T" in args or "--upload-file" in args or any(x.startswith("-F") or x.startswith("--data-binary") for x in args)):
            hit["XFER-2"].append(c["raw"])
        elif n in ("wget", "curl", "tftp", "ftpget", "fetch") and urls and not ({"-I", "--head"} & set(args)):
            hit["XFER-1"].append(c["raw"])
            for i, x in enumerate(args):
                if x in ("-O", "-o") and i + 1 < len(args) and not URL_RE.match(args[i + 1]) and args[i + 1] != "-":
                    downloaded.add(args[i + 1].rsplit("/", 1)[-1])
            if n == "curl" and "-O" in args or n == "wget" and not any(x.startswith("-O") or x == "-qO-" for x in args):
                downloaded.update(u.rstrip("/").rsplit("/", 1)[-1] for u in urls)
        if n == "scp" and len(args) >= 2:
            (hit["XFER-2"] if ":" in args[-1] else hit["XFER-1"]).append(c["raw"])
        if n in ("nc", "ncat", "netcat") and "<" in c["raw"]:
            hit["XFER-2"].append(c["raw"])
        if n in ("tar",) and args and re.match(r"^-?[a-zA-Z]*c", args[0]) or n in ("zip", "7z") or (n in ("gzip", "xz", "bzip2") and args):
            hit["STAGE-1"].append(c["raw"])
        if (n == "history" and "-c" in args) or (n == "unset" and "HISTFILE" in args) or (n == "export" and any(x.startswith(("HISTFILE=", "HISTSIZE=0")) for x in args)) \
                or (n == "rm" and any(x.endswith(".bash_history") for x in args)) or (n == "ln" and any(x.endswith(".bash_history") for x in args)):
            hit["EVADE-1"].append(c["raw"])
        if (n == "crontab" and not (set(args) <= {"-l"})) or (n == "systemctl" and args[:1] == ["enable"]) or n == "update-rc.d" \
                or any(x in ("/etc/rc.local", "/etc/crontab") or x.startswith("/etc/cron.") for x in c["redirections"] + args[-1:]) and c["redirections"]:
            hit["PERS-1"].append(c["raw"])
        if (n == "crontab" and set(args) <= {"-l"}) or (n in ("cat", "ls") and any(x == "/etc/crontab" or x.startswith("/etc/cron") for x in args)) \
                or (n in ("service", "systemctl") and any(x in ("status", "list-units", "--type=service", "is-active") for x in args)):
            hit["PERS-0"].append(c["raw"])
        if (n in ("nc", "ncat", "netcat") and any(x.startswith("-z") or x == "-zv" for x in args)) or n in ("ping", "nmap", "telnet", "masscan") \
                or (n == "curl" and {"-I", "--head"} & set(args)) or (n == "ssh" and args):
            hit["NET-1"].append(c["raw"])
    # execution of a file this session tried to download (same basename), after the download attempt
    for ln, c in sc_all:
        a, n = c["argv"], c["name"]
        if not a or not downloaded:
            continue
        target = None
        if c["local_exec"]:
            target = a[0][2:]
        elif n in ("sh", "bash") and len(a) > 1:
            target = a[1].rsplit("/", 1)[-1]
        elif n == "chmod" and len(a) > 2 and ("+x" in a[1] or re.match(r"^[0-7]*[1357][0-7]*$", a[1])):
            target = a[2].rsplit("/", 1)[-1]
        if target and target in downloaded:
            hit["EXEC-1"].append(c["raw"])
    for ln in cmds_lines:
        if re.search(r"\|\||&&|;|\|", ln):
            hit["CHAIN-1"].append(ln)
        if re.search(r"(?<![0-9&])>>?\s*(?!/dev/null)\S", ln) or re.search(r"(^|\s)1?>>?\s*(?!/dev/null)\S", ln):
            hit["REDIR-1"].append(ln)
    return hit


# ---------------------------------------------------------------------------------------------------------------
INDICATOR_IDS = ["AUTH-0", "AUTH-1", "AUTH-2", "SHELL-1", "DISC-1", "PRIV-1", "PRIV-2", "CRED-1", "FILE-1", "FILE-2", "XFER-1",
                 "XFER-1-OK", "XFER-2", "XFER-2-OK", "EXEC-1", "STAGE-1", "EVADE-1", "PERS-0", "PERS-1", "NET-1", "CHAIN-1", "REDIR-1",
                 "EMU-1", "ART-1", "SEQ-1"]
# Emulator latency calibration from the TRAINING split only (manifest wait_s >= 5 s); exact command strings.
_tcl = pd.read_csv(DS / "evidence" / "train_command_log.csv")
SLOW_COMMANDS = sorted(set(_tcl[_tcl.wait_s >= 5].command))


class _Slow:
    @staticmethod
    def match(line):
        return line.strip() in SLOW_COMMANDS


SLOW_KNOWN = _Slow()


def load(split):
    ev = defaultdict(list)
    for n, line in enumerate((DS / "raw" / split / "cowrie_slice.json").read_text(encoding="utf-8").splitlines()):
        e = json.loads(line)
        ev[e["session"]].append((e["timestamp"], n, e))
    lab = pd.read_csv(DS / "labels" / f"{split}_session_labels.csv", dtype=str)
    rows = []
    for r in lab.itertuples():
        es = [e for _, _, e in sorted(ev[r.session_ref])]
        lines = [e["input"] for e in es if e["eventid"] == "cowrie.command.input" and e["input"].strip() not in EXIT]
        rows.append({"session_ref": r.session_ref, "interaction_id": r.interaction_id, "attack_cat": r.attack_cat, "role": r.role,
                     "src_ip": es[0].get("src_ip"), "start": es[0]["timestamp"], "lines": lines,
                     "login_failed": sum(e["eventid"] == "cowrie.login.failed" for e in es),
                     "login_success": any(e["eventid"] == "cowrie.login.success" for e in es),
                     "failed_inputs": [e.get("input", "") for e in es if e["eventid"] == "cowrie.command.failed"],
                     "downloads_ok": sum(e["eventid"] == "cowrie.session.file_download" for e in es),
                     "uploads_ok": sum(e["eventid"] == "cowrie.session.file_upload" for e in es)})
    return pd.DataFrame(rows)


DF = {s: load(s) for s in SPLITS}
train_seqs = Counter(tuple(r.lines) for r in DF["train"].itertuples() if r.lines)


def session_indicators(df, split):
    out = []
    # AUTH-1/2 need a per-source window. Lab topology: every session arrives from one relay IP, so the deployable key
    # (src_ip) would merge all traffic. They are therefore evaluated with interaction_id as an ORACLE source key.
    by_src = df.groupby("src_ip").size().to_dict()
    oracle = df.groupby("interaction_id").agg(fails=("login_failed", "sum"), ok=("login_success", "max"))
    for r in df.itertuples():
        h = indicators_for(r.lines)
        flags = {k: bool(h.get(k)) for k in INDICATOR_IDS}
        flags["AUTH-0"] = r.login_failed > 0
        o = oracle.loc[r.interaction_id]
        flags["AUTH-1"] = bool(o.fails >= 3)                         # >= 3 failures from the same source in the window
        flags["AUTH-2"] = bool(o.fails >= 3 and o.ok and r.login_success)
        flags["SHELL-1"] = len(r.lines) >= 1
        flags["XFER-1-OK"] = r.downloads_ok > 0
        flags["XFER-2-OK"] = r.uploads_ok > 0
        flags["EMU-1"] = len(r.failed_inputs) > 0
        flags["ART-1"] = any(SLOW_KNOWN.match(x) for x in r.lines)
        flags["SEQ-1"] = bool(r.lines) and (split != "train") and tuple(r.lines) in train_seqs
        out.append({"session_ref": r.session_ref, **flags, "n_lines": len(r.lines),
                    "evidence": json.dumps({k: v[:3] for k, v in h.items()})})
    return pd.DataFrame(out), by_src


IND = {}
src_counts = {}
for s in SPLITS:
    ind, src_counts[s] = session_indicators(DF[s], s)
    IND[s] = DF[s].merge(ind, on="session_ref")
CATS = sorted(DF["train"].attack_cat.unique())

# ---- firing rates (logged-in sessions = one per interaction; AUTH on all sessions) ----
rate_rows = []
for s in SPLITS:
    D = IND[s]
    li = D.role == "logged_in"
    for k in INDICATOR_IDS:
        base = D if k.startswith("AUTH") else D[li]
        unit = "all sessions" if k.startswith("AUTH") else "logged-in sessions"
        row = {"split": s, "indicator": k, "unit": unit, "fires": int(base[k].sum()), "of": len(base),
               "interactions": int(base[base[k]].interaction_id.nunique())}
        for c in CATS:
            sub = base[base.attack_cat == c]
            row[f"rate_{c}"] = round(float(sub[k].mean()), 4) if len(sub) else None
        row["categories_firing_ge_5pct"] = sum((row[f"rate_{c}"] or 0) >= 0.05 for c in CATS)
        rate_rows.append(row)
rates = pd.DataFrame(rate_rows)
rates.to_csv(OUT / "indicator_rates_by_category.csv", index=False)

# ---- known-problem checks ----
checks = {}
for s in SPLITS:
    D = IND[s]
    li = D.role == "logged_in"
    bfail = D[(D.attack_cat == "benign") & (D.login_failed > 0)]
    # old substring categories vs proposed token indicators on the same lines
    sub_hits = tok_hits = 0
    examples = []
    for r in D[li].itertuples():
        for ln in r.lines:
            old = set(bpa.classify_command(ln))
            if "credential_attack" in old and not indicators_for([ln]).get("CRED-1") and not indicators_for([ln]).get("NET-1"):
                sub_hits += 1
                if len(examples) < 8:
                    examples.append(ln)
    checks[s] = {
        "benign_failed_login_sessions": len(bfail),
        "benign_failed_sessions_with_AUTH-1_repeated_failures": int(bfail["AUTH-1"].sum()),
        "benign_failed_sessions_labelled_credential_attack_by_old_rule": len(bfail),
        "max_failed_logins_from_one_interaction_by_category": D.groupby(["attack_cat", "interaction_id"]).login_failed.sum().groupby("attack_cat").max().to_dict(),
        "AUTH-1_fires_by_category_sessions": D.groupby("attack_cat")["AUTH-1"].mean().round(4).to_dict(),
        "lab_distinct_src_ips": len(src_counts[s]), "lab_sessions_per_src_ip": src_counts[s],
        "old_credential_attack_lines_not_supported_by_token_indicators": sub_hits, "examples": examples,
        "download_attempt_sessions": int(D[li]["XFER-1"].sum()), "download_success_events": int(D.downloads_ok.sum()),
        "upload_attempt_sessions": int(D[li]["XFER-2"].sum()), "upload_success_events": int(D.uploads_ok.sum()),
        "slow_find_sessions_ART-1": int(D[li]["ART-1"].sum()),
        "slow_find_sessions_by_category": D[li & D["ART-1"]].attack_cat.value_counts().to_dict(),
        "emulator_unknown_command_sessions_EMU-1": int(D[li]["EMU-1"].sum()),
        "emulator_unknown_command_names": dict(Counter(x.split()[0] for xs in D[li].failed_inputs for x in xs if x.split()).most_common(12)),
        "repeated_sequence_SEQ-1_by_category": D[li & D["SEQ-1"]].attack_cat.value_counts().to_dict() if s != "train" else "n/a (reference split)",
    }

# slow-find independence: do any behavioural indicators change when ART-1 is present? (indicators read only command text)
D = IND["train"]
li = D.role == "logged_in"
pe = D[li & (D.attack_cat == "privilege_escalation")]
checks["find_artefact_independence_train_pe"] = {
    "pe_logged_in": len(pe), "pe_with_ART-1": int(pe["ART-1"].sum()),
    "indicator_rates_with_vs_without_ART-1": {k: [round(float(pe[pe["ART-1"]][k].mean()), 3), round(float(pe[~pe["ART-1"]][k].mean()), 3)]
                                              for k in ("PRIV-1", "CRED-1", "FILE-1", "DISC-1")},
    "note": "ART-1 sessions differ in CRED-1/FILE-1 by construction (find -name id_rsa is itself the slow command); no indicator uses timing"}

# interaction-level interpretations under the proposed composite rules (section 'matching_design.md')
COMPOSITES = {
    "repeated authentication failures": lambda r: r["AUTH-1"],
    "credential-guessing followed by login": lambda r: r["AUTH-2"],
    "privilege-context reconnaissance": lambda r: r["PRIV-1"] and (r["CRED-1"] or r["FILE-1"] or r["DISC-1"]),
    "credential-material access attempt": lambda r: r["CRED-1"],
    "download attempt": lambda r: r["XFER-1"],
    "download-and-execute attempt": lambda r: r["XFER-1"] and r["EXEC-1"],
    "upload attempt": lambda r: r["XFER-2"],
    "archive-and-upload attempt": lambda r: r["STAGE-1"] and r["XFER-2"],
    "anti-forensic history tampering": lambda r: r["EVADE-1"],
    "persistence modification attempt": lambda r: r["PERS-1"],
    "internal network probing": lambda r: r["NET-1"],
    "system discovery only": lambda r: r["DISC-1"] and not any(r[k] for k in ("PRIV-1", "CRED-1", "XFER-1", "XFER-2", "EVADE-1", "PERS-1", "NET-1", "STAGE-1")),
    "insufficient evidence": lambda r: r["n_lines"] == 0 or not any(r[k] for k in ("DISC-1", "PRIV-1", "CRED-1", "FILE-1", "FILE-2", "XFER-1", "XFER-2", "EXEC-1",
                                                                                 "STAGE-1", "EVADE-1", "PERS-0", "PERS-1", "NET-1")),
}
comp_rows = []
for s in SPLITS:
    D = IND[s]
    li = D[D.role == "logged_in"]
    for name, fn in COMPOSITES.items():
        base = D if name.startswith(("repeated authentication", "credential-guessing")) else li
        m = base.apply(fn, axis=1)
        comp_rows.append({"split": s, "interpretation": name, "unit": "all sessions" if base is D else "logged-in sessions",
                          "sessions": int(m.sum()), "interactions": int(base[m].interaction_id.nunique()),
                          **{f"n_{c}": int((m & (base.attack_cat == c)).sum()) for c in CATS}})
pd.DataFrame(comp_rows).to_csv(OUT / "composite_interpretations_by_category.csv", index=False)

IND["validation"].drop(columns=["lines", "failed_inputs"]).to_csv(OUT / "validation_session_indicators.csv", index=False)
res = {"inputs_verified": True, "slow_commands_calibrated_from_train": SLOW_COMMANDS, "checks": checks, "test_like_paths_opened": [p for p in OPENED if "test" in p.rsplit("/", 1)[-1]]}
(OUT / "design_evidence.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
pd.set_option("display.width", 250)
print(rates[rates.split == "validation"].drop(columns=["split"]).to_string())
print(pd.DataFrame(comp_rows).to_string())
print(json.dumps(res, indent=1, default=str)[:6000])
