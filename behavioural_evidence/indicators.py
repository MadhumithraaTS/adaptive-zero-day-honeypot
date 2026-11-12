"""Command-text indicator matchers. Each returns Match records citing the source line, simple command and token.

Matching uses command names (basename of argv[0], after a sudo wrapper), specific flags, and path components or exact
paths. There is no substring matching on whole lines.
"""
import ipaddress
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

from .commandline import SimpleCommand, operands, options, path_components


@dataclass
class Match:
    indicator: str
    line_index: int
    line: str
    command: str          # the simple command
    token: str            # the token(s) that satisfied the rule
    detail: str = ""
    file: Optional[str] = None     # file name linked by XFER-1/EXEC-1
    position: int = 0              # simple-command position within the line (order)


DISCOVERY = frozenset({"whoami", "id", "groups", "w", "who", "uname", "hostname", "uptime", "lscpu", "nproc", "free", "df",
                       "ps", "ip", "ifconfig", "ss", "netstat", "arp", "route", "last", "lastlog", "env", "printenv"})
READERS = frozenset({"cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "strings", "vi", "vim", "nano", "view"})
CRED_FINAL = re.compile(r"^(shadow|gshadow|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|authorized_keys|\.bash_history)$")
CRED_FIND_NAMES = re.compile(r"^(id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|authorized_keys|shadow|\.bash_history)$")
SUID_MODES = frozenset({"-4000", "-u=s", "/4000", "-2000", "-g=s", "/2000", "/6000", "-6000"})
URL_RE = re.compile(r"^(https?|ftp|tftp)://[^\s]+$", re.I)
DOWNLOADERS = frozenset({"wget", "curl", "tftp", "ftpget", "fetch"})
SCANNERS = frozenset({"nmap", "masscan", "zmap", "unicornscan"})
PROBE_TOOLS = frozenset({"ping", "ping6", "telnet", "nc", "ncat", "netcat", "ssh", "traceroute", "tracepath", "arping", "hping3"})
NC_NAMES = frozenset({"nc", "ncat", "netcat"})
PERSIST_PATH = re.compile(r"^(/etc/crontab|/etc/cron\.[^/]+(/.*)?|/var/spool/cron(/.*)?|/etc/rc\.local|/etc/init\.d/.+|"
                          r"/etc/systemd/system/.+|/lib/systemd/system/.+)$")
DEFAULT_INTERNAL_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
                             "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128")


def _m(ind, c, line, token, detail="", file=None):
    return Match(ind, c.line_index, line, c.raw, token, detail, file, c.position)


def _is_path_arg(a):
    return not a.startswith("-") or "/" in a


# ---------------------------------------------------------------------------------------------------------------- PRIV
def priv(c: SimpleCommand, line: str) -> List[Match]:
    out = []
    if c.wrapper == "sudo" and not c.argv and ({"-l", "--list", "-ll"} & set(c.wrapper_options)):
        out.append(_m("PRIV-1", c, line, "sudo " + " ".join(c.wrapper_options), "sudo privilege listing"))
    if c.name in READERS:
        for a in operands(c.args):
            if a == "/etc/sudoers" or a.startswith("/etc/sudoers.d/"):
                out.append(_m("PRIV-1", c, line, a, "read of sudoers"))
    if c.name == "find":
        a = c.args
        for k, tok in enumerate(a[:-1]):
            if tok == "-perm" and a[k + 1] in SUID_MODES:
                out.append(_m("PRIV-1", c, line, f"-perm {a[k + 1]}", "SUID/SGID search"))
    if c.name in ("ls", "cd", "find"):
        for a in operands(c.args):
            comps = path_components(a)
            if (a.startswith("/root") and comps and comps[0] == "root") or a == "~root" or a.startswith("~root/"):
                out.append(_m("PRIV-1", c, line, a, "access to /root"))
    if c.wrapper == "sudo" and c.argv:
        out.append(_m("PRIV-2", c, line, "sudo", f"wrapped command {c.name}"))
    return out


# ---------------------------------------------------------------------------------------------------------------- CRED
def cred(c: SimpleCommand, line: str) -> List[Match]:
    out = []
    args = c.args
    for k, a in enumerate(args):
        if a.startswith("-"):
            continue
        if c.name == "find" and k > 0 and args[k - 1] in ("-name", "-iname"):
            if CRED_FIND_NAMES.match(a):
                out.append(_m("CRED-1", c, line, a, "find for credential file name"))
            continue
        comps = path_components(a)
        if not comps:
            continue
        if CRED_FINAL.match(comps[-1]) and (len(comps) > 1 or c.name in READERS | {"ls", "cp", "scp", "tar", "find", "chmod"}):
            out.append(_m("CRED-1", c, line, a, "credential file path"))
        elif ".ssh" in comps[:-1] or comps[-1] == ".ssh":
            out.append(_m("CRED-1", c, line, a, "path inside .ssh"))
    return out


# ---------------------------------------------------------------------------------------------------------------- FILE
def files(c: SimpleCommand, line: str) -> List[Match]:
    out = []
    if c.name == "find":
        for tok in ("-name", "-iname", "-path"):
            if tok in c.args:
                out.append(_m("FILE-1", c, line, tok))
                break
    if c.name == "du":
        out.append(_m("FILE-2", c, line, "du"))
    if c.name == "ls" and any(o == "--recursive" or (o.startswith("-") and not o.startswith("--") and "R" in o) for o in options(c.args)):
        out.append(_m("FILE-2", c, line, "ls -R"))
    return out


# ------------------------------------------------------------------------------------------------------------ TRANSFER
def transfer(c: SimpleCommand, line: str) -> List[Match]:
    out = []
    a = c.args
    urls = [x for x in a if URL_RE.match(x)]
    if c.name == "curl":
        upload = next((x for x in a if x in ("-T", "--upload-file") or x.startswith("--upload-file=") or x in ("-F", "--form")
                       or x.startswith("-F") and len(x) > 2), None)
        data_file = any(x.startswith("@") for x in a) and any(o in ("-d", "--data", "--data-binary") for o in a)
        if upload or data_file:
            out.append(_m("XFER-2", c, line, upload or "--data @file", "curl upload option"))
            return out
        if {"-I", "--head"} & set(a):
            return out                                   # HTTP HEAD: NET-0 (context), not a download
        if urls:
            target = None
            for k, x in enumerate(a):
                if x in ("-o", "--output") and k + 1 < len(a):
                    target = a[k + 1]
            if target is None and ({"-O", "--remote-name"} & set(a)):
                target = urls[0].rstrip("/").rsplit("/", 1)[-1]
            out.append(_m("XFER-1", c, line, urls[0], "curl URL", file=(target.rsplit("/", 1)[-1] if target and target != "-" else None)))
    elif c.name == "wget" and urls:
        target, stdout = None, False
        for k, x in enumerate(a):
            if x in ("-O", "--output-document") and k + 1 < len(a):
                target = a[k + 1]
            elif x.startswith("--output-document="):
                target = x.split("=", 1)[1]
            elif re.match(r"^-[a-zA-Z]*O$", x) and k + 1 < len(a):
                target = a[k + 1]
            elif re.match(r"^-[a-zA-Z]*O-$", x):
                stdout = True
        if target == "-":
            stdout = True
        if target is None and not stdout:
            target = urls[0].rstrip("/").rsplit("/", 1)[-1]
        out.append(_m("XFER-1", c, line, urls[0], "wget URL", file=None if stdout else target.rsplit("/", 1)[-1]))
    elif c.name in ("tftp",):
        if "-p" in a or "put" in a:
            out.append(_m("XFER-2", c, line, "tftp put"))
        elif "-g" in a or "get" in a or urls:
            out.append(_m("XFER-1", c, line, "tftp get"))
    elif c.name == "ftpget":
        out.append(_m("XFER-1", c, line, "ftpget"))
    elif c.name == "ftpput":
        out.append(_m("XFER-2", c, line, "ftpput"))
    elif c.name == "fetch" and urls:
        out.append(_m("XFER-1", c, line, urls[0]))
    elif c.name == "scp":
        ops = operands(a)
        if len(ops) >= 2:
            if ":" in ops[-1] and not ops[-1].startswith("/"):
                out.append(_m("XFER-2", c, line, ops[-1], "scp to remote"))
            elif any(":" in x for x in ops[:-1]):
                out.append(_m("XFER-1", c, line, ops[0], "scp from remote", file=ops[-1].rsplit("/", 1)[-1]))
    elif c.name in NC_NAMES and any(op == "<" for op, _ in c.redirections) and operands(a):
        out.append(_m("XFER-2", c, line, "<" + next(t for op, t in c.redirections if op == "<"), "nc with input file"))
    return out


def exec_after_download(cmds: Sequence[SimpleCommand], lines: Sequence[str], downloads: List[Match]) -> List[Match]:
    """EXEC-1: run/chmod +x of a file name an earlier XFER-1 targeted (order preserved by (line, position))."""
    out = []
    for c in cmds:
        earlier = {d.file for d in downloads if d.file and (d.line_index, d.position) < (c.line_index, c.position)}
        if not earlier or not c.argv:
            continue
        target = None
        if c.local_exec:
            target = c.argv[0][2:].rsplit("/", 1)[-1]
        elif c.name in ("sh", "bash", "dash", "busybox") and operands(c.args):
            target = operands(c.args)[0].rsplit("/", 1)[-1]
        elif c.name == "chmod" and len(c.args) >= 2 and (("+x" in c.args[0]) or re.match(r"^[0-7]*[1357][0-7]?[0-7]?$", c.args[0]) and len(c.args[0]) >= 3):
            target = c.args[-1].rsplit("/", 1)[-1]
        if target and target in earlier:
            out.append(_m("EXEC-1", c, lines[c.line_index], c.argv[0] if c.local_exec else f"{c.name} {target}", "uses downloaded file name", file=target))
    return out


# ------------------------------------------------------------------------------------------------ STAGE / EVADE / PERS
def stage_evade_persist(c: SimpleCommand, line: str) -> List[Match]:
    out = []
    a = c.args
    if c.name == "tar" and a:
        first = a[0]
        if "--create" in a or (re.match(r"^-?[A-Za-z]+$", first) and "c" in first.lstrip("-")) or any(re.match(r"^-[A-Za-z]*c[A-Za-z]*$", x) for x in options(a)):
            out.append(_m("STAGE-1", c, line, first, "tar create"))
    elif c.name in ("zip", "7z", "rar") and operands(a):
        out.append(_m("STAGE-1", c, line, c.name))
    elif c.name in ("gzip", "xz", "bzip2") and operands(a) and not ({"-d", "--decompress", "-l"} & set(a)):
        out.append(_m("STAGE-1", c, line, c.name))
    if (c.name == "history" and "-c" in a) or (c.name == "unset" and "HISTFILE" in a) \
            or (c.name == "export" and any(x.startswith(("HISTFILE=", "HISTSIZE=0", "HISTFILESIZE=0")) for x in a)) \
            or (c.name == "set" and a[:2] == ["+o", "history"]) \
            or (c.name in ("rm", "ln", "shred", "truncate") and any(path_components(x)[-1:] == [".bash_history"] for x in operands(a))):
        out.append(_m("EVADE-1", c, line, " ".join([c.name] + a[:2])))
    if c.name == "crontab":
        if operands(a) or ({"-e", "-r", "-i"} & set(a)) or any(op in ("<",) for op, _ in c.redirections):
            out.append(_m("PERS-1", c, line, " ".join(["crontab"] + a[:2]), "crontab modification"))
        elif "-l" in a:
            out.append(_m("PERS-0", c, line, "crontab -l"))
    if c.name == "systemctl" and a[:1] == ["enable"]:
        out.append(_m("PERS-1", c, line, "systemctl enable"))
    if c.name in ("update-rc.d", "chkconfig") and operands(a):
        out.append(_m("PERS-1", c, line, c.name))
    for op, t in c.redirections:
        if op.endswith(">") or op.endswith(">>"):
            if PERSIST_PATH.match(t):
                out.append(_m("PERS-1", c, line, f"{op} {t}", "write to persistence location"))
    if c.name in ("tee",) and any(PERSIST_PATH.match(x) for x in operands(a)):
        out.append(_m("PERS-1", c, line, "tee persistence path"))
    if c.name in READERS | {"ls"} and any(x == "/etc/crontab" or x.startswith("/etc/cron") for x in operands(a)):
        out.append(_m("PERS-0", c, line, next(x for x in operands(a) if x.startswith("/etc/cron")), "cron read"))
    if (c.name == "service" and "status" in a) or (c.name == "systemctl" and a[:1] and a[0] in ("status", "is-active", "list-units", "list-unit-files", "is-enabled")):
        out.append(_m("PERS-0", c, line, f"{c.name} {a[0] if c.name == 'systemctl' else 'status'}", "service status read"))
    return out


# ---------------------------------------------------------------------------------------------------------------- NET
class NetScope:
    """Qualifying internal/scan targets for NET-1. Hostname-only targets qualify only if listed explicitly."""

    def __init__(self, internal_networks: Iterable[str] = DEFAULT_INTERNAL_NETWORKS, internal_hosts: Iterable[str] = ()):
        self.networks = [ipaddress.ip_network(n, strict=False) for n in internal_networks]
        self.hosts = frozenset(internal_hosts)

    def qualifies(self, target: str) -> Optional[str]:
        t = target.split("@", 1)[-1]
        if t in self.hosts:
            return "configured internal host"
        if "/" in t:
            try:
                ipaddress.ip_network(t, strict=False)
                return "network range target"
            except ValueError:
                return None
        if re.match(r"^\d+\.\d+\.\d+\.\d+-\d+$", t):
            return "address range target"
        try:
            ip = ipaddress.ip_address(t)
        except ValueError:
            return None
        return "internal address" if any(ip in n for n in self.networks) else None


def network(c: SimpleCommand, line: str, scope: NetScope) -> List[Match]:
    out = []
    a = c.args
    if c.name == "curl" and ({"-I", "--head"} & set(a)):
        return [_m("NET-0", c, line, "curl -I", "HTTP HEAD reachability check")]
    if c.name in SCANNERS:
        return [_m("NET-1", c, line, c.name, "scanning tool")]
    if c.name in NC_NAMES and any(o.startswith("-") and not o.startswith("--") and "z" in o for o in options(a)):
        return [_m("NET-1", c, line, next(o for o in options(a) if "z" in o), "nc port scan mode")]
    if c.name in PROBE_TOOLS:
        ops = operands(a)
        if c.name in ("ping", "ping6"):          # values of -c/-i/-W are operands to shlex; keep only host-like tokens
            ops = [x for k, x in enumerate(a) if not x.startswith("-") and not (k > 0 and a[k - 1] in ("-c", "-i", "-W", "-w", "-s", "-t"))]
        if c.name in NC_NAMES and any(op == "<" for op, _ in c.redirections):
            return out                             # handled as upload attempt (XFER-2)
        targets = [x for x in ops if not x.isdigit()]
        for t in targets:
            why = scope.qualifies(t)
            if why:
                return [_m("NET-1", c, line, t, f"{c.name} to {why}")]
        if targets:
            return [_m("NET-0", c, line, targets[0], f"{c.name} to non-qualifying target")]
    return out


# --------------------------------------------------------------------------------------------------- DISC / composition
def discovery(c: SimpleCommand, line: str) -> List[Match]:
    return [_m("DISC-1", c, line, c.name)] if c.name in DISCOVERY else []


def composition(cmds: Sequence[SimpleCommand], line: str, line_index: int, has_operator: bool) -> List[Match]:
    out = []
    if has_operator:
        ops = sorted({c.operator_before for c in cmds if c.operator_before})
        out.append(Match("CHAIN-1", line_index, line, line, " ".join(ops)))
    for c in cmds:
        for op, t in c.redirections:
            if op.lstrip("0123456789") in (">", ">>") and op[:1] != "2" and t not in ("/dev/null", "&1", "&2") and t:
                out.append(_m("REDIR-1", c, line, f"{op} {t}"))
    return out


def match_lines(lines: Sequence[str], scope: NetScope):
    """All command-text indicator matches for one session, in command order. Returns (matches, parsed commands)."""
    from .commandline import parse_line
    matches: List[Match] = []
    parsed: List[SimpleCommand] = []
    for li, line in enumerate(lines):
        cmds, has_op = parse_line(line, li)
        parsed.extend(cmds)
        for c in cmds:
            if not c.argv and not c.wrapper:
                continue
            for fn in (discovery, priv, cred, files, transfer, stage_evade_persist):
                matches.extend(fn(c, line))
            matches.extend(network(c, line, scope))
        matches.extend(composition(cmds, line, li, has_op))
    downloads = [m for m in matches if m.indicator == "XFER-1"]
    matches.extend(exec_after_download(parsed, lines, downloads))
    matches.sort(key=lambda m: (m.line_index, m.position, m.indicator))
    return matches, parsed


def by_indicator(matches: Iterable[Match]) -> Dict[str, List[Match]]:
    d: Dict[str, List[Match]] = {}
    for m in matches:
        d.setdefault(m.indicator, []).append(m)
    return d
