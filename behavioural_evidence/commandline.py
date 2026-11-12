"""Command-line parsing: split at unquoted shell operators, tokenise with POSIX shlex, separate redirections.

Nothing is expanded (variables, aliases, $(), backticks, eval): those are flagged, never executed or guessed.
"""
import re
import shlex
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

OPERATORS = ("||", "&&", "|", ";")
REDIR_RE = re.compile(r"^(\d*)(>>|>|<)(.*)$")
SUDO_VALUE_OPTS = {"-u", "-g", "-p", "-C", "-h", "-U", "-r", "-t"}


@dataclass
class SimpleCommand:
    line_index: int
    position: int                         # order within the line
    raw: str
    argv: List[str]
    name: str                             # basename of argv[0]
    wrapper: Optional[str] = None         # 'sudo' when the command ran under sudo
    wrapper_options: List[str] = field(default_factory=list)
    redirections: List[Tuple[str, str]] = field(default_factory=list)   # (operator, target)
    local_exec: bool = False              # argv[0] starts with ./
    operator_before: Optional[str] = None
    parse_degraded: bool = False
    has_substitution: bool = False

    @property
    def args(self):
        return self.argv[1:]


def split_operators(line: str):
    """Split at unquoted operators. Returns [(segment, operator_before)] and whether any operator occurred."""
    parts, buf, op_before = [], [], None
    quote = None
    i = 0
    found = False
    while i < len(line):
        ch = line[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            elif ch == "\\" and quote == '"' and i + 1 < len(line):
                buf.append(line[i + 1])
                i += 1
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "\\" and i + 1 < len(line):
            buf.extend(line[i:i + 2])
            i += 2
            continue
        matched = next((op for op in OPERATORS if line.startswith(op, i)), None)
        if matched and not (matched == "|" and buf and buf[-1] == ">"):      # '>|' is a redirection, not a pipe
            parts.append(("".join(buf).strip(), op_before))
            op_before, buf, found = matched, [], True
            i += len(matched)
            continue
        buf.append(ch)
        i += 1
    parts.append(("".join(buf).strip(), op_before))
    return [(seg, op) for seg, op in parts if seg], found


def parse_line(line: str, line_index: int = 0) -> Tuple[List[SimpleCommand], bool]:
    """Return (simple commands in order, line_has_operator)."""
    segments, has_op = split_operators(line)
    out = []
    for pos, (seg, op) in enumerate(segments):
        degraded = False
        try:
            tokens = shlex.split(seg, posix=True)
        except ValueError:
            tokens, degraded = seg.split(), True
        argv, redirs = [], []
        k = 0
        while k < len(tokens):
            m = REDIR_RE.match(tokens[k])
            if m:
                target = m.group(3)
                if not target and k + 1 < len(tokens):
                    target = tokens[k + 1]
                    k += 1
                redirs.append((m.group(1) + m.group(2), target))
            else:
                argv.append(tokens[k])
            k += 1
        wrapper, wopts = None, []
        if argv and argv[0].rsplit("/", 1)[-1] == "sudo":
            wrapper = "sudo"
            rest = argv[1:]
            while rest and rest[0].startswith("-"):
                o = rest.pop(0)
                wopts.append(o)
                if o in SUDO_VALUE_OPTS and rest:
                    wopts.append(rest.pop(0))
                if o == "--":
                    break
            argv = rest
        name = argv[0].rsplit("/", 1)[-1] if argv else ""
        out.append(SimpleCommand(line_index=line_index, position=pos, raw=seg, argv=argv, name=name, wrapper=wrapper,
                                 wrapper_options=wopts, redirections=redirs, local_exec=bool(argv) and argv[0].startswith("./"),
                                 operator_before=op, parse_degraded=degraded,
                                 has_substitution=("$(" in seg) or ("`" in seg)))
    return out, has_op


def options(argv_args):
    """Option tokens (start with '-' and are not just '-')."""
    return [a for a in argv_args if a.startswith("-") and a != "-"]


def operands(argv_args):
    return [a for a in argv_args if not (a.startswith("-") and a != "-")]


def path_components(p: str):
    return [c for c in p.replace("\\", "/").split("/") if c not in ("", ".")]
