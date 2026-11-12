"""Versioned indicator and interpretation definitions (single source of truth for IDs, kinds and limitations).

Kinds:
  action   may support an interpretation
  context  descriptive; never establishes an interpretation on its own
  caveat   emulator/generator/sensor property; never behavioural evidence and never converted into an indicator
Evidence classes follow reports/behavioural_evidence_framework_design_20261111/evidence_semantics.md.
"""
from dataclasses import dataclass, field
from typing import Dict, Tuple

CATALOGUE_VERSION = "v2-evidence-1.1"
DESIGN_VERSION = "v2-evidence-1.0"
SUPPORTED_CATALOGUE_VERSIONS = (CATALOGUE_VERSION,)

AMENDMENTS = [
    {"version": "v2-evidence-1.1", "from": DESIGN_VERSION, "approved": "Task 22 (design open decisions 1-2)",
     "changes": [
         "NET-1 restricted to scanning tools, or probe tools aimed at qualifying internal/scan targets (FP-4).",
         "NET-0 added (context): HTTP HEAD (curl -I/--head) and probe tools aimed at non-qualifying targets are "
         "reachability checks, never reconnaissance.",
         "AUTH-1/AUTH-2: >= 3 distinct failures within 300 s from the same observed src_ip; relay/NAT sources and "
         "sessions without attribution are 'indeterminate'.",
         "TIME-0 may carry an 'unusual timing' caveat from the reference timing calibration (caveat only).",
     ]},
]

T_INPUT = "cowrie.command.input (input)"


@dataclass(frozen=True)
class Indicator:
    id: str
    name: str
    category: str
    kind: str                 # action | context | caveat
    evidence_class: str       # directly_observed | inferred | emulator_dependent | generator_dependent | sensor_calibration
    telemetry: Tuple[str, ...]
    limitations: str
    outcome_capable: bool = False   # attempt indicators whose outcome is reported separately


INDICATORS: Dict[str, Indicator] = {i.id: i for i in [
    Indicator("AUTH-0", "authentication failure in session", "authentication", "context", "directly_observed",
              ("cowrie.login.failed",), "a rejected login; says nothing about intent or other attempts"),
    Indicator("AUTH-1", "repeated authentication failures from one source", "authentication", "action", "directly_observed",
              ("cowrie.login.failed", "src_ip", "timestamp"),
              "one network source failed >= 3 times in 300 s; cannot separate actors behind shared/NAT/relay addresses"),
    Indicator("AUTH-2", "login success after repeated failures", "authentication", "action", "directly_observed",
              ("cowrie.login.failed", "cowrie.login.success", "src_ip", "timestamp"),
              "does not show the credentials were guessed rather than known"),
    Indicator("SHELL-1", "interactive command activity", "execution", "context", "directly_observed", (T_INPUT,),
              "commands were issued; not what they did"),
    Indicator("DISC-1", "system/identity discovery command", "discovery", "context", "directly_observed", (T_INPUT,),
              "ordinary administration uses the same commands"),
    Indicator("PRIV-1", "privilege-context probe", "privilege", "action", "directly_observed", (T_INPUT,),
              "attempted enumeration only; Cowrie output (what was found) is not logged"),
    Indicator("PRIV-2", "command run under sudo", "privilege", "context", "directly_observed", (T_INPUT,),
              "elevation requested; success is emulated and not logged"),
    Indicator("CRED-1", "credential-material access attempt", "credential_access", "action", "directly_observed", (T_INPUT,),
              "does not show the file existed or was read"),
    Indicator("FILE-1", "named file search", "file_discovery", "context", "directly_observed", (T_INPUT,),
              "search issued; results not logged"),
    Indicator("FILE-2", "filesystem size/recursive survey", "file_discovery", "context", "directly_observed", (T_INPUT,),
              "routine disk administration"),
    Indicator("XFER-1", "download attempt", "transfer", "action", "directly_observed", (T_INPUT, "cowrie.session.file_download"),
              "attempt only; success requires a cowrie.session.file_download event", outcome_capable=True),
    Indicator("XFER-1-OK", "download recorded by honeypot", "transfer", "action", "directly_observed",
              ("cowrie.session.file_download",), "the honeypot stored a file; not that it ran"),
    Indicator("XFER-2", "upload attempt", "transfer", "action", "directly_observed", (T_INPUT, "cowrie.session.file_upload"),
              "attempt only; success requires a cowrie.session.file_upload event", outcome_capable=True),
    Indicator("XFER-2-OK", "upload recorded by honeypot", "transfer", "action", "directly_observed",
              ("cowrie.session.file_upload",), "the honeypot received a file"),
    Indicator("EXEC-1", "execution of a file this session tried to download", "execution", "action", "inferred", (T_INPUT,),
              "links two typed commands; does not show the file existed or ran"),
    Indicator("STAGE-1", "archive creation attempt", "staging", "action", "directly_observed", (T_INPUT,),
              "does not show an archive was created"),
    Indicator("EVADE-1", "shell-history tampering", "defence_evasion", "action", "directly_observed", (T_INPUT,),
              "does not show history was unrecoverable"),
    Indicator("PERS-0", "persistence-related read", "persistence", "context", "directly_observed", (T_INPUT,),
              "inspection only; never persistence"),
    Indicator("PERS-1", "persistence modification attempt", "persistence", "action", "directly_observed", (T_INPUT,),
              "does not show the change persisted"),
    Indicator("NET-0", "reachability check", "network", "context", "directly_observed", (T_INPUT,),
              "connectivity/HTTP HEAD check; not reconnaissance"),
    Indicator("NET-1", "network probe attempt", "network", "action", "directly_observed", (T_INPUT,),
              "attempted probe; not a successful scan (lab network is isolated)"),
    Indicator("CHAIN-1", "shell operator / chaining", "composition", "context", "directly_observed", (T_INPUT,),
              "pipelines are ubiquitous"),
    Indicator("REDIR-1", "output redirection to a file", "composition", "context", "directly_observed", (T_INPUT,),
              "file content not logged"),
    Indicator("EMU-1", "emulator could not run a command", "emulator", "caveat", "emulator_dependent", ("cowrie.command.failed",),
              "a property of Cowrie, not of the client"),
    Indicator("ART-1", "known emulator latency artefact", "sensor", "caveat", "sensor_calibration",
              (T_INPUT, "sensor calibration slow-command list"), "timing of this session is inflated by emulator execution"),
    Indicator("SEQ-1", "previously seen exact command sequence", "repetition", "caveat", "generator_dependent",
              (T_INPUT, "reference sequence store"), "templates/automation repeat; not identity"),
    Indicator("TIME-0", "timing context", "timing", "caveat", "generator_dependent",
              ("cowrie.command.input timestamps", "cowrie.session.closed duration"),
              "pacing and emulator latency are not separable in Cowrie JSON"),
]}

ACTION = frozenset(k for k, v in INDICATORS.items() if v.kind == "action")
CONTEXT = frozenset(k for k, v in INDICATORS.items() if v.kind == "context")
CAVEAT = frozenset(k for k, v in INDICATORS.items() if v.kind == "caveat")


@dataclass(frozen=True)
class Interpretation:
    name: str
    all_of: Tuple[str, ...] = ()           # every listed action indicator required
    any_of: Tuple[str, ...] = ()           # plus at least one of these (action or context, as supporting evidence)
    same_file: bool = False                # XFER-1 and EXEC-1 must reference the same file name
    scope: str = "session"                 # session | source_window
    supporting: Tuple[str, ...] = field(default=())   # extra action indicators that raise E1 -> E2 when present


INTERPRETATIONS: Tuple[Interpretation, ...] = (
    Interpretation("repeated authentication failures", all_of=("AUTH-1",), scope="source_window"),
    Interpretation("credential guessing followed by login", all_of=("AUTH-1", "AUTH-2"), scope="source_window"),
    Interpretation("privilege-context reconnaissance attempt", all_of=("PRIV-1",), any_of=("CRED-1", "FILE-1", "DISC-1"),
                   supporting=("CRED-1",)),
    Interpretation("credential-material access attempt", all_of=("CRED-1",), supporting=("PRIV-1",)),
    Interpretation("download attempt", all_of=("XFER-1",), supporting=("XFER-1-OK", "EXEC-1")),
    Interpretation("download-and-execute attempt", all_of=("XFER-1", "EXEC-1"), same_file=True, supporting=("XFER-1-OK",)),
    Interpretation("upload attempt", all_of=("XFER-2",), supporting=("XFER-2-OK", "STAGE-1")),
    Interpretation("archive-and-upload attempt", all_of=("STAGE-1", "XFER-2"), supporting=("XFER-2-OK",)),
    Interpretation("history tampering attempt", all_of=("EVADE-1",)),
    Interpretation("persistence modification attempt", all_of=("PERS-1",)),
    Interpretation("network probing attempt", all_of=("NET-1",)),
)
OUTCOME_EVENTS = {"XFER-1": "XFER-1-OK", "XFER-2": "XFER-2-OK"}


def catalogue_document():
    """Machine-readable catalogue (written next to outputs; also the compatibility contract)."""
    return {"catalogue_version": CATALOGUE_VERSION, "design_version": DESIGN_VERSION, "amendments": AMENDMENTS,
            "indicators": [{"id": i.id, "name": i.name, "category": i.category, "kind": i.kind, "evidence_class": i.evidence_class,
                            "telemetry": list(i.telemetry), "limitations": i.limitations, "outcome_capable": i.outcome_capable}
                           for i in INDICATORS.values()],
            "interpretations": [{"name": r.name, "all_of": list(r.all_of), "any_of": list(r.any_of), "same_file": r.same_file,
                                 "scope": r.scope, "supporting": list(r.supporting)} for r in INTERPRETATIONS]}


def check_catalogue(doc):
    """Raise CatalogueError unless an external catalogue document is exactly compatible with this implementation."""
    from .errors import CatalogueError
    if doc.get("catalogue_version") not in SUPPORTED_CATALOGUE_VERSIONS:
        raise CatalogueError(f"unsupported catalogue version {doc.get('catalogue_version')!r}; supported {SUPPORTED_CATALOGUE_VERSIONS}")
    ids = [i.get("id") for i in doc.get("indicators", [])]
    if sorted(ids) != sorted(INDICATORS):
        raise CatalogueError(f"catalogue indicator set differs: missing {sorted(set(INDICATORS) - set(ids))}, "
                             f"unknown {sorted(set(ids) - set(INDICATORS))}")
    for i in doc["indicators"]:
        if i.get("kind") != INDICATORS[i["id"]].kind:
            raise CatalogueError(f"{i['id']}: kind {i.get('kind')!r} differs from implementation {INDICATORS[i['id']].kind!r}")
    for r in INTERPRETATIONS:
        for ind in r.all_of:
            if INDICATORS[ind].kind != "action":
                raise CatalogueError(f"interpretation {r.name!r} requires non-action indicator {ind}")
    return True
