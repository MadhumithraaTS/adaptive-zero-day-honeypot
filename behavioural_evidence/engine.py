"""Session evidence aggregation, source-window authentication, interpretations, evidence levels and abstention."""
import hashlib
import json
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

from .calibration import SensorCalibration
from .catalogue import (ACTION, CATALOGUE_VERSION, CONTEXT, INDICATORS, INTERPRETATIONS, OUTCOME_EVENTS, catalogue_document,
                        check_catalogue)
from .errors import AttributionError
from .indicators import DEFAULT_INTERNAL_NETWORKS, Match, NetScope, by_indicator, match_lines
from .schema import KNOWN_EVENTS, SOURCE_DEPENDENT_EVENTS, check_schema_version, validate_event

EXIT_LINES = ("exit", "logout")
LEVELS = ("E0", "E1", "E2", "E3")


def _ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


@dataclass
class EvidenceConfig:
    telemetry_schema: str = "cowrie-json-2.9"
    relay_sources: FrozenSet[str] = frozenset()          # known relay/NAT/shared addresses -> AUTH 'indeterminate'
    auth_failure_threshold: int = 3
    auth_window_s: float = 300.0
    internal_networks: Tuple[str, ...] = DEFAULT_INTERNAL_NETWORKS
    internal_hosts: Tuple[str, ...] = ()
    calibration: Optional[SensorCalibration] = None
    reference_sequences: Optional[FrozenSet[Tuple[str, ...]]] = None   # SEQ-1 store from a reference period

    def digest(self):
        doc = {"schema": self.telemetry_schema, "relay": sorted(self.relay_sources), "thr": self.auth_failure_threshold,
               "win": self.auth_window_s, "nets": list(self.internal_networks), "hosts": sorted(self.internal_hosts),
               "cal": self.calibration.digest() if self.calibration else None,
               "seq": hashlib.sha256(json.dumps(sorted(self.reference_sequences)).encode()).hexdigest()[:16] if self.reference_sequences else None}
        return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()[:16]


class EvidenceEngine:
    def __init__(self, config: EvidenceConfig = None, catalogue: Mapping = None):
        self.config = config or EvidenceConfig()
        check_schema_version(self.config.telemetry_schema)
        check_catalogue(catalogue if catalogue is not None else catalogue_document())
        self.scope = NetScope(self.config.internal_networks, self.config.internal_hosts)

    # ------------------------------------------------------------------------------------------------ sessions
    def _sessions(self, events: Iterable[dict]):
        per, unknown = defaultdict(list), Counter()
        for n, e in enumerate(events):
            validate_event(e, n)
            if e["eventid"] not in KNOWN_EVENTS:
                unknown[e["eventid"]] += 1
            per[e["session"]].append((_ts(e["timestamp"]), n, e))
        sessions = {}
        for sid, evs in per.items():
            evs.sort(key=lambda t: (t[0], t[1]))
            es = [e for _, _, e in evs]
            src = next((e.get("src_ip") for e in es if e.get("src_ip")), None)
            for e in es:
                if e["eventid"] in SOURCE_DEPENDENT_EVENTS and not (e.get("src_ip") or src):
                    raise AttributionError(f"session {sid}: {e['eventid']} without any src_ip; repeated-failure rules need attribution")
            inputs = [(t, e["input"]) for t, _, e in evs if e["eventid"] == "cowrie.command.input" and e["input"].strip() not in EXIT_LINES]
            sessions[sid] = {"session_ref": sid, "src_ip": src, "events": evs,
                             "lines": [x for _, x in inputs], "input_times": [t for t, _ in inputs],
                             "failed": [(t, e) for t, _, e in evs if e["eventid"] == "cowrie.login.failed"],
                             "success": [(t, e) for t, _, e in evs if e["eventid"] == "cowrie.login.success"],
                             "downloads": [e for _, _, e in evs if e["eventid"] == "cowrie.session.file_download"],
                             "uploads": [e for _, _, e in evs if e["eventid"] == "cowrie.session.file_upload"],
                             "cmd_failed": [e["input"] for _, _, e in evs if e["eventid"] == "cowrie.command.failed"],
                             "closed": next((e for _, _, e in evs if e["eventid"] == "cowrie.session.closed"), None)}
        return sessions, unknown

    # ------------------------------------------------------------------------------------------- authentication
    def _auth(self, sessions):
        cfg = self.config
        per_src = defaultdict(list)
        for s in sessions.values():
            for t, e in s["failed"]:
                per_src[e.get("src_ip") or s["src_ip"]].append((t, s["session_ref"], e.get("username"), e.get("password")))
        qual_fail_sessions, windows = defaultdict(set), {}
        for src, fails in per_src.items():
            if src in cfg.relay_sources:
                continue
            fails = sorted(set(fails))                      # distinct failure events
            lo = 0
            for hi in range(len(fails)):
                while (fails[hi][0] - fails[lo][0]).total_seconds() > cfg.auth_window_s:
                    lo += 1
                if hi - lo + 1 >= cfg.auth_failure_threshold:
                    wid = f"{src}@{fails[lo][0].isoformat()}"
                    windows.setdefault(wid, {"src_ip": src, "failures": 0, "sessions": set()})
                    for f in fails[lo:hi + 1]:
                        qual_fail_sessions[f[1]].add(wid)
                        windows[wid]["sessions"].add(f[1])
                    windows[wid]["failures"] = max(windows[wid]["failures"], hi - lo + 1)
        status, auth_hits = {}, defaultdict(list)
        for s in sessions.values():
            sid, src = s["session_ref"], s["src_ip"]
            has_auth = bool(s["failed"] or s["success"])
            if not has_auth:
                status[sid] = "no_authentication_events"
                continue
            if src in cfg.relay_sources:
                status[sid] = "indeterminate:shared_source"
                continue
            if sid in qual_fail_sessions:
                for wid in sorted(qual_fail_sessions[sid]):
                    auth_hits[sid].append(Match("AUTH-1", -1, "", "", wid, f">= {cfg.auth_failure_threshold} failures in {cfg.auth_window_s:.0f} s from {src}"))
            for t, e in s["success"]:
                prior = [f for f in per_src.get(src, []) if 0 <= (t - f[0]).total_seconds() <= cfg.auth_window_s]
                if len(set(prior)) >= cfg.auth_failure_threshold:
                    auth_hits[sid].append(Match("AUTH-2", -1, "", "", f"login.success {e.get('username')}@{t.isoformat()}",
                                                f"{len(set(prior))} failures from {src} in the preceding {cfg.auth_window_s:.0f} s"))
                    if not any(m.indicator == "AUTH-1" for m in auth_hits[sid]):
                        auth_hits[sid].append(Match("AUTH-1", -1, "", "", f"{src}@window-before-success", "failures precede this success"))
            if auth_hits.get(sid):
                status[sid] = "repeated_failures" + ("+success" if any(m.indicator == "AUTH-2" for m in auth_hits[sid]) else "")
            else:
                status[sid] = "below_threshold" if s["failed"] else "success_without_repeated_failures"
        return status, auth_hits, {k: {**v, "sessions": sorted(v["sessions"])} for k, v in windows.items()}

    # ------------------------------------------------------------------------------------------------- evaluate
    def evaluate(self, events: Iterable[dict], novelty: Optional[Mapping[str, Mapping]] = None) -> Dict:
        sessions, unknown = self._sessions(events)
        auth_status, auth_hits, windows = self._auth(sessions)
        cal = self.config.calibration
        records = []
        for sid in sorted(sessions, key=lambda k: (sessions[k]["events"][0][0], k)):
            s = sessions[sid]
            matches, parsed = match_lines(s["lines"], self.scope)
            matches = list(auth_hits.get(sid, [])) + matches
            for t, e in s["failed"]:
                matches.append(Match("AUTH-0", -1, "", "", f"{e.get('username')}@{t.isoformat()}", "cowrie.login.failed"))
            if s["lines"]:
                matches.append(Match("SHELL-1", 0, s["lines"][0], s["lines"][0], f"{len(s['lines'])} line(s)"))
            for d in s["downloads"]:
                matches.append(Match("XFER-1-OK", -1, "", "", d.get("url") or d.get("shasum", ""), "cowrie.session.file_download"))
            for u in s["uploads"]:
                matches.append(Match("XFER-2-OK", -1, "", "", u.get("filename") or u.get("shasum", ""), "cowrie.session.file_upload"))
            failed_lines = set()
            for inp in s["cmd_failed"]:
                li = next((k for k, x in enumerate(s["lines"]) if x == inp), None)
                if li is None:
                    li = next((k for k, x in enumerate(s["lines"]) if inp and inp in [c.raw for c in parsed if c.line_index == k]), -1)
                failed_lines.add(li)
                matches.append(Match("EMU-1", li, s["lines"][li] if li >= 0 else "", inp, inp.split()[0] if inp.split() else inp,
                                     "cowrie.command.failed (emulator)"))
            caveats = []
            if cal:
                for k, x in enumerate(s["lines"]):
                    if cal.is_slow(x):
                        matches.append(Match("ART-1", k, x, x, x, f"calibrated slow command on sensor {cal.sensor} ({cal.version})"))
            if self.config.reference_sequences is not None and s["lines"] and tuple(s["lines"]) in self.config.reference_sequences:
                matches.append(Match("SEQ-1", 0, s["lines"][0], "", f"{len(s['lines'])}-line sequence", "seen in reference period"))
            gaps = [(b - a).total_seconds() for a, b in zip(s["input_times"], s["input_times"][1:])]
            timing = {"session_duration_s": float(s["closed"]["duration"]) if s["closed"] else None,
                      "inter_input_gaps": len(gaps), "inter_input_mean_s": round(statistics.fmean(gaps), 6) if gaps else None,
                      "inter_input_max_s": round(max(gaps), 6) if gaps else None}
            unusual = bool(cal and cal.inter_input_gap_reference_p99_s and gaps and max(gaps) > cal.inter_input_gap_reference_p99_s)
            if unusual:
                matches.append(Match("TIME-0", -1, "", "", f"max gap {max(gaps):.3f} s > reference p99 {cal.inter_input_gap_reference_p99_s:.3f} s", "unusual timing (caveat)"))
            if any(c.parse_degraded for c in parsed):
                caveats.append("parse_degraded: a line could not be tokenised with shell quoting")
            if any(c.has_substitution for c in parsed):
                caveats.append("command substitution present ($() or backticks): not expanded")

            idx = by_indicator(matches)
            outcomes = {}
            for ind in ACTION:
                if ind not in idx or ind in ("XFER-1-OK", "XFER-2-OK", "AUTH-1", "AUTH-2"):
                    continue
                ok = OUTCOME_EVENTS.get(ind)
                if ok and ok in idx:
                    outcomes[ind] = "observed_success"
                elif any(m.line_index in failed_lines for m in idx[ind]):
                    outcomes[ind] = "observed_failure:emulator_rejected"
                else:
                    outcomes[ind] = "not_observed"
            if "AUTH-2" in idx:
                outcomes["AUTH-2"] = "observed_success"

            interps = []
            for r in INTERPRETATIONS:
                if not all(i in idx for i in r.all_of):
                    continue
                if r.any_of and not any(i in idx for i in r.any_of):
                    continue
                files = None
                if r.same_file:
                    files = sorted({m.file for m in idx["XFER-1"] if m.file} & {m.file for m in idx["EXEC-1"] if m.file})
                    if not files:
                        continue
                support = sorted({i for i in r.all_of + r.any_of + r.supporting if i in idx and i in ACTION})
                level = "E2" if len(support) >= 2 else "E1"
                if level == "E2" and any(outcomes.get(i) == "observed_success" or i in ("XFER-1-OK", "XFER-2-OK") for i in support):
                    level = "E3"
                interps.append({"name": r.name, "scope": r.scope, "requires": list(r.all_of), "requires_one_of": list(r.any_of),
                                "supporting_action_indicators": support, "evidence_level": level,
                                "outcome": {i: outcomes[i] for i in support if i in outcomes}, **({"files": files} if files else {})})
            action_present = sorted(i for i in idx if i in ACTION)
            session_level = max([LEVELS.index(x["evidence_level"]) for x in interps] + [1 if action_present else 0])
            if interps:
                status, reason = "interpreted", None
            elif action_present:
                status, reason = "insufficient_evidence", f"action indicator(s) {action_present} without a satisfied interpretation rule"
            elif not s["lines"] and (s["failed"] or s["success"]) and auth_status[sid].startswith("indeterminate"):
                status, reason = "indeterminate", f"authentication-only session; source attribution {auth_status[sid].split(':', 1)[1]}"
            elif "DISC-1" in idx:
                status, reason = "system_discovery_only", "context indicators only"
            elif not s["lines"]:
                status, reason = "insufficient_evidence", "no command input"
            else:
                status, reason = "insufficient_evidence", "context and/or caveat indicators only"
            ind_records = []
            for i in sorted(idx, key=lambda k: list(INDICATORS).index(k)):
                d = INDICATORS[i]
                line_caveats = sorted({c.indicator for c in matches if c.indicator in ("EMU-1", "ART-1") and
                                       c.line_index >= 0 and c.line_index in {m.line_index for m in idx[i]} and c.indicator != i})
                ind_records.append({"id": i, "name": d.name, "category": d.category, "kind": d.kind, "evidence_class": d.evidence_class,
                                    "required_telemetry": list(d.telemetry), "limitations": d.limitations,
                                    **({"outcome": outcomes[i]} if i in outcomes else {}),
                                    "caveats_on_same_lines": line_caveats,
                                    "matches": [{"line_index": m.line_index, "line": m.line, "command": m.command, "token": m.token,
                                                 "detail": m.detail, **({"file": m.file} if m.file else {})} for m in idx[i]]})
            caveat_ids = sorted(i for i in idx if INDICATORS[i].kind == "caveat")
            nov = dict(novelty[sid]) if novelty and sid in novelty else None
            records.append({
                "session_ref": sid, "src_ip": s["src_ip"], "catalogue_version": CATALOGUE_VERSION,
                "telemetry_schema": self.config.telemetry_schema, "config_digest": self.config.digest(),
                "calibration": {"sensor": cal.sensor, "version": cal.version, "digest": cal.digest()} if cal else None,
                "n_input_lines": len(s["lines"]), "authentication_status": auth_status[sid],
                "behavioural_status": status, "abstention_reason": reason, "evidence_level": LEVELS[session_level],
                "interpretations": interps, "indicators": ind_records,
                "action_indicators": action_present, "context_indicators": sorted(i for i in idx if i in CONTEXT),
                "caveat_indicators": caveat_ids, "caveats": caveats, "timing_context": timing,
                "statistical_novelty": None if nov is None else {"value": nov, "independent_of_behavioural_evidence": True,
                                                                 "explanatory_caveats": [c for c in caveat_ids if c in ("ART-1", "EMU-1", "TIME-0")]},
            })
        return {"catalogue_version": CATALOGUE_VERSION, "telemetry_schema": self.config.telemetry_schema,
                "config_digest": self.config.digest(), "sessions": records, "authentication_windows": windows,
                "unknown_event_types": dict(unknown)}


def read_jsonl(path):
    from .errors import SchemaError
    out = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SchemaError(f"{path}:{n}: malformed JSON ({exc})") from exc
    return out
