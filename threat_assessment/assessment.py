"""Findings, severity, attribution and policy tiers from behavioural_evidence session records (read, never modified)."""
import copy
import ipaddress
import json
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

from behavioural_evidence import CATALOGUE_VERSION as EVIDENCE_CATALOGUE
from behavioural_evidence.schema import SUPPORTED_TELEMETRY_SCHEMAS

from .attribution import ATTRIBUTABLE_STATES, attribute
from .config import ATTRIBUTION_SCHEMA_V3, POLICY_SCHEMA_V21, AttributionConfig, PolicyConfig
from .signed_attribution import VerifiedAttribution, verify_results
from .errors import AssessmentConfigError, AssessmentInputError
from .severity import ORDER as SEV_ORDER, finding_severity

LEVELS = ("E0", "E1", "E2", "E3")
REQUIRED_RECORD = ("session_ref", "src_ip", "catalogue_version", "telemetry_schema", "config_digest", "authentication_status",
                   "behavioural_status", "evidence_level", "interpretations", "indicators", "action_indicators",
                   "caveat_indicators", "n_input_lines", "statistical_novelty")
REQUIRED_INTERP = ("name", "scope", "evidence_level", "supporting_action_indicators", "outcome")
LOGIN_STATUSES = ("success_without_repeated_failures", "repeated_failures+success")
INTENT = {
    "repeated authentication failures": "consistent with password guessing",
    "credential guessing followed by login": "consistent with guessed credentials being accepted",
    "privilege-context reconnaissance attempt": "consistent with looking for a way to elevate privileges",
    "credential-material access attempt": "consistent with an attempt to obtain credentials or host trust information",
    "download attempt": "consistent with an attempt to retrieve tooling or content",
    "download-and-execute attempt": "consistent with an attempt to retrieve and run code",
    "upload attempt": "consistent with an attempt to move data off the host",
    "archive-and-upload attempt": "consistent with an attempt to stage and move data off the host",
    "history tampering attempt": "consistent with an attempt to hide activity",
    "persistence modification attempt": "consistent with an attempt to keep access",
    "network probing attempt": "consistent with mapping other hosts or services",
}


class ThreatAssessor:
    def __init__(self, attribution: AttributionConfig, policy: PolicyConfig, evidence_config):
        """evidence_config: the behavioural_evidence.EvidenceConfig that produced the records (its digest is recomputed)."""
        if policy.catalogue != EVIDENCE_CATALOGUE:
            raise AssessmentConfigError(f"policy requires catalogue {policy.catalogue!r}; installed behavioural_evidence is {EVIDENCE_CATALOGUE!r}")
        v3, p21 = attribution.schema == ATTRIBUTION_SCHEMA_V3, policy.schema_version == POLICY_SCHEMA_V21
        if v3 != p21:
            raise AssessmentConfigError(f"incompatible versions: attribution config {attribution.schema} with policy schema "
                                        f"{policy.schema_version} (v3 requires policy 2.1 and vice versa)")
        self.att, self.policy, self.ecfg = attribution, policy, evidence_config
        self.evidence_digest = evidence_config.digest()
        self.config_checks = self._config_checks()

    def _config_checks(self):
        c = {}
        c["policy_pins_attribution_digest"] = self.policy.attribution_digest == self.att.digest
        c["evidence_relays_cover_attribution_relays"] = set(self.att.relay_strings) <= set(self.ecfg.relay_sources)
        try:
            ev_nets = {ipaddress.ip_network(n, strict=False) for n in self.ecfg.internal_networks}
        except ValueError:
            ev_nets = set()
        c["evidence_internal_networks_equal_explicit_config"] = ev_nets == set(self.att.internal)
        c["evidence_auth_rule_approved"] = (self.ecfg.auth_failure_threshold, self.ecfg.auth_window_s) == (3, 300.0)
        if self.policy.schema_version == POLICY_SCHEMA_V21:
            c["policy_and_attribution_pin_same_address_safety"] = self.policy.address_safety_digest == self.att.address_safety_digest
        return c

    # ------------------------------------------------------------------------------------------------ validation
    def _validate(self, r) -> List[str]:
        errs = [f"missing field {k}" for k in REQUIRED_RECORD if k not in r]
        if errs:
            return errs
        if r["catalogue_version"] != EVIDENCE_CATALOGUE:
            errs.append(f"catalogue {r['catalogue_version']!r} != {EVIDENCE_CATALOGUE!r}")
        if r["telemetry_schema"] not in SUPPORTED_TELEMETRY_SCHEMAS:
            errs.append(f"unsupported telemetry schema {r['telemetry_schema']!r}")
        if r["evidence_level"] not in LEVELS:
            errs.append(f"invalid session evidence level {r['evidence_level']!r}")
        for i in r["interpretations"]:
            miss = [k for k in REQUIRED_INTERP if k not in i]
            if miss:
                errs.append(f"interpretation missing {miss}")
            elif i["evidence_level"] not in LEVELS[1:]:
                errs.append(f"interpretation {i['name']!r} has invalid evidence level {i['evidence_level']!r}")
        return errs

    # --------------------------------------------------------------------------------------------------- assess
    def verify_attribution(self, attribution_results, now: Optional[datetime] = None) -> Optional[VerifiedAttribution]:
        """Verify signed attribution result documents (public key only). Unsigned or invalid documents are rejected whole."""
        if attribution_results is None:
            return None
        docs = attribution_results if isinstance(attribution_results, list) else [attribution_results]
        return verify_results(docs, self.att, now or datetime.now(timezone.utc))

    def assess(self, record: dict, attribution_results=None, now: Optional[datetime] = None) -> dict:
        """attribution_results: signed attribution result document(s) produced by client_attribution (v3 configs).
        They are verified here with the pinned public key; nothing unverified is used."""
        return self._assess(record, self.verify_attribution(attribution_results, now), attribution_results is not None)

    def _assess(self, record: dict, store: Optional[VerifiedAttribution], supplied: bool) -> dict:
        r = copy.deepcopy(record)                          # the evidence record itself is never modified
        errors = self._validate(r)
        mapping, inputs_verified = None, True
        if supplied:
            if not self.att.mapping_enabled:
                errors.append("attribution results supplied but the attribution config has no proxy client mapping (v1)")
            else:
                inputs_verified = store.all_verified and bool(store.accepted)
                mapping = store.lookup(r.get("session_ref"))
        findings = []
        by_id = {i["id"]: i for i in r.get("indicators", [])}
        if not errors:
            for k, interp in enumerate(r["interpretations"]):
                try:
                    sev, basis = finding_severity(interp, by_id)
                except KeyError:
                    errors.append(f"unknown interpretation {interp['name']!r}")
                    continue
                outcome = dict(interp["outcome"])
                evidence = [{"indicator": a, "line_index": m.get("line_index"), "line": m.get("line"), "command": m.get("command"),
                             "token": m.get("token"), "detail": m.get("detail")}
                            for a in interp["supporting_action_indicators"] for m in by_id.get(a, {}).get("matches", [])]
                line_idx = {e["line_index"] for e in evidence if e["line_index"] is not None and e["line_index"] >= 0}
                caveats = sorted({c for a in interp["supporting_action_indicators"] for c in by_id.get(a, {}).get("caveats_on_same_lines", [])})
                findings.append({
                    "finding_id": f"{r['session_ref']}#{k}", "interpretation": interp["name"], "scope": interp["scope"],
                    "evidence_level": interp["evidence_level"],                       # interpretation-specific; never the session level
                    "supporting_action_indicators": list(interp["supporting_action_indicators"]),
                    "severity": sev, "severity_basis": basis,
                    "attempted": True, "outcome": outcome,
                    "success_observed": any(v == "observed_success" for v in outcome.values()),
                    "observed": evidence, "observed_line_indices": sorted(line_idx),
                    "possible_intent": INTENT.get(interp["name"], "") + " (inferred; not established)",
                    "caveat_annotations": caveats,
                    "attribution": attribute(r, self.att, mapping),
                })
        att = attribute(r, self.att, mapping) if "session_ref" in r else {"state": "unattributed:no_source"}
        digests_ok = (not errors) and r.get("config_digest") == self.evidence_digest and all(self.config_checks.values()) \
            and inputs_verified
        login_basis, auth_evidence = None, None
        if not errors:
            if self.policy.require_authentication_event:
                login_basis, auth_evidence = self._authentication_event(r, mapping)
            elif r["authentication_status"] in LOGIN_STATUSES:
                login_basis = f"authentication_status={r['authentication_status']}"
            elif r["n_input_lines"] > 0:
                login_basis = "command input recorded (Cowrie records input only after a successful login)"
        sev_min = SEV_ORDER.index(self.policy.conditions["min_finding_severity"])
        lvl_min = LEVELS.index(self.policy.conditions["min_interpretation_evidence_level"])
        qualifying = [f for f in findings if SEV_ORDER.index(f["severity"]) >= sev_min and LEVELS.index(f["evidence_level"]) >= lvl_min]
        distinct = sorted({a for f in qualifying for a in f["supporting_action_indicators"]})
        gates = {
            "1_severity_S2_or_higher": any(SEV_ORDER.index(f["severity"]) >= sev_min for f in findings),
            "2_interpretation_E2_or_higher_on_an_S2plus_finding": bool(qualifying),
            "3_two_distinct_action_indicators": len(distinct) >= self.policy.conditions["min_distinct_action_indicators"],
            "4_successful_login": login_basis is not None,
            "5_attributable_source": bool(findings) and all(f["attribution"]["state"] in ATTRIBUTABLE_STATES for f in qualifying or findings),
            "6_not_protected_or_shared": att.get("state") not in ("protected", "shared_source", "enforcement_excluded"),
            "7_verified_configuration_digests": digests_ok,
            "8_no_processing_errors": not errors,
        }
        status = r.get("behavioural_status")
        if errors:
            tier, reason = "abstain", "processing/validation error: " + "; ".join(errors)
        elif status in ("indeterminate", "insufficient_evidence"):
            tier, reason = "abstain", f"behavioural_status={status}: {r.get('abstention_reason')}"
        elif not gates["1_severity_S2_or_higher"]:
            tier, reason = "record", ("no findings (context only)" if not findings else "only S0/S1 findings")
        elif all(gates.values()):
            tier, reason = "propose", "all proposal conditions met; manual approval required"
        else:
            tier, reason = "review", "S2+ finding; failed: " + ", ".join(k for k, v in gates.items() if not v)
        proposal = None
        if tier == "propose":
            a = self.policy.action
            subject = att.get("subject") or r["src_ip"]
            proposal = {"type": a["type"], "subject": subject, "scope": a["scope"], "mode": a["mode"], "ttl_seconds": a["ttl_seconds"],
                        "inverse": {"type": a["inverse"], "subject": subject}, "manual_approval": "pending", "execution": "not_executed",
                        "subject_basis": att.get("state"), "relay_connection_id": (att.get("mapping") or {}).get("connection_id")}
        nov = r.get("statistical_novelty")
        return {
            "session_ref": r.get("session_ref"), "src_ip": r.get("src_ip"), "tier": tier, "tier_reason": reason,
            "gates": gates, "distinct_action_indicators_on_qualifying_findings": distinct, "successful_login_basis": login_basis,
            "findings": findings, "session_attribution": att, "processing_errors": errors,
            "behavioural_status": status, "authentication_status": r.get("authentication_status"),
            "session_evidence_level_reference": r.get("evidence_level"),
            "caveat_annotations": list(r.get("caveat_indicators", [])),
            "novelty_annotation": None if nov is None else {"value": nov.get("value"), "used_for_assessment": False},
            "proposed_action": proposal,
            "versions": {"assessment": "threat-assessment-1.2.0", "policy_schema": self.policy.schema_version, "evidence_catalogue": r.get("catalogue_version"),
                         "telemetry_schema": r.get("telemetry_schema"), "evidence_config_digest_record": r.get("config_digest"),
                         "evidence_config_digest_expected": self.evidence_digest, "attribution_config_version": self.att.config_version,
                         "attribution_config_digest": self.att.digest, "policy_version": self.policy.policy_version,
                         "policy_digest": self.policy.digest, "configuration_checks": self.config_checks,
                         "attribution_results": None if store is None else {
                             "accepted": store.accepted, "rejected": store.rejected, "conflicts": sorted(store.conflicts)}},
            "authentication_evidence": auth_evidence,
        }

    def _authentication_event(self, r, mapping):
        """Policy 2.1 (F-2): successful login needs an authentication EVENT. Direct sources: the evidence engine's
        success statuses (derived from cowrie.login.success). Relay sessions: the session-ID-correlated login.success in
        a verified signed attribution result. Command input never counts; anything else stays indeterminate."""
        ip_s = r.get("src_ip")
        try:
            ip = ipaddress.ip_address(ip_s)
            relay = ip in self.att.relay_addresses or any(ip in n for n in self.att.trusted_proxies)
        except (ValueError, TypeError):
            relay = False
        if not relay:
            ok = r["authentication_status"] in LOGIN_STATUSES
            ev = {"source": "behavioural_evidence authentication_status", "state": r["authentication_status"], "event_observed": ok}
            return (f"authentication_status={r['authentication_status']}" if ok else None), ev
        if not mapping or mapping.get("status") != "verified":
            return None, {"source": "signed attribution result", "state": "indeterminate:no_verified_result",
                          "event_observed": False, "reason": (mapping or {}).get("reason")}
        a = mapping["entry"]["authentication"]
        ok = a["state"] == "login_success_observed" and (mapping["entry"]["relay_to_cowrie"] or {}).get("src_ip") == ip_s
        ev = {"source": "signed attribution result", "result_id": mapping["result_id"], "state": a["state"], "reason": a["reason"],
              "login_success_utc": a["login_success_utc"], "event_observed": ok}
        return (f"cowrie.login.success at {a['login_success_utc']} correlated by session ID (signed result {mapping['result_id']})"
                if ok else None), ev


def assess_sessions(records: Iterable[dict], assessor: ThreatAssessor, attribution_results=None, now: Optional[datetime] = None) -> List[dict]:
    store = assessor.verify_attribution(attribution_results, now)                 # verified once for the batch
    return [assessor._assess(r, store, attribution_results is not None) for r in records]


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
