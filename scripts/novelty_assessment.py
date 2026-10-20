#!/usr/bin/env python3
"""Novelty assessment for behavioural signatures.

The project already generates evidence-backed behavioural signatures from DEC
cluster analysis. This module compares an incoming or held-out Cowrie session
against those signatures and classifies the session as one of:

- Known-like
- Potentially Novel
- Insufficient Evidence
- Ambiguous

The implementation intentionally follows the project's real schema:

- session records are read from data/parsed/session_details.json
- each record may contain a nested ``features`` dict with the DEC-model feature
  set and a top-level ``commands`` list plus ``auth_success``
- signatures are loaded from reports/behaviour_signatures/behaviour_signatures.json

The comparison is conservative: it only compares compatible numerical features,
only uses categorical evidence when present and directly comparable, and it never
infers a definitive zero-day label from a failed match alone.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.behaviour_pattern_analysis import (
    aggregate_command_analysis,
    build_cluster_summary,
    build_session_profiles,
    calculate_cluster_distribution,
    classify_command,
    compute_cluster_feature_statistics,
)
from scripts.behaviour_signature_generation import build_signatures, store_outputs


DEFAULT_THRESHOLDS = {
    "known_threshold": 0.70,
    "ambiguous_margin": 0.05,
    "min_compatible_features": 1,
    "borderline_score": 0.60,
}


class NoveltyAssessmentError(RuntimeError):
    """Raised when required novelty-assessment inputs are malformed."""


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parent.parent


def _safe_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed):
        return None
    return parsed


def _as_session_id(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _normalise_signature_list(raw_signatures: Any) -> List[Dict[str, Any]]:
    if raw_signatures is None:
        return []
    if isinstance(raw_signatures, list):
        signatures = raw_signatures
    elif isinstance(raw_signatures, dict):
        if "signatures" in raw_signatures and isinstance(raw_signatures["signatures"], list):
            signatures = raw_signatures["signatures"]
        elif "signature_id" in raw_signatures or "behaviour_label" in raw_signatures:
            signatures = [raw_signatures]
        else:
            raise NoveltyAssessmentError("Signature file does not contain a valid signatures list.")
    else:
        raise NoveltyAssessmentError("Signature payload is not a list/dictionary.")

    clean: List[Dict[str, Any]] = []
    for item in signatures:
        if not isinstance(item, dict):
            continue
        if not item.get("signature_id"):
            continue
        clean.append(item)
    return clean


def load_signature_catalog(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        raise NoveltyAssessmentError(f"Signature file not found: {path}")
    if not path.is_file():
        raise NoveltyAssessmentError(f"Signature path is not a file: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except json.JSONDecodeError as exc:
        raise NoveltyAssessmentError(f"Malformed signature JSON: {path}: {exc}") from exc

    signatures = _normalise_signature_list(payload)
    if not signatures:
        raise NoveltyAssessmentError(f"No valid behavioural signatures found in: {path}")
    return signatures


def catalog_reference_session_ids(signatures: Sequence[Dict[str, Any]]) -> Optional[set]:
    """Return the exact session IDs the catalogue was built from, or None if any signature lacks them."""
    reference_ids: set = set()
    for signature in signatures:
        activity = signature.get("activity_profile")
        session_ids = activity.get("session_ids") if isinstance(activity, dict) else None
        if not isinstance(session_ids, list):
            return None
        reference_ids.update(str(item) for item in session_ids if item is not None and str(item))
    return reference_ids


def reference_independence(
    session_records: Dict[str, Dict[str, Any]],
    signatures: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    """Derive the evaluation mode from exact session-ID overlap with the catalogue's source sessions."""
    reference_ids = catalog_reference_session_ids(signatures)
    if reference_ids is None:
        return {
            "evaluation_mode": "reference-provenance-unknown",
            "reference_session_id_count": None,
            "overlapping_session_count": None,
            "overlapping_session_ids": None,
            "warnings": [
                "The signature catalogue does not record source session IDs for every signature; "
                "independence of the assessed sessions from the reference sessions could not be verified."
            ],
        }
    overlapping = sorted(set(session_records) & reference_ids)
    warnings = []
    if overlapping:
        warnings.append(
            f"{len(overlapping)} of {len(session_records)} assessed session(s) were used to build the "
            "reference signature catalogue; results for those sessions are in-sample and must not be "
            "interpreted as independent generalization performance."
        )
    return {
        "evaluation_mode": "overlapping" if overlapping else "independent",
        "reference_session_id_count": len(reference_ids),
        "overlapping_session_count": len(overlapping),
        "overlapping_session_ids": overlapping,
        "warnings": warnings,
    }


def load_session_records(path: Path) -> Dict[str, Dict[str, Any]]:
    if not path.exists():
        return {}
    if not path.is_file():
        raise NoveltyAssessmentError(f"Session data path is not a file: {path}")

    if path.suffix.lower() == ".json":
        try:
            with path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except json.JSONDecodeError as exc:
            raise NoveltyAssessmentError(f"Malformed session JSON: {path}: {exc}") from exc
        if payload in (None, "", [], ""):
            return {}
        if not isinstance(payload, dict):
            raise NoveltyAssessmentError(f"Session JSON does not contain an object keyed by session_id: {path}")
        return {str(key): value for key, value in payload.items()}

    if path.suffix.lower() == ".csv":
        try:
            df = __import__("pandas").read_csv(path)
        except Exception as exc:  # pragma: no cover - pandas may be unavailable in some envs
            raise NoveltyAssessmentError(f"Could not read CSV session data: {path}: {exc}") from exc
        if df.empty:
            return {}
        records: Dict[str, Dict[str, Any]] = {}
        for row in df.to_dict(orient="records"):
            sid = _as_session_id(row.get("session_id"))
            if not sid:
                continue
            records[sid] = row
        return records

    raise NoveltyAssessmentError(f"Unsupported session data format: {path}")


def _extract_session_features(session_record: Dict[str, Any]) -> Tuple[Dict[str, float], Dict[str, Any], List[str], Optional[int]]:
    numeric_features: Dict[str, float] = {}
    raw_features = session_record.get("features") if isinstance(session_record.get("features"), dict) else session_record
    if not isinstance(raw_features, dict):
        return numeric_features, {}, [], None

    for key, value in raw_features.items():
        if key in {"session_id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "proto", "service", "attack_cat", "label"}:
            continue
        parsed = _safe_float(value)
        if parsed is not None:
            numeric_features[str(key)] = parsed

    observed_commands: List[str] = []
    commands_value = session_record.get("commands")
    if isinstance(commands_value, list):
        observed_commands = [str(item).strip() for item in commands_value if str(item).strip()]
    elif isinstance(commands_value, str):
        observed_commands = [part.strip() for part in commands_value.split(",") if part.strip()]

    category_set: set[str] = set()
    for command in observed_commands:
        category_set.update(classify_command(command))

    auth_value = session_record.get("auth_success")
    try:
        auth_success = int(auth_value)
    except (TypeError, ValueError):
        auth_success = None

    return numeric_features, raw_features, sorted(category_set), auth_success


def _feature_stat_map(signature: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    profile = signature.get("feature_profile", {}) if isinstance(signature.get("feature_profile"), dict) else {}
    selected_features = profile.get("selected_features", []) if isinstance(profile.get("selected_features"), list) else []
    feature_map: Dict[str, Dict[str, Any]] = {}
    for item in selected_features:
        if not isinstance(item, dict):
            continue
        feature_name = str(item.get("feature", "")).strip()
        if not feature_name:
            continue
        feature_map[feature_name] = item
    return feature_map


def _compare_session_numeric_features(
    session_numeric: Dict[str, float],
    feature_stats: Dict[str, Dict[str, Any]],
) -> Tuple[float, List[str], int, List[Dict[str, Any]]]:
    if not feature_stats:
        return 0.0, [], 0, []
    scores: List[float] = []
    comparable_names: List[str] = []
    feature_details: List[Dict[str, Any]] = []
    for feature_name, stats in feature_stats.items():
        if feature_name not in session_numeric:
            continue
        raw_value = session_numeric.get(feature_name)
        if raw_value is None:
            continue
        mean_value = _safe_float(stats.get("mean"))
        std_value = _safe_float(stats.get("std"))
        min_value = _safe_float(stats.get("min"))
        max_value = _safe_float(stats.get("max"))
        if mean_value is None:
            continue

        if std_value is not None and std_value > 0:
            distance = abs(raw_value - mean_value) / std_value
        elif min_value is not None and max_value is not None and max_value > min_value:
            distance = abs(raw_value - mean_value) / (max_value - min_value)
        else:
            distance = abs(raw_value - mean_value) / max(abs(mean_value), 1.0)

        distance = min(max(distance, 0.0), 10.0)
        similarity = max(0.0, 1.0 - min(distance / 3.0, 1.0))
        comparable_names.append(feature_name)
        scores.append(similarity)
        feature_details.append({
            "feature": feature_name,
            "session_value": raw_value,
            "signature_mean": mean_value,
            "signature_std": std_value,
            "signature_min": min_value,
            "signature_max": max_value,
            "normalized_distance": round(distance, 6),
            "similarity": round(similarity, 6),
            "weighted_contribution": 0.0,
        })

    if not scores:
        return 0.0, [], 0, []
    for detail in feature_details:
        detail["weighted_contribution"] = round(
            0.70 * detail["similarity"] / len(scores),
            6,
        )
    return sum(scores) / len(scores), comparable_names, len(comparable_names), feature_details


def _compare_session_commands(session_categories: Sequence[str], signature_categories: Sequence[str]) -> float:
    session_set = set(str(item).strip().lower() for item in session_categories if str(item).strip())
    signature_set = set(str(item).strip().lower() for item in signature_categories if str(item).strip())
    if not session_set or not signature_set:
        return 0.0
    union = session_set | signature_set
    if not union:
        return 0.0
    intersection = len(session_set & signature_set)
    return intersection / len(union)


def _compare_session_auth(session_auth: Optional[int], signature: Dict[str, Any]) -> float:
    if session_auth is None:
        return 0.0
    auth_profile = signature.get("authentication_profile") if isinstance(signature.get("authentication_profile"), dict) else {}
    success_rate = _safe_float(auth_profile.get("success_rate"))
    if success_rate is None:
        return 0.0
    target = success_rate / 100.0
    return max(0.0, 1.0 - abs(float(session_auth) - target))


def compare_session_to_signature(session_record: Dict[str, Any], signature: Dict[str, Any]) -> Dict[str, Any]:
    session_numeric, raw_features, session_categories, session_auth = _extract_session_features(session_record)
    feature_stats = _feature_stat_map(signature)
    feature_similarity, comparable_names, comparable_count, feature_details = _compare_session_numeric_features(session_numeric, feature_stats)
    signature_categories = signature.get("command_categories", []) if isinstance(signature.get("command_categories"), list) else []
    command_similarity = _compare_session_commands(session_categories, signature_categories)
    auth_similarity = _compare_session_auth(session_auth, signature)
    auth_profile = signature.get("authentication_profile") if isinstance(signature.get("authentication_profile"), dict) else {}
    signature_auth_rate = _safe_float(auth_profile.get("success_rate"))
    contradictions = []
    if session_categories and signature_categories and command_similarity == 0:
        contradictions.append("command_categories")
    if session_auth is not None and signature_auth_rate is not None and auth_similarity == 0:
        contradictions.append("authentication")

    weight_features = 0.70
    weight_commands = 0.20
    weight_auth = 0.10
    overall = (weight_features * feature_similarity) + (weight_commands * command_similarity) + (weight_auth * auth_similarity)
    distance = 1.0 - overall

    evidence: List[str] = []
    if comparable_names:
        evidence.append(f"Comparable numerical features: {', '.join(comparable_names)}")
    else:
        evidence.append("No compatible numerical features for the stored signature profile.")
    if session_categories:
        evidence.append(f"Observed command categories: {', '.join(session_categories)}")
    if signature_categories:
        evidence.append(f"Signature command categories: {', '.join(str(item) for item in signature_categories)}")
    if session_auth is not None:
        evidence.append(f"Session auth_success={session_auth}")

    return {
        "signature_id": signature.get("signature_id", "unknown"),
        "behaviour_label": signature.get("behaviour_label", "unknown"),
        "score": round(max(0.0, min(1.0, overall)), 6),
        "distance": round(max(0.0, min(1.0, distance)), 6),
        "feature_similarity": round(max(0.0, min(1.0, feature_similarity)), 6),
        "command_similarity": round(max(0.0, min(1.0, command_similarity)), 6),
        "auth_similarity": round(max(0.0, min(1.0, auth_similarity)), 6),
        "comparable_features": comparable_count,
        "feature_details": feature_details,
        "command_evidence_status": (
            "missing" if not session_categories or not signature_categories else
            "conflict" if command_similarity == 0 else
            "comparable"
        ),
        "authentication_evidence_status": (
            "missing" if session_auth is None or signature_auth_rate is None else
            "conflict" if auth_similarity == 0 else
            "comparable"
        ),
        "contradictory_evidence": contradictions,
        "evidence": "; ".join(evidence),
    }


def assess_session_against_signatures(
    session_record: Dict[str, Any],
    signatures: Sequence[Dict[str, Any]],
    known_threshold: float = DEFAULT_THRESHOLDS["known_threshold"],
    ambiguous_margin: float = DEFAULT_THRESHOLDS["ambiguous_margin"],
    min_compatible_features: int = DEFAULT_THRESHOLDS["min_compatible_features"],
    borderline_score: float = DEFAULT_THRESHOLDS["borderline_score"],
) -> Dict[str, Any]:
    sid = _as_session_id(session_record.get("session_id") or session_record.get("features", {}).get("session_id"))
    if not signatures:
        return {
            "session_id": sid,
            "assessment_category": "Insufficient Evidence",
            "closest_signature_id": None,
            "score": 0.0,
            "distance": 1.0,
            "evidence": "No behavioural signatures were available for comparison.",
            "reason": "Signature catalogue was empty or missing; no defensible similarity comparison could be made.",
        }

    comparisons = [compare_session_to_signature(session_record, sig) for sig in signatures]
    comparisons = [item for item in comparisons if item["score"] > 0.0 or item["comparable_features"] > 0]
    if not comparisons:
        return {
            "session_id": sid,
            "assessment_category": "Insufficient Evidence",
            "closest_signature_id": None,
            "score": 0.0,
            "distance": 1.0,
            "evidence": "No comparable numerical or categorical features were available.",
            "reason": "The session lacks compatible evidence for the stored signature schema; insufficient evidence for a reliable decision.",
        }

    ordered = sorted(comparisons, key=lambda item: item["score"], reverse=True)
    best = ordered[0]
    second = ordered[1] if len(ordered) > 1 else None
    top_score = best["score"]
    second_score = second["score"] if second is not None else 0.0
    margin = top_score - second_score
    comparable_total = best["comparable_features"]

    if comparable_total < min_compatible_features:
        category = "Insufficient Evidence"
        reason = "The session did not provide enough compatible evidence to compare meaningfully against a stored signature."
    elif top_score >= known_threshold and (second is None or margin >= ambiguous_margin):
        if best["contradictory_evidence"]:
            category = "Potentially Novel"
            reason = (
                "The numerical similarity passed the known threshold, but available "
                "categorical evidence conflicts with the closest signature: "
                + ", ".join(best["contradictory_evidence"])
                + "."
            )
        else:
            category = "Known-like"
            reason = f"The session matched the closest signature {best['signature_id']} with a similarity score of {best['score']:.3f}, above the configured known threshold {known_threshold:.2f}."
    elif top_score >= borderline_score and second is not None and margin < ambiguous_margin:
        category = "Ambiguous"
        reason = f"Multiple signatures were close to the session (top score {best['score']:.3f}, second score {second['score']:.3f}); the result is borderline and not decisive."
    elif comparable_total > 0:
        category = "Potentially Novel"
        reason = f"The session had comparable evidence ({comparable_total} compatible feature comparisons) but no signature exceeded the configured known threshold {known_threshold:.2f}."
    else:
        category = "Insufficient Evidence"
        reason = "The session's feature profile lacked compatible evidence for a reliable assessment."

    return {
        "session_id": sid,
        "assessment_category": category,
        "closest_signature_id": best["signature_id"],
        "score": round(best["score"], 6),
        "distance": round(best["distance"], 6),
        "evidence": best["evidence"],
        "reason": reason,
        "best_signature_label": best["behaviour_label"],
        "second_score": round(second_score, 6) if second is not None else None,
        "comparable_feature_count": best["comparable_features"],
        "contradictory_evidence": best["contradictory_evidence"],
    }


def create_session_split(
    session_records: Dict[str, Dict[str, Any]],
    held_out_ratio: float = 0.2,
    random_seed: int = 42,
) -> Dict[str, List[str]]:
    if not session_records:
        return {"reference_sessions": [], "held_out_sessions": []}
    if not 0.0 < held_out_ratio < 1.0:
        raise NoveltyAssessmentError(f"held_out_ratio must be greater than 0 and less than 1, got {held_out_ratio}.")

    session_ids = sorted(session_records.keys())
    if len(session_ids) < 2:
        raise NoveltyAssessmentError("At least two distinct sessions are required for a reference/held-out split.")

    import random

    rng = random.Random(random_seed)
    sample = session_ids[:]
    rng.shuffle(sample)
    split_index = max(1, min(len(sample) - 1, int(round(len(sample) * held_out_ratio))))
    held_out = sorted(sample[:split_index])
    held_out_set = set(held_out)
    reference = [session_id for session_id in session_ids if session_id not in held_out_set]
    return {"reference_sessions": reference, "held_out_sessions": held_out}


def _count_or_unknown(value: Optional[int]) -> str:
    return "unknown" if value is None else str(value)


def write_assessment_outputs(
    results: List[Dict[str, Any]],
    output_dir: Path,
    evaluation_context: Optional[Dict[str, Any]] = None,
    reference_independence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    evaluation_context = evaluation_context or {}
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "novelty_assessment_results.csv"
    json_path = output_dir / "novelty_assessment_results.json"
    report_path = output_dir / "novelty_assessment_report.md"
    summary_path = output_dir / "novelty_assessment_summary.json"

    csv_fields = [
        "session_id",
        "assessment_category",
        "closest_signature_id",
        "score",
        "distance",
        "evidence",
        "reason",
        "best_signature_label",
        "second_score",
        "comparable_feature_count",
        "contradictory_evidence",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=csv_fields)
        writer.writeheader()
        for row in results:
            writer.writerow({key: row.get(key, "") for key in csv_fields})

    json_payload = {"schema_version": "1.0", "results": results}
    json_path.write_text(json.dumps(json_payload, indent=2, ensure_ascii=False), encoding="utf-8")

    category_counts: Dict[str, int] = {}
    for entry in results:
        category = entry.get("assessment_category", "Unknown")
        category_counts[category] = category_counts.get(category, 0) + 1

    lines: List[str] = []
    lines.append("# Novelty Assessment Report")
    lines.append("")
    lines.append("## Methodology")
    if evaluation_context.get("evaluation_mode") == "held-out-reference-signatures":
        lines.append("- Generate a fresh signature catalogue from reference sessions only; held-out sessions are excluded from all signature statistics and evidence.")
    else:
        lines.append("- Load the project's behavioural signatures from the stored `behaviour_signatures.json` artifact.")
    lines.append("- Compare each session against each signature using only compatible numerical features in the session `features` dict and the signature `feature_profile.selected_features` summary.")
    lines.append("- For each compatible feature, normalize absolute deviation from the signature mean by standard deviation; if unavailable or zero, use the signature range, then `max(abs(mean), 1)` as the fallback scale. Cap normalized deviation at 10, convert it to similarity `max(0, 1 - min(d / 3, 1))`, then average available feature similarities.")
    lines.append("- Use command-category Jaccard similarity when both the session and signature expose comparable command classes.")
    lines.append("- Use authentication success-rate similarity only when `auth_success` and the stored signature authentication profile are available.")
    lines.append("- Overall score is `0.70 * feature similarity + 0.20 * command Jaccard similarity + 0.10 * authentication similarity`; unavailable evidence is not imputed and contributes no similarity. Reported distance is `1 - score`.")
    lines.append("- Treat unknown or incompatible feature sets as `Insufficient Evidence` rather than silently substituting values.")
    lines.append("- `Known-like` requires the known threshold, a top-to-runner-up margin at least as large as the ambiguous margin, and no direct contradiction in available command-category or authentication evidence; `Ambiguous` requires a score at least the borderline threshold with a smaller margin; otherwise comparable evidence below the known threshold is `Potentially Novel`.")
    lines.append("")
    if evaluation_context:
        lines.append("## Evaluation design")
        lines.append(f"- Evaluation mode: {evaluation_context.get('evaluation_mode', 'unspecified')}")
        lines.append(f"- Reference sessions: {evaluation_context.get('reference_session_count', 0)}")
        lines.append(f"- Held-out sessions: {evaluation_context.get('held_out_session_count', 0)}")
        lines.append(f"- Signatures generated from reference sessions: {evaluation_context.get('signature_count', 0)}")
        lines.append(f"- Split ratio: {evaluation_context.get('held_out_ratio')}")
        lines.append(f"- Split seed: {evaluation_context.get('random_seed')}")
        lines.append(f"- Split manifest: `{evaluation_context.get('split_manifest', '')}`")
        lines.append(f"- Split method: {evaluation_context.get('split_method', 'not recorded')}")
        lines.append("")
    if reference_independence:
        overlapping_ids = reference_independence.get("overlapping_session_ids")
        lines.append("## Reference independence")
        lines.append(f"- Evaluation mode: {reference_independence.get('evaluation_mode')}")
        lines.append(f"- Reference catalogue session IDs: {_count_or_unknown(reference_independence.get('reference_session_id_count'))}")
        lines.append(f"- Assessed sessions overlapping the reference catalogue: {_count_or_unknown(reference_independence.get('overlapping_session_count'))}")
        if overlapping_ids:
            lines.append(f"- Overlapping session IDs: {', '.join(overlapping_ids)}")
        for warning in reference_independence.get("warnings", []):
            lines.append(f"- Warning: {warning}")
        lines.append("")
    lines.append("## Thresholds")
    thresholds = evaluation_context.get("thresholds", DEFAULT_THRESHOLDS)
    lines.append(f"- Known-like threshold: {thresholds.get('known_threshold', DEFAULT_THRESHOLDS['known_threshold']):.2f}")
    lines.append(f"- Ambiguous margin: {thresholds.get('ambiguous_margin', DEFAULT_THRESHOLDS['ambiguous_margin']):.2f}")
    lines.append(f"- Minimum compatible feature comparisons: {thresholds.get('min_compatible_features', DEFAULT_THRESHOLDS['min_compatible_features'])}")
    lines.append(f"- Borderline score: {thresholds.get('borderline_score', DEFAULT_THRESHOLDS['borderline_score']):.2f}")
    lines.append("")
    lines.append("## Category counts")
    for category_name in ["Known-like", "Potentially Novel", "Insufficient Evidence", "Ambiguous"]:
        lines.append(f"- {category_name}: {category_counts.get(category_name, 0)}")
    lines.append("")
    lines.append("## Closest matches")
    for row in sorted(results, key=lambda item: item.get("score", 0.0), reverse=True)[:5]:
        lines.append(f"- {row.get('session_id')} -> {row.get('closest_signature_id')} (score={row.get('score')}, category={row.get('assessment_category')})")
    lines.append("")
    if evaluation_context:
        lines.append("## Data quality and limitations")
        evaluation_warnings = evaluation_context.get("warnings", [])
        for warning in evaluation_warnings:
            lines.append(f"- Data-quality warning: {warning}")
        if not evaluation_warnings:
            lines.append("- No join exclusions or data-quality warnings were found in the evaluated inputs.")
        for limitation in evaluation_context.get("limitations", []):
            lines.append(f"- {limitation}")
        lines.append("- This is a behavioural novelty assessment, not an attack classification or zero-day detection claim.")
        lines.append("- No attack labels or ground-truth novelty labels were used; accuracy, precision, and recall are not reported.")
        lines.append("")
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results_count": len(results),
        "category_counts": category_counts,
        "output_files": {
            "csv": str(csv_path),
            "json": str(json_path),
            "report": str(report_path),
            "summary": str(summary_path),
        },
        "status": "success",
    }
    summary.update(evaluation_context)
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


def assess_sessions(
    session_records: Dict[str, Dict[str, Any]],
    signatures: Sequence[Dict[str, Any]],
    known_threshold: float = DEFAULT_THRESHOLDS["known_threshold"],
    ambiguous_margin: float = DEFAULT_THRESHOLDS["ambiguous_margin"],
    min_compatible_features: int = DEFAULT_THRESHOLDS["min_compatible_features"],
    borderline_score: float = DEFAULT_THRESHOLDS["borderline_score"],
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for session_id in sorted(session_records.keys()):
        result = assess_session_against_signatures(
            session_records[session_id],
            signatures,
            known_threshold=known_threshold,
            ambiguous_margin=ambiguous_margin,
            min_compatible_features=min_compatible_features,
            borderline_score=borderline_score,
        )
        result["session_id"] = session_id
        results.append(result)
    return results


def generate_novelty_assessment(
    session_details_path: Path,
    signature_path: Path,
    output_dir: Path,
    known_threshold: float = DEFAULT_THRESHOLDS["known_threshold"],
    ambiguous_margin: float = DEFAULT_THRESHOLDS["ambiguous_margin"],
    min_compatible_features: int = DEFAULT_THRESHOLDS["min_compatible_features"],
    borderline_score: float = DEFAULT_THRESHOLDS["borderline_score"],
    held_out_ratio: float = 0.0,
    random_seed: int = 42,
    held_out_sessions: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    if held_out_ratio > 0.0 or held_out_sessions is not None:
        raise NoveltyAssessmentError(
            "Selecting held-out rows against an existing signature catalog can leak evaluation sessions. "
            "Use run_held_out_evaluation() or the CLI --held-out-evaluation mode to build reference-only signatures."
        )
    session_records = load_session_records(session_details_path)

    if not session_records:
        output_dir.mkdir(parents=True, exist_ok=True)
        empty_summary = {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "results_count": 0,
            "category_counts": {},
            "output_files": {
                "csv": str(output_dir / "novelty_assessment_results.csv"),
                "json": str(output_dir / "novelty_assessment_results.json"),
                "report": str(output_dir / "novelty_assessment_report.md"),
                "summary": str(output_dir / "novelty_assessment_summary.json"),
            },
            "status": "success",
            "input_session_count": 0,
            "processed_session_count": 0,
            "thresholds": {
                "known_threshold": known_threshold,
                "ambiguous_margin": ambiguous_margin,
                "min_compatible_features": min_compatible_features,
                "borderline_score": borderline_score,
            },
            "held_out_ratio": held_out_ratio,
            "random_seed": random_seed,
            "evaluation_mode": "no-sessions",
            "warnings": ["No sessions were available for assessment; results are empty."],
        }
        (output_dir / "novelty_assessment_results.csv").write_text("session_id,assessment_category,closest_signature_id,score,distance,evidence,reason,best_signature_label,second_score,comparable_feature_count\n", encoding="utf-8")
        (output_dir / "novelty_assessment_results.json").write_text(json.dumps({"schema_version": "1.0", "results": []}, indent=2, ensure_ascii=False), encoding="utf-8")
        (output_dir / "novelty_assessment_report.md").write_text("# Novelty Assessment Report\n\nNo sessions were available for assessment.\n", encoding="utf-8")
        (output_dir / "novelty_assessment_summary.json").write_text(json.dumps(empty_summary, indent=2, ensure_ascii=False), encoding="utf-8")
        return empty_summary

    signatures = load_signature_catalog(signature_path)

    session_subset = session_records

    if not session_subset:
        output_dir.mkdir(parents=True, exist_ok=True)
        empty_summary = {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "results_count": 0,
            "category_counts": {},
            "output_files": {
                "csv": str(output_dir / "novelty_assessment_results.csv"),
                "json": str(output_dir / "novelty_assessment_results.json"),
                "report": str(output_dir / "novelty_assessment_report.md"),
                "summary": str(output_dir / "novelty_assessment_summary.json"),
            },
            "status": "success",
            "input_session_count": len(session_records),
            "processed_session_count": 0,
            "thresholds": {
                "known_threshold": known_threshold,
                "ambiguous_margin": ambiguous_margin,
                "min_compatible_features": min_compatible_features,
                "borderline_score": borderline_score,
            },
            "held_out_ratio": held_out_ratio,
            "random_seed": random_seed,
            "evaluation_mode": "no-sessions",
            "warnings": ["No sessions were available for assessment; results are empty."],
        }
        (output_dir / "novelty_assessment_results.csv").write_text("session_id,assessment_category,closest_signature_id,score,distance,evidence,reason,best_signature_label,second_score,comparable_feature_count\n", encoding="utf-8")
        (output_dir / "novelty_assessment_results.json").write_text(json.dumps({"schema_version": "1.0", "results": []}, indent=2, ensure_ascii=False), encoding="utf-8")
        (output_dir / "novelty_assessment_report.md").write_text("# Novelty Assessment Report\n\nNo sessions were available for assessment.\n", encoding="utf-8")
        (output_dir / "novelty_assessment_summary.json").write_text(json.dumps(empty_summary, indent=2, ensure_ascii=False), encoding="utf-8")
        return empty_summary

    results = assess_sessions(
        session_subset,
        signatures,
        known_threshold=known_threshold,
        ambiguous_margin=ambiguous_margin,
        min_compatible_features=min_compatible_features,
        borderline_score=borderline_score,
    )

    independence = reference_independence(session_records, signatures)
    summary = write_assessment_outputs(results, output_dir, reference_independence=independence)
    summary["input_session_count"] = len(session_records)
    summary["processed_session_count"] = len(results)
    summary["status"] = "success" if results or len(session_records) == 0 else "success"
    summary["thresholds"] = {
        "known_threshold": known_threshold,
        "ambiguous_margin": ambiguous_margin,
        "min_compatible_features": min_compatible_features,
        "borderline_score": borderline_score,
    }
    summary["held_out_ratio"] = held_out_ratio
    summary["random_seed"] = random_seed
    summary["evaluation_mode"] = independence["evaluation_mode"]
    summary["reference_session_id_count"] = independence["reference_session_id_count"]
    summary["overlapping_session_count"] = independence["overlapping_session_count"]
    summary["overlapping_session_ids"] = independence["overlapping_session_ids"]
    summary["warnings"] = list(independence["warnings"])

    summary_path = output_dir / "novelty_assessment_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


def _validate_thresholds(
    known_threshold: float,
    ambiguous_margin: float,
    min_compatible_features: int,
    borderline_score: float,
) -> Dict[str, Any]:
    thresholds = {
        "known_threshold": known_threshold,
        "ambiguous_margin": ambiguous_margin,
        "min_compatible_features": min_compatible_features,
        "borderline_score": borderline_score,
    }
    if not 0.0 <= known_threshold <= 1.0:
        raise NoveltyAssessmentError("known_threshold must be between 0 and 1.")
    if not 0.0 <= borderline_score <= 1.0:
        raise NoveltyAssessmentError("borderline_score must be between 0 and 1.")
    if not 0.0 <= ambiguous_margin <= 1.0:
        raise NoveltyAssessmentError("ambiguous_margin must be between 0 and 1.")
    if min_compatible_features < 1:
        raise NoveltyAssessmentError("min_compatible_features must be at least 1.")
    return thresholds


def _read_dec_results(path: Path) -> pd.DataFrame:
    if not path.exists() or not path.is_file():
        raise NoveltyAssessmentError(f"DEC results CSV not found or is not a file: {path}")
    try:
        dec_df = pd.read_csv(path)
    except (OSError, pd.errors.ParserError, UnicodeDecodeError) as exc:
        raise NoveltyAssessmentError(f"Could not read DEC results CSV {path}: {exc}") from exc
    required = {"session_id", "dec_cluster"}
    missing = sorted(required - set(dec_df.columns))
    if missing:
        raise NoveltyAssessmentError(f"DEC results CSV is missing required columns: {missing}")
    if dec_df.empty:
        raise NoveltyAssessmentError(f"DEC results CSV is empty: {path}")
    dec_df = dec_df.copy()
    dec_df["session_id"] = dec_df["session_id"].astype(str).str.strip()
    if (dec_df["session_id"] == "").any():
        raise NoveltyAssessmentError("DEC results contain an empty session_id.")
    duplicated = dec_df.loc[dec_df["session_id"].duplicated(keep=False), "session_id"].unique().tolist()
    if duplicated:
        raise NoveltyAssessmentError(f"DEC results contain duplicate session IDs: {duplicated[:5]}")
    dec_df["dec_cluster"] = pd.to_numeric(dec_df["dec_cluster"], errors="coerce")
    if dec_df["dec_cluster"].isna().any():
        raise NoveltyAssessmentError("DEC results contain missing or invalid cluster assignments.")
    return dec_df


def _reference_only_signatures(
    reference_dec_df: pd.DataFrame,
    reference_details: Dict[str, Dict[str, Any]],
    dec_results_path: Path,
    session_details_path: Path,
) -> List[Dict[str, Any]]:
    profiles_df, _ = build_session_profiles(reference_dec_df, reference_details, {})
    feature_stats_df = compute_cluster_feature_statistics(reference_dec_df)
    distribution_df = calculate_cluster_distribution(reference_dec_df)
    command_analysis_df = aggregate_command_analysis(profiles_df, reference_dec_df, reference_details)
    cluster_summary_df = build_cluster_summary(
        reference_dec_df,
        distribution_df,
        feature_stats_df,
        profiles_df,
        reference_details,
        command_analysis_df,
    )
    signatures = build_signatures(
        cluster_summary_df,
        feature_stats_df,
        command_analysis_df,
        profiles_df,
        reference_details,
        source_files=[
            f"{dec_results_path} (reference rows only)",
            f"{session_details_path} (reference session IDs only)",
        ],
    )
    if not signatures:
        raise NoveltyAssessmentError("No behavioural signatures could be generated from the reference sessions.")

    reference_ids = set(reference_dec_df["session_id"].astype(str))
    leaked_ids = {
        str(session_id)
        for signature in signatures
        for session_id in signature.get("activity_profile", {}).get("session_ids", [])
        if str(session_id) not in reference_ids
    }
    if leaked_ids:
        raise NoveltyAssessmentError(f"Reference signature generation included non-reference session IDs: {sorted(leaked_ids)[:5]}")
    return signatures


def run_held_out_evaluation(
    dec_results_path: Path,
    session_details_path: Path,
    output_dir: Path,
    held_out_ratio: float = 0.2,
    random_seed: int = 42,
    known_threshold: float = DEFAULT_THRESHOLDS["known_threshold"],
    ambiguous_margin: float = DEFAULT_THRESHOLDS["ambiguous_margin"],
    min_compatible_features: int = DEFAULT_THRESHOLDS["min_compatible_features"],
    borderline_score: float = DEFAULT_THRESHOLDS["borderline_score"],
) -> Dict[str, Any]:
    """Build signatures from reference sessions and assess the disjoint holdout."""
    thresholds = _validate_thresholds(
        known_threshold,
        ambiguous_margin,
        min_compatible_features,
        borderline_score,
    )
    if not 0.0 < held_out_ratio < 1.0:
        raise NoveltyAssessmentError("held_out_ratio must be greater than 0 and less than 1.")
    if not session_details_path.exists() or not session_details_path.is_file():
        raise NoveltyAssessmentError(f"Session details JSON not found or is not a file: {session_details_path}")

    dec_df = _read_dec_results(dec_results_path)
    session_records = load_session_records(session_details_path)
    if not session_records:
        raise NoveltyAssessmentError(f"No session records were available in {session_details_path}.")

    dec_ids = set(dec_df["session_id"].astype(str))
    detail_ids = set(session_records)
    missing_details = sorted(dec_ids - detail_ids)
    details_without_dec = sorted(detail_ids - dec_ids)
    malformed_details = sorted(
        session_id
        for session_id in dec_ids & detail_ids
        if not isinstance(session_records[session_id], dict)
    )
    usable_detail_ids = detail_ids - set(malformed_details)
    eligible_dec_df = dec_df[dec_df["session_id"].isin(usable_detail_ids)].copy()
    if len(eligible_dec_df) < 2:
        raise NoveltyAssessmentError("At least two DEC sessions with session-details records are required.")

    eligible_records = {
        str(session_id): session_records[str(session_id)]
        for session_id in eligible_dec_df["session_id"].tolist()
    }
    split = create_session_split(eligible_records, held_out_ratio, random_seed)
    reference_ids = set(split["reference_sessions"])
    held_out_ids = set(split["held_out_sessions"])
    if reference_ids & held_out_ids or reference_ids | held_out_ids != set(eligible_records):
        raise NoveltyAssessmentError("The session split is not a complete, disjoint partition of eligible sessions.")

    reference_dec_df = eligible_dec_df[eligible_dec_df["session_id"].isin(reference_ids)].copy()
    held_out_dec_df = eligible_dec_df[eligible_dec_df["session_id"].isin(held_out_ids)].copy()
    reference_details = {sid: eligible_records[sid] for sid in split["reference_sessions"]}
    held_out_details = {sid: eligible_records[sid] for sid in split["held_out_sessions"]}

    signatures = _reference_only_signatures(
        reference_dec_df,
        reference_details,
        dec_results_path,
        session_details_path,
    )
    signature_feature_names = sorted({
        feature_name
        for signature in signatures
        for feature_name in _feature_stat_map(signature)
    })
    missing_feature_columns = sorted(set(signature_feature_names) - set(held_out_dec_df.columns))
    if missing_feature_columns:
        raise NoveltyAssessmentError(
            "Held-out DEC rows are missing features used by reference signatures: "
            + ", ".join(missing_feature_columns)
        )

    # Use the exact numeric columns from the same DEC result table that supplied
    # the reference statistics; commands and authentication remain per-session
    # evidence from the corresponding Cowrie record.
    held_out_records: Dict[str, Dict[str, Any]] = {}
    for _, row in held_out_dec_df.iterrows():
        session_id = str(row["session_id"])
        record = dict(held_out_details[session_id])
        record["session_id"] = session_id
        record["features"] = {
            feature_name: row[feature_name]
            for feature_name in signature_feature_names
            if feature_name in row.index
        }
        held_out_records[session_id] = record

    results = assess_sessions(
        held_out_records,
        signatures,
        known_threshold=known_threshold,
        ambiguous_margin=ambiguous_margin,
        min_compatible_features=min_compatible_features,
        borderline_score=borderline_score,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    signature_dir = output_dir / "reference_signatures"
    signature_summary = store_outputs(signatures, signature_dir)
    signature_summary.update({
        "generation_scope": "reference-only",
        "reference_session_count": len(reference_ids),
        "reference_session_ids": split["reference_sessions"],
        "held_out_session_ids_excluded": split["held_out_sessions"],
    })
    (signature_dir / "signature_generation_summary.json").write_text(
        json.dumps(signature_summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    split_manifest_path = output_dir / "session_split.json"
    split_manifest = {
        "schema_version": "1.0",
        "split_method": "sorted session IDs shuffled with Python random.Random(seed); held-out count is round(N * ratio), constrained to leave at least one session in each partition",
        "held_out_ratio": held_out_ratio,
        "random_seed": random_seed,
        "eligible_session_count": len(eligible_records),
        "reference_session_count": len(reference_ids),
        "held_out_session_count": len(held_out_ids),
        "reference_session_ids": split["reference_sessions"],
        "held_out_session_ids": split["held_out_sessions"],
        "overlap_session_ids": sorted(reference_ids & held_out_ids),
    }
    split_manifest_path.write_text(json.dumps(split_manifest, indent=2), encoding="utf-8")

    warnings: List[str] = []
    if missing_details:
        warnings.append(f"{len(missing_details)} DEC session(s) had no session-details record and were excluded before splitting.")
    if details_without_dec:
        warnings.append(f"{len(details_without_dec)} session-details record(s) had no DEC row and were excluded before splitting.")
    if malformed_details:
        warnings.append(f"{len(malformed_details)} DEC session(s) had malformed non-object session-details records and were excluded before splitting.")
    limitations = [
        "Signatures, feature statistics, command evidence, and authentication profiles were derived exclusively from the reference session IDs.",
        "Held-out numeric features were taken from the same existing dec_results.csv rows used to compute reference statistics; the DEC model and preprocessing were not retrained or changed.",
        "Existing DEC assignments are reused. If the DEC model or scaler was trained using these held-out sessions, this is a signature-level holdout conditional on the existing model, not an independent end-to-end model evaluation.",
        "The dataset has no suitable ground-truth novelty labels; category counts are descriptive and do not establish zero-day detection accuracy.",
    ]
    evaluation_context = {
        "evaluation_mode": "held-out-reference-signatures",
        "held_out_ratio": held_out_ratio,
        "random_seed": random_seed,
        "reference_session_count": len(reference_ids),
        "held_out_session_count": len(held_out_ids),
        "signature_count": len(signatures),
        "processed_session_count": len(results),
        "input_dec_session_count": len(dec_df),
        "eligible_session_count": len(eligible_records),
        "excluded_dec_without_details_count": len(missing_details),
        "excluded_details_without_dec_count": len(details_without_dec),
        "excluded_malformed_details_count": len(malformed_details),
        "thresholds": thresholds,
        "split_manifest": str(split_manifest_path),
        "split_method": split_manifest["split_method"],
        "reference_signature_dir": str(signature_dir),
        "warnings": warnings,
        "limitations": limitations,
    }
    summary = write_assessment_outputs(results, output_dir, evaluation_context)
    return summary


def generate_held_out_diagnostics(
    evaluation_dir: Path,
    session_details_path: Path,
    dec_results_path: Path,
) -> Dict[str, Any]:
    """Write score/component and threshold sensitivity diagnostics for a saved holdout."""
    results_path = evaluation_dir / "novelty_assessment_results.json"
    split_path = evaluation_dir / "session_split.json"
    signature_path = evaluation_dir / "reference_signatures" / "behaviour_signatures.json"
    summary_path = evaluation_dir / "novelty_assessment_summary.json"
    required_paths = (results_path, split_path, signature_path, summary_path)
    missing_paths = [str(path) for path in required_paths if not path.is_file()]
    if missing_paths:
        raise NoveltyAssessmentError(f"Held-out diagnostic inputs are missing: {', '.join(missing_paths)}")

    try:
        saved_results = json.loads(results_path.read_text(encoding="utf-8"))["results"]
        split = json.loads(split_path.read_text(encoding="utf-8"))
        signatures = load_signature_catalog(signature_path)
        run_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise NoveltyAssessmentError(f"Malformed held-out diagnostic input: {exc}") from exc

    if run_summary.get("evaluation_mode") != "held-out-reference-signatures":
        raise NoveltyAssessmentError("Diagnostics require held-out-reference-signatures results.")
    if not isinstance(saved_results, list) or not isinstance(split.get("held_out_session_ids"), list):
        raise NoveltyAssessmentError("Held-out results or session split manifest have an invalid schema.")

    results_by_id = {
        _as_session_id(item.get("session_id")): item
        for item in saved_results
        if isinstance(item, dict) and _as_session_id(item.get("session_id"))
    }
    held_out_ids = split["held_out_session_ids"]
    if set(results_by_id) != set(held_out_ids):
        raise NoveltyAssessmentError("Saved result session IDs do not match the held-out split manifest.")

    session_records = load_session_records(session_details_path)
    dec_df = _read_dec_results(dec_results_path)
    dec_by_id = dec_df.set_index("session_id", drop=False)
    missing_ids = [sid for sid in held_out_ids if sid not in session_records or sid not in dec_by_id.index]
    if missing_ids:
        raise NoveltyAssessmentError(f"Cannot reconstruct diagnostics for held-out sessions: {missing_ids[:5]}")

    signature_feature_names = sorted({
        name for signature in signatures for name in _feature_stat_map(signature)
    })
    diagnostic_rows: List[Dict[str, Any]] = []
    comparisons_by_session: Dict[str, List[Dict[str, Any]]] = {}
    source_rows: List[Dict[str, Any]] = []

    for session_id in held_out_ids:
        source_row = dec_by_id.loc[session_id]
        if isinstance(source_row, pd.DataFrame):
            raise NoveltyAssessmentError(f"Duplicate DEC result rows found for held-out session {session_id}.")
        session_record = dict(session_records[session_id])
        session_record["session_id"] = session_id
        session_record["features"] = {
            feature_name: source_row[feature_name]
            for feature_name in signature_feature_names
            if feature_name in source_row.index
        }
        session_numeric, _, observed_categories, session_auth = _extract_session_features(session_record)
        comparisons = [compare_session_to_signature(session_record, signature) for signature in signatures]
        comparisons.sort(key=lambda item: (-item["score"], item["signature_id"]))
        comparisons_by_session[session_id] = comparisons
        best = comparisons[0]
        second = comparisons[1] if len(comparisons) > 1 else None
        saved = results_by_id[session_id]
        if saved.get("closest_signature_id") != best["signature_id"]:
            raise NoveltyAssessmentError(f"Reconstructed closest signature differs for held-out session {session_id}.")
        signature = next(item for item in signatures if item["signature_id"] == best["signature_id"])
        signature_categories = signature.get("command_categories", [])
        signature_auth = signature.get("authentication_profile", {}).get("success_rate")
        feature_details = sorted(
            best["feature_details"],
            key=lambda item: (-item["weighted_contribution"], item["feature"]),
        )
        command_available = bool(observed_categories and signature_categories)
        auth_available = session_auth is not None and _safe_float(signature_auth) is not None
        diagnostic_rows.append({
            "diagnostic_basis": "saved_pre_revision_held_out_evaluation",
            "session_id": session_id,
            "assessment_category": saved["assessment_category"],
            "closest_signature_id": best["signature_id"],
            "best_score": best["score"],
            "second_best_score": second["score"] if second else None,
            "score_margin": round(best["score"] - (second["score"] if second else 0.0), 6),
            "comparable_feature_count_best_signature": best["comparable_features"],
            "comparable_feature_count_legacy_aggregate": sum(item["comparable_features"] for item in comparisons),
            "feature_similarity": best["feature_similarity"],
            "feature_weighted_contribution": round(0.70 * best["feature_similarity"], 6),
            "command_similarity": best["command_similarity"],
            "command_weighted_contribution": round(0.20 * best["command_similarity"], 6),
            "command_evidence_status": (
                   "conflict" if best["command_evidence_status"] == "conflict" else
                   "comparable" if command_available else
                   "session_categories_missing" if not observed_categories else
                   "signature_categories_missing"
               ),
            "authentication_similarity": best["auth_similarity"],
            "authentication_weighted_contribution": round(0.10 * best["auth_similarity"], 6),
            "authentication_evidence_status": (
                   "conflict" if best["authentication_evidence_status"] == "conflict" else
                   "comparable" if auth_available else
                   "session_auth_missing" if session_auth is None else
                   "signature_auth_profile_missing"
               ),
            "contradictory_evidence": json.dumps(best["contradictory_evidence"], ensure_ascii=False),
            "observed_command_categories": json.dumps(observed_categories),
            "signature_command_categories": json.dumps(signature_categories),
            "session_auth_success": session_auth,
            "signature_auth_success_rate": signature_auth,
            "top_contributing_features": json.dumps(feature_details[:5], ensure_ascii=False),
            "all_feature_similarities": json.dumps(feature_details, ensure_ascii=False),
            "reason": saved.get("reason", ""),
        })
        source_rows.append({
            "session_id": session_id,
            "session_record": session_record,
            "session_numeric": session_numeric,
            "comparisons": comparisons,
            "saved_result": saved,
        })

    diag_csv = evaluation_dir / "score_diagnostics.csv"
    pd.DataFrame(diagnostic_rows).to_csv(diag_csv, index=False)
    sensitivity_csv = evaluation_dir / "threshold_sensitivity.csv"
    threshold_grid = {
        "known_threshold": [0.70, 0.75, 0.80, 0.85, 0.90],
        "ambiguous_margin": [0.05, 0.10, 0.15, 0.20],
        "borderline_score": [0.60, 0.65, 0.70],
        "min_compatible_features": [1, 4, 8, 9],
    }
    sensitivity_rows: List[Dict[str, Any]] = []
    from itertools import product

    for known, margin, borderline, min_features in product(
        threshold_grid["known_threshold"],
        threshold_grid["ambiguous_margin"],
        threshold_grid["borderline_score"],
        threshold_grid["min_compatible_features"],
    ):
        counts = {category: 0 for category in ("Known-like", "Potentially Novel", "Ambiguous", "Insufficient Evidence")}
        for row in source_rows:
            classified = assess_session_against_signatures(
                row["session_record"],
                signatures,
                known_threshold=known,
                ambiguous_margin=margin,
                min_compatible_features=min_features,
                borderline_score=borderline,
            )
            counts[classified["assessment_category"]] += 1
        sensitivity_rows.append({
            "decision_rule": "explicit_categorical_contradiction_veto",
            "known_threshold": known,
            "ambiguous_margin": margin,
            "borderline_score": borderline,
            "min_compatible_features": min_features,
            **{category.lower().replace("-", "_").replace(" ", "_") + "_count": count for category, count in counts.items()},
            "total_sessions": len(source_rows),
        })
    pd.DataFrame(sensitivity_rows).to_csv(sensitivity_csv, index=False)

    scores = [float(row["best_score"]) for row in diagnostic_rows]
    population_std = statistics.pstdev(scores) if len(scores) > 1 else 0.0
    sample_std = statistics.stdev(scores) if len(scores) > 1 else 0.0
    signature_tally = Counter(row["closest_signature_id"] for row in diagnostic_rows)
    constant_feature_details: Dict[str, List[str]] = {}
    signature_lines: List[str] = []
    for signature in signatures:
        feature_items = _feature_stat_map(signature)
        constant_features = []
        rendered_features = []
        for feature_name, item in feature_items.items():
            mean_value = _safe_float(item.get("mean"))
            std_value = _safe_float(item.get("std"))
            min_value = _safe_float(item.get("min"))
            max_value = _safe_float(item.get("max"))
            if std_value is None or std_value == 0 or (min_value is not None and max_value is not None and min_value == max_value):
                constant_features.append(feature_name)
            rendered_features.append(
                f"`{feature_name}` mean={mean_value}, std={std_value}, range=[{min_value}, {max_value}]"
            )
        constant_feature_details[signature["signature_id"]] = constant_features
        variability_summary = (
            f"{len(constant_features)}/{len(feature_items)} selected features have no estimated variability"
            if feature_items else
            "no numerical features selected because within-cluster variability is not estimable"
        )
        feature_summary = "; ".join(rendered_features) if rendered_features else "No numerical feature ranges are available."
        signature_lines.append(
            f"- **{signature['signature_id']}** (cluster {signature.get('cluster_id')}, n={signature.get('session_count')}): "
            f"{variability_summary}. Command categories: {signature.get('command_categories', []) or 'none'}; "
            f"authentication success rate: {signature.get('authentication_profile', {}).get('success_rate')}%.\n  - "
            + feature_summary
        )

    session_table_lines = [
        "| Session | Closest signature | Best | Second | Margin | Features (best) | Category |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for row in diagnostic_rows:
        session_table_lines.append(
            f"| {row['session_id']} | {row['closest_signature_id']} | {row['best_score']:.6f} | "
            f"{row['second_best_score']:.6f} | {row['score_margin']:.6f} | "
            f"{row['comparable_feature_count_best_signature']} | {row['assessment_category']} |"
        )

    category_columns = {
        "Known-like": "known_like_count",
        "Potentially Novel": "potentially_novel_count",
        "Ambiguous": "ambiguous_count",
        "Insufficient Evidence": "insufficient_evidence_count",
    }
    sensitivity_table = [
        "| Known | Margin | Borderline | Min features | Known-like | Potentially Novel | Ambiguous | Insufficient |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in sensitivity_rows:
        if row["min_compatible_features"] == 1 and row["borderline_score"] in {0.60, 0.70}:
            sensitivity_table.append(
                f"| {row['known_threshold']:.2f} | {row['ambiguous_margin']:.2f} | {row['borderline_score']:.2f} | "
                f"{row['min_compatible_features']} | {row['known_like_count']} | {row['potentially_novel_count']} | "
                f"{row['ambiguous_count']} | {row['insufficient_evidence_count']} |"
            )

    command_status_counts = Counter(row["command_evidence_status"] for row in diagnostic_rows)
    auth_status_counts = Counter(row["authentication_evidence_status"] for row in diagnostic_rows)
    feature_counts = [row["comparable_feature_count_best_signature"] for row in diagnostic_rows]
    selected_by_variability = all(
        "relative variability" in str(signature.get("feature_profile", {}).get("summary", "")).lower()
        or "no numerical features with estimable" in str(signature.get("feature_profile", {}).get("summary", "")).lower()
        for signature in signatures
    )
    dominant_signature_id, dominant_signature_matches = signature_tally.most_common(1)[0]

    out_report = evaluation_dir / "novelty_diagnostics.md"
    report_lines = [
        "# Held-out Novelty Diagnostics",
        "",
        f"This report diagnoses the saved held-out results using {'relative-variability' if selected_by_variability else 'the original alphabetical'} feature-profile selection. It is a diagnostic of signature-level matching, not an attack-detection performance report.",
        "",
        "## Score distribution",
        f"- Sessions: {len(scores)}",
        f"- Minimum: {min(scores):.6f}",
        f"- Maximum: {max(scores):.6f}",
        f"- Mean: {statistics.mean(scores):.6f}",
        f"- Median: {statistics.median(scores):.6f}",
        f"- Standard deviation (population): {population_std:.6f}",
        f"- Standard deviation (sample): {sample_std:.6f}",
        "",
        "## Per-session scores",
        *session_table_lines,
        "",
        "Detailed components and feature-level comparisons are in `score_diagnostics.csv`.",
        "",
        "## Why sessions matched",
        f"- Signature match counts: {dict(signature_tally)}.",
        "- The saved result schema did not persist component scores. This diagnostic reconstructs them by rerunning the existing comparison function with the saved signatures and the same DEC feature rows; the score formula and production defaults are unchanged.",
        f"- Each matched signature's numerical similarity averages its {min(feature_counts)}–{max(feature_counts)} compatible selected features and contributes 70% of the total score. Command-category Jaccard contributes 20%; authentication similarity contributes 10%. Unavailable categorical evidence contributes zero without renormalizing the weights.",
        f"- Command evidence statuses: {dict(command_status_counts)}. Authentication evidence statuses: {dict(auth_status_counts)}. These distinguish missing evidence from an observed conflict; missing command categories are not counted as disagreement.",
        f"- {dominant_signature_matches} of {len(diagnostic_rows)} sessions selected {dominant_signature_id} as their closest signature. Consult each session's feature details below and in the CSV to see whether the match is carried by multiple variable dimensions or weak/broad evidence.",
        "- Compare the per-feature values and weighted contributions in the CSV. Largest contributors are explicitly ranked per session; do not interpret constant dimensions as discriminative evidence merely because the value agrees.",
        "",
        "## Reference signature feature ranges and variability",
        *signature_lines,
        "",
        "## Comparison-method audit",
        f"- A single compatible feature can satisfy `min_compatible_features=1`; because component weights are fixed, that one feature can contribute as much as 0.70, with matching authentication adding 0.10 and matching commands up to 0.20. The default is permissive in principle. In this saved run, the closest-signature feature count ranged from {min(feature_counts)} to {max(feature_counts)}; this does not justify changing the default without labelled calibration.",
        "- The diagnostic reports comparable features for the closest signature; the prior aggregate count summed matching dimensions across all signatures and overstated evidence (24 instead of 8 for the baseline example). The corrected count does not change the similarity score.",
        "- Missing command/authentication data contributes zero without renormalizing weights; diagnostics distinguish missing evidence from observed conflict. A confirmed defect was that contradictory command or authentication evidence could be masked by numerical similarity. The revised decision rule prevents a Known-like classification when either available categorical signal directly conflicts; it does not change the similarity score or configured threshold.",
        (
            "- The saved signature profiles use non-constant features ranked by relative variability where such estimates exist; the singleton signature has no estimable numerical variability and therefore has no selected numerical features."
            if selected_by_variability else
            "- The saved profiles selected the first eight features alphabetically, not the most variable dimensions. This made profiles broad and weakly discriminative. Signature generation now selects non-constant dimensions ranked by relative variability when available; saved signature files are not modified by this diagnostic."
        ),
        "- The thresholds are configuration choices, not empirically justified values; there are no suitable ground-truth novelty labels in the dataset.",
        "",
        "## Threshold sensitivity",
        "- Grid: known threshold 0.70–0.90, margin 0.05–0.20, borderline score 0.60–0.70, and minimum comparable features 1/4/8/9. Full combinations are in `threshold_sensitivity.csv`; threshold values are exploratory and not calibrated.",
        "- The table below shows minimum-feature=1 representative cases. These are sensitivity counts on this fixed, unlabeled holdout; they are not a threshold-selection criterion.",
        *sensitivity_table,
        "",
        "## Validity and limitations",
        "- This is a session-level signature holdout only. The existing DEC model and scaler may have been fitted using records in the holdout, and the available artifacts do not establish otherwise. This is not independent end-to-end generalization.",
        "- No attack labels or ground-truth novelty labels were used. Do not interpret Known-like or Potentially Novel counts as accuracy, recall, precision, or zero-day detection.",
        "- Three signatures are generated from a small dataset; one has a single supporting session, and the dominant profile has limited variability in its currently selected fields.",
        "",
    ]
    out_report.write_text("\n".join(report_lines), encoding="utf-8")

    return {
        "score_diagnostics_csv": str(diag_csv),
        "threshold_sensitivity_csv": str(sensitivity_csv),
        "diagnostic_report": str(out_report),
        "score_min": min(scores),
        "score_max": max(scores),
        "score_mean": statistics.mean(scores),
        "score_median": statistics.median(scores),
        "score_population_std": population_std,
        "score_sample_std": sample_std,
        "signature_match_counts": dict(signature_tally),
        "constant_feature_details": constant_feature_details,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Assess behavioural novelty of Cowrie sessions against stored behavioural signatures")
    parser.add_argument("--diagnose-held-out", action="store_true", help="Generate score/component and threshold sensitivity diagnostics from an existing held-out run")
    parser.add_argument("--held-out-evaluation", action="store_true", help="Build signatures only from reference sessions, then assess the disjoint held-out sessions")
    parser.add_argument("--dec-results", type=Path, default=None, help="Path to dec_results.csv (held-out evaluation only)")
    parser.add_argument("--session-details", type=Path, default=None, help="Path to the session-details JSON or CSV dataset to assess")
    parser.add_argument("--signature-file", type=Path, default=None, help="Path to behaviour_signatures.json")
    parser.add_argument("--output-dir", type=Path, default=None, help="Directory for novelty assessment outputs")
    parser.add_argument("--known-threshold", type=float, default=DEFAULT_THRESHOLDS["known_threshold"], help="Similarity threshold for Known-like classification")
    parser.add_argument("--ambiguous-margin", type=float, default=DEFAULT_THRESHOLDS["ambiguous_margin"], help="Minimum separation between top scores for a clear Known-like decision")
    parser.add_argument("--min-compatible-features", type=int, default=DEFAULT_THRESHOLDS["min_compatible_features"], help="Minimum number of compatible feature comparisons before using a comparison-based decision")
    parser.add_argument("--borderline-score", type=float, default=DEFAULT_THRESHOLDS["borderline_score"], help="Score below which borderline matches are treated as ambiguous")
    parser.add_argument("--held-out-ratio", type=float, default=None, help="Held-out session fraction for --held-out-evaluation (default: 0.2)")
    parser.add_argument("--random-seed", type=int, default=42, help="Seed for deterministic held-out splits")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    repo_root = repo_root_from_script()
    session_path = args.session_details or (repo_root / "data/parsed/session_details.json")
    signature_path = args.signature_file or (repo_root / "reports/behaviour_signatures/behaviour_signatures.json")
    output_dir = args.output_dir or (repo_root / "reports/novelty_assessment")

    try:
        if args.diagnose_held_out:
            diagnostic_dir = output_dir
            if args.output_dir is None:
                diagnostic_dir = output_dir / "held_out"
            summary = generate_held_out_diagnostics(
                diagnostic_dir,
                session_path,
                args.dec_results or (repo_root / "data/processed/dec_results.csv"),
            )
            print("HELD-OUT DIAGNOSTICS")
            print(f"Score range: {summary['score_min']:.6f} - {summary['score_max']:.6f}")
            print(f"Mean / median: {summary['score_mean']:.6f} / {summary['score_median']:.6f}")
            print(f"Signature match counts: {summary['signature_match_counts']}")
            print(f"Diagnostic report: {summary['diagnostic_report']}")
            return

        if args.held_out_evaluation:
            dec_results_path = args.dec_results or (repo_root / "data/processed/dec_results.csv")
            evaluation_output_dir = output_dir
            if args.output_dir is None:
                evaluation_output_dir = output_dir / "held_out"
            summary = run_held_out_evaluation(
                dec_results_path=dec_results_path,
                session_details_path=session_path,
                output_dir=evaluation_output_dir,
                held_out_ratio=args.held_out_ratio if args.held_out_ratio is not None else 0.2,
                random_seed=args.random_seed,
                known_threshold=args.known_threshold,
                ambiguous_margin=args.ambiguous_margin,
                min_compatible_features=args.min_compatible_features,
                borderline_score=args.borderline_score,
            )
            print("HELD-OUT NOVELTY ASSESSMENT")
            print(f"Reference sessions: {summary['reference_session_count']}")
            print(f"Held-out sessions assessed: {summary['processed_session_count']}")
            print(f"Reference signatures generated: {summary['signature_count']}")
            print(f"Category counts: {summary['category_counts']}")
            print(f"Output directory: {evaluation_output_dir}")
            print(f"Status: {summary['status']}")
            print(f"Warnings: {len(summary['warnings'])}")
            return

        if args.held_out_ratio is not None:
            parser.error("--held-out-ratio requires --held-out-evaluation.")
        summary = generate_novelty_assessment(
            session_details_path=session_path,
            signature_path=signature_path,
            output_dir=output_dir,
            known_threshold=args.known_threshold,
            ambiguous_margin=args.ambiguous_margin,
            min_compatible_features=args.min_compatible_features,
            borderline_score=args.borderline_score,
            held_out_ratio=0.0,
            random_seed=args.random_seed,
            held_out_sessions=None,
        )
        print("NOVELTY ASSESSMENT")
        print(f"Sessions assessed: {summary.get('processed_session_count', 0)}")
        print(f"Input sessions: {summary.get('input_session_count', 0)}")
        print(f"Output directory: {output_dir}")
        print(f"Status: {summary.get('status', 'success')}")
        print(f"Warnings: {len(summary.get('warnings', []))}")
    except NoveltyAssessmentError as exc:
        raise SystemExit(f"Error: {exc}")


if __name__ == "__main__":
    main()
