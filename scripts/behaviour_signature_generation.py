#!/usr/bin/env python3
"""Generate evidence-backed behavioural signatures from DEC cluster outputs.

This module reads the outputs already produced by the Behaviour Pattern Analysis
pipeline and converts cluster-level evidence into reusable behavioural signatures.
The goal is to provide structured summaries that can later be consumed by a
Novelty Assessment module without implementing novelty detection here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

LOGGER = logging.getLogger("behaviour_signature_generation")


class SignatureGenerationError(RuntimeError):
    """Raised when required input validation or processing fails."""


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parent.parent


def configure_logging(verbose: bool = False) -> None:
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def _ensure_file(path: Path, description: str) -> None:
    if not path.exists():
        raise SignatureGenerationError(f"{description} not found: {path}")
    if not path.is_file():
        raise SignatureGenerationError(f"{description} is not a file: {path}")


def _safe_float(value: Any) -> Optional[float]:
    try:
        if value is None or pd.isna(value):
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return [str(value).strip()] if str(value).strip() else []


def _parse_cluster_id(value: Any) -> Optional[int]:
    if value is None or pd.isna(value):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _signature_id_for(cluster_id: Any, behaviour_label: str, session_count: int, feature_profile: Dict[str, Any], command_categories: Iterable[str]) -> str:
    canonical = {
        "cluster_id": cluster_id,
        "behaviour_label": behaviour_label,
        "session_count": int(session_count),
        "feature_profile": feature_profile,
        "command_categories": sorted(set(command_categories)),
    }
    digest = hashlib.sha256(_canonical_json(canonical).encode("utf-8")).hexdigest()
    return f"sig-{digest[:16]}"


def load_cluster_summary(path: Path) -> pd.DataFrame:
    _ensure_file(path, "Cluster summary CSV")
    df = pd.read_csv(path)
    if df.empty:
        raise SignatureGenerationError(f"Cluster summary CSV is empty: {path}")
    required = {"cluster_id", "session_count", "percentage_of_sessions"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise SignatureGenerationError(f"Cluster summary CSV missing required columns: {missing}")
    df = df.copy()
    df["cluster_id"] = df["cluster_id"].map(_parse_cluster_id)
    df = df.dropna(subset=["cluster_id"]).reset_index(drop=True)
    return df


def load_cluster_feature_statistics(path: Path) -> pd.DataFrame:
    _ensure_file(path, "Cluster feature statistics CSV")
    df = pd.read_csv(path)
    if df.empty:
        raise SignatureGenerationError(f"Cluster feature statistics CSV is empty: {path}")
    required = {"cluster_id", "feature_name", "mean", "median", "std", "min", "max"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise SignatureGenerationError(f"Cluster feature statistics CSV missing required columns: {missing}")
    df = df.copy()
    df["cluster_id"] = df["cluster_id"].map(_parse_cluster_id)
    df = df.dropna(subset=["cluster_id"]).reset_index(drop=True)
    return df


def load_cluster_command_analysis(path: Path) -> pd.DataFrame:
    _ensure_file(path, "Cluster command analysis CSV")
    df = pd.read_csv(path)
    if df.empty:
        return pd.DataFrame(columns=["cluster_id", "command_or_category", "frequency", "sessions_containing", "percentage_of_sessions"])
    required = {"cluster_id", "command_or_category", "frequency", "sessions_containing", "percentage_of_sessions"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise SignatureGenerationError(f"Cluster command analysis CSV missing required columns: {missing}")
    df = df.copy()
    df["cluster_id"] = df["cluster_id"].map(_parse_cluster_id)
    df = df.dropna(subset=["cluster_id"]).reset_index(drop=True)
    return df


def load_session_profiles(path: Path) -> pd.DataFrame:
    _ensure_file(path, "Session behaviour profiles CSV")
    df = pd.read_csv(path)
    if df.empty:
        return pd.DataFrame(columns=["session_id", "dec_cluster", "behavioural_interpretation", "observed_command_categories", "observed_commands", "evidence"])
    required = {"session_id", "dec_cluster", "behavioural_interpretation", "observed_command_categories", "observed_commands", "evidence"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise SignatureGenerationError(f"Session behaviour profiles CSV missing required columns: {missing}")
    df = df.copy()
    df["session_id"] = df["session_id"].astype(str).str.strip()
    df["dec_cluster"] = df["dec_cluster"].map(_parse_cluster_id)
    df = df.dropna(subset=["session_id", "dec_cluster"]).reset_index(drop=True)
    return df


def load_session_details(path: Path) -> Dict[str, Dict[str, Any]]:
    _ensure_file(path, "Session details JSON")
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise SignatureGenerationError(f"Session details JSON must be an object keyed by session_id: {path}")
    return payload


def load_cluster_analysis_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {"validation": {}, "cluster_distribution": [], "cluster_summary": []}
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        return {"validation": {}, "cluster_distribution": [], "cluster_summary": []}
    return payload


def validate_data_quality(
    dec_total: int,
    session_profiles_df: pd.DataFrame,
    session_details: Dict[str, Dict[str, Any]],
    validation_data: Dict[str, Any],
) -> List[str]:
    warnings: List[str] = []
    if session_profiles_df.empty:
        warnings.append("No session profiles available; signature generation may be empty.")
    duplicated_sessions = session_profiles_df["session_id"][session_profiles_df["session_id"].duplicated(keep=False)].unique().tolist()
    if duplicated_sessions:
        warnings.append(f"Duplicate session IDs in session profiles: {len(duplicated_sessions)}")
    missing_details = sorted(set(session_profiles_df["session_id"]) - set(session_details.keys()))
    if missing_details:
        warnings.append(f"Session profiles missing session_details records: {len(missing_details)}")
    dup_dec = validation_data.get("duplicate_dec_sessions", [])
    if dup_dec:
        warnings.append(f"Duplicate DEC session IDs detected: {len(dup_dec)}")
    missing_mapping = validation_data.get("missing_in_mapping", [])
    if missing_mapping:
        warnings.append(f"DEC sessions missing mapping entries: {len(missing_mapping)}")
    missing_session_details = validation_data.get("missing_in_session_details", [])
    if missing_session_details:
        warnings.append(f"DEC sessions missing session detail records: {len(missing_session_details)}")
    if dec_total <= 0:
        warnings.append("No DEC rows were available for signature generation.")
    return warnings


def build_feature_profile(cluster_id: int, feature_stats_df: pd.DataFrame) -> Dict[str, Any]:
    rows = feature_stats_df[feature_stats_df["cluster_id"] == cluster_id].copy()
    if rows.empty:
        return {"selected_features": [], "summary": "No feature statistics available for this cluster."}
    rows["mean_numeric"] = pd.to_numeric(rows["mean"], errors="coerce")
    rows["std_numeric"] = pd.to_numeric(rows["std"], errors="coerce")
    variable_rows = rows[
        rows["std_numeric"].notna() & (rows["std_numeric"] > 0)
    ].copy()
    if variable_rows.empty:
        return {
            "selected_features": [],
            "summary": "No numerical features with estimable within-cluster variability; numerical matching is unavailable for this signature.",
        }
    denominator = variable_rows["mean_numeric"].abs().replace(0, pd.NA)
    variable_rows["relative_variability"] = (
        variable_rows["std_numeric"] / denominator
    ).fillna(variable_rows["std_numeric"])
    rows = variable_rows.sort_values(
        ["relative_variability", "feature_name"],
        ascending=[False, True],
        kind="stable",
    )
    selected = []
    for _, row in rows.head(8).iterrows():
        selected.append({
            "feature": str(row["feature_name"]),
            "mean": _safe_float(row["mean"]),
            "median": _safe_float(row["median"]),
            "std": _safe_float(row["std"]),
            "min": _safe_float(row["min"]),
            "max": _safe_float(row["max"]),
        })
    return {
        "selected_features": selected,
        "summary": "Features are ranked by cluster-specific relative variability; constant dimensions are excluded when variable dimensions are available.",
    }


def _session_auth_profile(support_sessions: pd.DataFrame, session_details: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    auth_values: List[int] = []
    for session_id in support_sessions["session_id"].tolist():
        record = session_details.get(str(session_id), {})
        if isinstance(record, dict):
            auth_value = record.get("auth_success")
            try:
                auth_values.append(int(auth_value))
            except (TypeError, ValueError):
                pass
    if not auth_values:
        return {"observed": False, "success_count": 0, "failure_count": 0, "success_rate": None, "notes": "Authentication evidence unavailable."}
    success_count = sum(1 for value in auth_values if value == 1)
    failure_count = sum(1 for value in auth_values if value == 0)
    return {
        "observed": True,
        "success_count": success_count,
        "failure_count": failure_count,
        "success_rate": round((success_count / len(auth_values)) * 100.0, 2) if auth_values else None,
        "notes": "Authentication success/failure observed from session_details.json.",
    }


def _cluster_command_categories(cluster_id: int, command_analysis_df: pd.DataFrame) -> List[str]:
    rows = command_analysis_df[command_analysis_df["cluster_id"] == cluster_id].copy()
    if rows.empty:
        return []
    rows = rows.sort_values(["frequency", "command_or_category"], ascending=[False, True])
    return [str(item) for item in rows["command_or_category"].tolist()]


def _representative_commands(support_sessions: pd.DataFrame) -> List[str]:
    commands: List[str] = []
    for _, row in support_sessions.iterrows():
        observed = _as_list(row.get("observed_commands"))
        if observed:
            commands.extend(observed)
    deduped: List[str] = []
    seen = set()
    for command in commands:
        if command not in seen:
            seen.add(command)
            deduped.append(command)
    return deduped[:5]


def compute_evidence_strength(support_sessions: pd.DataFrame, command_categories: List[str], auth_profile: Dict[str, Any]) -> Dict[str, Any]:
    session_count = len(support_sessions)
    if session_count == 0:
        return {"score": 0.0, "label": "Low", "method": "score = min(1.0, 0.25 + 0.3 * min(1, session_count / 5) + 0.25 * interpretation_consistency + 0.1 * command_evidence + 0.1 * auth_evidence)"}
    interpretations = support_sessions["behavioural_interpretation"].fillna("Unknown").astype(str)
    unique_count = interpretations.nunique()
    consistency = 1.0 if unique_count <= 1 else 0.6 if unique_count <= 2 else 0.35
    command_evidence = 1.0 if command_categories else 0.0
    auth_evidence = 1.0 if auth_profile.get("observed") else 0.0
    score = 0.25 + (0.30 * min(1.0, session_count / 5.0)) + (0.25 * consistency) + (0.10 * command_evidence) + (0.10 * auth_evidence)
    score = min(1.0, score)
    if score >= 0.8:
        label = "High"
    elif score >= 0.55:
        label = "Medium"
    else:
        label = "Low"
    return {
        "score": round(score, 4),
        "label": label,
        "method": "0.25 + 0.30 * support_ratio + 0.25 * interpretation_consistency + 0.10 * command_evidence + 0.10 * auth_evidence, capped at 1.0",
    }


def build_signatures(
    cluster_summary_df: pd.DataFrame,
    feature_stats_df: pd.DataFrame,
    command_analysis_df: pd.DataFrame,
    session_profiles_df: pd.DataFrame,
    session_details: Dict[str, Dict[str, Any]],
    validation_data: Optional[Dict[str, Any]] = None,
    source_files: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    if validation_data is None:
        validation_data = {}
    if cluster_summary_df.empty and session_profiles_df.empty:
        return []

    total_sessions = int(len(session_profiles_df))
    patterns_examined: List[int] = []
    signatures: List[Dict[str, Any]] = []

    cluster_ids = []
    if not cluster_summary_df.empty:
        cluster_ids.extend(sorted(cluster_summary_df["cluster_id"].astype(int).unique().tolist()))
    if not session_profiles_df.empty:
        cluster_ids.extend(sorted(session_profiles_df["dec_cluster"].astype(int).unique().tolist()))
    cluster_ids = sorted(set(cluster_ids))

    for cluster_id in cluster_ids:
        support_sessions = session_profiles_df[session_profiles_df["dec_cluster"] == cluster_id].copy()
        if support_sessions.empty:
            continue
        patterns_examined.append(cluster_id)
        summary_row = cluster_summary_df[cluster_summary_df["cluster_id"] == cluster_id]
        session_count = int(len(support_sessions))
        support_percentage = float(summary_row["percentage_of_sessions"].iloc[0]) if not summary_row.empty else (session_count / total_sessions * 100.0) if total_sessions else 0.0
        interpretation_counts = support_sessions["behavioural_interpretation"].fillna("Unknown").astype(str).value_counts()
        behaviour_label = str(interpretation_counts.idxmax()) if not interpretation_counts.empty else "Mixed/Unclassified"
        command_categories = _cluster_command_categories(cluster_id, command_analysis_df)
        representative_commands = _representative_commands(support_sessions)
        feature_profile = build_feature_profile(cluster_id, feature_stats_df)
        auth_profile = _session_auth_profile(support_sessions, session_details)
        evidence_strength = compute_evidence_strength(support_sessions, command_categories, auth_profile)
        support_evidence = []
        for _, row in support_sessions.head(5).iterrows():
            evidence = str(row.get("evidence", "")).strip()
            if evidence:
                support_evidence.append(evidence)

        limitations: List[str] = []
        if session_count < 2:
            limitations.append("Small sample size: fewer than two supporting sessions.")
        if not command_categories:
            limitations.append("No command-category evidence available for this cluster.")
        if not auth_profile.get("observed"):
            limitations.append("Authentication data unavailable for this cluster.")
        if behaviour_label in {"Mixed/Unclassified", "Insufficient Evidence"}:
            limitations.append("Behavioural interpretation is mixed or weakly supported by the available evidence.")
        if evidence_strength["label"] == "Low":
            limitations.append("Evidence strength is low relative to the required support threshold.")

        signature = {
            "signature_id": _signature_id_for(cluster_id, behaviour_label, session_count, feature_profile, command_categories),
            "signature_version": "1.0",
            "cluster_id": int(cluster_id),
            "behaviour_label": behaviour_label,
            "session_count": session_count,
            "support_percentage": round(float(support_percentage), 4),
            "feature_profile": feature_profile,
            "command_categories": command_categories,
            "representative_commands": representative_commands,
            "authentication_profile": auth_profile,
            "activity_profile": {
                "dominant_interpretation": behaviour_label,
                "supporting_sessions": session_count,
                "observed_categories": command_categories,
                "session_ids": support_sessions["session_id"].tolist(),
            },
            "supporting_evidence": support_evidence,
            "limitations": limitations,
            "evidence_strength": evidence_strength,
            "confidence": float(evidence_strength["score"]),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_files": source_files or [
                "data/processed/dec_results.csv",
                "data/processed/session_mapping.csv",
                "data/parsed/session_details.json",
                "data/processed/model_input.csv",
                "reports/behaviour_analysis/cluster_summary.csv",
                "reports/behaviour_analysis/cluster_feature_statistics.csv",
                "reports/behaviour_analysis/cluster_command_analysis.csv",
                "reports/behaviour_analysis/session_behaviour_profiles.csv",
            ],
        }
        signatures.append(signature)

    return signatures


def _flatten_signature(signature: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "signature_id": signature["signature_id"],
        "signature_version": signature["signature_version"],
        "cluster_id": signature["cluster_id"],
        "behaviour_label": signature["behaviour_label"],
        "session_count": signature["session_count"],
        "support_percentage": signature["support_percentage"],
        "feature_profile": json.dumps(signature["feature_profile"], ensure_ascii=False),
        "command_categories": json.dumps(signature["command_categories"], ensure_ascii=False),
        "representative_commands": json.dumps(signature["representative_commands"], ensure_ascii=False),
        "authentication_profile": json.dumps(signature["authentication_profile"], ensure_ascii=False),
        "activity_profile": json.dumps(signature["activity_profile"], ensure_ascii=False),
        "supporting_evidence": json.dumps(signature["supporting_evidence"], ensure_ascii=False),
        "limitations": json.dumps(signature["limitations"], ensure_ascii=False),
        "evidence_strength": json.dumps(signature["evidence_strength"], ensure_ascii=False),
        "confidence": signature["confidence"],
        "created_at": signature["created_at"],
        "source_files": json.dumps(signature["source_files"], ensure_ascii=False),
    }


def store_outputs(signatures: List[Dict[str, Any]], output_dir: Path) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "behaviour_signatures.json"
    csv_path = output_dir / "behaviour_signatures.csv"
    report_path = output_dir / "signature_generation_report.md"
    summary_path = output_dir / "signature_generation_summary.json"

    payload = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "signature_count": len(signatures),
        "signatures": signatures,
    }
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")

    if signatures:
        df = pd.DataFrame([_flatten_signature(item) for item in signatures])
    else:
        df = pd.DataFrame(columns=[
            "signature_id", "signature_version", "cluster_id", "behaviour_label", "session_count",
            "support_percentage", "feature_profile", "command_categories", "representative_commands",
            "authentication_profile", "activity_profile", "supporting_evidence", "limitations",
            "evidence_strength", "confidence", "created_at", "source_files",
        ])
    df.to_csv(csv_path, index=False)

    low_confidence = sum(1 for sig in signatures if sig["evidence_strength"]["label"] in {"Low"})
    lines: List[str] = []
    lines.append("# Behavioural Signature Generation Report")
    lines.append("")
    lines.append(f"- Signature schema version: {payload['schema_version']}")
    lines.append(f"- Signatures generated: {len(signatures)}")
    lines.append(f"- Low-confidence signatures: {low_confidence}")
    lines.append("")
    lines.append("## Signature summary")
    for signature in signatures:
        lines.append(f"### {signature['signature_id']} ({signature['behaviour_label']})")
        lines.append(f"- Cluster ID: {signature['cluster_id']}")
        lines.append(f"- Supporting sessions: {signature['session_count']} ({signature['support_percentage']:.2f}%)")
        lines.append(f"- Evidence strength: {signature['evidence_strength']['label']} ({signature['evidence_strength']['score']})")
        lines.append(f"- Command categories: {', '.join(signature['command_categories']) if signature['command_categories'] else 'None observed'}")
        lines.append(f"- Representative commands: {', '.join(signature['representative_commands']) if signature['representative_commands'] else 'None observed'}")
        lines.append(f"- Authentication profile: {json.dumps(signature['authentication_profile'], ensure_ascii=False)}")
        lines.append(f"- Supporting evidence: {json.dumps(signature['supporting_evidence'], ensure_ascii=False)}")
        if signature["limitations"]:
            lines.append(f"- Limitations: {'; '.join(signature['limitations'])}")
        lines.append("")
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary = {
        "schema_version": payload["schema_version"],
        "generated_at": payload["generated_at"],
        "signature_count": len(signatures),
        "low_confidence_signatures": low_confidence,
        "output_files": {
            "json": str(json_path),
            "csv": str(csv_path),
            "report": str(report_path),
            "summary": str(summary_path),
        },
        "status": "success" if signatures or True else "success",
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False, allow_nan=False), encoding="utf-8")
    return summary


def generate_behaviour_signatures(
    cluster_summary_path: Path,
    feature_stats_path: Path,
    command_analysis_path: Path,
    session_profiles_path: Path,
    session_details_path: Path,
    cluster_analysis_path: Path,
    output_dir: Path,
) -> Dict[str, Any]:
    cluster_summary_df = load_cluster_summary(cluster_summary_path)
    feature_stats_df = load_cluster_feature_statistics(feature_stats_path)
    command_analysis_df = load_cluster_command_analysis(command_analysis_path)
    session_profiles_df = load_session_profiles(session_profiles_path)
    session_details = load_session_details(session_details_path)
    validation_data = load_cluster_analysis_json(cluster_analysis_path)
    validation_data = validation_data.get("validation", {})

    warnings = validate_data_quality(
        dec_total=int(session_profiles_df["dec_cluster"].nunique()) if not session_profiles_df.empty else 0,
        session_profiles_df=session_profiles_df,
        session_details=session_details,
        validation_data=validation_data,
    )

    signatures = build_signatures(
        cluster_summary_df,
        feature_stats_df,
        command_analysis_df,
        session_profiles_df,
        session_details,
        validation_data,
    )

    summary = store_outputs(signatures, output_dir)
    summary["warnings"] = warnings
    summary["session_count"] = int(len(session_profiles_df))
    summary["patterns_examined"] = int(len(cluster_summary_df)) if not cluster_summary_df.empty else int(len(session_profiles_df["dec_cluster"].unique()))
    summary["records_skipped"] = int(summary.get("records_skipped", 0))
    summary["output_dir"] = str(output_dir)
    summary_path = output_dir / "signature_generation_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate behaviour signatures from DEC cluster analysis outputs")
    parser.add_argument("--cluster-summary", type=Path, default=None, help="Path to cluster_summary.csv")
    parser.add_argument("--feature-stats", type=Path, default=None, help="Path to cluster_feature_statistics.csv")
    parser.add_argument("--command-analysis", type=Path, default=None, help="Path to cluster_command_analysis.csv")
    parser.add_argument("--session-profiles", type=Path, default=None, help="Path to session_behaviour_profiles.csv")
    parser.add_argument("--session-details", type=Path, default=None, help="Path to session_details.json")
    parser.add_argument("--cluster-analysis", type=Path, default=None, help="Optional path to cluster_analysis.json")
    parser.add_argument("--output-dir", type=Path, default=None, help="Directory for generated behavioural signatures")
    parser.add_argument("--verbose", action="store_true", help="Enable info logging")
    args = parser.parse_args()
    configure_logging(args.verbose)

    repo_root = repo_root_from_script()
    cluster_summary_path = args.cluster_summary or (repo_root / "reports/behaviour_analysis/cluster_summary.csv")
    feature_stats_path = args.feature_stats or (repo_root / "reports/behaviour_analysis/cluster_feature_statistics.csv")
    command_analysis_path = args.command_analysis or (repo_root / "reports/behaviour_analysis/cluster_command_analysis.csv")
    session_profiles_path = args.session_profiles or (repo_root / "reports/behaviour_analysis/session_behaviour_profiles.csv")
    session_details_path = args.session_details or (repo_root / "data/parsed/session_details.json")
    cluster_analysis_path = args.cluster_analysis or (repo_root / "reports/behaviour_analysis/cluster_analysis.json")
    output_dir = args.output_dir or (repo_root / "reports/behaviour_signatures")

    try:
        summary = generate_behaviour_signatures(
            cluster_summary_path,
            feature_stats_path,
            command_analysis_path,
            session_profiles_path,
            session_details_path,
            cluster_analysis_path,
            output_dir,
        )
        print("BEHAVIOURAL SIGNATURE GENERATION")
        print("Inputs validated")
        print(f"Sessions analysed: {summary.get('session_count', 0)}")
        print(f"Patterns examined: {summary.get('patterns_examined', 0)}")
        print(f"Signatures generated: {summary.get('signature_count', 0)}")
        print(f"Low-confidence signatures: {summary.get('low_confidence_signatures', 0)}")
        print(f"Records skipped: {summary.get('records_skipped', 0)}")
        print("")
        print("Reports saved to:")
        print(output_dir)
    except SignatureGenerationError as exc:
        raise SystemExit(f"Error: {exc}")


if __name__ == "__main__":
    main()
