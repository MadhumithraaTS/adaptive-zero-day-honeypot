#!/usr/bin/env python3
"""Behaviour Pattern Analysis for DEC cluster outputs.

This module reads the actual DEC output and Cowrie session metadata that the
project has already generated, validates the join keys, and produces evidence-
backed behavioural summaries for each cluster.

It intentionally does not retrain the DEC model or alter the existing pipeline.
"""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import pandas as pd


LOGGER = logging.getLogger("behaviour_pattern_analysis")

EXCLUDED_COLUMNS = {
    "session_id",
    "src_ip",
    "src_port",
    "attack_cat",
    "label",
    "dec_cluster",
    "dec_confidence",
    "cluster_0_prob",
    "cluster_1_prob",
    "cluster_2_prob",
}

CATEGORY_KEYWORDS = {
    "reconnaissance": [
        "whoami",
        "uname",
        "id",
        "pwd",
        "ls",
        "cat /etc/passwd",
        "cat /etc/issue",
        "hostname",
        "w",
        "ps",
        "ifconfig",
        "ip a",
        "netstat",
        "route",
        "arp",
        "cat /etc/shadow",
    ],
    "credential_attack": [
        "hydra",
        "medusa",
        "ncrack",
        "ssh",
        "bruteforce",
        "login",
        "curl -u",
        "user",
        "passwd",
        "password",
        "root",
        "admin",
    ],
    "file_transfer": [
        "wget",
        "curl",
        "scp",
        "ftp",
        "tftp",
        "nc",
        "base64",
        "tar",
        "gzip",
        "xz",
        "chmod +x",
    ],
    "file_system": [
        "ls",
        "cd ",
        "mkdir",
        "rm ",
        "mv ",
        "cp ",
        "chmod",
        "cat ",
        "echo ",
        "touch",
        "find",
        "nano",
        "vim",
        "sed ",
    ],
    "persistence": [
        "crontab",
        "systemctl",
        "service",
        "update-rc.d",
        "/etc/rc.local",
        "chkconfig",
        "/etc/init.d",
        "rc.local",
        "init.d",
    ],
    "privilege_escalation": [
        "sudo",
        "su",
        "/etc/shadow",
        "id_rsa",
        "chmod 777",
        "chmod +s",
        "sudo -n",
        "whoami",
    ],
    "networking": [
        "ping",
        "nc",
        "wget",
        "curl",
        "scp",
        "ftp",
        "tftp",
        "ssh",
        "telnet",
        "ss -lnt",
        "ip a",
    ],
    "evasion": [
        "rm ",
        "history -c",
        "unset histfile",
        "histsize=0",
        "kill",
        "killall",
        "pkill",
        "unset HISTFILE",
    ],
}


class AnalysisError(RuntimeError):
    """Raised when input validation fails."""


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parent.parent


def configure_logging(verbose: bool = False) -> None:
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def _ensure_file(path: Path, description: str) -> None:
    if not path.exists():
        raise AnalysisError(f"{description} not found: {path}")
    if not path.is_file():
        raise AnalysisError(f"{description} is not a file: {path}")


def _to_string_column(series: pd.Series) -> pd.Series:
    return series.astype(str).replace("nan", "").replace("None", "")


def load_dec_results(path: Path) -> pd.DataFrame:
    _ensure_file(path, "DEC results CSV")
    df = pd.read_csv(path)
    if df.empty:
        raise AnalysisError(f"DEC results CSV is empty: {path}")
    required = {"session_id", "dec_cluster"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise AnalysisError(f"DEC results CSV missing required columns: {missing}")
    df = df.copy()
    df["session_id"] = _to_string_column(df["session_id"]).str.strip()
    df["dec_cluster"] = pd.to_numeric(df["dec_cluster"], errors="coerce")
    return df


def load_session_mapping(path: Path) -> pd.DataFrame:
    _ensure_file(path, "Session mapping CSV")
    df = pd.read_csv(path)
    if df.empty:
        raise AnalysisError(f"Session mapping CSV is empty: {path}")
    required = {"session_id"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise AnalysisError(f"Session mapping CSV missing required columns: {missing}")
    df = df.copy()
    df["session_id"] = _to_string_column(df["session_id"]).str.strip()
    return df


def load_session_details(path: Path) -> Dict[str, Dict[str, Any]]:
    _ensure_file(path, "Session details JSON")
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise AnalysisError(f"Session details JSON must be an object keyed by session_id: {path}")
    return payload


def load_model_input(path: Path) -> pd.DataFrame:
    _ensure_file(path, "Model input CSV")
    df = pd.read_csv(path)
    if df.empty:
        raise AnalysisError(f"Model input CSV is empty: {path}")
    return df


def validate_join_consistency(dec_df: pd.DataFrame, mapping_df: pd.DataFrame, session_details: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    dec_session_ids = dec_df["session_id"].dropna()
    mapping_session_ids = mapping_df["session_id"].dropna()

    duplicates_in_dec = dec_session_ids[dec_session_ids.duplicated(keep=False)].unique().tolist()
    duplicates_in_mapping = mapping_session_ids[mapping_session_ids.duplicated(keep=False)].unique().tolist()

    missing_in_mapping = sorted(set(dec_session_ids) - set(mapping_session_ids))
    missing_in_dec = sorted(set(mapping_session_ids) - set(dec_session_ids))
    missing_in_session_details = sorted(set(dec_session_ids) - set(session_details.keys()))

    validation = {
        "total_dec_sessions": int(len(dec_session_ids)),
        "total_mapping_sessions": int(len(mapping_session_ids)),
        "duplicate_dec_sessions": duplicates_in_dec,
        "duplicate_mapping_sessions": duplicates_in_mapping,
        "missing_in_mapping": missing_in_mapping,
        "missing_in_dec": missing_in_dec,
        "missing_in_session_details": missing_in_session_details,
    }
    return validation


def classify_command(command: str) -> List[str]:
    if not command:
        return []
    normalized = command.strip().lower()
    matched: List[str] = []
    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(keyword in normalized for keyword in keywords):
            matched.append(category)
    return matched


def infer_session_interpretation(session_record: Dict[str, Any], command_categories: Iterable[str], auth_success: Any = None) -> str:
    categories = list(dict.fromkeys(command_categories))
    auth_value = session_record.get("auth_success") if isinstance(session_record, dict) else auth_success
    try:
        auth_success_int = int(auth_value)
    except (TypeError, ValueError):
        auth_success_int = None

    if not categories and auth_success_int is None:
        return "Insufficient Evidence"

    if "credential_attack" in categories or auth_success_int == 0:
        if "persistence" in categories:
            return "Mixed/Unclassified"
        if "reconnaissance" in categories or "file_transfer" in categories:
            return "Mixed/Unclassified"
        return "Credential-attack behaviour"

    if "persistence" in categories:
        return "Persistence-related activity"
    if "file_transfer" in categories:
        return "Download or payload retrieval"
    if "privilege_escalation" in categories:
        return "Command execution / privilege escalation"
    if "reconnaissance" in categories:
        return "Reconnaissance"
    if len(categories) > 1:
        return "Mixed/Unclassified"
    if categories:
        return "Command execution"
    return "Insufficient Evidence"


def build_session_profiles(
    dec_df: pd.DataFrame,
    session_details: Dict[str, Dict[str, Any]],
    validation: Dict[str, Any],
) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
    rows: List[Dict[str, Any]] = []
    session_profile_records: List[Dict[str, Any]] = []

    for _, row in dec_df.iterrows():
        session_id = str(row.get("session_id", "")).strip()
        cluster_id = row.get("dec_cluster")
        session_record = session_details.get(session_id, {})
        commands = session_record.get("commands", [])
        if not isinstance(commands, list):
            commands = []

        command_categories: List[str] = []
        command_counts: Counter[str] = Counter()
        for command in commands:
            if not isinstance(command, str):
                continue
            command = command.strip()
            if not command:
                continue
            command_counts[command] += 1
            for category in classify_command(command):
                command_categories.append(category)

        category_counter: Counter[str] = Counter(command_categories)
        session_evidence = []
        if command_counts:
            session_evidence.append(f"Observed commands: {', '.join(sorted(command_counts)[:5])}")
        if category_counter:
            session_evidence.append(f"Command categories: {', '.join(sorted(category_counter))}")
        if session_record.get("auth_success") is not None:
            session_evidence.append(f"Authentication success flag: {session_record.get('auth_success')}")
        if session_record.get("session_duration") is not None:
            session_evidence.append(f"Session duration: {session_record.get('session_duration')}")

        interpretation = infer_session_interpretation(session_record, category_counter.keys(), session_record.get("auth_success"))
        evidence_text = "; ".join(session_evidence) if session_evidence else "No behavioural evidence available in session_data."

        profile_row = {
            "session_id": session_id,
            "dec_cluster": cluster_id,
            "evidence_count": len(command_categories),
            "observed_command_categories": ", ".join(sorted(dict.fromkeys(command_categories))) if command_categories else "",
            "observed_commands": ", ".join(sorted(command_counts.keys())[:10]) if command_counts else "",
            "behavioural_interpretation": interpretation,
            "evidence": evidence_text,
        }
        rows.append(profile_row)

        session_profile_records.append({
            "session_id": session_id,
            "cluster_id": cluster_id,
            "behavioural_interpretation": interpretation,
            "evidence": evidence_text,
            "session_record": session_record,
        })

    session_profiles_df = pd.DataFrame(rows)
    return session_profiles_df, session_profile_records


def calculate_cluster_distribution(dec_df: pd.DataFrame) -> pd.DataFrame:
    cluster_counts = dec_df["dec_cluster"].dropna().astype(int).value_counts().sort_index()
    total_valid = int(cluster_counts.sum())
    distribution = []
    for cluster_id, count in cluster_counts.items():
        pct = (count / total_valid * 100.0) if total_valid else 0.0
        distribution.append({
            "cluster_id": int(cluster_id),
            "session_count": int(count),
            "percentage_of_sessions": round(pct, 4),
        })
    return pd.DataFrame(distribution)


def compute_cluster_feature_statistics(dec_df: pd.DataFrame) -> pd.DataFrame:
    excluded = {"session_id", "src_ip", "src_port", "attack_cat", "label", "dec_cluster", "dec_confidence"}
    excluded |= {"cluster_0_prob", "cluster_1_prob", "cluster_2_prob"}
    numeric_columns = [
        col for col in dec_df.columns
        if col not in excluded and pd.api.types.is_numeric_dtype(dec_df[col])
    ]

    if not numeric_columns:
        return pd.DataFrame(columns=["cluster_id", "feature_name", "mean", "median", "std", "min", "max"]) 

    rows: List[Dict[str, Any]] = []
    for cluster_id, cluster_group in dec_df.groupby("dec_cluster", dropna=False, sort=True):
        cluster_key = "NaN" if pd.isna(cluster_id) else int(cluster_id)
        for feature in numeric_columns:
            series = cluster_group[feature].dropna()
            if series.empty:
                continue
            rows.append({
                "cluster_id": cluster_key,
                "feature_name": feature,
                "mean": round(float(series.mean()), 8) if not pd.isna(series.mean()) else None,
                "median": round(float(series.median()), 8) if not pd.isna(series.median()) else None,
                "std": round(float(series.std(ddof=1)), 8) if series.size > 1 and not pd.isna(series.std(ddof=1)) else None,
                "min": round(float(series.min()), 8) if not pd.isna(series.min()) else None,
                "max": round(float(series.max()), 8) if not pd.isna(series.max()) else None,
            })
    return pd.DataFrame(rows)


def build_distinguishing_features(dec_df: pd.DataFrame, top_n: int = 5) -> Dict[Any, str]:
    cluster_summary: Dict[Any, str] = {}
    numeric_columns = [
        col for col in dec_df.columns
        if col not in EXCLUDED_COLUMNS and pd.api.types.is_numeric_dtype(dec_df[col])
    ]
    if not numeric_columns:
        return cluster_summary

    overall_means = dec_df[numeric_columns].mean(numeric_only=True)
    for cluster_id, cluster_group in dec_df.groupby("dec_cluster", dropna=False, sort=True):
        if pd.isna(cluster_id):
            cluster_label = "NaN"
        else:
            cluster_label = int(cluster_id)
        cluster_means = cluster_group[numeric_columns].mean(numeric_only=True)
        differences = []
        for feature in numeric_columns:
            diff = abs(float(cluster_means.get(feature, 0.0)) - float(overall_means.get(feature, 0.0)))
            differences.append((diff, feature, float(cluster_means.get(feature, 0.0))))
        top = sorted(differences, reverse=True)[:top_n]
        key_text = "; ".join(f"{feature}={value:.3f}" for _, feature, value in top)
        cluster_summary[cluster_label] = key_text
    return cluster_summary


def aggregate_command_analysis(
    session_profiles_df: pd.DataFrame,
    dec_df: pd.DataFrame,
    session_details: Dict[str, Dict[str, Any]],
) -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []
    for _, row in dec_df.iterrows():
        cluster_id = row.get("dec_cluster")
        session_id = str(row.get("session_id", "")).strip()
        session_record = session_details.get(session_id, {})
        command_list = session_record.get("commands", [])
        if not isinstance(command_list, list):
            command_list = []
        categories_for_session: Counter[str] = Counter()
        for command in command_list:
            if not isinstance(command, str):
                continue
            for category in classify_command(command):
                categories_for_session[category] += 1
        for category_name, count in categories_for_session.items():
            rows.append({
                "cluster_id": int(cluster_id) if not pd.isna(cluster_id) else "NaN",
                "command_or_category": category_name,
                "frequency": int(count),
                "sessions_containing": 1,
            })

    if not rows:
        return pd.DataFrame(columns=["cluster_id", "command_or_category", "frequency", "sessions_containing", "percentage_of_sessions"]) 

    command_df = pd.DataFrame(rows)
    cluster_totals = command_df.groupby("cluster_id", dropna=False).size().to_dict()
    summary_rows = []
    for (cluster_id, command_category), group in command_df.groupby(["cluster_id", "command_or_category"], dropna=False):
        total_sessions = int(cluster_totals.get(cluster_id, 0))
        percent = 0.0 if total_sessions == 0 else (group["sessions_containing"].sum() / total_sessions) * 100.0
        summary_rows.append({
            "cluster_id": cluster_id,
            "command_or_category": command_category,
            "frequency": int(group["frequency"].sum()),
            "sessions_containing": int(group["sessions_containing"].sum()),
            "percentage_of_sessions": round(percent, 4),
        })
    return pd.DataFrame(summary_rows).sort_values(["cluster_id", "frequency"], ascending=[True, False])


def build_cluster_summary(
    dec_df: pd.DataFrame,
    distribution_df: pd.DataFrame,
    feature_stats_df: pd.DataFrame,
    session_profiles_df: pd.DataFrame,
    session_details: Dict[str, Dict[str, Any]],
    command_analysis_df: pd.DataFrame,
) -> pd.DataFrame:
    distinguishing_features = build_distinguishing_features(dec_df)
    summary_rows = []
    cluster_order = sorted(dec_df["dec_cluster"].dropna().astype(int).unique().tolist())
    for cluster_id in cluster_order:
        cluster_group = dec_df[dec_df["dec_cluster"] == cluster_id]
        session_count = len(cluster_group)
        percent = distribution_df.loc[distribution_df["cluster_id"] == cluster_id, "percentage_of_sessions"]
        pct = float(percent.iloc[0]) if not percent.empty else 0.0
        profile_cluster = session_profiles_df[session_profiles_df["dec_cluster"] == cluster_id]
        dominant_interpretation = "Insufficient Evidence"
        if not profile_cluster.empty:
            counts = profile_cluster["behavioural_interpretation"].value_counts()
            if not counts.empty:
                dominant_interpretation = str(counts.idxmax())

        top_categories = command_analysis_df[command_analysis_df["cluster_id"] == cluster_id].head(5)
        top_categories_str = "; ".join(
            f"{row['command_or_category']} ({row['frequency']})" for _, row in top_categories.iterrows()
        ) if not top_categories.empty else "No command category evidence"

        summary_rows.append({
            "cluster_id": int(cluster_id),
            "session_count": int(session_count),
            "percentage_of_sessions": round(float(pct), 4),
            "key_distinguishing_features": distinguishing_features.get(cluster_id, "N/A"),
            "dominant_behavioural_interpretation": dominant_interpretation,
            "top_command_categories": top_categories_str,
        })
    return pd.DataFrame(summary_rows)


def create_markdown_report(
    dec_df: pd.DataFrame,
    distribution_df: pd.DataFrame,
    cluster_summary_df: pd.DataFrame,
    feature_stats_df: pd.DataFrame,
    command_analysis_df: pd.DataFrame,
    session_profiles_df: pd.DataFrame,
    validation: Dict[str, Any],
    output_path: Path,
) -> None:
    lines: List[str] = []
    lines.append("# Behaviour Pattern Analysis Report")
    lines.append("")
    lines.append(f"- Total DEC sessions analysed: {len(dec_df)}")
    lines.append(f"- Valid cluster assignments: {int(dec_df['dec_cluster'].notna().sum())}")
    lines.append(f"- Missing/invalid cluster assignments: {int(dec_df['dec_cluster'].isna().sum())}")
    lines.append(f"- Duplicate DEC session IDs: {len(validation['duplicate_dec_sessions'])}")
    lines.append(f"- Unmatched DEC-to-mapping sessions: {len(validation['missing_in_mapping'])}")
    lines.append(f"- Sessions without session-details record: {len(validation['missing_in_session_details'])}")
    lines.append("")
    lines.append("## Cluster distribution")
    lines.append("")
    lines.append("| Cluster ID | Session Count | Percentage |")
    lines.append("|---|---:|---:|")
    for _, row in distribution_df.iterrows():
        lines.append(f"| {row['cluster_id']} | {int(row['session_count'])} | {float(row['percentage_of_sessions']):.2f}% |")
    lines.append("")

    lines.append("## Cluster characteristics")
    lines.append("")
    for _, row in cluster_summary_df.iterrows():
        lines.append(f"### Cluster {int(row['cluster_id'])}")
        lines.append(f"- Session count: {int(row['session_count'])}")
        lines.append(f"- Percentage of sessions: {float(row['percentage_of_sessions']):.2f}%")
        lines.append(f"- Dominant behavioural interpretation: {row['dominant_behavioural_interpretation']}")
        lines.append(f"- Key distinguishing features: {row['key_distinguishing_features']}")
        lines.append(f"- Top command categories: {row['top_command_categories']}")
        lines.append("")

    lines.append("## Command and activity evidence")
    lines.append("")
    if command_analysis_df.empty:
        lines.append("No command-category evidence was available.")
    else:
        for cluster_id in sorted(command_analysis_df["cluster_id"].dropna().astype(str).unique(), key=lambda value: int(float(value)) if value != "NaN" else 999):
            cluster_rows = command_analysis_df[command_analysis_df["cluster_id"] == cluster_id].head(5)
            lines.append(f"### Cluster {cluster_id}")
            for _, item in cluster_rows.iterrows():
                lines.append(
                    f"- {item['command_or_category']}: frequency={int(item['frequency'])}, "
                    f"sessions_containing={int(item['sessions_containing'])}, "
                    f"percentage_of_sessions={float(item['percentage_of_sessions']):.2f}%"
                )
            lines.append("")

    lines.append("## Evidence-backed behavioural interpretation")
    lines.append("")
    if session_profiles_df.empty:
        lines.append("No behavioural profiles were generated because the session data were empty or not usable.")
    else:
        for cluster_id in sorted(session_profiles_df["dec_cluster"].dropna().astype(int).unique().tolist()):
            subset = session_profiles_df[session_profiles_df["dec_cluster"] == cluster_id]
            interpretation_counts = subset["behavioural_interpretation"].value_counts()
            lines.append(f"### Cluster {cluster_id}")
            lines.append(f"- Most common interpretation: {interpretation_counts.idxmax()} ({interpretation_counts.iloc[0]} sessions)")
            for _, row in subset.head(3).iterrows():
                lines.append(f"- Session {row['session_id']}: {row['behavioural_interpretation']} — {row['evidence']}")
            lines.append("")

    lines.append("## Ambiguities and limitations")
    lines.append("")
    lines.append("- Cluster IDs are mathematical group labels, not attack labels.")
    lines.append("- Interpretation is limited to fields present in the repository data and to the evidence available in session metadata.")
    lines.append("- If a cluster lacks reliable command or auth evidence, it is reported as Mixed/Unclassified or Insufficient Evidence.")
    lines.append("- Some session records may be absent from session_details.json or mapping files; these are tracked explicitly in validation output.")
    lines.append("")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def generate_outputs(
    dec_df: pd.DataFrame,
    mapping_df: pd.DataFrame,
    model_input_df: pd.DataFrame,
    session_details: Dict[str, Dict[str, Any]],
    output_dir: Path,
) -> Dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    validation = validate_join_consistency(dec_df, mapping_df, session_details)
    distribution_df = calculate_cluster_distribution(dec_df)
    feature_stats_df = compute_cluster_feature_statistics(dec_df)
    session_profiles_df, session_profile_records = build_session_profiles(dec_df, session_details, validation)
    command_analysis_df = aggregate_command_analysis(session_profiles_df, dec_df, session_details)
    cluster_summary_df = build_cluster_summary(dec_df, distribution_df, feature_stats_df, session_profiles_df, session_details, command_analysis_df)

    distribution_df.to_csv(output_dir / "cluster_summary.csv", index=False)
    feature_stats_df.to_csv(output_dir / "cluster_feature_statistics.csv", index=False)
    command_analysis_df.to_csv(output_dir / "cluster_command_analysis.csv", index=False)
    session_profiles_df.to_csv(output_dir / "session_behaviour_profiles.csv", index=False)

    cluster_interpretation_report = output_dir / "cluster_interpretation_report.md"
    create_markdown_report(
        dec_df,
        distribution_df,
        cluster_summary_df,
        feature_stats_df,
        command_analysis_df,
        session_profiles_df,
        validation,
        cluster_interpretation_report,
    )

    cluster_payload = {
        "source_files": {
            "dec_results": "data/processed/dec_results.csv",
            "session_mapping": "data/processed/session_mapping.csv",
            "session_details": "data/parsed/session_details.json",
            "model_input": "data/processed/model_input.csv",
        },
        "validation": validation,
        "cluster_distribution": distribution_df.to_dict(orient="records"),
        "cluster_summary": cluster_summary_df.to_dict(orient="records"),
        "cluster_feature_statistics": feature_stats_df.to_dict(orient="records"),
        "cluster_command_analysis": command_analysis_df.to_dict(orient="records"),
        "session_behaviour_profiles": session_profiles_df.to_dict(orient="records"),
        "notes": {
            "cluster_ids_are_not_attack_labels": True,
            "feature_source_used": "DEC results file (contains session ID + cluster assignment + the same numerical feature columns used to cluster the sessions)",
        },
    }
    (output_dir / "cluster_analysis.json").write_text(json.dumps(cluster_payload, indent=2), encoding="utf-8")

    return {
        "validation": validation,
        "distribution": distribution_df,
        "feature_stats": feature_stats_df,
        "command_analysis": command_analysis_df,
        "cluster_summary": cluster_summary_df,
        "session_profiles": session_profiles_df,
        "cluster_analysis_json": output_dir / "cluster_analysis.json",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Behaviour Pattern Analysis for Cowrie DEC clusters")
    parser.add_argument("--dec-results", type=Path, default=None, help="Path to DEC output CSV")
    parser.add_argument("--mapping", type=Path, default=None, help="Path to session mapping CSV")
    parser.add_argument("--session-details", type=Path, default=None, help="Path to session_details.json")
    parser.add_argument("--model-input", type=Path, default=None, help="Path to model_input.csv")
    parser.add_argument("--output-dir", type=Path, default=None, help="Directory for generated reports")
    parser.add_argument("--verbose", action="store_true", help="Enable info logging")
    args = parser.parse_args()
    configure_logging(args.verbose)

    repo_root = repo_root_from_script()
    dec_result_path = args.dec_results or (repo_root / "data/processed/dec_results.csv")
    mapping_path = args.mapping or (repo_root / "data/processed/session_mapping.csv")
    session_details_path = args.session_details or (repo_root / "data/parsed/session_details.json")
    model_input_path = args.model_input or (repo_root / "data/processed/model_input.csv")
    output_dir = args.output_dir or (repo_root / "reports/behaviour_analysis")

    try:
        dec_df = load_dec_results(dec_result_path)
        mapping_df = load_session_mapping(mapping_path)
        session_details = load_session_details(session_details_path)
        model_input_df = load_model_input(model_input_path)

        if model_input_df.empty:
            raise AnalysisError("model_input.csv is empty")

        LOGGER.warning("Loaded DEC results, mapping, details, and model input successfully.")
        results = generate_outputs(dec_df, mapping_df, model_input_df, session_details, output_dir)
        LOGGER.warning("Generated behaviour analysis outputs in %s", output_dir)

        print(f"Processed {len(dec_df)} DEC sessions.")
        print(f"Output directory: {output_dir}")
        print(f"Cluster summary: {output_dir / 'cluster_summary.csv'}")
        print(f"Feature statistics: {output_dir / 'cluster_feature_statistics.csv'}")
        print(f"Command analysis: {output_dir / 'cluster_command_analysis.csv'}")
        print(f"Session behaviour profiles: {output_dir / 'session_behaviour_profiles.csv'}")
        print(f"Report: {output_dir / 'cluster_interpretation_report.md'}")
        print(f"Machine-readable JSON: {output_dir / 'cluster_analysis.json'}")

    except AnalysisError as exc:
        raise SystemExit(f"Error: {exc}")


if __name__ == "__main__":
    main()
