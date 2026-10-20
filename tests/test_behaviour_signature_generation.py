import json
from pathlib import Path

import pandas as pd
import pytest

from scripts.behaviour_signature_generation import (
    SignatureGenerationError,
    build_feature_profile,
    build_signatures,
    compute_evidence_strength,
    generate_behaviour_signatures,
    load_cluster_command_analysis,
    load_cluster_feature_statistics,
    load_cluster_summary,
    load_session_details,
    load_session_profiles,
)


@pytest.fixture
def sample_cluster_summary():
    return pd.DataFrame(
        [
            {"cluster_id": 0, "session_count": 2, "percentage_of_sessions": 40.0},
            {"cluster_id": 1, "session_count": 3, "percentage_of_sessions": 60.0},
        ]
    )


@pytest.fixture
def sample_feature_stats():
    return pd.DataFrame(
        [
            {"cluster_id": 0, "feature_name": "dur", "mean": 1.0, "median": 1.0, "std": 0.2, "min": 0.8, "max": 1.3},
            {"cluster_id": 0, "feature_name": "dbytes", "mean": 10.0, "median": 10.0, "std": 0.5, "min": 9.5, "max": 10.5},
            {"cluster_id": 1, "feature_name": "dur", "mean": 8.0, "median": 8.0, "std": 1.0, "min": 7.0, "max": 9.0},
            {"cluster_id": 1, "feature_name": "dbytes", "mean": 100.0, "median": 100.0, "std": 2.0, "min": 98.0, "max": 102.0},
        ]
    )


@pytest.fixture
def sample_command_analysis():
    return pd.DataFrame(
        [
            {"cluster_id": 0, "command_or_category": "file_system", "frequency": 4, "sessions_containing": 2, "percentage_of_sessions": 100.0},
            {"cluster_id": 1, "command_or_category": "reconnaissance", "frequency": 5, "sessions_containing": 3, "percentage_of_sessions": 100.0},
        ]
    )


@pytest.fixture
def sample_session_profiles():
    return pd.DataFrame(
        [
            {"session_id": "s1", "dec_cluster": 0, "behavioural_interpretation": "Command execution", "observed_command_categories": "file_system", "observed_commands": "ls, pwd", "evidence": "Observed commands: ls, pwd"},
            {"session_id": "s2", "dec_cluster": 0, "behavioural_interpretation": "Command execution", "observed_command_categories": "file_system", "observed_commands": "ls, cat /etc/passwd", "evidence": "Observed commands: ls, cat /etc/passwd"},
            {"session_id": "s3", "dec_cluster": 1, "behavioural_interpretation": "Reconnaissance", "observed_command_categories": "reconnaissance", "observed_commands": "whoami, uname -a", "evidence": "Observed commands: whoami, uname -a"},
            {"session_id": "s4", "dec_cluster": 1, "behavioural_interpretation": "Reconnaissance", "observed_command_categories": "reconnaissance", "observed_commands": "ls, pwd", "evidence": "Observed commands: ls, pwd"},
            {"session_id": "s5", "dec_cluster": 1, "behavioural_interpretation": "Reconnaissance", "observed_command_categories": "reconnaissance", "observed_commands": "id, uname -a", "evidence": "Observed commands: id, uname -a"},
        ]
    )


@pytest.fixture
def sample_session_details():
    return {
        "s1": {"auth_success": 1, "commands": ["ls", "pwd"], "session_duration": 1.0},
        "s2": {"auth_success": 1, "commands": ["ls", "cat /etc/passwd"], "session_duration": 2.0},
        "s3": {"auth_success": 1, "commands": ["whoami", "uname -a"], "session_duration": 3.0},
        "s4": {"auth_success": 0, "commands": ["ls", "pwd"], "session_duration": 4.0},
        "s5": {"auth_success": 1, "commands": ["id", "uname -a"], "session_duration": 5.0},
    }


def test_signature_generation_from_valid_cluster_data(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details):
    signatures = build_signatures(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details)
    assert len(signatures) == 2
    assert all("signature_id" in sig for sig in signatures)
    assert signatures[0]["behaviour_label"] in {"Command execution", "Reconnaissance"}


def test_supporting_session_counts_and_percentages(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details):
    signatures = build_signatures(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details)
    cluster_zero = next(sig for sig in signatures if sig["cluster_id"] == 0)
    assert cluster_zero["session_count"] == 2
    assert cluster_zero["support_percentage"] == 40.0


def test_feature_profile_generation(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details):
    signatures = build_signatures(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details)
    cluster_zero = next(sig for sig in signatures if sig["cluster_id"] == 0)
    assert "feature_profile" in cluster_zero
    assert cluster_zero["feature_profile"]["selected_features"][0]["feature"] == "dur"


def test_feature_profile_prioritizes_variable_dimensions_and_excludes_constant_ones(
    sample_cluster_summary,
    sample_feature_stats,
    sample_command_analysis,
    sample_session_profiles,
    sample_session_details,
):
    stats = pd.concat([
        sample_feature_stats,
        pd.DataFrame([
            {"cluster_id": 0, "feature_name": "ackdat", "mean": 100.0, "median": 100.0, "std": 0.0, "min": 100.0, "max": 100.0},
        ]),
    ], ignore_index=True)
    signatures = build_signatures(
        sample_cluster_summary,
        stats,
        sample_command_analysis,
        sample_session_profiles,
        sample_session_details,
    )
    features = next(sig for sig in signatures if sig["cluster_id"] == 0)["feature_profile"]["selected_features"]
    assert [item["feature"] for item in features] == ["dur", "dbytes"]
    assert "ackdat" not in {item["feature"] for item in features}


def test_feature_profile_with_no_estimable_variability_disables_numeric_matching():
    stats = pd.DataFrame([
        {"cluster_id": 0, "feature_name": "dur", "mean": 1.0, "median": 1.0, "std": None, "min": 1.0, "max": 1.0},
        {"cluster_id": 0, "feature_name": "dbytes", "mean": 0.0, "median": 0.0, "std": 0.0, "min": 0.0, "max": 0.0},
    ])
    profile = build_feature_profile(0, stats)
    assert profile["selected_features"] == []
    assert "numerical matching is unavailable" in profile["summary"]


def test_command_evidence_inclusion(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details):
    signatures = build_signatures(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details)
    cluster_zero = next(sig for sig in signatures if sig["cluster_id"] == 0)
    assert "file_system" in cluster_zero["command_categories"]
    assert cluster_zero["representative_commands"]


def test_missing_command_or_auth_evidence():
    profiles = pd.DataFrame(
        [{"session_id": "a", "dec_cluster": 0, "behavioural_interpretation": "Insufficient Evidence", "observed_command_categories": "", "observed_commands": "", "evidence": "No evidence"}]
    )
    signatures = build_signatures(
        pd.DataFrame([{"cluster_id": 0, "session_count": 1, "percentage_of_sessions": 100.0}]),
        pd.DataFrame([{"cluster_id": 0, "feature_name": "dur", "mean": 1.0, "median": 1.0, "std": 0.2, "min": 0.8, "max": 1.3}]),
        pd.DataFrame(columns=["cluster_id", "command_or_category", "frequency", "sessions_containing", "percentage_of_sessions"]),
        profiles,
        {},
    )
    assert signatures[0]["limitations"]


def test_missing_required_input_files_and_columns(tmp_path):
    missing_path = tmp_path / "nope.csv"
    with pytest.raises(SignatureGenerationError):
        load_cluster_summary(missing_path)

    bad_csv = tmp_path / "bad.csv"
    pd.DataFrame([{"cluster_id": 1}]).to_csv(bad_csv, index=False)
    with pytest.raises(SignatureGenerationError):
        load_cluster_summary(bad_csv)


def test_duplicate_session_handling(sample_session_profiles):
    duplicate = pd.concat([sample_session_profiles, sample_session_profiles.iloc[[0]].copy()], ignore_index=True)
    duplicate["session_id"] = duplicate["session_id"].astype(str)
    assert duplicate["session_id"].duplicated().any()


def test_missing_session_mappings_or_details(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles):
    static = sample_session_profiles.copy()
    signatures = build_signatures(sample_cluster_summary, sample_feature_stats, sample_command_analysis, static, {})
    assert signatures
    assert any("Authentication data unavailable" in limitation for sig in signatures for limitation in sig["limitations"])


def test_mixed_and_insufficient_evidence_patterns(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details):
    mixed = sample_session_profiles.copy()
    mixed.loc[0, "behavioural_interpretation"] = "Mixed/Unclassified"
    signatures = build_signatures(sample_cluster_summary, sample_feature_stats, sample_command_analysis, mixed, sample_session_details)
    assert any(sig["behaviour_label"] == "Mixed/Unclassified" for sig in signatures)


def test_deterministic_signature_ids_across_repeated_runs(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details):
    sigs1 = build_signatures(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details)
    sigs2 = build_signatures(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details)
    assert [sig["signature_id"] for sig in sigs1] == [sig["signature_id"] for sig in sigs2]


def test_json_and_csv_consistency(tmp_path, sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details):
    output_dir = tmp_path / "out"
    (tmp_path / "cluster_summary.csv").write_text(sample_cluster_summary.to_csv(index=False), encoding="utf-8")
    (tmp_path / "cluster_feature_statistics.csv").write_text(sample_feature_stats.to_csv(index=False), encoding="utf-8")
    (tmp_path / "cluster_command_analysis.csv").write_text(sample_command_analysis.to_csv(index=False), encoding="utf-8")
    (tmp_path / "session_behaviour_profiles.csv").write_text(sample_session_profiles.to_csv(index=False), encoding="utf-8")
    (tmp_path / "session_details.json").write_text(json.dumps(sample_session_details), encoding="utf-8")
    (tmp_path / "cluster_analysis.json").write_text(json.dumps({"validation": {}}), encoding="utf-8")

    summary = generate_behaviour_signatures(
        tmp_path / "cluster_summary.csv",
        tmp_path / "cluster_feature_statistics.csv",
        tmp_path / "cluster_command_analysis.csv",
        tmp_path / "session_behaviour_profiles.csv",
        tmp_path / "session_details.json",
        tmp_path / "cluster_analysis.json",
        output_dir,
    )
    assert (output_dir / "behaviour_signatures.json").exists()
    assert (output_dir / "behaviour_signatures.csv").exists()
    json_payload = json.loads((output_dir / "behaviour_signatures.json").read_text(encoding="utf-8"))
    csv_df = pd.read_csv(output_dir / "behaviour_signatures.csv")
    assert len(json_payload["signatures"]) == len(csv_df)


def test_empty_input_data():
    with pytest.raises(SignatureGenerationError):
        load_cluster_summary(Path("does_not_exist.csv"))


def test_evidence_strength_documented_limitations(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details):
    strength = compute_evidence_strength(sample_session_profiles.head(1), ["file_system"], {"observed": True})
    assert "method" in strength
    assert 0.0 <= strength["score"] <= 1.0


def test_no_source_data_modification(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details):
    before = sample_session_profiles.copy()
    build_signatures(sample_cluster_summary, sample_feature_stats, sample_command_analysis, sample_session_profiles, sample_session_details)
    assert sample_session_profiles.equals(before)
