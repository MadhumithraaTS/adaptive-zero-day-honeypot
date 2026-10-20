import csv
import json
from pathlib import Path

import pandas as pd
import pytest

from scripts.prepare_fresh_evaluation import (
    FreshEvaluationError,
    prepare_fresh_evaluation,
)


DEC_FEATURES = ["dur", "spkts", "dpkts"]


def _write_inputs(tmp_path: Path, snapshot_ids=("old", "new-a", "new-b")):
    baseline_path = tmp_path / "baseline.json"
    snapshot_path = tmp_path / "snapshot.json"
    features_path = tmp_path / "snapshot_features.csv"
    config_path = tmp_path / "dec_config.json"

    baseline_path.write_text(
        json.dumps({"old": {"features": {"session_id": "old"}}}),
        encoding="utf-8",
    )
    snapshot_path.write_text(
        json.dumps({
            session_id: {"features": {"session_id": session_id}}
            for session_id in snapshot_ids
        }),
        encoding="utf-8",
    )
    pd.DataFrame([
        {
            "session_id": session_id,
            "dur": float(index + 1),
            "proto": "ssh",
            "spkts": index + 2,
            "dpkts": index + 3,
            "label": 0,
        }
        for index, session_id in enumerate(snapshot_ids)
    ], columns=["session_id", "dur", "proto", "spkts", "dpkts", "label"]).to_csv(
        features_path,
        index=False,
    )
    config_path.write_text(
        json.dumps({"features": DEC_FEATURES}),
        encoding="utf-8",
    )
    return baseline_path, snapshot_path, features_path, config_path


def _run_prepare(tmp_path: Path, paths):
    baseline, snapshot, features, config = paths
    return prepare_fresh_evaluation(
        baseline,
        snapshot,
        features,
        config,
        tmp_path / "fresh" / "session_details.json",
        tmp_path / "fresh" / "features.csv",
        tmp_path / "fresh" / "summary.json",
    )


def test_excludes_historical_and_selects_new_sessions(tmp_path):
    summary = _run_prepare(tmp_path, _write_inputs(tmp_path))

    details = json.loads(Path(summary["output_paths"]["session_details_json"]).read_text(encoding="utf-8"))
    selected = pd.read_csv(summary["output_paths"]["features_csv"], dtype={"session_id": "string"})

    assert set(details) == {"new-a", "new-b"}
    assert selected["session_id"].tolist() == ["new-a", "new-b"]
    assert summary["baseline_session_count"] == 1
    assert summary["snapshot_session_count"] == 3
    assert summary["new_session_count"] == 2
    assert summary["excluded_historical_session_count"] == 1


def test_output_ids_match_and_feature_columns_keep_original_order(tmp_path):
    summary = _run_prepare(tmp_path, _write_inputs(tmp_path))

    details = json.loads(Path(summary["output_paths"]["session_details_json"]).read_text(encoding="utf-8"))
    feature_frame = pd.read_csv(summary["output_paths"]["features_csv"])
    assert set(details) == set(feature_frame["session_id"].astype(str))
    assert list(feature_frame.columns) == [
        "session_id", "dur", "proto", "spkts", "dpkts", "label"
    ]
    assert [column for column in feature_frame.columns if column in DEC_FEATURES] == DEC_FEATURES


def test_summary_is_written_with_output_paths(tmp_path):
    summary = _run_prepare(tmp_path, _write_inputs(tmp_path))
    saved = json.loads(Path(summary["output_paths"]["summary_json"]).read_text(encoding="utf-8"))
    assert saved == summary
    assert saved["status"] == "success"


def test_rejects_duplicate_feature_session_ids(tmp_path):
    paths = _write_inputs(tmp_path)
    features_path = paths[2]
    frame = pd.read_csv(features_path)
    pd.concat([frame, frame.iloc[[0]]], ignore_index=True).to_csv(features_path, index=False)

    with pytest.raises(FreshEvaluationError, match="duplicate session IDs"):
        _run_prepare(tmp_path, paths)


def test_rejects_mismatched_ids_between_snapshot_files(tmp_path):
    paths = _write_inputs(tmp_path)
    baseline, snapshot, features, config = paths
    frame = pd.read_csv(features)
    frame.loc[frame["session_id"] == "new-b", "session_id"] = "not-in-details"
    frame.to_csv(features, index=False)

    with pytest.raises(FreshEvaluationError, match="session IDs differ"):
        prepare_fresh_evaluation(
            baseline, snapshot, features, config,
            tmp_path / "out-details.json", tmp_path / "out-features.csv",
            tmp_path / "out-summary.json",
        )


@pytest.mark.parametrize(
    ("column", "value", "message"),
    [
        ("dpkts", None, "missing, non-numeric, or non-finite"),
        ("spkts", "not-a-number", "missing, non-numeric, or non-finite"),
        ("dur", float("inf"), "missing, non-numeric, or non-finite"),
    ],
)
def test_rejects_missing_non_numeric_and_non_finite_required_values(
    tmp_path, column, value, message
):
    paths = _write_inputs(tmp_path)
    frame = pd.read_csv(paths[2])
    frame[column] = frame[column].astype(object)
    frame.loc[frame["session_id"] == "new-a", column] = value
    frame.to_csv(paths[2], index=False)

    with pytest.raises(FreshEvaluationError, match=message):
        _run_prepare(tmp_path, paths)


def test_rejects_missing_required_dec_feature(tmp_path):
    paths = _write_inputs(tmp_path)
    pd.read_csv(paths[2]).drop(columns=["dpkts"]).to_csv(paths[2], index=False)

    with pytest.raises(FreshEvaluationError, match="missing DEC features"):
        _run_prepare(tmp_path, paths)


def test_rejects_empty_fresh_selection(tmp_path):
    paths = _write_inputs(tmp_path, snapshot_ids=("old",))
    with pytest.raises(FreshEvaluationError, match="No fresh sessions"):
        _run_prepare(tmp_path, paths)


def test_rejects_duplicate_session_ids_in_details_json(tmp_path):
    paths = _write_inputs(tmp_path)
    snapshot_path = paths[1]
    snapshot_path.write_text(
        '{"old": {}, "old": {}, "new-a": {}, "new-b": {}}',
        encoding="utf-8",
    )
    with pytest.raises(FreshEvaluationError, match="Duplicate JSON object key"):
        _run_prepare(tmp_path, paths)


def test_refuses_existing_output_paths(tmp_path):
    paths = _write_inputs(tmp_path)
    existing_output = tmp_path / "protected.json"
    existing_output.write_text("keep", encoding="utf-8")
    baseline, snapshot, features, config = paths
    with pytest.raises(FreshEvaluationError, match="Refusing to overwrite"):
        prepare_fresh_evaluation(
            baseline, snapshot, features, config,
            existing_output, tmp_path / "out-features.csv",
            tmp_path / "out-summary.json",
        )
    assert existing_output.read_text(encoding="utf-8") == "keep"
