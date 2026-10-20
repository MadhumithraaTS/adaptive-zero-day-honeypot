#!/usr/bin/env python3
"""Select newly observed Cowrie sessions for isolated DEC evaluation."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pandas as pd


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BASELINE = REPO_ROOT / "data/parsed/session_details.json"
DEFAULT_DEC_CONFIG = (
    REPO_ROOT
    / "ml/cowrie_dec_integration_skeleton/ml/cowrie_dec/artifacts/config.json"
)


class FreshEvaluationError(ValueError):
    """Raised when fresh-evaluation inputs or destinations are invalid."""


def _reject_duplicate_json_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FreshEvaluationError(f"Duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_non_finite_json_constant(value: str) -> None:
    raise FreshEvaluationError(f"Non-standard non-finite JSON value: {value}")


def _read_session_details(path: Path, description: str) -> Dict[str, Dict[str, Any]]:
    if not path.is_file():
        raise FreshEvaluationError(f"{description} JSON file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(
                handle,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_non_finite_json_constant,
            )
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise FreshEvaluationError(f"Malformed {description} JSON at {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise FreshEvaluationError(
            f"{description} JSON must be an object keyed by session ID: {path}"
        )

    records: Dict[str, Dict[str, Any]] = {}
    for raw_session_id, record in payload.items():
        session_id = str(raw_session_id)
        if not session_id or session_id != session_id.strip():
            raise FreshEvaluationError(
                f"{description} contains an empty or whitespace-padded session ID."
            )
        if not isinstance(record, dict):
            raise FreshEvaluationError(
                f"{description} record for session {session_id!r} must be an object."
            )
        nested_features = record.get("features")
        if isinstance(nested_features, dict) and nested_features.get("session_id") is not None:
            nested_id = str(nested_features["session_id"])
            if nested_id != session_id:
                raise FreshEvaluationError(
                    f"{description} key {session_id!r} does not match nested "
                    f"features.session_id {nested_id!r}."
                )
        records[session_id] = record
    return records


def _load_dec_features(config_path: Path) -> List[str]:
    if not config_path.is_file():
        raise FreshEvaluationError(f"DEC config file not found: {config_path}")
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise FreshEvaluationError(f"Malformed DEC config JSON at {config_path}: {exc}") from exc

    features = config.get("features") if isinstance(config, dict) else None
    if not isinstance(features, list) or not features:
        raise FreshEvaluationError(
            f"DEC config must define a non-empty 'features' list: {config_path}"
        )
    if any(not isinstance(feature, str) or not feature.strip() for feature in features):
        raise FreshEvaluationError("DEC config contains an invalid feature name.")
    if len(set(features)) != len(features):
        raise FreshEvaluationError("DEC config contains duplicate feature names.")
    return features


def _read_feature_csv(path: Path, required_features: List[str]) -> pd.DataFrame:
    if not path.is_file():
        raise FreshEvaluationError(f"Extracted feature CSV not found: {path}")
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            header = next(csv.reader(handle), None)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise FreshEvaluationError(f"Could not read feature CSV header at {path}: {exc}") from exc

    if not header:
        raise FreshEvaluationError(f"Extracted feature CSV is empty: {path}")
    if len(header) != len(set(header)):
        raise FreshEvaluationError(f"Feature CSV contains duplicate column names: {path}")
    if "session_id" not in header:
        raise FreshEvaluationError(f"Feature CSV is missing required column 'session_id': {path}")

    missing = [feature for feature in required_features if feature not in header]
    if missing:
        raise FreshEvaluationError(f"Feature CSV is missing DEC features: {missing}")
    present_dec_order = [column for column in header if column in set(required_features)]
    if present_dec_order != required_features:
        raise FreshEvaluationError(
            "Feature CSV DEC feature order does not match the saved DEC config. "
            f"Expected {required_features}; found {present_dec_order}."
        )

    try:
        frame = pd.read_csv(path, dtype={"session_id": "string"})
    except (
        OSError,
        UnicodeDecodeError,
        pd.errors.EmptyDataError,
        pd.errors.ParserError,
    ) as exc:
        raise FreshEvaluationError(f"Could not read feature CSV at {path}: {exc}") from exc

    if frame.empty:
        raise FreshEvaluationError(f"Feature CSV contains no session rows: {path}")
    session_ids = frame["session_id"]
    if session_ids.isna().any() or (session_ids.str.strip() == "").any():
        raise FreshEvaluationError("Feature CSV contains an empty session ID.")
    padded_ids = session_ids != session_ids.str.strip()
    if padded_ids.any():
        raise FreshEvaluationError("Feature CSV contains whitespace-padded session IDs.")
    duplicates = session_ids[session_ids.duplicated(keep=False)].unique().tolist()
    if duplicates:
        raise FreshEvaluationError(
            f"Feature CSV contains duplicate session IDs: {duplicates[:5]}"
        )

    for feature in required_features:
        numeric = pd.to_numeric(frame[feature], errors="coerce")
        invalid = numeric.isna()
        if not invalid.any():
            invalid = ~numeric.map(lambda value: math.isfinite(float(value)))
        if invalid.any():
            row_index = int(invalid[invalid].index[0])
            session_id = str(frame.loc[row_index, "session_id"])
            raise FreshEvaluationError(
                f"DEC feature {feature!r} has a missing, non-numeric, or non-finite "
                f"value for session {session_id!r}."
            )
    return frame


def _check_output_paths(
    output_paths: List[Path],
    input_paths: List[Path],
) -> List[Path]:
    resolved_outputs = [path.resolve() for path in output_paths]
    if len(set(resolved_outputs)) != len(resolved_outputs):
        raise FreshEvaluationError("Output file paths must be distinct.")

    protected_paths = {path.resolve() for path in input_paths}
    collisions = [str(path) for path in resolved_outputs if path in protected_paths]
    if collisions:
        raise FreshEvaluationError(
            "Output paths must not overwrite baseline, source, or DEC config files: "
            + ", ".join(collisions)
        )
    existing = [str(path) for path in resolved_outputs if path.exists()]
    if existing:
        raise FreshEvaluationError(
            "Refusing to overwrite existing output file(s): " + ", ".join(existing)
        )
    return resolved_outputs


def prepare_fresh_evaluation(
    baseline_session_details: Path,
    snapshot_session_details: Path,
    snapshot_features: Path,
    dec_config: Path,
    output_session_details: Path,
    output_features: Path,
    summary_output: Path,
) -> Dict[str, Any]:
    """Filter a parsed snapshot to sessions not present in the preserved baseline."""
    inputs = [
        baseline_session_details,
        snapshot_session_details,
        snapshot_features,
        dec_config,
    ]
    outputs = _check_output_paths(
        [output_session_details, output_features, summary_output],
        inputs,
    )
    output_details_path, output_features_path, summary_path = outputs

    baseline = _read_session_details(baseline_session_details, "Baseline")
    snapshot = _read_session_details(snapshot_session_details, "Snapshot")
    dec_features = _load_dec_features(dec_config)
    feature_frame = _read_feature_csv(snapshot_features, dec_features)

    details_ids = set(snapshot)
    feature_ids = set(feature_frame["session_id"].astype(str))
    if details_ids != feature_ids:
        only_details = sorted(details_ids - feature_ids)
        only_features = sorted(feature_ids - details_ids)
        raise FreshEvaluationError(
            "Snapshot session IDs differ between details JSON and feature CSV. "
            f"Only in details: {only_details[:5]}; only in features: {only_features[:5]}."
        )

    baseline_ids = set(baseline)
    fresh_ids = details_ids - baseline_ids
    if not fresh_ids:
        raise FreshEvaluationError(
            "No fresh sessions were found; every snapshot session is already in the baseline."
        )

    selected_details = {
        session_id: record
        for session_id, record in snapshot.items()
        if session_id in fresh_ids
    }
    selected_features = feature_frame[
        feature_frame["session_id"].astype(str).isin(fresh_ids)
    ].copy()
    selected_features = selected_features.reset_index(drop=True)

    if set(selected_details) != set(selected_features["session_id"].astype(str)):
        raise FreshEvaluationError(
            "Internal validation failed: selected details and feature session IDs differ."
        )

    summary = {
        "schema_version": "1.0",
        "status": "success",
        "baseline_session_count": len(baseline_ids),
        "snapshot_session_count": len(details_ids),
        "new_session_count": len(fresh_ids),
        "excluded_historical_session_count": len(details_ids & baseline_ids),
        "required_dec_features": dec_features,
        "output_paths": {
            "session_details_json": str(output_details_path),
            "features_csv": str(output_features_path),
            "summary_json": str(summary_path),
        },
    }

    for path in outputs:
        path.parent.mkdir(parents=True, exist_ok=True)

    temporary_paths: List[Path] = []
    try:
        for destination in outputs:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{destination.name}.",
                suffix=".tmp",
                dir=destination.parent,
            )
            os.close(descriptor)
            temporary_paths.append(Path(temporary_name))

        temporary_details, temporary_features, temporary_summary = temporary_paths
        temporary_details.write_text(
            json.dumps(selected_details, indent=2, ensure_ascii=False, allow_nan=False)
            + "\n",
            encoding="utf-8",
        )
        selected_features.to_csv(temporary_features, index=False)
        temporary_summary.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        for temporary, destination in zip(temporary_paths, outputs):
            temporary.replace(destination)
    finally:
        for temporary in temporary_paths:
            if temporary.exists():
                temporary.unlink()

    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Filter a Cowrie snapshot to sessions absent from the preserved baseline."
    )
    parser.add_argument(
        "--baseline-session-details",
        type=Path,
        default=DEFAULT_BASELINE,
        help="Existing baseline session-details JSON (read-only).",
    )
    parser.add_argument(
        "--snapshot-session-details",
        type=Path,
        required=True,
        help="Parsed session-details JSON for the new Cowrie log snapshot.",
    )
    parser.add_argument(
        "--snapshot-features",
        type=Path,
        required=True,
        help="Extracted feature CSV corresponding to the same snapshot.",
    )
    parser.add_argument(
        "--dec-config",
        type=Path,
        default=DEFAULT_DEC_CONFIG,
        help="Saved DEC config.json used to validate required feature names and order.",
    )
    parser.add_argument(
        "--output-session-details",
        type=Path,
        required=True,
        help="New output path for filtered session-details JSON; must not already exist.",
    )
    parser.add_argument(
        "--output-features",
        type=Path,
        required=True,
        help="New output path for filtered feature CSV; must not already exist.",
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        required=True,
        help="New output path for the run summary JSON; must not already exist.",
    )
    args = parser.parse_args()

    try:
        summary = prepare_fresh_evaluation(
            args.baseline_session_details,
            args.snapshot_session_details,
            args.snapshot_features,
            args.dec_config,
            args.output_session_details,
            args.output_features,
            args.summary_output,
        )
    except (FreshEvaluationError, OSError) as exc:
        parser.exit(2, f"Error: {exc}\n")

    print("Fresh-session evaluation inputs prepared.")
    print(f"Baseline sessions: {summary['baseline_session_count']}")
    print(f"Snapshot sessions: {summary['snapshot_session_count']}")
    print(f"New sessions: {summary['new_session_count']}")
    print(f"Excluded historical sessions: {summary['excluded_historical_session_count']}")
    print(f"Summary: {summary['output_paths']['summary_json']}")


if __name__ == "__main__":
    main()
