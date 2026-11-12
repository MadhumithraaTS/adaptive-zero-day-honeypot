"""Task 19B Phase 1: verify the frozen novelty baseline BEFORE any test data exists or is accessed (read-only).

    ml\\cowrie_dec_integration_skeleton\\.venv-dec-smoke\\Scripts\\python.exe reports\\cowrie_sealed_exfiltration_evaluation_20261111\\freeze_verify.py

Checks hashes against the Task 18 / Task 19A records, the 7 inputs and order, the saved training-only medians and scaler,
the three thresholds, the inference batch size (256), and the primary/secondary designation. Nothing is repaired.
Writes evidence/freeze_verification.json (later merged into run_manifest.json). Exit 1 if any check fails.
"""
import hashlib
import json
import sys
from pathlib import Path

import joblib
import numpy as np

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
NCFG = REPO / "configs" / "cowrie_novelty_baseline_v1.json"
MODELS = REPO / "models" / "cowrie_novelty_baseline_20261111"
AUDIT = REPO / "reports" / "cowrie_novelty_freeze_audit_20261111"
T18 = REPO / "reports" / "cowrie_novelty_baseline_20261111"
EXPECTED = {
    "novelty_config_sha256": "bd3a399ede44d17d31eca47d8c5aa506c2b5423c58c22db066d7c6af158ef6f3",
    "clustering_v1_1_0_sha256": "18a4ab2be8d0d71148212e3306c9cf318075eac63c999e24cefb39564c84d299",
    "clustering_v1_0_0_sha256": "8ae17612eabbbc46240aa1011aff8d6e3617df85380b3daa523201675fc3c288",
    "features": ["session_duration_s", "input_line_count", "shell_operator_lines", "time_to_first_input_s",
                 "inter_input_mean_s", "inter_input_std_s", "tty_output_bytes"],
    "thresholds": {"A_ae_reconstruction": 1.171445, "B_latent_knn": 0.729190, "C_input_knn": 1.692104},
    "predict_batch_size": 256,
}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


ncfg = json.loads(NCFG.read_text(encoding="utf-8"))
audit = json.loads((AUDIT / "evidence" / "novelty_audit.json").read_text(encoding="utf-8"))
art = json.loads((MODELS / "artifact_sha256.json").read_text())
sums = {}
for line in (AUDIT / "SHA256SUMS").read_text().splitlines():
    h, p = line.split(maxsplit=1)
    sums[p.lstrip("*")] = h
scaler, medians = joblib.load(MODELS / "scaler.joblib"), joblib.load(MODELS / "medians.joblib")
status_section = (T18 / "report.md").read_text(encoding="utf-8")
c = {
    "novelty_config_hash": sha(NCFG) == EXPECTED["novelty_config_sha256"],
    "novelty_config_hash_matches_task19a_SHA256SUMS": sums.get("../../configs/cowrie_novelty_baseline_v1.json") == sha(NCFG),
    "clustering_configs_unchanged": sha(REPO / "configs" / "model_features_v2_frozen_v1.1.0.json") == EXPECTED["clustering_v1_1_0_sha256"]
                                    and sha(REPO / "configs" / "model_features_v2_frozen.json") == EXPECTED["clustering_v1_0_0_sha256"],
    "novelty_config_records_v1_1_0": ncfg["relation_to_clustering_config"]["sha256"] == EXPECTED["clustering_v1_1_0_sha256"],
    "model_files_match_artifact_sha256": all(sha(MODELS / k) == v for k, v in art.items()),
    "model_files_match_config_artefact_sha256": all(sha(MODELS / k) == v for k, v in ncfg["artefact_sha256"].items()),
    "task19a_audit_all_pass": audit["all_pass"] is True,
    "features_exact_order": ncfg["features"] == EXPECTED["features"] and list(scaler.feature_names_in_) == EXPECTED["features"]
                            and list(medians) == EXPECTED["features"],
    "medians_equal_audited_training_medians": all(np.isclose(medians[f], ncfg["preprocessing"]["medians"][f]) for f in EXPECTED["features"])
                                              and all(audit["training_only_parameters"]["medians_equal_logged_in_train_medians"].values()),
    "scaler_training_only": audit["training_only_parameters"]["scaler_mean_equals_train_mean"]
                            and audit["training_only_parameters"]["scaler_scale_equals_train_population_sd"] and int(scaler.n_samples_seen_) == 1500,
    "scaler_params_equal_config": bool(np.allclose(scaler.mean_, [ncfg["preprocessing"]["scaler_mean"][f] for f in EXPECTED["features"]], atol=1e-6)
                                       and np.allclose(scaler.scale_, [ncfg["preprocessing"]["scaler_scale"][f] for f in EXPECTED["features"]], atol=1e-6)),
    "no_missingness_indicators": ncfg["preprocessing"]["missingness_indicators"] is False and scaler.n_features_in_ == 7,
    "thresholds_equal_expected": all(abs(ncfg["thresholds_seed42"][m] - t) < 5e-7 for m, t in EXPECTED["thresholds"].items()),
    "predict_batch_size_256": ncfg["autoencoder"]["predict_batch_size"] == EXPECTED["predict_batch_size"],
    "k_nn_5": ncfg["k_nn"] == 5,
    "method_C_primary_A_B_secondary_documented": "**Method C** (input-space kNN distance) is the **primary experimental candidate**" in status_section
                                                 and "**Methods A** (AE reconstruction error) and **B** (latent kNN distance) are **secondary comparisons**" in status_section,
}
out = {
    "checks": c, "all_pass": all(c.values()),
    "pre_registration": {"primary_method": "C_input_knn", "secondary_methods": ["A_ae_reconstruction", "B_latent_knn"],
                         "source": "reports/cowrie_novelty_baseline_20261111/report.md status section (Task 19A); the frozen novelty "
                                   "configuration has no primary field and is not modified",
                         "thresholds": EXPECTED["thresholds"], "inference_batch_size": 256,
                         "validation_reference_flag_rates": {m: v["validation_flag_rate"] for m, v in
                                                             json.loads((T18 / "outputs" / "results.json").read_text())["methods"].items()}},
    "hashes": {"configs/cowrie_novelty_baseline_v1.json": sha(NCFG),
               "configs/model_features_v2_frozen_v1.1.0.json": sha(REPO / "configs" / "model_features_v2_frozen_v1.1.0.json"),
               "configs/model_features_v2_frozen.json": sha(REPO / "configs" / "model_features_v2_frozen.json"),
               "configs/feature_spec_v2.json": sha(REPO / "configs" / "feature_spec_v2.json"),
               "configs/feature_spec_v2_draft4.json": sha(REPO / "configs" / "feature_spec_v2_draft4.json"),
               "scripts/extract_features_v2.py": sha(REPO / "scripts" / "extract_features_v2.py"),
               "dataset_builder/generate_labelled_traffic.py": sha(REPO / "dataset_builder" / "generate_labelled_traffic.py"),
               "dataset_builder/profiles_v2_revised.json": sha(REPO / "dataset_builder" / "profiles_v2_revised.json"),
               **{f"models/cowrie_novelty_baseline_20261111/{k}": sha(MODELS / k) for k in sorted(art)}},
    "versions": {"novelty_config": ncfg["config_version"], "clustering_config_used_by_baseline": "1.1.0",
                 "feature_spec_extractor_contract": "2.0.0-draft.3", "feature_spec_eligibility": "2.0.0-draft.4", "generator": "2.1"},
}
(HERE / "evidence").mkdir(exist_ok=True)
(HERE / "evidence" / "freeze_verification.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"all_pass": out["all_pass"], "checks": c}, indent=1))
sys.exit(0 if out["all_pass"] else 1)
