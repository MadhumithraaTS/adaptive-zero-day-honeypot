"""Task 22: indicator_implementation_status.csv from the implemented catalogue, unit tests and validation rates.

    .venv/Scripts/python.exe reports/behavioural_evidence_framework_implementation_20261111/make_status.py
"""
import json
import re
import sys
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
from behavioural_evidence.catalogue import INDICATORS, INTERPRETATIONS  # noqa: E402

design = pd.read_csv(REPO / "reports" / "behavioural_evidence_framework_design_20261111" / "indicator_catalogue.csv").set_index("indicator_id")
rates = pd.read_csv(HERE / "evidence" / "indicator_rates_by_category.csv")
tests = (REPO / "tests" / "test_behavioural_evidence.py").read_text(encoding="utf-8")
CATS = ["benign", "botnet", "brute_force", "lateral_movement", "privilege_escalation", "reconnaissance"]
MATCHER = {"AUTH-0": "engine.evaluate (login.failed events)", "AUTH-1": "engine._auth (source window)", "AUTH-2": "engine._auth (success after window)",
           "SHELL-1": "engine.evaluate", "DISC-1": "indicators.discovery", "PRIV-1": "indicators.priv", "PRIV-2": "indicators.priv",
           "CRED-1": "indicators.cred", "FILE-1": "indicators.files", "FILE-2": "indicators.files", "XFER-1": "indicators.transfer",
           "XFER-1-OK": "engine.evaluate (file_download event)", "XFER-2": "indicators.transfer", "XFER-2-OK": "engine.evaluate (file_upload event)",
           "EXEC-1": "indicators.exec_after_download", "STAGE-1": "indicators.stage_evade_persist", "EVADE-1": "indicators.stage_evade_persist",
           "PERS-0": "indicators.stage_evade_persist", "PERS-1": "indicators.stage_evade_persist", "NET-0": "indicators.network",
           "NET-1": "indicators.network", "CHAIN-1": "indicators.composition", "REDIR-1": "indicators.composition",
           "EMU-1": "engine.evaluate (command.failed events)", "ART-1": "engine.evaluate + calibration.SensorCalibration",
           "SEQ-1": "engine.evaluate (reference_sequences)", "TIME-0": "engine.evaluate + calibration (unusual-gap caveat)"}
rows = []
for k, d in INDICATORS.items():
    tv = rates[(rates.split == "validation") & (rates.indicator == k)].iloc[0]
    tt = rates[(rates.split == "train") & (rates.indicator == k)].iloc[0]
    n_tests = len(re.findall(r'["\']' + re.escape(k) + r'["\']', tests))
    used_by = [r.name for r in INTERPRETATIONS if k in r.all_of + r.any_of + r.supporting]
    status = "implemented; validated on V2 (fires)" if tv.sessions or tt.sessions else "implemented; unit-tested only (0 occurrences in train/validation)"
    if k == "NET-0":
        origin = "added in v2-evidence-1.1 (approved FP-4 amendment)"
    elif k in design.index:
        origin = "design v2-evidence-1.0" + (" (semantics amended in 1.1)" if k in ("NET-1", "AUTH-1", "AUTH-2", "TIME-0") else "")
    else:
        origin = "?"
    rows.append({"indicator_id": k, "name": d.name, "category": d.category, "kind": d.kind, "evidence_class": d.evidence_class,
                 "origin": origin, "required_telemetry": "; ".join(d.telemetry), "implementation": MATCHER[k],
                 "used_by_interpretations": "; ".join(used_by), "unit_test_references": n_tests, "status": status,
                 "train_sessions": int(tt.sessions), "validation_sessions": int(tv.sessions), "validation_unit": tv.unit,
                 "validation_rate_by_category": json.dumps({c: tv[f"rate_{c}"] for c in CATS}), "limitations": d.limitations})
pd.DataFrame(rows).to_csv(HERE / "indicator_implementation_status.csv", index=False)
print(pd.DataFrame(rows)[["indicator_id", "kind", "unit_test_references", "train_sessions", "validation_sessions", "status"]].to_string())
