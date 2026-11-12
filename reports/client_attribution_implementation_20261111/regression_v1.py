"""Regression: threat-assessment 1.1.0 with the unchanged v1 attribution config and v2.0 policy reproduces the stored
Task 24 (1.0.0) outputs on the Task 24 train/validation evidence records, apart from the declared additive fields."""
import json
import sys
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
from behavioural_evidence import EvidenceConfig  # noqa: E402
from behavioural_evidence.calibration import load_calibration  # noqa: E402
from behavioural_evidence.engine import read_jsonl  # noqa: E402
from threat_assessment import ThreatAssessor, load_attribution_config, load_policy  # noqa: E402

T24 = REPO / "reports" / "threat_assessment_implementation_20261111" / "evidence"
T22 = REPO / "reports" / "behavioural_evidence_framework_implementation_20261111"
DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
att = load_attribution_config(REPO / "configs" / "threat_attribution_v1.json")
pol = load_policy(REPO / "configs" / "defence_policy_v2.json")
train = read_jsonl(DS / "raw" / "train" / "cowrie_slice.json")
ref_seq = frozenset(tuple(v) for v in pd.DataFrame(
    [(e["session"], e["timestamp"], e["input"]) for e in train
     if e["eventid"] == "cowrie.command.input" and e["input"].strip() not in ("exit", "logout")],
    columns=["s", "t", "i"]).sort_values(["s", "t"], kind="stable").groupby("s").i.apply(tuple))
ecfg = EvidenceConfig(relay_sources=frozenset(att.relay_strings), internal_networks=att.internal_cidr_strings,
                      calibration=load_calibration(T22 / "config" / "sensor_calibration_lab_train.json"), reference_sequences=ref_seq)
a = ThreatAssessor(att, pol, ecfg)


def norm(o):
    """Remove only the declared 1.1.0 additions: attribution.subject, versions.assessment, versions.client_attribution_digest_ok."""
    o = json.loads(json.dumps(o))
    o["versions"].pop("assessment"); o["versions"].pop("client_attribution_digest_ok", None)
    o["session_attribution"].pop("subject", None)
    for f in o["findings"]:
        f["attribution"].pop("subject", None)
    return o


out = {}
for s in ("train", "validation"):
    ev = [json.loads(l) for l in open(T24 / f"{s}_evidence.jsonl", encoding="utf-8")]
    old = [json.loads(l) for l in open(T24 / f"{s}_assessments.jsonl", encoding="utf-8")]
    new = [a.assess(r) for r in ev]
    diff = [o["session_ref"] for o, n in zip(old, new) if norm(o) != norm(n)]
    tiers = pd.Series([n["tier"] for n in new]).value_counts().to_dict()
    out[s] = {"sessions": len(ev), "identical_after_declared_additions": len(ev) - len(diff), "differences": diff[:10],
              "old_version": old[0]["versions"]["assessment"], "new_version": new[0]["versions"]["assessment"], "tiers": tiers}
(HERE / "regression_v1_results.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
print(json.dumps(out, indent=1))
