"""Task 19B: derive the sealed-test generator configuration (approved design, 2026-11-11). Refuses to overwrite.

    .venv/Scripts/python.exe reports/cowrie_sealed_exfiltration_evaluation_20261111/make_test_config.py

From dataset_builder/profiles_v2_revised.json (unchanged): keep only the held-out data_exfiltration profile (steps,
credentials and noise unchanged) and replace the {ip} and {domain} placeholder pools with documentation-only values
(RFC 5737 addresses, .example domains) disjoint from train/validation (protocol section 5). {dir} values are kept
(they decide whether `tar` can write in Cowrie's emulated filesystem). Unused pools are kept as they are.
Checks the new values never occur in any train/validation command and that nothing else changed.
Output: config/profiles_v2_sealed_exfiltration.json
"""
import copy
import csv
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SRC = REPO / "dataset_builder" / "profiles_v2_revised.json"
DST = HERE / "config" / "profiles_v2_sealed_exfiltration.json"
DS = REPO / "reports" / "dataset_v2_training_validation_20261110"
NEW = {"ip": ["192.0.2.77", "198.51.100.88", "203.0.113.99", "192.0.2.150"],
       "domain": ["archive.example", "backup-store.example", "upload-node.example"]}

if DST.exists():
    sys.exit(f"{DST} exists; refusing to overwrite")
src = json.loads(SRC.read_text(encoding="utf-8"))
cfg = copy.deepcopy(src)
old = {k: list(src["placeholders"][k]) for k in NEW}
cfg["placeholders"].update(NEW)
cfg["profiles"] = [p for p in src["profiles"] if p["name"] == "data_exfiltration"]
assert len(cfg["profiles"]) == 1 and cfg["profiles"][0]["held_out"] is True
cfg["version"] = src["version"] + "+sealed-exfiltration-test"
cfg["derived_from"] = {"file": "dataset_builder/profiles_v2_revised.json", "sha256": hashlib.sha256(SRC.read_bytes()).hexdigest(),
                       "changes": ["profiles: data_exfiltration only (held_out: true; steps, credentials, noise unchanged)",
                                   "placeholders.ip and placeholders.domain replaced by disjoint documentation-only values",
                                   "placeholders.dir, lan_ip, bin, user unchanged"],
                       "task": "Task 19B sealed test run (single approved evaluation)"}
# disjointness against every train/validation command actually sent
used = []
for split in ("train", "validation"):
    with open(DS / "evidence" / f"{split}_command_log.csv", encoding="utf-8", newline="") as f:
        used += [r["command"] for r in csv.DictReader(f)]
hits = {v: sum(v in c for c in used) for vals in NEW.values() for v in vals}
overlap_with_old = {k: sorted(set(NEW[k]) & set(old[k] + src["placeholders"].get("lan_ip", []))) for k in NEW}
assert not any(hits.values()), hits
assert not any(overlap_with_old.values()), overlap_with_old
steps_same = cfg["profiles"][0] == [p for p in src["profiles"] if p["name"] == "data_exfiltration"][0]
assert steps_same
DST.parent.mkdir(exist_ok=True)
DST.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"written": str(DST.relative_to(REPO)), "sha256": hashlib.sha256(DST.read_bytes()).hexdigest(),
                  "old_pools": old, "new_pools": NEW, "occurrences_in_train_validation_commands": hits,
                  "exfiltration_profile_identical_to_revised": steps_same, "train_validation_commands_checked": len(used)}, indent=1))
