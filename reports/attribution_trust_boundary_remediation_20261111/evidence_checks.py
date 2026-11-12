"""Task 26C evidence: unchanged artefacts, exclusions on the real captured log, key custody, live state, no enforcement.
Read-only except for files written into this report directory."""
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO))
EV = HERE / "evidence"
OUT = {}


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def manifest(path, select):
    rows = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        h, n = line.split(maxsplit=1)
        n = n.lstrip("*")
        if select(n):
            p = (Path(path).parent / n).resolve()
            rows.append((n, p.exists() and sha(p) == h))
    return rows


# --- unchanged artefacts
be = manifest(REPO / "reports/behavioural_evidence_framework_implementation_20261111/SHA256SUMS", lambda n: "behavioural_evidence/" in n)
t24 = manifest(REPO / "reports/threat_assessment_implementation_20261111/SHA256SUMS", lambda n: "threat_assessment/" in n)
a26 = manifest(REPO / "reports/client_attribution_implementation_20261111/SHA256SUMS", lambda n: n.startswith("../../"))
OUT["behavioural_evidence_vs_task22"] = {"checked": len(be), "mismatched": [n for n, ok in be if not ok]}
OUT["threat_assessment_vs_task24"] = {n.split("threat_assessment/")[1]: ok for n, ok in t24}
OUT["task26A_artefacts_now"] = {n.replace("../../", ""): ok for n, ok in a26}

# --- exclusions applied to the real captured Cowrie log (all five demo sessions)
spec = importlib.util.spec_from_file_location("efv2", REPO / "scripts" / "extract_features_v2.py")
efv2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(efv2)
summary = efv2.extract([str(REPO / "reports/client_attribution_implementation_20261111/evidence/cowrie_events_after_baseline.jsonl")],
                       str(EV / "exclusion_extract_demo_log"))
OUT["extractor_on_demo_log"] = {"events_read": summary["events_read"], "sessions_output": summary["sessions"],
                                "session_exclusions": summary["session_exclusions"]}
from session_exclusions import load_exclusions  # noqa: E402
ex = load_exclusions()
OUT["session_exclusions_config"] = {"version": ex.version, "digest": ex.digest, "ids": sorted(ex.ids), "categories": ex.categories}

# --- key custody (host ACLs, relay access) and live state
def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return (p.stdout + p.stderr).strip()


A = REPO / "cowrie" / "attributing_relay"
OUT["acl"] = {name: run(["icacls", str(A / name)]).splitlines()[0] for name in
              ("secrets", "secrets/relay_mapping_ed25519.pem", "records", "records/relay_mapping.jsonl")}
OUT["relay_key_check"] = run(["docker", "exec", "cowrie-ssh-relay", "/cowrie/cowrie-env/bin/python3", "-c",
                              "import hashlib,os,stat;from cryptography.hazmat.primitives import serialization as s;"
                              "k=s.load_pem_private_key(open('/run/relay/relay_mapping_ed25519.pem','rb').read(),None);"
                              "print(hashlib.sha256(k.public_key().public_bytes(s.Encoding.Raw,s.PublicFormat.Raw)).hexdigest(),"
                              "oct(stat.S_IMODE(os.stat('/run/relay/relay_mapping_ed25519.pem').st_mode)),"
                              "os.access('/run/relay/relay_mapping_ed25519.pem',os.W_OK))"])
OUT["containers"] = run(["docker", "ps", "-a", "--filter", "name=cowrie", "--format", "{{.ID}} {{.Names}} {{.Status}}"]).splitlines()
OUT["cowrie"] = run(["docker", "inspect", "cowrie-project", "--format", "{{.Id}} {{.State.StartedAt}} restarts={{.RestartCount}}"])
OUT["relay"] = run(["docker", "inspect", "cowrie-ssh-relay", "--format", "{{.Id}} {{.State.StartedAt}} restarts={{.RestartCount}}"])
OUT["relay_mounts"] = run(["docker", "inspect", "cowrie-ssh-relay", "--format", "{{range .Mounts}}{{.Destination}} rw={{.RW}}; {{end}}"])
rec = (A / "records" / "relay_mapping.jsonl").read_bytes()
OUT["relay_records"] = {"lines": rec.count(b"\n"), "sha256": hashlib.sha256(rec).hexdigest(),
                        "equals_26A_copy": rec == (REPO / "reports/client_attribution_implementation_20261111/evidence/relay_mapping.jsonl").read_bytes()}
SP = Path(sys.argv[1]) if len(sys.argv) > 1 else None
if SP and SP.exists():
    fw = subprocess.run(["wsl.exe", "-d", "docker-desktop", "-u", "root", "sh", "-s"], stdin=open(SP, "rb"), capture_output=True)
    OUT["firewall"] = fw.stdout.decode("utf-8", "replace").strip().splitlines()
OUT["wsl_volume_access_from_host_account"] = Path(r"\\wsl.localhost\docker-desktop\mnt\docker-desktop-disk\data\docker\volumes").exists()
(EV / "evidence_checks.json").write_text(json.dumps(OUT, indent=2) + "\n", encoding="utf-8")
print(json.dumps(OUT, indent=1))
