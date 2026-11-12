"""DEMO wrapper: records every file opened inside the assessment container, by phase ('isolation_scan' = the
existing run_signed self-check that reads every repository file looking for private-key material; 'assessment' = everything
else), then runs threat_assessment.run_signed unchanged."""
import json, os, sys
phase, opened = ["startup"], {}
sys.addaudithook(lambda e, a: opened.setdefault(phase[0], set()).add(os.fsdecode(a[0]))
                 if e == "open" and a and isinstance(a[0], (str, bytes, os.PathLike)) else None)
sys.path.insert(0, "/opt/project")
from threat_assessment import run_signed
_scan = run_signed.isolation_report


def _phased_scan(*a, **k):
    phase[0] = "isolation_scan"
    try:
        return _scan(*a, **k)
    finally:
        phase[0] = "assessment"


run_signed.isolation_report = _phased_scan
out = sys.argv[sys.argv.index("--out-dir") + 1]
try:
    run_signed.main(sys.argv[1:])
finally:
    os.makedirs(out, exist_ok=True)
    json.dump({k: sorted(v) for k, v in opened.items()}, open(os.path.join(out, "opened_files.json"), "w"), indent=1)
