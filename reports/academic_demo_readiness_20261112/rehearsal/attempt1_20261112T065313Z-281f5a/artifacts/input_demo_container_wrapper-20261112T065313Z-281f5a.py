"""DEMO wrapper: records every file opened inside the assessment container, then runs threat_assessment.run_signed."""
import json, os, sys
opened = []
sys.addaudithook(lambda e, a: opened.append(os.fsdecode(a[0])) if e == "open" and a and isinstance(a[0], (str, bytes, os.PathLike)) else None)
sys.path.insert(0, "/opt/project")
from threat_assessment import run_signed
out = sys.argv[sys.argv.index("--out-dir") + 1]
try:
    run_signed.main(sys.argv[1:])
finally:
    os.makedirs(out, exist_ok=True)
    json.dump(sorted(set(opened)), open(os.path.join(out, "opened_files.json"), "w"), indent=1)
