"""Task 25A: ONE controlled connection to 127.0.0.1:2223 and a read-only observation of the relay's accepted socket.

    .venv/Scripts/python.exe reports/relay_client_address_verification_20261111/observe_once.py

No instrumentation: the relay and Cowrie are not modified, restarted or reconfigured. While the single connection is
held open, the kernel TCP tables (/proc/net/tcp, /proc/net/tcp6) are read inside both containers with `docker exec
python3` (read-only), which shows the relay's accepted socket (local/peer = what getpeername() would return) and its
outbound socket to Cowrie. The connection sends NO bytes (no SSH version string, no credentials); it only reads the
server banner and closes. Afterwards the new Cowrie JSON lines are read. Refuses to run twice (lock file).
DIAGNOSTIC ONLY - these records are not attribution evidence.
"""
import json
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOCK = HERE / "evidence" / "OBSERVATION_DONE.lock"
LOG = "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"
(HERE / "evidence").mkdir(exist_ok=True)
if LOCK.exists():
    sys.exit("observation already performed once; refusing a second connection")

READ_TCP = r"""
import json
def dec(h):
    a, p = h.split(':')
    if len(a) == 8:
        ip = '.'.join(str(int(a[i:i+2], 16)) for i in (6, 4, 2, 0))
    else:
        b = bytes.fromhex(a); ip = ':'.join(b[i:i+4][::-1].hex() for i in range(0, 16, 4))
    return ip, int(p, 16)
ST = {'01':'ESTABLISHED','02':'SYN_SENT','03':'SYN_RECV','06':'TIME_WAIT','08':'CLOSE_WAIT','0A':'LISTEN'}
out = []
for f in ('/proc/net/tcp', '/proc/net/tcp6'):
    try:
        for line in open(f).read().splitlines()[1:]:
            c = line.split()
            l, r = dec(c[1]), dec(c[2])
            out.append({'table': f, 'local': f'{l[0]}:{l[1]}', 'remote': f'{r[0]}:{r[1]}', 'state': ST.get(c[3], c[3]), 'inode': c[9]})
    except FileNotFoundError:
        pass
print(json.dumps(out))
"""
COUNT = f"print(sum(1 for _ in open({LOG!r}, encoding='utf-8')))"


def dexec(container, code):
    r = subprocess.run(["docker", "exec", container, "python3", "-c", code], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise SystemExit(f"docker exec {container} failed: {r.stderr}")
    return r.stdout


def utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


obs = {"diagnostic_only": True, "purpose": "Task 25A relay peer-address verification; NOT attribution evidence"}
obs["cowrie_log_lines_before"] = int(dexec("cowrie-project", COUNT))
obs["before"] = {"relay": json.loads(dexec("cowrie-ssh-relay", READ_TCP)), "cowrie": json.loads(dexec("cowrie-project", READ_TCP))}

LOCK.write_text(utc() + "\n")                       # lock before connecting: there is exactly one attempt
s = socket.create_connection(("127.0.0.1", 2223), timeout=10)
obs["client"] = {"connected_utc": utc(), "client_local": "%s:%d" % s.getsockname()[:2], "client_peer": "%s:%d" % s.getpeername()[:2]}
s.settimeout(5)
try:
    banner = s.recv(256)
except socket.timeout:
    banner = b""
obs["client"]["banner"] = banner.decode("ascii", "replace").strip()
time.sleep(1.0)
obs["during"] = []
for k in range(2):
    obs["during"].append({"sampled_utc": utc(), "relay": json.loads(dexec("cowrie-ssh-relay", READ_TCP)),
                          "cowrie": json.loads(dexec("cowrie-project", READ_TCP))})
    time.sleep(0.5)
s.close()
obs["client"]["closed_utc"] = utc()
time.sleep(3.0)
after = int(dexec("cowrie-project", COUNT))
obs["cowrie_log_lines_after"] = after
obs["cowrie_new_events"] = [json.loads(l) for l in dexec("cowrie-project",
    f"import sys\nlines=open({LOG!r}, encoding='utf-8').read().splitlines()\nprint('\\n'.join(lines[{obs['cowrie_log_lines_before']}:]))").splitlines() if l.strip()]
(HERE / "evidence" / "raw_observation.json").write_text(json.dumps(obs, indent=2), encoding="utf-8")
print(json.dumps({"client": obs["client"], "new_cowrie_events": len(obs["cowrie_new_events"])}, indent=1))
