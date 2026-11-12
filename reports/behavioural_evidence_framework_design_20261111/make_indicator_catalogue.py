"""Task 21: write indicator_catalogue.csv (design text + measured Dataset V2 firing rates from evidence/).

    .venv/Scripts/python.exe reports/behavioural_evidence_framework_design_20261111/make_indicator_catalogue.py
"""
import json
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
rates = pd.read_csv(HERE / "evidence" / "indicator_rates_by_category.csv")
CATS = ["benign", "botnet", "brute_force", "lateral_movement", "privilege_escalation", "reconnaissance"]

T_CMD = "cowrie.command.input (recorded line text)"
CAT = [
    # id, name, evidence_class, telemetry, semantics, establishes, cannot, fp, support
    ("AUTH-0", "authentication failure in session", "directly observed", "cowrie.login.failed",
     "session has >= 1 cowrie.login.failed event",
     "a login attempt with these credentials was rejected by the honeypot",
     "intent; attack; that other attempts exist", "any mistyped password; scanners probing once",
     "descriptive only; never an interpretation on its own"),
    ("AUTH-1", "repeated authentication failures from one source", "directly observed (aggregate)", "cowrie.login.failed with src_ip, timestamp",
     ">= 3 cowrie.login.failed events from the same src_ip within 300 s (window and count are parameters fixed before evaluation)",
     "repeated rejected logins from one network source in a short window",
     "a single actor behind a shared/NAT/relay IP; distributed guessing across IPs; success",
     "shared egress IPs, NAT, honeypot relays (lab: every session has src_ip 172.22.0.2), users retrying a forgotten password",
     "NOT deployable in the lab topology (1 source IP for all sessions); evaluated with interaction_id as an oracle key only, where it separates brute force by generator construction (failed_attempts [3,5] vs <= 2)"),
    ("AUTH-2", "login success after repeated failures", "directly observed (aggregate)", "login.failed + login.success, src_ip, timestamp",
     "AUTH-1 holds and a later cowrie.login.success from the same src_ip within the window",
     "a source that failed repeatedly then authenticated",
     "that the credentials were guessed rather than known; any later behaviour", "as AUTH-1", "as AUTH-1 (oracle only)"),
    ("SHELL-1", "interactive command activity", "directly observed", T_CMD,
     "session has >= 1 recorded input line other than exit/logout; depth = number of lines (reported, not thresholded)",
     "the client issued commands after login", "what the commands did", "monitoring/automation clients", "descriptive"),
    ("DISC-1", "system/identity discovery command", "directly observed", T_CMD,
     "a simple command whose name (basename of argv[0], after a sudo wrapper) is in {whoami,id,groups,w,who,uname,hostname,uptime,lscpu,nproc,free,df,ps,ip,ifconfig,ss,netstat,arp,route,last,lastlog,env,printenv}",
     "the client ran a standard discovery command", "malicious intent", "ordinary administration (100% of benign validation logins)",
     "context only; never sufficient for an interpretation"),
    ("PRIV-1", "privilege-context probe", "directly observed", T_CMD,
     "`sudo -l`; read of /etc/sudoers*; find with -perm and a SUID/SGID mode (-4000, -u=s, /4000, -2000, -g=s); ls/cd/find on /root",
     "an attempt to enumerate privilege-related configuration", "that privileges were gained or that the probe returned anything (Cowrie output is not logged)",
     "administrators auditing sudo/SUID", "supported: 69/69 PE validation logins, 0 elsewhere (template-specific in lab)"),
    ("PRIV-2", "command run under sudo", "directly observed", T_CMD,
     "first token of a simple command is `sudo` (wrapper recorded; wrapped command analysed separately)",
     "the client requested elevated execution", "that elevation succeeded (Cowrie emulates sudo; outcome not in JSON)", "routine admin use", "descriptive"),
    ("CRED-1", "credential-material access attempt", "directly observed", T_CMD,
     "an argument path whose final component is shadow/gshadow, id_rsa|id_dsa|id_ecdsa|id_ed25519(.pub), authorized_keys, .bash_history, or any path inside a .ssh directory; or find -name with one of those names",
     "an attempt to read or locate credential material", "that the file existed or was read (find printed nothing in Cowrie)",
     "users inspecting their own ~/.ssh/known_hosts or config", "fires on lateral (91%) and PE (77%) validation logins; 0 benign"),
    ("FILE-1", "named file search", "directly observed", T_CMD, "find with -name/-iname/-path",
     "a filename-pattern search was issued", "what was found", "admins searching logs/configs", "PE only (13%)"),
    ("FILE-2", "filesystem size/recursive survey", "directly observed", T_CMD, "du; ls with a recursive -R flag",
     "a directory-size or recursive listing was requested", "data staging intent", "routine disk administration (benign 35%)", "benign only in lab: descriptive"),
    ("XFER-1", "download attempt", "directly observed (attempt) / emulator-dependent (outcome)", T_CMD + "; cowrie.session.file_download",
     "wget/curl/tftp/ftpget/fetch with an http(s)/ftp/tftp URL argument and no -I/--head; scp whose last argument is local",
     "a download was attempted", "that anything was downloaded: outcome = success ONLY with a cowrie.session.file_download event, otherwise 'not observed'",
     "package/mirror checks, IP-echo services (recon 28% via `curl -s http://.../ip`)",
     "attempt supported (botnet 100%); success never observed (0 download events)"),
    ("XFER-1-OK", "download recorded by honeypot", "directly observed", "cowrie.session.file_download",
     "event present", "Cowrie fetched and stored a file", "that the attacker could run it", "none known", "0 in train/validation (isolated lab)"),
    ("XFER-2", "upload attempt", "directly observed (attempt) / emulator-dependent (outcome)", T_CMD + "; cowrie.session.file_upload",
     "curl -T/--upload-file/-F/--data-binary; scp whose last argument contains host:; nc/ncat with input redirection",
     "an upload was attempted", "that data left the host (Cowrie rejects curl -T; isolated network)", "file-sharing admin tasks",
     "cannot be validated: 0 occurrences in train/validation (upload profiles are held out)"),
    ("XFER-2-OK", "upload recorded by honeypot", "directly observed", "cowrie.session.file_upload", "event present", "Cowrie received an upload", "destination", "none known", "0 in train/validation"),
    ("EXEC-1", "execution of a file this session tried to download", "inferred (link between two observed commands)", T_CMD,
     "after an XFER-1 whose target basename is F: `./F`, `sh F`/`bash F`, or chmod +x / executable mode on F",
     "the session tried to run what it tried to download", "that the file existed or ran (Cowrie returns 'command not found' -> also EMU-1)",
     "installer scripts", "botnet 100% (template)"),
    ("STAGE-1", "archive creation attempt", "directly observed (attempt)", T_CMD,
     "tar whose first argument contains c; zip; 7z; gzip/xz/bzip2 with an argument",
     "an archive operation was requested", "that an archive was created (Cowrie tar fails: no output logged)", "backups",
     "cannot be validated: 0 in train/validation"),
    ("EVADE-1", "shell-history tampering", "directly observed", T_CMD,
     "history -c; unset HISTFILE; export HISTFILE=... or HISTSIZE=0; rm or ln targeting .bash_history",
     "an attempt to suppress or clear shell history", "that history was actually unrecoverable", "privacy-conscious users", "botnet 30% (template cleanup)"),
    ("PERS-0", "persistence-related READ", "directly observed", T_CMD,
     "crontab -l; cat/ls of /etc/crontab or /etc/cron*; service/systemctl status|is-active|list-units",
     "configuration was inspected", "any modification", "routine administration (benign 63%)", "descriptive only; never persistence"),
    ("PERS-1", "persistence modification attempt", "directly observed (attempt)", T_CMD,
     "crontab with arguments other than -l (e.g. -e, a file); systemctl enable; update-rc.d; redirection (>, >>) into /etc/crontab, /etc/cron.*, /etc/rc.local",
     "an attempt to change scheduled/boot execution", "that it persisted (Cowrie filesystem is ephemeral)", "admins installing jobs",
     "cannot be validated: 0 in train/validation"),
    ("NET-1", "network probe attempt", "directly observed (attempt)", T_CMD,
     "nc/ncat with -z; ping; nmap; telnet; masscan; ssh with a host argument; curl -I/--head",
     "an attempt to reach or scan another host", "reachability (lab is isolated; nmap is unknown to Cowrie)", "benign connectivity checks (benign 20% via curl -I)",
     "lateral 85%, benign 20%"),
    ("CHAIN-1", "shell operator / chaining", "directly observed", T_CMD, "line contains |, ;, && or || outside quotes",
     "multi-step command composition", "intent", "pipelines are ubiquitous (5 of 6 categories)", "descriptive only"),
    ("REDIR-1", "output redirection to a file", "directly observed", T_CMD, "> or >> to a target other than /dev/null",
     "the client wrote command output to a file", "file content", "logging by admins", "0 in train/validation"),
    ("EMU-1", "emulator could not run a command", "emulator-dependent", "cowrie.command.failed",
     "cowrie.command.failed for a line of the session",
     "Cowrie did not implement the command (e.g. systemctl, journalctl, nmap, arp, ./payload)", "anything about the client's intent; real-system behaviour",
     "every unimplemented legitimate command", "benign 31%, botnet 65%, lateral 59%: an emulator property"),
    ("ART-1", "known emulator latency artefact", "emulator-dependent", T_CMD + " (exact string); sensor calibration list",
     "line equals a command on the sensor's calibrated slow list (measured on the training split: `find / -name id_rsa 2>/dev/null`)",
     "timing features of this session are inflated by emulator execution time", "anything behavioural", "n/a (it is a caveat flag)",
     "exactly the 30 train / 9 validation slow sessions"),
    ("SEQ-1", "previously seen exact command sequence", "generator-dependent (lab)", T_CMD + "; reference sequence store",
     "the session's full ordered line list equals one stored from the reference period",
     "exact repetition of an earlier session", "same actor; maliciousness", "templates, cron-like automation, common one-liners",
     "brute force 48% of validation logins (3-command pool): template repetition"),
    ("TIME-0", "timing context (not an indicator)", "generator- and emulator-dependent", "command.input timestamps; session.closed duration",
     "reported descriptively (duration, inter-input statistics); never used to raise or lower an interpretation",
     "how the session was paced", "operator vs script, think time vs execution time (Cowrie JSON does not separate them)",
     "generator pacing tails, emulator latency (ART-1)", "excluded from interpretation by design (Tasks 14B-19B)"),
]
rows = []
for c in CAT:
    r = rates[(rates.split == "validation") & (rates.indicator == c[0])]
    t = rates[(rates.split == "train") & (rates.indicator == c[0])]
    row = {"indicator_id": c[0], "name": c[1], "evidence_class": c[2], "required_telemetry": c[3], "matching_semantics": c[4],
           "establishes": c[5], "cannot_establish": c[6], "known_false_positive_conditions": c[7], "dataset_v2_support": c[8]}
    if len(r):
        r, t = r.iloc[0], t.iloc[0]
        row.update({"unit": r.unit, "train_fires": int(t.fires), "validation_fires": int(r.fires), "validation_of": int(r.of),
                    "validation_rate_by_category": json.dumps({k: r[f"rate_{k}"] for k in CATS})})
    rows.append(row)
pd.DataFrame(rows).to_csv(HERE / "indicator_catalogue.csv", index=False)
print(len(rows), "indicators written")
