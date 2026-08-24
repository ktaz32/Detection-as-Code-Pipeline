# MITRE ATT&CK Coverage

This document summarizes the ATT&CK techniques represented by the 10-case portfolio.

| Technique | Name | Detection(s) |
|---|---|---|
| T1059.001 | PowerShell | DET-001, DET-002, DET-010 |
| T1105 | Ingress Tool Transfer | DET-002 |
| T1110 | Brute Force | DET-003, DET-004 |
| T1078 | Valid Accounts | DET-004 |
| T1098 | Account Manipulation | DET-005 |
| T1562.001 | Impair Defenses: Disable or Modify Tools | DET-006 |
| T1053.005 | Scheduled Task/Job: Scheduled Task | DET-007 |
| T1003.001 | OS Credential Dumping: LSASS Memory | DET-008 |
| T1218 | System Binary Proxy Execution | DET-009 |
| T1218.005 | Mshta | DET-009 |
| T1218.010 | Regsvr32 | DET-009 |
| T1218.011 | Rundll32 | DET-009 |

## Tactic Coverage

The portfolio demonstrates detections associated with:

- Execution
- Credential Access
- Persistence
- Privilege Escalation
- Defense Evasion
- Initial Access / Valid Account follow-up
- Command and Control / tool transfer context

ATT&CK mappings are used as a behavioral taxonomy. A technique tag does not imply that every matching event is malicious.
