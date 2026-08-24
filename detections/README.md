# Detection Rules

This directory contains the Sigma-style detection rules used by the project.

| ID | Rule | Category |
|---|---|---|
| DET-001 | Encoded PowerShell execution | PowerShell / Execution |
| DET-002 | PowerShell download cradle | PowerShell / Execution |
| DET-003 | Multiple failed logons | Authentication |
| DET-004 | Success after repeated failures | Authentication |
| DET-005 | Local Administrators membership | Account Management |
| DET-006 | Defender weakened | Defense Evasion |
| DET-007 | Scheduled task creation | Persistence |
| DET-008 | LSASS process access | Credential Access |
| DET-009 | Suspicious LOLBin execution | Defense Evasion |
| DET-010 | PowerShell unusual child | Execution |

Each rule is paired with positive/negative fixtures under `tests/` and an analyst playbook under `investigations/`.

> Note: `scripts/validate_sigma.py` performs structural YAML/metadata validation. Behavioral semantics are tested separately by `scripts/test_detections.py`.
