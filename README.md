# Detection-as-Code Pipeline

A Windows detection-engineering portfolio that treats security detections like software: **version-controlled Sigma rules, positive and negative test fixtures, automated Python validation, MITRE ATT&CK mapping, analyst playbooks, and GitHub Actions CI**.

The repository contains **10 detection cases** spanning execution, authentication, credential access, privilege escalation, persistence, defense evasion, and living-off-the-land behavior.

## Project Objective

The goal is not to collect a large number of copied rules. Each detection is built as a small engineering unit with:

1. a Sigma-style detection rule;
2. an explicit behavioral specification;
3. positive test telemetry that must alert;
4. negative test telemetry that must not alert;
5. a Python reference matcher used by the automated test suite;
6. MITRE ATT&CK mapping;
7. false-positive and limitation analysis;
8. an analyst investigation playbook;
9. CI validation on every push and pull request to `main`.

This demonstrates the workflow behind detection engineering rather than rule authoring alone.

## Detection Coverage

| ID | Detection | Primary telemetry | Severity | ATT&CK |
|---|---|---|---|---|
| [DET-001](detections/windows/powershell/DET-001-encoded-powershell.yml) | Encoded PowerShell execution | Process creation | Medium | T1059.001 |
| [DET-002](detections/windows/powershell/DET-002-powershell-download-cradle.yml) | Suspicious PowerShell download cradle | Process creation | High | T1059.001, T1105 |
| [DET-003](detections/windows/authentication/DET-003-multiple-failed-logons.yml) | Multiple failed Windows logons | Security 4625 correlation | Medium | T1110 |
| [DET-004](detections/windows/authentication/DET-004-success-after-failures.yml) | Successful logon after repeated failures | Security 4625 → 4624 correlation | High | T1110, T1078 |
| [DET-005](detections/windows/account-management/DET-005-local-admin-membership.yml) | User added to local Administrators | Security 4732 | High | T1098 |
| [DET-006](detections/windows/defense-evasion/DET-006-defender-disabled.yml) | Windows Defender disabled or weakened | PowerShell process creation | High | T1562.001 |
| [DET-007](detections/windows/persistence/DET-007-suspicious-scheduled-task.yml) | Suspicious scheduled task creation | Process creation | High | T1053.005 |
| [DET-008](detections/windows/credential-access/DET-008-lsass-access.yml) | Suspicious LSASS process access | Sysmon ProcessAccess | High | T1003.001 |
| [DET-009](detections/windows/defense-evasion/DET-009-suspicious-lolbin-execution.yml) | Suspicious LOLBin execution | Process creation | High | T1218 family |
| [DET-010](detections/windows/execution/DET-010-powershell-unusual-child.yml) | PowerShell spawning unusual child process | Parent/child process creation | High | T1059.001 |

A tactic-oriented view is available in [`docs/mitre-coverage.md`](docs/mitre-coverage.md).

## How the Pipeline Works

```text
Detection rule change
        ↓
Git push / pull request
        ↓
GitHub Actions
        ↓
Install Python dependencies
        ↓
Validate Sigma YAML structure
        ↓
Run positive + negative behavioral tests
        ↓
PASS → change is accepted by CI
FAIL → broken/missing detection coverage is surfaced
```

The workflow is defined in [`.github/workflows/detection-ci.yml`](.github/workflows/detection-ci.yml).

## Current Test Status

The repository contains:

- **10 Sigma rules**
- **10 positive test fixtures**
- **10 negative test fixtures**
- **20 behavioral tests total**
- **10 analyst playbooks**

A successful local run produces:

```text
Tests run: 20
Failures:  0

SUCCESS: All detection tests passed.
```

## Repository Structure

```text
Detection-as-Code-Pipeline/
├── .github/
│   └── workflows/
│       └── detection-ci.yml
│
├── detections/
│   └── windows/
│       ├── account-management/
│       ├── authentication/
│       ├── credential-access/
│       ├── defense-evasion/
│       ├── execution/
│       ├── persistence/
│       └── powershell/
│
├── investigations/
│   ├── DET-001/
│   ├── DET-002/
│   ├── ...
│   └── DET-010/
│
├── tests/
│   ├── positive/
│   └── negative/
│
├── scripts/
│   ├── test_detections.py
│   └── validate_sigma.py
│
├── docs/
│   ├── architecture.md
│   ├── detection-methodology.md
│   └── mitre-coverage.md
│
├── requirements.txt
├── LICENSE
└── README.md
```

## Detection Engineering Methodology

Each case follows the same lifecycle:

```text
Define threat behavior
        ↓
Identify required telemetry
        ↓
Write detection logic
        ↓
Create positive fixture
        ↓
Create negative fixture
        ↓
Automate behavioral testing
        ↓
Document ATT&CK + false positives
        ↓
Write analyst playbook
        ↓
Run CI validation
        ↓
Tune based on evidence
```

The detailed methodology is documented in [`docs/detection-methodology.md`](docs/detection-methodology.md).

## Testing Model

The project uses two complementary validation layers.

### 1. Sigma YAML Structure Validation

[`scripts/validate_sigma.py`](scripts/validate_sigma.py) recursively validates the detection YAML files and checks that required fields such as `title`, `id`, `status`, `description`, `logsource`, `detection`, and `level` are present and structurally valid.

This is intentionally a lightweight structural validator; it is **not presented as a full pySigma compiler or SIEM backend validation engine**.

### 2. Behavioral Detection Testing

[`scripts/test_detections.py`](scripts/test_detections.py) contains reference matchers for DET-001 through DET-010.

For every detection:

```text
Positive fixture → must MATCH
Negative fixture → must NOT MATCH
```

The test runner fails closed when a required positive or negative fixture is missing, preventing incomplete test coverage from silently passing CI.

## Correlation Detections

The repository includes both single-event and multi-event analytics.

**Single-event examples:**
- DET-001 encoded PowerShell
- DET-006 Defender modification
- DET-008 LSASS process access

**Multi-event examples:**
- DET-003: 5+ failed logons for the same user/source within 5 minutes
- DET-004: repeated failures followed by successful authentication for the same user/source

This distinction is documented explicitly because a single Windows event does not, by itself, prove a brute-force sequence.

## Analyst Playbooks

Every detection has a dedicated playbook under [`investigations/`](investigations/).

Each playbook covers:

- alert objective;
- relevant telemetry;
- initial triage;
- key investigative questions;
- false positives;
- escalation indicators;
- evidence preservation;
- analyst decision criteria;
- detection limitations;
- recommended production refinements.

See [`investigations/README.md`](investigations/README.md) for the complete index.

## Skills Demonstrated

- Detection engineering
- Sigma rule authoring
- Windows Security Event analysis
- Sysmon telemetry analysis
- PowerShell detection
- Authentication correlation
- Credential-access detection
- Persistence detection
- Living-off-the-land analysis
- MITRE ATT&CK mapping
- Python automation
- Positive/negative test design
- GitHub Actions CI/CD
- False-positive analysis
- SOC triage and analyst playbook development

## Local Validation

Requirements:

```text
Python 3.12+
PyYAML
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Validate rule structure:

```bash
python scripts/validate_sigma.py
```

Run the behavioral test suite:

```bash
python scripts/test_detections.py
```

Both commands should succeed before a detection change is considered complete.

## Design Principles

### Explainable detections

The rules favor transparent logic that an analyst can understand and defend rather than opaque scoring.

### Test both sides

A rule is not considered tested merely because malicious-looking telemetry matches. Each case also includes benign or non-matching telemetry to check false-positive boundaries.

### Context over verdicts

Many security behaviors in this project are dual-use. PowerShell, scheduled tasks, LSASS access, local administrator changes, and LOLBins all have legitimate uses. The playbooks explicitly treat alerts as investigative signals rather than automatic compromise verdicts.

### Production realism

The repository distinguishes portfolio reference logic from production deployment. Production SIEM/EDR implementations would require environment-specific field mappings, baselining, allowlists, threshold tuning, and backend-specific correlation syntax.

## Scope and Limitations

This is a controlled detection-engineering portfolio, not a production SOC content pack.

The test fixtures are synthetic and designed to exercise specific detection behaviors. They do not contain real credentials, malware, customer information, or production telemetry.

The custom Python matchers model the intended behavior for automated testing; they do not replace full Sigma-to-SIEM translation or validation against a production telemetry pipeline.

## Future Enhancements

Possible extensions after the initial portfolio include:

- pySigma/backend compilation validation;
- SIEM-specific translations for Microsoft Sentinel, Splunk, or Elastic;
- richer multi-event test datasets;
- detection severity/risk scoring;
- ATT&CK Navigator export;
- environment-aware allowlists;
- code coverage and linting;
- automated rule metadata checks.

These are intentionally future enhancements rather than requirements for the initial 10-case portfolio.

## Ethical Use

All test events and examples in this repository are synthetic and intended for defensive security education, detection engineering, and authorized SOC analysis.

## License

This project is licensed under the [MIT License](LICENSE).
