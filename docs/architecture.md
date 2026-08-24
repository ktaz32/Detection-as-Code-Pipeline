# Detection-as-Code Architecture

## Overview

The project separates detection content, test data, validation logic, analyst guidance, and CI orchestration.

```text
                    ┌────────────────────────────┐
                    │      Detection Author      │
                    └──────────────┬─────────────┘
                                   │
                                   v
                    ┌────────────────────────────┐
                    │ Sigma-style detection YAML│
                    │       detections/          │
                    └──────────────┬─────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
                    v                             v
          ┌──────────────────┐          ┌──────────────────┐
          │ Positive fixtures│          │ Negative fixtures│
          │ tests/positive/  │          │ tests/negative/  │
          └─────────┬────────┘          └─────────┬────────┘
                    │                             │
                    └──────────────┬──────────────┘
                                   v
                    ┌────────────────────────────┐
                    │ Python behavioral test     │
                    │ scripts/test_detections.py│
                    └──────────────┬─────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │                             │
                    v                             v
          ┌──────────────────┐          ┌──────────────────┐
          │ YAML validation  │          │ Analyst playbooks│
          │ validate_sigma.py│          │ investigations/  │
          └─────────┬────────┘          └──────────────────┘
                    │
                    v
          ┌──────────────────────────────┐
          │      GitHub Actions CI       │
          │ push / pull request to main  │
          └──────────────────────────────┘
```

## Components

### Detection rules

`detections/windows/` stores rules by behavioral domain so the repository remains navigable as coverage expands.

### Behavioral reference implementation

`test_detections.py` provides Python matchers that encode the intended behavior of each portfolio detection and make that behavior automatically testable.

### Test telemetry

Synthetic fixtures are intentionally small and deterministic. Positive samples exercise the alert path, while negative samples exercise a non-alert path.

### Analyst layer

`investigations/` connects engineering output to SOC operations by defining triage, escalation, evidence collection, false positives, and limitations.

### CI layer

GitHub Actions creates an ephemeral runner, installs dependencies, validates the rule files, and executes all tests. Any validation or behavior failure exits non-zero and fails the workflow.

## Trust Boundary

This repository does not connect to a live SIEM or EDR. No production credentials, endpoints, or customer telemetry are required. All fixtures are synthetic.
