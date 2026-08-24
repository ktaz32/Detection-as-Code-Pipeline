# Detection Engineering Methodology

## 1. Define the behavior

Start from an observable adversary or security-relevant behavior rather than a product-specific query language.

Examples:

- encoded PowerShell;
- repeated failed authentication;
- LSASS process access;
- scheduled task creation.

## 2. Identify telemetry

Map the behavior to the telemetry required to observe it.

Examples include:

- Windows Security Event 4688 process creation;
- Windows Security 4624/4625 authentication;
- Windows Security 4732 group changes;
- Sysmon Event ID 10 ProcessAccess.

## 3. Define an explicit detection contract

State the conditions that should cause a match.

Example for DET-003:

```text
5+ Event ID 4625 failures
same target user
same source IP
within 5 minutes
```

The contract is intentionally explainable and testable.

## 4. Write the Sigma-style rule

The YAML file documents platform, log source, detection selections, condition, false positives, severity, and ATT&CK tags.

## 5. Build positive telemetry

Create at least one controlled event or event sequence that should alert.

## 6. Build negative telemetry

Create at least one related but benign/non-matching event that should not alert. This checks that the detector has a meaningful boundary.

## 7. Implement automated behavior tests

The Python reference matcher is exercised against both fixture types.

Expected invariant:

```text
positive → True
negative → False
```

Missing fixture coverage is also considered a failure.

## 8. Validate rule structure

The YAML validator checks required metadata and detection structure before behavioral tests run.

## 9. Map to MITRE ATT&CK

ATT&CK mapping describes the behavior represented by the rule. It is not used as proof that an event is malicious.

## 10. Document analyst workflow

Every case receives a playbook covering:

- initial triage;
- contextual pivots;
- false positives;
- escalation indicators;
- evidence preservation;
- decision criteria;
- limitations.

## 11. Run CI

Every push and pull request to `main` runs the validation pipeline. A detection is not considered complete until CI succeeds.

## 12. Tune without hiding tradeoffs

Detection rules are not universal. Production use requires environment-specific tuning, field mapping, allowlists, baselines, and backend-specific correlation logic.

The repository keeps those limitations explicit rather than presenting synthetic tests as production validation.
