# DET-003 — Multiple Failed Windows Logons

## Alert Description

This detection identifies repeated failed Windows authentication attempts associated with the same user account and source address within a short period.

The detection is based on Windows Security Event ID **4625 — An account failed to log on**.

A single failed logon is common and usually benign. Multiple failures clustered by the same account and source in a short time window may indicate:

- brute-force authentication attempts;
- credential guessing;
- repeated unauthorized access attempts;
- automated password attacks;
- misconfigured services or applications;
- stale or expired credentials.

DET-003 should be treated as an **authentication anomaly requiring contextual investigation**, not automatic evidence of compromise.

---

## Detection Objective

Identify repeated Windows authentication failures that may represent credential-access activity.

The current Detection-as-Code correlation logic triggers when:

```text
5 or more failed logons
        +
same target user
        +
same source IP
        +
within 5 minutes
        =
DET-003 match
```

This threshold is intentionally transparent and testable. In a production SIEM, the threshold should be tuned to the environment, authentication volume, account type, and acceptable false-positive rate.

---

## MITRE ATT&CK Mapping

### T1110 — Brute Force

Adversaries may attempt to gain access to accounts by systematically guessing passwords or other authentication material.

### Primary Tactic

- Credential Access

### Related Techniques

Depending on the observed pattern, activity may resemble:

- **T1110.001 — Password Guessing**
- **T1110.003 — Password Spraying**
- **T1110.004 — Credential Stuffing**

The exact technique should be determined from the authentication pattern rather than assumed from Event ID 4625 alone.

---

## Primary Windows Event

### Event ID 4625 — An Account Failed to Log On

Event ID 4625 records an unsuccessful Windows logon attempt.

Useful fields commonly include:

- `TargetUserName`
- `TargetDomainName`
- `LogonType`
- `Status`
- `SubStatus`
- `IpAddress`
- `IpPort`
- `WorkstationName`
- `ProcessName`
- `AuthenticationPackageName`
- `Computer`
- timestamp

Field availability can vary depending on the authentication method and log source.

---

## Initial Triage

When DET-003 triggers, collect and review:

1. Target username
2. Target domain
3. Source IP address
4. Destination host
5. Number of failures
6. Time window
7. Logon type
8. Status and substatus codes
9. Authentication package
10. Source workstation, if available
11. Whether a successful logon followed
12. Whether other accounts were targeted from the same source
13. Whether the account is privileged
14. Related endpoint, VPN, identity, firewall, and EDR telemetry

---

## Key Questions

The analyst should determine:

- Is the target account valid?
- Is the account privileged or sensitive?
- Is the source IP expected?
- Is the source internal or external?
- Are all failures targeting one account?
- Is the same source targeting many accounts?
- Did authentication eventually succeed?
- What logon type was used?
- Do the status/substatus codes indicate a bad password, disabled account, or another cause?
- Is the activity consistent with a user mistyping a password?
- Is a service, script, or scheduled task using stale credentials?
- Are similar failures occurring elsewhere in the environment?

---

## Correlation Logic

DET-003 is a multi-event detection.

The Sigma rule identifies the relevant failed-logon telemetry:

```text
Event ID 4625
```

The Detection-as-Code test layer performs the correlation:

```text
Group events by:
TargetUserName + IpAddress

Then evaluate:
count >= 5
within 5 minutes
```

Example:

```text
10:00:00  4625  jsmith  192.0.2.50
10:00:12  4625  jsmith  192.0.2.50
10:00:25  4625  jsmith  192.0.2.50
10:00:41  4625  jsmith  192.0.2.50
10:00:58  4625  jsmith  192.0.2.50
```

Result:

```text
DET-003 = MATCH
```

A single failed authentication event does not satisfy the correlation threshold.

---

## Logon Type Analysis

The Windows logon type provides important context.

Common values include:

| Logon Type | Meaning | SOC Relevance |
|---|---|---|
| 2 | Interactive | Local console authentication |
| 3 | Network | SMB, remote resource access, many network authentications |
| 4 | Batch | Scheduled task or batch process |
| 5 | Service | Service account authentication |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Network authentication where credentials may be passed in cleartext form to the authentication package |
| 9 | NewCredentials | Alternate credentials used for outbound connections |
| 10 | RemoteInteractive | RDP / Remote Desktop |
| 11 | CachedInteractive | Cached domain credentials |

The same failure count can have very different significance depending on the logon type.

For example:

```text
5 failed Type 2 logons
from a user's workstation
```

may represent a user mistyping a password.

Whereas:

```text
50 failed Type 10 logons
from an unfamiliar source
against an administrator account
```

should receive substantially higher priority.

---

## Status and SubStatus Analysis

Event ID 4625 includes status information that can help explain why authentication failed.

Examples analysts may encounter include:

```text
0xC0000064
User name does not exist
```

```text
0xC000006A
Incorrect password
```

```text
0xC0000234
Account locked out
```

```text
0xC0000072
Account disabled
```

```text
0xC0000193
Account expired
```

```text
0xC0000071
Password expired
```

These values should be interpreted in context.

For example, repeated failures against nonexistent usernames may indicate account enumeration or spraying, while repeated failures against one legitimate account with an incorrect-password code may indicate password guessing or simply stale credentials.

---

## Brute Force vs Password Spraying

### Password Guessing / Brute Force

Typical pattern:

```text
One account
        +
many passwords
        +
same source
        =
possible password guessing
```

Example:

```text
jsmith ← 192.0.2.50
jsmith ← 192.0.2.50
jsmith ← 192.0.2.50
jsmith ← 192.0.2.50
jsmith ← 192.0.2.50
```

DET-003 is primarily designed to identify this type of pattern.

### Password Spraying

Typical pattern:

```text
Many accounts
        +
one/few passwords
        +
same source
        =
possible password spraying
```

Example:

```text
jsmith ← 192.0.2.50
agarcia ← 192.0.2.50
mlee ← 192.0.2.50
admin ← 192.0.2.50
service1 ← 192.0.2.50
```

Because DET-003 groups by the same user and source IP, a low-and-slow password spray may not trigger this rule.

That behavior should be covered by a separate detection or SIEM correlation rule.

---

## Source IP Investigation

Review the source address associated with the failed attempts.

Determine:

- internal vs external;
- VPN-assigned vs direct Internet source;
- known administrative workstation;
- server or service host;
- known vulnerability scanner;
- previously observed source;
- geographic location where appropriate;
- reputation where external;
- whether the address is shared by NAT or proxy infrastructure.

Do not assume that one source IP always represents one physical user or device.

---

## Target Account Investigation

Determine whether the targeted account is:

- standard user;
- privileged administrator;
- service account;
- shared account;
- disabled account;
- dormant account;
- recently created account;
- high-value identity.

Repeated failures against privileged accounts should generally receive higher priority.

Examples include:

```text
Administrator
Domain Admin
server administrator
backup administrator
service accounts with elevated access
```

---

## Account Lockout Correlation

Repeated failed authentication may cause an account lockout.

Where available, correlate with:

### Event ID 4740 — A User Account Was Locked Out

A sequence such as:

```text
4625
4625
4625
4625
4625
   ↓
4740
```

provides additional evidence that repeated authentication failures affected the account.

Analysts should determine whether the lockout originated from:

- a user's workstation;
- a mobile device;
- cached credentials;
- a mapped drive;
- a Windows service;
- a scheduled task;
- an attacker-controlled system.

---

## Successful Authentication Follow-Up

A critical question is whether a successful logon occurred after the failures.

Correlate with:

### Event ID 4624 — An Account Was Successfully Logged On

Example:

```text
4625
4625
4625
4625
4625
   ↓
4624
```

This sequence may indicate successful credential guessing and should generally receive higher priority than failures alone.

This behavior is covered separately by **DET-004 — Successful Logon After Repeated Failures**.

---

## Time-Based Analysis

Review more than just the immediate five-minute detection window.

Consider:

```text
15 minutes before
        ↓
DET-003 alert
        ↓
30–60 minutes after
```

Look for:

- earlier authentication failures;
- successful logons;
- account lockouts;
- privilege changes;
- remote-service use;
- new process execution;
- lateral movement;
- suspicious network connections.

A narrow alert window should not limit the investigation timeline.

---

## Escalation Indicators

Increase severity or escalate when:

- the target account is privileged;
- the source IP is unknown or suspicious;
- the source is external where external authentication is unexpected;
- failures occur across multiple sensitive systems;
- the account becomes locked out;
- a successful authentication follows;
- the same source targets additional accounts;
- remote interactive/RDP logons are involved;
- failures occur outside normal working patterns;
- the account owner denies the activity;
- related EDR or identity alerts exist;
- post-authentication suspicious activity appears.

---

## False Positives

Common legitimate explanations include:

- a user repeatedly entering the wrong password;
- recently changed passwords;
- stale cached credentials;
- mapped drives using old credentials;
- mobile devices using expired passwords;
- scheduled tasks with outdated credentials;
- Windows services using stale service-account passwords;
- automated applications repeatedly retrying authentication;
- administrative troubleshooting.

The purpose of triage is to distinguish these operational causes from malicious credential attacks.

---

## Suggested Triage Flow

```text
DET-003 Alert
     |
     v
Identify target account
     |
     v
Identify source IP / workstation
     |
     v
Confirm failure count + time window
     |
     v
Review LogonType
     |
     v
Review Status / SubStatus
     |
     +---- Expected user/service behavior?
     |               |
     |              Yes
     |               |
     |       Validate operational cause
     |
     v
Check other targeted accounts
     |
     v
Check Event ID 4740
     |
     v
Check Event ID 4624
     |
     v
Review endpoint / identity telemetry
     |
     v
Determine benign vs suspicious
```

---

## Analyst Decision

### Benign / Expected

Close as benign when:

- the failures are attributable to a known user mistake;
- stale credentials are confirmed;
- a legitimate service or scheduled task is responsible;
- the source is expected;
- the authentication pattern is consistent with normal operations;
- no suspicious successful authentication or follow-on activity exists.

Document the root cause.

### Suspicious

Escalate when:

- the source cannot be explained;
- the account owner denies the attempts;
- an unusual host repeatedly targets the account;
- multiple sensitive systems are involved;
- failures are consistent with automated guessing;
- additional accounts are being targeted;
- related security alerts exist.

### High Priority / Possible Compromise

Treat as higher priority when:

- repeated failures are followed by a successful authentication;
- a privileged account is targeted;
- successful authentication is followed by suspicious activity;
- the source is known malicious;
- lateral movement or privilege escalation follows.

Potential response actions may include:

- temporarily restrict or lock the affected account when warranted;
- reset credentials;
- revoke active sessions;
- block malicious source infrastructure where appropriate;
- isolate compromised endpoints;
- review MFA and identity-provider activity;
- hunt for related authentication attempts;
- escalate according to the incident-response process.

---

## Evidence to Preserve

Collect and preserve:

- all relevant Event ID 4625 records;
- target username;
- target domain;
- source IP;
- source port;
- workstation name;
- destination computer;
- timestamps;
- failure count;
- LogonType;
- Status;
- SubStatus;
- authentication package;
- related Event ID 4624 records;
- related Event ID 4740 records;
- VPN or identity-provider logs;
- firewall/proxy evidence;
- relevant EDR telemetry;
- analyst timeline.

---

## Example Detection Scenario

### Authentication Events

```text
10:00:00  EventID 4625  jsmith  192.0.2.50
10:00:12  EventID 4625  jsmith  192.0.2.50
10:00:25  EventID 4625  jsmith  192.0.2.50
10:00:41  EventID 4625  jsmith  192.0.2.50
10:00:58  EventID 4625  jsmith  192.0.2.50
```

### Detection Reason

```text
5 failed logons
        +
same user
        +
same source IP
        +
within 5 minutes
        =
DET-003 match
```

### Expected Analyst Action

The analyst should determine whether the attempts are caused by legitimate credential issues or represent automated credential guessing, then check for account lockout, successful authentication, additional targeted accounts, and suspicious follow-on activity.

---

## Detection Limitations

DET-003 intentionally uses a simple, explainable correlation model.

It may miss:

- low-and-slow brute force;
- password spraying across many accounts;
- attacks distributed across multiple source IPs;
- authentication attempts where the source IP is unavailable;
- attacks occurring outside the five-minute window;
- credential attacks against non-Windows identity systems.

It may also generate false positives from stale credentials and misconfigured services.

Production deployments should tune:

- failure threshold;
- time window;
- account exclusions;
- service-account behavior;
- source-IP exclusions;
- privileged-account severity;
- environment-specific baselines.

---

## Detection Engineering Notes

DET-003 demonstrates a different detection-engineering model from DET-001 and DET-002.

```text
DET-001 / DET-002
Single-event behavioral detection

DET-003
Multi-event temporal correlation
```

The Sigma rule identifies relevant Windows Security events, while the Detection-as-Code Python layer validates the temporal correlation behavior using controlled positive and negative test fixtures.

This separation makes the detection logic explicit, testable, and suitable for later translation into SIEM-specific correlation syntax.

---

## Final Analyst Principle

> Repeated failed logons are a pattern, not a verdict. Their significance depends on the account being targeted, the source of the attempts, the authentication context, whether other identities are affected, and whether access eventually succeeds.
