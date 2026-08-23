# DET-004 — Successful Windows Logon After Repeated Failures

## Alert Description

This detection identifies a successful Windows logon that occurs after multiple failed authentication attempts associated with the same user account and source address within a short period.

The correlation uses:

- **Event ID 4625** — An account failed to log on
- **Event ID 4624** — An account was successfully logged on

A sequence of repeated failures followed by a success may indicate:

- successful password guessing;
- brute-force compromise;
- credential stuffing;
- password spraying that ultimately succeeded;
- unauthorized access using guessed or recovered credentials.

However, the same sequence can also occur when a legitimate user repeatedly mistypes a password and then enters the correct one.

DET-004 should therefore be treated as a **high-value authentication correlation requiring immediate contextual investigation**, not automatic proof of compromise.

---

## Detection Objective

Identify authentication sequences where repeated failed logons are followed by a successful logon from the same source against the same account.

The current Detection-as-Code correlation logic triggers when:

```text
5 or more failed logons
        +
same target user
        +
same source IP
        +
within 5 minutes
        +
successful logon afterward
        =
DET-004 match
```

This correlation is more significant than failed logons alone because it may represent a transition from attempted credential access to successful account use.

---

## MITRE ATT&CK Mapping

### T1110 — Brute Force

Adversaries may attempt to gain account access through repeated authentication attempts.

Relevant sub-techniques may include:

- **T1110.001 — Password Guessing**
- **T1110.003 — Password Spraying**
- **T1110.004 — Credential Stuffing**

### T1078 — Valid Accounts

If authentication succeeds, an adversary may begin operating with valid credentials.

### Primary Tactics

- Credential Access
- Initial Access
- Persistence
- Privilege Escalation
- Defense Evasion

The exact tactic depends on what the account is used for after successful authentication.

---

## Relevant Windows Events

### Event ID 4625 — An Account Failed to Log On

This event records unsuccessful Windows authentication.

Important fields may include:

- `TargetUserName`
- `TargetDomainName`
- `LogonType`
- `Status`
- `SubStatus`
- `IpAddress`
- `IpPort`
- `WorkstationName`
- `AuthenticationPackageName`
- `ProcessName`
- `Computer`
- timestamp

### Event ID 4624 — An Account Was Successfully Logged On

This event records successful Windows authentication.

Important fields may include:

- `TargetUserName`
- `TargetDomainName`
- `LogonType`
- `IpAddress`
- `IpPort`
- `WorkstationName`
- `AuthenticationPackageName`
- `ProcessName`
- `Computer`
- timestamp

The analyst should correlate these fields across the failure and success sequence.

---

## Initial Triage

When DET-004 triggers, collect and review:

1. Target username
2. Target domain
3. Source IP address
4. Destination computer
5. Number of failed logons
6. Timestamp of the first failure
7. Timestamp of the final failure
8. Timestamp of the successful logon
9. Logon type
10. Authentication package
11. Status and SubStatus from the failures
12. Source workstation
13. Whether the account is privileged
14. Whether MFA or identity-provider telemetry is available
15. Processes and activity occurring after the successful logon
16. Related authentication attempts against other accounts
17. Related EDR, firewall, VPN, and identity alerts

---

## Key Questions

The analyst should determine:

- Is the account valid and active?
- Is the account privileged or sensitive?
- Is the source IP expected for this account?
- Is the source internal, VPN-based, or external?
- Does the user recognize the authentication activity?
- Are the failed and successful logons from the same workstation or network source?
- What logon type was used?
- Did the successful logon occur immediately after the failure sequence?
- Did the source target other accounts?
- Did suspicious activity follow the successful logon?
- Was MFA involved?
- Was a new device or location involved?
- Did the account access sensitive hosts or resources afterward?

---

## Correlation Logic

DET-004 is a multi-event temporal correlation.

The detection considers:

```text
Event ID 4625
        ↓
repeated failures
        ↓
same user + same source IP
        ↓
Event ID 4624
        ↓
successful authentication
```

Example:

```text
10:00:00  4625  jsmith  192.0.2.50
10:00:15  4625  jsmith  192.0.2.50
10:00:29  4625  jsmith  192.0.2.50
10:00:43  4625  jsmith  192.0.2.50
10:00:57  4625  jsmith  192.0.2.50
10:01:10  4624  jsmith  192.0.2.50
```

Result:

```text
DET-004 = MATCH
```

The success must occur after the correlated failures.

---

## Why DET-004 Is Higher Priority Than DET-003

DET-003 identifies repeated authentication failure.

DET-004 identifies a possible change in state:

```text
Credential attack
        ↓
Repeated failures
        ↓
Successful authentication
        ↓
Possible account compromise
```

This makes DET-004 more actionable because the attacker may now have valid access.

The analyst should immediately investigate what occurred after the successful authentication.

---

## Logon Type Analysis

The Windows logon type strongly affects risk interpretation.

| Logon Type | Meaning | SOC Relevance |
|---|---|---|
| 2 | Interactive | Local console login |
| 3 | Network | SMB and other network authentication |
| 4 | Batch | Scheduled task or batch process |
| 5 | Service | Service authentication |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Network authentication involving cleartext credentials to the authentication package |
| 9 | NewCredentials | Alternate credentials for outbound connections |
| 10 | RemoteInteractive | RDP / Remote Desktop |
| 11 | CachedInteractive | Cached domain credentials |

Examples:

```text
5 failures + successful Logon Type 2
```

may represent a user mistyping a local password.

Whereas:

```text
5 failures + successful Logon Type 10
from an unfamiliar source
against a privileged account
```

should receive significantly higher priority.

---

## Failure Status and SubStatus Analysis

Review Event ID 4625 failure codes.

Examples include:

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

A sequence dominated by incorrect-password failures followed by success can be especially relevant to password guessing.

---

## Source IP Investigation

Analyze the source IP responsible for both the failures and the success.

Determine whether the address is:

- internal;
- VPN-assigned;
- externally routable;
- associated with a trusted administrative host;
- associated with a known user endpoint;
- shared through NAT;
- related to a proxy or gateway;
- previously observed for the account;
- associated with threat-intelligence reporting.

For external sources, review:

- reputation;
- geolocation;
- ASN;
- hosting provider;
- VPN/proxy indicators;
- previous activity;
- other targeted identities.

Do not treat IP reputation alone as proof of compromise.

---

## Target Account Investigation

Determine the account's role and sensitivity.

Classify it as:

- standard user;
- administrator;
- domain administrator;
- service account;
- shared account;
- dormant account;
- recently created account;
- privileged application account;
- sensitive business account.

A successful authentication following repeated failures against a privileged account should generally be handled as higher priority.

---

## User Validation

Where operational processes allow, determine whether the legitimate account owner recognizes the activity.

Useful questions include:

- Were you attempting to sign in at this time?
- Were you using this device or network?
- Did you recently change your password?
- Were you using VPN or remote access?
- Did you experience repeated failed-login messages?
- Did you approve any MFA prompts?

User confirmation is supporting evidence, not the only investigation method.

---

## Password Guessing vs Legitimate Mistyping

### Possible Legitimate Sequence

```text
User enters wrong password
        ↓
several failures
        ↓
user remembers correct password
        ↓
successful authentication
```

Indicators favoring benign activity:

- known workstation;
- expected location;
- normal working hours;
- familiar logon type;
- no suspicious post-login activity;
- user confirms activity.

### Possible Credential Attack

```text
Automated guessing
        ↓
multiple failures
        ↓
correct password found
        ↓
successful login
        ↓
post-compromise activity
```

Indicators favoring malicious activity:

- unknown source;
- unusual location;
- privileged account;
- automated timing;
- other targeted accounts;
- suspicious post-login activity;
- user denies activity.

---

## Password Spraying Considerations

A password spray often targets many accounts rather than repeatedly attacking one account.

Example:

```text
jsmith   ← 192.0.2.50
agarcia  ← 192.0.2.50
mlee     ← 192.0.2.50
admin    ← 192.0.2.50
```

If one of those accounts later authenticates successfully from the same source, the event may indicate a successful spray.

DET-004 currently groups by:

```text
TargetUserName + source IP
```

Therefore, analysts should also pivot on the source IP and review all accounts targeted by that source.

---

## Authentication Package Review

Review the authentication mechanism where available.

Examples may include:

- Kerberos
- NTLM
- Negotiate

Unexpected NTLM usage, legacy authentication, or authentication behavior inconsistent with the environment may provide additional context.

Authentication package alone does not determine maliciousness.

---

## Account Lockout Correlation

Review:

### Event ID 4740 — A User Account Was Locked Out

Possible sequence:

```text
4625
4625
4625
4625
4625
   ↓
4740
```

If a later successful logon occurs after an account lockout or unlock event, investigate how access was restored and whether the activity was legitimate.

---

## Post-Authentication Investigation

This is the most important stage of DET-004 triage.

Once authentication succeeds, determine what the account did next.

Review approximately:

```text
30 minutes before
        ↓
DET-004 correlation
        ↓
30–60+ minutes after
```

Look for:

- process execution;
- PowerShell activity;
- remote-service access;
- RDP sessions;
- SMB connections;
- administrative-share access;
- scheduled-task creation;
- service creation;
- privilege escalation;
- account changes;
- group-membership changes;
- credential dumping;
- file access;
- persistence;
- outbound network connections.

---

## Process Execution After Login

Review endpoint telemetry on the destination system.

Potentially suspicious processes include:

```text
powershell.exe
cmd.exe
rundll32.exe
regsvr32.exe
mshta.exe
wscript.exe
cscript.exe
certutil.exe
schtasks.exe
net.exe
net1.exe
whoami.exe
nltest.exe
```

The presence of administrative tools is not inherently malicious. Interpret them using user, parent-process, timing, and business context.

---

## Lateral Movement Indicators

After successful authentication, look for signs that the account was used to move to additional systems.

Examples include:

- RDP connections;
- SMB access;
- administrative shares;
- remote service creation;
- WMI activity;
- WinRM;
- PsExec-like behavior;
- authentication to multiple hosts.

A successful credential attack followed by lateral movement should be escalated immediately.

---

## Privilege Escalation and Account Changes

Review security events for:

- group membership changes;
- new accounts;
- privileged account creation;
- token manipulation;
- elevated process execution;
- administrative-role assignment.

Examples of Windows events that may be useful include:

```text
4720 — User account created
4728 — Member added to global security group
4732 — Member added to local security group
4756 — Member added to universal security group
```

Availability depends on audit configuration.

---

## Network Correlation

Review network telemetry following the successful authentication.

Useful sources include:

- firewall logs;
- EDR network telemetry;
- DNS;
- proxy logs;
- VPN logs;
- identity-provider logs.

Look for:

```text
successful authentication
        ↓
new outbound connection
        ↓
unknown destination
```

or:

```text
successful authentication
        ↓
connections to additional internal hosts
```

---

## MFA Correlation

If MFA is available, determine:

- whether MFA was challenged;
- whether the user approved the request;
- whether repeated MFA prompts occurred;
- whether an unusual device was registered;
- whether MFA was bypassed;
- whether legacy authentication avoided MFA.

A successful password authentication does not necessarily mean the attacker completed MFA.

---

## Escalation Indicators

Escalate promptly when:

- a successful logon follows repeated failures;
- the user denies the activity;
- the source IP is unknown or suspicious;
- a privileged account is involved;
- RDP or remote network authentication succeeds;
- the source targeted multiple accounts;
- the account subsequently accesses multiple hosts;
- suspicious processes execute after login;
- persistence is created;
- security controls are modified;
- credentials are accessed;
- privilege escalation occurs;
- abnormal outbound network traffic follows;
- MFA anomalies are present;
- the authentication occurs from a new geography or device;
- multiple related identity alerts exist.

---

## False Positives

Potential legitimate causes include:

- user repeatedly mistyping a password;
- password recently changed;
- stale cached credentials;
- VPN credential synchronization issues;
- remote desktop retries;
- administrative troubleshooting;
- applications retrying authentication before updated credentials are supplied;
- service or scheduled-task credential issues.

A successful authentication after failures should still be validated, particularly for privileged accounts.

---

## Suggested Triage Flow

```text
DET-004 Alert
     |
     v
Confirm 4625 → 4624 sequence
     |
     v
Identify user + source IP
     |
     v
Determine account sensitivity
     |
     v
Review LogonType
     |
     v
Review Status / SubStatus
     |
     v
Validate source / workstation
     |
     +---- User confirms activity?
     |             |
     |            Yes
     |             |
     |     Validate normal context
     |
     v
Review other accounts targeted
     |
     v
Investigate post-login activity
     |
     v
Check endpoint + network telemetry
     |
     v
Check privilege / persistence activity
     |
     v
Determine benign vs compromise
```

---

## Analyst Decision

### Benign / Expected

Close as benign when:

- the user confirms the activity;
- the source device or network is expected;
- failures are consistent with password mistyping or a recent credential change;
- the successful logon type is expected;
- no suspicious post-authentication activity exists;
- no other identities are being targeted.

Document the root cause.

### Suspicious

Escalate when:

- the user cannot explain the activity;
- the source is unfamiliar;
- authentication timing appears automated;
- the account is sensitive;
- multiple accounts are targeted;
- the successful login originates from unusual infrastructure;
- related security alerts are present.

### Confirmed or Probable Compromise

Treat as probable or confirmed compromise when the successful authentication is followed by adversary behavior such as:

- unauthorized remote access;
- lateral movement;
- credential dumping;
- privilege escalation;
- malicious PowerShell;
- persistence creation;
- security-control modification;
- suspicious data access;
- malicious outbound communication.

Potential response actions may include:

- contain or isolate affected endpoints;
- disable or restrict the compromised account;
- reset credentials;
- revoke active sessions or tokens;
- require MFA reauthentication;
- block malicious source infrastructure;
- remove persistence;
- investigate lateral movement;
- hunt for related indicators across the environment;
- preserve forensic evidence;
- escalate according to the incident-response process.

---

## Evidence to Preserve

Collect and preserve:

- all relevant Event ID 4625 records;
- the correlated Event ID 4624 record;
- Event ID 4740 if present;
- target username;
- target domain;
- source IP;
- source port;
- source workstation;
- destination computer;
- timestamps;
- failure count;
- LogonType;
- Status;
- SubStatus;
- authentication package;
- VPN telemetry;
- MFA logs;
- identity-provider telemetry;
- EDR process events;
- network connections;
- DNS queries;
- account and group changes;
- related alerts;
- analyst timeline.

---

## Example Detection Scenario

### Authentication Timeline

```text
10:00:00  EventID 4625  jsmith  192.0.2.50
10:00:15  EventID 4625  jsmith  192.0.2.50
10:00:29  EventID 4625  jsmith  192.0.2.50
10:00:43  EventID 4625  jsmith  192.0.2.50
10:00:57  EventID 4625  jsmith  192.0.2.50
10:01:10  EventID 4624  jsmith  192.0.2.50
```

### Detection Reason

```text
5 failed authentication attempts
        +
same account
        +
same source
        +
successful authentication afterward
        =
DET-004 match
```

### Expected Analyst Action

The analyst should validate whether the account owner recognizes the activity, determine whether the source is expected, investigate the authentication type, and immediately examine activity following the successful logon for evidence of compromise.

---

## Detection Limitations

DET-004 intentionally uses a simple and explainable correlation model.

It may miss:

- low-and-slow credential attacks;
- failures distributed across multiple source IPs;
- password spraying across many accounts;
- successful authentication occurring outside the five-minute window;
- authentication telemetry without usable source IP information;
- attacks against non-Windows identity systems.

It may produce false positives when users mistype credentials multiple times before successfully authenticating.

Production deployments should consider tuning:

- failure threshold;
- correlation window;
- source grouping;
- account sensitivity;
- logon type;
- privileged-account weighting;
- service-account exclusions;
- VPN/NAT behavior;
- environment-specific authentication baselines.

---

## Detection Engineering Notes

DET-004 extends the correlation model established by DET-003.

```text
DET-003
4625 + 4625 + 4625 + 4625 + 4625
        ↓
Repeated failures

DET-004
4625 + 4625 + 4625 + 4625 + 4625
        ↓
4624
        ↓
Possible successful compromise
```

The Sigma rule identifies the relevant Windows Security events, while the Python Detection-as-Code layer validates the multi-event temporal relationship using controlled positive and negative fixtures.

This approach makes the detection:

- reproducible;
- testable;
- explainable;
- version-controlled;
- suitable for CI validation;
- adaptable to future SIEM-specific correlation syntax.

---

## Relationship to DET-003

DET-003 should generally be considered an earlier-stage authentication anomaly.

DET-004 represents an escalation condition.

```text
DET-003
Repeated failed authentication
        ↓
investigation

DET-004
Repeated failures + success
        ↓
higher-priority investigation
```

The two rules therefore complement rather than duplicate each other.

---

## Final Analyst Principle

> A successful logon after repeated failures is not proof of compromise, but it marks a critical transition from attempted access to possible valid-account use. The analyst must determine who authenticated, from where, whether the activity was expected, and what the account did immediately afterward.
