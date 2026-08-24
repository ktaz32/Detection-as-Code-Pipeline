# DET-005 — User Added to Local Administrators Group

## Alert Description

This detection identifies a user or security principal being added to the local **Administrators** group on a Windows system.

The detection is based primarily on:

- **Event ID 4732 — A member was added to a security-enabled local group**

Membership in the local Administrators group grants powerful privileges over the endpoint. Unauthorized additions may indicate privilege escalation, persistence, account takeover, misuse of legitimate administrative credentials, or post-exploitation activity.

However, local administrator membership changes can also occur during legitimate IT operations, endpoint provisioning, software deployment, or approved support activity.

DET-005 should therefore be treated as a **high-priority privilege change requiring contextual investigation**, not automatic proof of compromise.

---

## Detection Objective

Identify changes that place a user or other security principal into the local Administrators group.

The intended Detection-as-Code logic is:

```text
Event ID 4732
        +
Target group = Administrators
        =
DET-005 match
```

For production environments, detection should preferably rely on the built-in Administrators group SID where available rather than only the localized group name.

```text
S-1-5-32-544
```

---

## MITRE ATT&CK Mapping

### T1098 — Account Manipulation

Adversaries may manipulate existing accounts to maintain access or increase privileges.

### Related Tactics

- Persistence
- Privilege Escalation

Depending on surrounding behavior, local administrator membership changes may also support Valid Accounts, Account Creation, Remote Services, or lateral movement.

---

## Primary Windows Event

### Event ID 4732 — A Member Was Added to a Security-Enabled Local Group

Important fields commonly include:

- `SubjectUserName`
- `SubjectDomainName`
- `SubjectUserSid`
- `MemberName`
- `MemberSid`
- `TargetUserName`
- `TargetDomainName`
- `TargetSid`
- `Computer`
- timestamp

Field names may vary depending on the collection or normalization schema.

---

## Initial Triage

When DET-005 triggers, collect and review:

1. Hostname
2. Timestamp
3. Account that performed the change
4. Account or principal added to the group
5. Target group
6. Target group SID
7. Member SID
8. Source process or management tool, if available
9. Whether the change was approved
10. Whether the added account is newly created
11. Whether the added account is privileged elsewhere
12. Whether remote access followed
13. Related account-management events
14. Related authentication events
15. Related PowerShell or command-line activity
16. EDR alerts around the same timestamp

---

## Key Questions

The analyst should determine:

- Who added the member to the Administrators group?
- Which account or principal was added?
- Was the change approved?
- Is the added account newly created?
- Is the account normally an administrator?
- Was the change performed by an authorized IT administrator?
- Did PowerShell, `net.exe`, `net1.exe`, or another administrative utility perform the change?
- Did the newly privileged account authenticate afterward?
- Did it access additional hosts?
- Did persistence or defense evasion occur afterward?
- Is the affected endpoint high value or sensitive?

---

## Why Local Administrator Membership Matters

Membership in the local Administrators group may permit a user to:

- install software;
- modify services;
- alter local users and groups;
- change firewall settings;
- create scheduled tasks;
- modify the registry;
- access sensitive files;
- weaken security controls;
- establish persistence;
- perform credential-access activity;
- remotely administer the host.

Unauthorized administrator membership is therefore materially more significant than a routine group membership change.

---

## Group Identification

The strongest way to identify the built-in Administrators group is by SID:

```text
S-1-5-32-544
```

A name-based check such as:

```text
Administrators
```

may fail on non-English Windows systems because the group name can be localized.

Production-grade logic should therefore prefer:

```text
EventID == 4732
AND
TargetSid == S-1-5-32-544
```

where the telemetry schema exposes the target group SID.

---

## Related Account-Creation Events

Review for:

### Event ID 4720 — A User Account Was Created

A sequence such as:

```text
4720
new user created
        ↓
4732
new user added to Administrators
```

is especially important because it may indicate creation of an unauthorized privileged backdoor account.

---

## Other Relevant Account-Management Events

Useful Windows Security events may include:

```text
4720 — User account created
4722 — User account enabled
4724 — Attempt made to reset an account password
4725 — User account disabled
4726 — User account deleted
4732 — Member added to local security group
4733 — Member removed from local security group
4738 — User account changed
4740 — User account locked out
```

Availability depends on audit policy and collection configuration.

---

## Authentication Follow-Up

Determine whether the newly privileged account authenticated after being added to the Administrators group.

Review:

### Event ID 4624 — Successful Logon

Example:

```text
4732
user added to Administrators
        ↓
4624
same user logs on
```

Investigate the source IP, workstation, logon type, destination host, authentication package, and post-login behavior.

---

## Remote Access Indicators

Administrator privileges become more significant when followed by remote access.

Review for:

- RDP;
- SMB;
- WinRM;
- WMI;
- PsExec-like behavior;
- remote service creation;
- administrative-share access.

Example:

```text
User added to Administrators
        ↓
successful RDP authentication
        ↓
PowerShell execution
```

If unauthorized, this sequence should generally be escalated quickly.

---

## Command-Line and Process Investigation

Review process telemetry around the membership change.

Common legitimate or attacker-abused tools include:

```text
net.exe
net1.exe
powershell.exe
cmd.exe
wmic.exe
lusrmgr.msc
mmc.exe
```

Relevant command patterns include:

```text
net localgroup Administrators <user> /add
```

```text
net localgroup Administrators domain\user /add
```

PowerShell may use:

```text
Add-LocalGroupMember
```

The tool itself is not sufficient to classify the activity. Evaluate user, parent process, command line, host, timing, and business context together.

---

## PowerShell Correlation

Review nearby PowerShell activity for:

- `Add-LocalGroupMember`
- `New-LocalUser`
- encoded commands
- download cradles
- privilege-modification scripts
- remote execution
- security-control modification

Example suspicious sequence:

```text
powershell.exe
        ↓
New-LocalUser
        ↓
Add-LocalGroupMember Administrators
```

This pattern should receive high investigative priority when not expected.

---

## Privileged Actor Analysis

Determine which account performed the group membership change.

Questions include:

- Is the actor a domain administrator?
- Is the actor a local administrator?
- Is it a service account?
- Is the actor expected to manage this endpoint?
- Was the actor recently compromised?
- Did the actor authenticate from an unusual source?
- Did the actor make similar changes on other systems?

A legitimate privileged account can still be abused by an attacker.

---

## Newly Created Account Analysis

If the added member is newly created, investigate:

- account creation time;
- creator account;
- account naming pattern;
- password-reset events;
- account enabled/disabled history;
- first successful logon;
- remote connections;
- privilege use;
- persistence activity.

Potentially suspicious names may include generic or deceptive names such as:

```text
support
backup
admin2
helpdesk
svc-update
tempadmin
```

Names alone are weak evidence, but suspicious naming combined with unauthorized creation and privilege assignment is significant.

---

## Persistence Considerations

Adding a controlled account to local Administrators can provide durable access.

Possible attacker sequence:

```text
Initial compromise
        ↓
create or identify account
        ↓
add to Administrators
        ↓
retain privileged access
```

Review for additional persistence such as scheduled tasks, services, startup entries, registry Run keys, WMI subscriptions, and remote-management configuration.

---

## Defense Evasion Follow-Up

After gaining administrative privileges, an attacker may attempt to weaken security controls.

Look for:

- Defender exclusions;
- antivirus disablement;
- firewall modification;
- audit policy changes;
- log clearing;
- EDR tampering;
- service stopping;
- PowerShell policy changes.

This behavior should increase severity substantially.

---

## Credential Access Follow-Up

Review for:

- LSASS access;
- SAM or SECURITY hive access;
- credential-dumping tools;
- token manipulation;
- browser credential extraction;
- DPAPI-related activity.

A privilege change followed by credential access is a strong escalation indicator.

---

## Lateral Movement Follow-Up

Determine whether the privileged account was used on additional hosts.

Look for:

- repeated 4624 events across multiple systems;
- SMB sessions;
- RDP;
- WinRM;
- service creation;
- administrative shares;
- remote scheduled tasks;
- WMI execution.

Example:

```text
4732 on HOST-A
        ↓
4624 on HOST-A
        ↓
4624 on HOST-B
        ↓
remote execution
```

This may indicate lateral movement.

---

## Escalation Indicators

Escalate when one or more of the following are present:

- the membership change was not approved;
- the added account is newly created;
- a privileged or sensitive host is affected;
- the actor account is unexpected;
- the actor authenticated from an unfamiliar source;
- the added account logs in immediately afterward;
- remote access follows;
- suspicious PowerShell or command-line account manipulation is observed;
- persistence is created;
- Defender or EDR is modified;
- credential-access behavior follows;
- similar privilege changes occur across multiple endpoints;
- the account owner or system owner denies the change.

---

## False Positives

Potential legitimate causes include:

- authorized help desk elevation;
- endpoint provisioning;
- device migration;
- approved temporary local administrator access;
- software installation requiring administrative rights;
- endpoint-management automation;
- support troubleshooting;
- break-glass procedures.

To close as benign, confirm:

```text
Who made the change
+
Why it was required
+
Which account was added
+
Which endpoint was affected
+
Whether the change was approved
```

---

## Suggested Triage Flow

```text
DET-005 Alert
     |
     v
Confirm Event ID 4732
     |
     v
Confirm target = Administrators
     |
     v
Identify added account
     |
     v
Identify actor account
     |
     v
Was the change approved?
     |
     +---- Yes ----------------------+
     |                               |
     |                      Validate business context
     |
     v
Was the account newly created?
     |
     v
Review 4720 / account events
     |
     v
Check successful logons
     |
     v
Review process / PowerShell telemetry
     |
     v
Check persistence / defense evasion
     |
     v
Check lateral movement
     |
     v
Determine benign vs suspicious
```

---

## Analyst Decision

### Benign / Expected

Close as benign when:

- the change is explicitly authorized;
- the actor is expected;
- the added account has a documented administrative requirement;
- the endpoint is within the actor's management scope;
- no suspicious authentication or follow-on activity exists.

Document the justification.

### Suspicious

Escalate when:

- authorization cannot be confirmed;
- the actor is unusual;
- the account is newly created;
- command-line or PowerShell activity appears suspicious;
- the newly privileged account logs on unexpectedly;
- the affected system is sensitive;
- similar changes appear elsewhere.

### Confirmed or Probable Compromise

Treat as probable or confirmed compromise when the administrator addition is associated with:

- unauthorized account creation;
- persistence;
- remote access;
- lateral movement;
- credential dumping;
- Defender or EDR tampering;
- malicious PowerShell;
- suspicious outbound communication.

Potential response actions may include:

- remove unauthorized administrator membership;
- disable or restrict the affected account;
- reset credentials;
- revoke active sessions;
- isolate affected endpoints;
- block malicious source infrastructure;
- remove persistence;
- hunt for similar changes across the environment;
- preserve forensic evidence;
- escalate according to the incident-response process.

---

## Evidence to Preserve

Collect and preserve:

- Event ID 4732 record;
- target group name;
- target group SID;
- added member name;
- added member SID;
- actor username;
- actor SID;
- hostname;
- timestamp;
- Event ID 4720 if applicable;
- Event ID 4624 events for the added account;
- command-line telemetry;
- PowerShell logs;
- EDR process tree;
- remote-access events;
- group-removal events;
- account-change events;
- Defender or security-control events;
- related alerts;
- analyst timeline.

---

## Example Detection Scenario

### Security Event

```text
EventID:
4732

TargetUserName:
Administrators

TargetSid:
S-1-5-32-544

MemberName:
WIN11-LAB\tempadmin

SubjectUserName:
administrator

Computer:
WIN11-LAB
```

### Detection Reason

```text
Event ID 4732
        +
built-in Administrators group
        =
DET-005 match
```

### Expected Analyst Action

Determine whether the administrator membership was authorized, identify who performed the change, investigate whether the added account was newly created, and review subsequent authentication and endpoint activity.

---

## Detection Limitations

DET-005 intentionally detects administrator group membership changes rather than attempting to classify them as malicious automatically.

It may miss:

- privilege changes where local Security auditing is unavailable;
- changes performed through mechanisms not generating collected Event ID 4732 telemetry;
- equivalent privilege assignments outside the local Administrators group;
- cloud or identity-provider administrative-role changes;
- domain-level group changes requiring different Windows events.

Name-only detection can also fail on localized Windows installations.

Production implementations should prefer:

```text
TargetSid = S-1-5-32-544
```

where available.

---

## Detection Engineering Notes

DET-005 expands the portfolio beyond process and authentication detection into **account and privilege-change telemetry**.

Current coverage:

```text
DET-001 — Encoded PowerShell execution
DET-002 — PowerShell download behavior
DET-003 — Repeated authentication failures
DET-004 — Failures followed by successful authentication
DET-005 — Local administrator privilege assignment
```

This demonstrates single-event behavioral detection, temporal correlation, authentication analytics, and privilege-change monitoring.

Positive and negative test fixtures should be maintained so future logic changes cannot silently broaden or break DET-005.

---

## Recommended Production Refinement

The initial fixture may use:

```text
TargetUserName = Administrators
```

for readability.

The production-grade logic should prefer:

```text
EventID = 4732
AND
TargetSid = S-1-5-32-544
```

If the telemetry schema does not expose the group SID, use the group name with environment-specific normalization.

---

## Final Analyst Principle

> Local administrator membership is a privilege transition, not a compromise verdict. Its significance depends on who made the change, which account received the privilege, whether the action was authorized, and what the newly privileged identity did afterward.
