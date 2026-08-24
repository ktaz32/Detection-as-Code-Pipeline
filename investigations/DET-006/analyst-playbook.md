# DET-006 — Windows Defender Disabled or Weakened

## Alert Description

This detection identifies PowerShell activity that modifies Microsoft Defender Antivirus settings in ways that may reduce endpoint protection.

Examples include commands that:

- disable real-time monitoring;
- disable behavior monitoring;
- disable IOAV protection;
- add path exclusions;
- add process exclusions;
- add file-extension exclusions.

These actions can be legitimate during troubleshooting, software deployment, laboratory testing, or approved endpoint-security administration. However, attackers and malware also attempt to weaken or bypass Defender before executing payloads, establishing persistence, or performing credential-access activity.

DET-006 should therefore be treated as a **high-priority defense-evasion signal requiring contextual investigation**, not automatic proof of compromise.

---

## Detection Objective

Identify PowerShell commands associated with weakening Microsoft Defender protections.

The current Detection-as-Code logic is conceptually:

```text
PowerShell execution
        +
Defender configuration-change command
        =
DET-006 match
```

Examples of relevant indicators include:

```text
Set-MpPreference
Add-MpPreference
-DisableRealtimeMonitoring
-DisableBehaviorMonitoring
-DisableIOAVProtection
-ExclusionPath
-ExclusionProcess
-ExclusionExtension
```

---

## MITRE ATT&CK Mapping

### T1562.001 — Impair Defenses: Disable or Modify Tools

Adversaries may modify or disable security tools to avoid detection or prevent defensive controls from blocking malicious activity.

### Primary Tactic

- Defense Evasion

### Related Behaviors

Depending on surrounding activity, the same sequence may also support:

- Execution
- Persistence
- Credential Access
- Command and Control

The exact ATT&CK interpretation should be based on what occurred before and after the Defender change.

---

## Relevant Telemetry

DET-006 is designed around Windows process-creation telemetry.

Common sources include:

- Windows Security Event ID 4688;
- Sysmon Event ID 1;
- EDR process telemetry;
- PowerShell operational logs;
- Microsoft Defender operational events.

Important process fields may include:

- `Image`
- `CommandLine`
- `ParentImage`
- `ParentCommandLine`
- `User`
- `Computer`
- `ProcessId`
- `ParentProcessId`
- timestamp

---

## Initial Triage

When DET-006 triggers, collect and review:

1. Hostname
2. User account
3. Full PowerShell command line
4. Parent process
5. Process ID and parent PID
6. Timestamp
7. Exact Defender setting modified
8. Whether the command succeeded
9. Whether the change was authorized
10. Whether exclusions were added
11. Whether malware or scripts executed afterward
12. Related Defender alerts
13. Related PowerShell events
14. EDR telemetry
15. Network activity around the same time
16. Persistence or credential-access activity

---

## Key Questions

The analyst should determine:

- Who executed the PowerShell command?
- Was the user expected to administer Defender?
- What launched PowerShell?
- Which Defender protection was modified?
- Was the command part of an approved change?
- Were exclusions created?
- Which paths, processes, or extensions were excluded?
- Did suspicious code execute immediately afterward?
- Was Defender restored later?
- Did other security tools report activity on the host?
- Are similar Defender changes occurring on additional systems?
- Is the endpoint high value or sensitive?

---

## Why Defender Modification Matters

Microsoft Defender provides endpoint protections such as:

- real-time malware scanning;
- behavior monitoring;
- file and download inspection;
- cloud-delivered protection;
- attack-surface reduction;
- antivirus exclusions;
- threat detection.

Weakening these controls may create an execution window for malicious code.

A common attacker sequence may resemble:

```text
Initial execution
        ↓
PowerShell
        ↓
Defender weakened
        ↓
payload execution
        ↓
persistence / credential access
```

The Defender change is therefore often more significant when correlated with follow-on activity.

---

## High-Risk Defender Changes

### Disable Real-Time Monitoring

Example:

```text
Set-MpPreference -DisableRealtimeMonitoring $true
```

This can reduce real-time inspection of files and processes.

---

### Disable Behavior Monitoring

Example:

```text
Set-MpPreference -DisableBehaviorMonitoring $true
```

Behavioral monitoring helps detect suspicious runtime behavior.

---

### Disable IOAV Protection

Example:

```text
Set-MpPreference -DisableIOAVProtection $true
```

This may reduce scanning of downloaded files and attachments.

---

### Add Path Exclusion

Example:

```text
Add-MpPreference -ExclusionPath "C:\Temp"
```

Files within excluded paths may receive reduced antivirus inspection.

---

### Add Process Exclusion

Example:

```text
Add-MpPreference -ExclusionProcess "powershell.exe"
```

Process exclusions can be especially concerning because they may reduce inspection of activity generated by the excluded process.

---

### Add Extension Exclusion

Example:

```text
Add-MpPreference -ExclusionExtension ".exe"
```

Broad extension exclusions can materially reduce protection and should receive high scrutiny.

---

## Command-Line Analysis

Review the entire command, not only the triggering keyword.

For example:

```text
powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true
```

is materially different from:

```text
powershell.exe Get-MpComputerStatus
```

The latter is a status query and should not trigger DET-006.

Similarly:

```text
Add-MpPreference
```

by itself is too broad for a production-quality verdict.

The analyst should identify:

```text
Command
+
Parameter
+
Value
+
Target
```

to determine what actually changed.

---

## Parent-Process Analysis

Review the process that launched PowerShell.

Expected examples might include:

- approved management agents;
- administrator shells;
- endpoint-management tools;
- configuration-management software.

Higher-risk parents may include:

```text
winword.exe
excel.exe
outlook.exe
mshta.exe
wscript.exe
cscript.exe
rundll32.exe
unknown temporary executable
```

Example suspicious chain:

```text
winword.exe
        ↓
powershell.exe
        ↓
Set-MpPreference -DisableRealtimeMonitoring $true
```

An Office application causing Defender modification should receive immediate scrutiny.

---

## User and Privilege Analysis

Defender preference modification commonly requires elevated privileges.

Determine:

- whether the user is a local administrator;
- whether the process ran elevated;
- whether the account is expected to perform security administration;
- whether the account was recently compromised;
- whether the user recognizes the action.

A legitimate administrator account can still be abused by an attacker.

---

## Exclusion Analysis

If an exclusion was added, identify exactly what was excluded.

Examples:

```text
C:\Users\Public
C:\Temp
C:\ProgramData
powershell.exe
cmd.exe
*.exe
*.dll
```

Investigate whether the excluded location or process subsequently hosted or executed suspicious content.

Example sequence:

```text
Add Defender exclusion for C:\Temp
        ↓
payload.exe written to C:\Temp
        ↓
payload.exe executed
```

This correlation substantially increases confidence in malicious intent.

---

## Defender State Validation

Determine the endpoint's Defender state after the command.

Useful PowerShell status query:

```text
Get-MpComputerStatus
```

Relevant defensive properties may include:

- real-time protection state;
- antivirus enabled state;
- behavior monitoring;
- antispyware state;
- engine status.

Do not execute commands on a production endpoint unless authorized. Use existing telemetry or approved administrative procedures.

---

## Microsoft Defender Operational Logs

Where available, review Defender-specific telemetry for configuration changes and detections.

Useful sources may include:

```text
Microsoft-Windows-Windows Defender/Operational
```

Correlate configuration changes with:

- malware detections;
- remediation actions;
- protection-state changes;
- exclusion modifications;
- service status changes.

Event availability can vary by Windows version and Defender configuration.

---

## PowerShell Correlation

Review nearby PowerShell activity for:

- encoded commands;
- download cradles;
- `Invoke-WebRequest`;
- `DownloadString`;
- `IEX`;
- `Invoke-Expression`;
- scheduled-task creation;
- account manipulation;
- credential-access commands.

Example suspicious sequence:

```text
Encoded PowerShell
        ↓
download payload
        ↓
disable Defender
        ↓
execute payload
```

This should be treated as substantially more suspicious than an isolated Defender configuration command.

---

## Process Follow-Up

Investigate processes executed shortly after the Defender change.

Look for:

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
unknown executables
```

Review:

- hashes;
- signer information;
- parent-child relationships;
- command lines;
- file paths;
- prevalence;
- associated network activity.

---

## File-System Follow-Up

Determine whether files were created or downloaded near the Defender modification.

Preserve:

```text
filename
full path
SHA256
creation time
modification time
execution status
```

Pay particular attention to files placed in newly excluded directories.

---

## Network Correlation

Review network activity around the Defender modification.

Useful telemetry includes:

- DNS;
- firewall logs;
- proxy logs;
- EDR network events;
- TLS telemetry.

Example:

```text
PowerShell
        ↓
Defender disabled
        ↓
outbound connection
        ↓
remote payload retrieved
```

This sequence should raise investigation priority.

---

## Persistence Follow-Up

After weakening defenses, an attacker may establish persistence.

Look for:

- scheduled tasks;
- services;
- startup entries;
- Run/RunOnce registry keys;
- WMI subscriptions;
- new local accounts;
- local administrator membership changes.

Example:

```text
DET-006
Defender weakened
        ↓
DET-007-like behavior
scheduled task created
```

Cross-detection correlation increases confidence.

---

## Credential-Access Follow-Up

Review for subsequent credential-access activity such as:

- LSASS access;
- SAM or SECURITY hive access;
- credential-dumping tools;
- browser credential theft;
- token manipulation.

Example:

```text
Defender disabled
        ↓
LSASS accessed
```

This combination should generally be treated as high severity.

---

## Defense Evasion Chaining

Attackers may combine multiple evasion techniques.

Look for:

- Defender disablement;
- AMSI bypass;
- ETW bypass;
- event-log clearing;
- firewall changes;
- EDR service stopping;
- process injection;
- obfuscated PowerShell.

Multiple defensive impairments occurring together are substantially more concerning than one isolated configuration change.

---

## Escalation Indicators

Escalate when one or more of the following are present:

- the Defender change was unauthorized;
- real-time monitoring was disabled;
- behavior monitoring was disabled;
- broad exclusions were added;
- PowerShell was launched by an unusual parent;
- the user is not expected to administer Defender;
- the command is encoded or obfuscated;
- malware executes immediately afterward;
- a downloaded payload executes from an excluded location;
- suspicious network traffic follows;
- persistence is established;
- credential-access activity follows;
- Defender or EDR alerts appear nearby;
- multiple endpoints show similar changes;
- the setting is not restored.

---

## False Positives

Potential legitimate causes include:

- endpoint troubleshooting;
- software installation;
- application compatibility testing;
- malware-analysis laboratories;
- approved penetration testing;
- configuration-management automation;
- temporary vendor exclusions;
- authorized security administration.

To close as benign, validate:

```text
Who made the change
+
Why it was required
+
What setting changed
+
What scope was affected
+
Whether the change was approved
+
Whether protection was restored
```

---

## Suggested Triage Flow

```text
DET-006 Alert
     |
     v
Identify user + endpoint
     |
     v
Review full command line
     |
     v
Identify Defender setting changed
     |
     v
Review parent process
     |
     v
Was the change authorized?
     |
     +---- Yes -----------------------+
     |                                |
     |                       Validate business context
     |
     v
Check exclusions / disable flags
     |
     v
Check Defender state
     |
     v
Review processes and files afterward
     |
     v
Review network activity
     |
     v
Check persistence / credential access
     |
     v
Determine benign vs suspicious
```

---

## Analyst Decision

### Benign / Expected

Close as benign when:

- the change is authorized;
- the actor is expected;
- the command is part of documented administration or troubleshooting;
- exclusions are narrowly scoped and justified;
- no suspicious follow-on activity exists;
- protection is restored where the change was temporary.

Document the business justification.

### Suspicious

Escalate when:

- authorization cannot be confirmed;
- the user is unexpected;
- the command disables important protections;
- broad exclusions are added;
- the parent process is unusual;
- suspicious scripts or binaries execute afterward;
- related security alerts exist.

### Confirmed or Probable Compromise

Treat as probable or confirmed compromise when Defender weakening is associated with:

- malware execution;
- credential dumping;
- persistence;
- lateral movement;
- malicious PowerShell;
- EDR tampering;
- suspicious outbound communication;
- unauthorized privileged activity.

Potential response actions may include:

- isolate the affected endpoint;
- restore Defender protections;
- remove unauthorized exclusions;
- terminate malicious processes;
- quarantine malicious files;
- reset compromised credentials where justified;
- revoke active sessions;
- hunt for similar configuration changes;
- preserve forensic evidence;
- escalate according to the incident-response process.

---

## Evidence to Preserve

Collect and preserve:

- full PowerShell command line;
- PowerShell executable path;
- process ID;
- parent process and parent PID;
- user account;
- hostname;
- timestamp;
- Defender setting modified;
- exclusion path/process/extension;
- Defender operational events;
- process tree;
- created or downloaded files;
- SHA256 hashes;
- network connections;
- DNS queries;
- related PowerShell events;
- EDR alerts;
- persistence events;
- credential-access indicators;
- analyst timeline.

---

## Example Detection Scenario

### Process Event

```text
EventID:
4688

Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

CommandLine:
powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true

User:
LAB\test-user

Computer:
WIN11-LAB
```

### Detection Reason

```text
PowerShell
        +
Defender configuration modification
        +
real-time monitoring disable flag
        =
DET-006 match
```

### Expected Analyst Action

Determine whether the security-control change was authorized, investigate the executing user and parent process, verify the Defender protection state, and review all endpoint and network activity that followed.

---

## Detection Limitations

DET-006 intentionally focuses on PowerShell-based Defender modifications.

It may miss:

- Defender changes made through registry modification;
- Group Policy;
- WMI;
- management APIs;
- third-party tools;
- direct service manipulation;
- tampering where process command-line telemetry is unavailable.

It may also generate false positives from legitimate security administration.

Production deployments should combine process telemetry with Defender-specific configuration events where possible.

---

## Detection Engineering Notes

DET-006 adds **defense-evasion detection** to the portfolio.

Current coverage now includes:

```text
DET-001 — Encoded PowerShell execution
DET-002 — PowerShell download behavior
DET-003 — Repeated authentication failures
DET-004 — Failures followed by successful authentication
DET-005 — Local administrator privilege assignment
DET-006 — Defender protection modification
```

This expands the project across:

- Execution
- Credential Access
- Valid Account abuse
- Persistence
- Privilege Escalation
- Defense Evasion

Positive and negative fixtures should remain version-controlled so future changes to the matcher cannot silently broaden or break DET-006.

---

## Recommended Production Refinement

A production-quality detector should avoid treating every use of:

```text
Set-MpPreference
```

or:

```text
Add-MpPreference
```

as equally suspicious.

Prefer logic that combines the cmdlet with risky parameters, for example:

```text
Set-MpPreference
        +
-DisableRealtimeMonitoring $true
```

or:

```text
Add-MpPreference
        +
-ExclusionPath
```

This reduces false positives and better represents actual impairment of protections.

---

## Final Analyst Principle

> A Defender configuration change is a security-control event, not a compromise verdict. Its significance depends on who made the change, what protection was weakened, whether the action was authorized, and what occurred on the endpoint immediately afterward.
