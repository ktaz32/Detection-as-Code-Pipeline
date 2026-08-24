# DET-007 — Suspicious Scheduled Task Creation

## Alert Description

This detection identifies Windows scheduled-task creation performed through `schtasks.exe` or PowerShell scheduled-task cmdlets.

Scheduled tasks are a legitimate Windows administration mechanism used for:

- maintenance;
- software deployment;
- backup operations;
- patching;
- monitoring;
- enterprise automation.

However, adversaries also abuse scheduled tasks to establish persistence, execute payloads, run code at logon or system startup, and execute with elevated privileges.

DET-007 should therefore be treated as a **high-priority persistence and execution signal requiring contextual investigation**, not automatic proof of compromise.

---

## Detection Objective

Identify newly created scheduled tasks that may be used for persistence, execution, or privilege escalation.

The current Detection-as-Code logic is conceptually:

```text
schtasks.exe
        +
task creation arguments
```

or:

```text
PowerShell
        +
scheduled-task creation cmdlets
        =
DET-007 match
```

Relevant command patterns include:

```text
schtasks.exe /create
Register-ScheduledTask
New-ScheduledTask
New-ScheduledTaskAction
New-ScheduledTaskTrigger
```

---

## MITRE ATT&CK Mapping

### T1053.005 — Scheduled Task/Job: Scheduled Task

Adversaries may abuse Windows Task Scheduler to execute programs at specified times or in response to specific events.

### Related Tactics

- Persistence
- Privilege Escalation
- Execution

Depending on task configuration and follow-on activity, scheduled tasks may also support Defense Evasion or Lateral Movement.

---

## Relevant Telemetry

DET-007 is designed primarily around Windows process-creation telemetry.

Useful sources include:

- Windows Security Event ID 4688;
- Sysmon Event ID 1;
- EDR process telemetry;
- Microsoft-Windows-TaskScheduler operational logs;
- PowerShell operational logs.

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

When DET-007 triggers, collect and review:

1. Hostname
2. User account
3. Full command line
4. Parent process
5. Process ID and parent PID
6. Timestamp
7. Task name
8. Task action
9. Trigger type
10. Account used to run the task
11. Run level
12. Referenced executable or script
13. Referenced file path
14. Whether the task actually executed
15. Whether the task is still present
16. Related PowerShell activity
17. Related EDR alerts
18. Network activity around task creation and execution

---

## Key Questions

The analyst should determine:

- Who created the scheduled task?
- Was the user expected to create tasks?
- What launched `schtasks.exe` or PowerShell?
- What is the task name?
- What command does the task execute?
- Where is the referenced payload stored?
- What trigger causes execution?
- Does the task run at logon or startup?
- Does it run as `SYSTEM` or another privileged account?
- Is the task hidden?
- Was the task created remotely?
- Did the task execute successfully?
- Did suspicious activity follow execution?
- Is the same task present on other endpoints?
- Is there a legitimate business reason for the task?

---

## Why Scheduled Tasks Matter

Task Scheduler can provide durable and flexible execution.

A scheduled task may execute:

- at system startup;
- at user logon;
- on a recurring schedule;
- when the system becomes idle;
- in response to an event;
- under a different security context.

A common adversary sequence may resemble:

```text
Initial access
        ↓
payload written to disk
        ↓
scheduled task created
        ↓
task executes payload
        ↓
persistence maintained
```

---

## `schtasks.exe` Analysis

`schtasks.exe` is a legitimate Windows binary used to manage scheduled tasks.

Task creation commonly uses:

```text
/create
```

Example:

```text
schtasks.exe /create /tn UpdateCheck /tr "powershell.exe -File C:\Users\Public\update.ps1" /sc onlogon
```

Important arguments include:

```text
/TN
Task name

/TR
Program or command to execute

/SC
Schedule type

/RU
Run-as user

/RL
Run level

/ST
Start time
```

The analyst should reconstruct the complete task configuration.

---

## PowerShell Scheduled-Task Analysis

PowerShell can create tasks using cmdlets such as:

```text
Register-ScheduledTask
New-ScheduledTask
New-ScheduledTaskAction
New-ScheduledTaskTrigger
New-ScheduledTaskPrincipal
```

Example:

```text
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\Users\Public\update.ps1"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "UpdateCheck" -Action $action -Trigger $trigger
```

Review the complete PowerShell command or script rather than judging a single cmdlet.

---

## High-Risk Trigger Types

Certain triggers deserve additional scrutiny.

### At Logon

Example:

```text
/sc onlogon
```

or PowerShell:

```text
New-ScheduledTaskTrigger -AtLogOn
```

This can provide persistence whenever a user signs in.

### At Startup

Example:

```text
/sc onstart
```

or:

```text
New-ScheduledTaskTrigger -AtStartup
```

Startup-triggered tasks can establish durable system-level persistence.

### Frequent Recurrence

Tasks configured to execute every minute or every few minutes may indicate automated persistence or beaconing.

### Event-Based Execution

Tasks triggered by system or security events can provide stealthier execution and should be examined carefully.

---

## Privileged Execution

Review whether the task executes as:

```text
SYSTEM
```

or another privileged identity.

Relevant `schtasks.exe` example:

```text
/RU SYSTEM
```

High run level may be specified with:

```text
/RL HIGHEST
```

A task created by a standard user but configured for elevated execution is particularly significant if the creation path indicates privilege abuse.

---

## Suspicious Task Actions

The task action is often the most important field.

Higher-risk actions may launch:

```text
powershell.exe
cmd.exe
rundll32.exe
regsvr32.exe
mshta.exe
wscript.exe
cscript.exe
certutil.exe
bitsadmin.exe
unknown executable
```

Example:

```text
Task:
UpdateCheck

Action:
powershell.exe -WindowStyle Hidden -File C:\Users\Public\update.ps1
```

The task name may look legitimate while the action is malicious.

Always investigate the action rather than relying on the name.

---

## User-Writable Paths

Increase scrutiny when the task executes content from locations such as:

```text
C:\Users\Public
C:\Users\<user>\AppData
C:\Users\<user>\Downloads
C:\Temp
%TEMP%
%APPDATA%
%LOCALAPPDATA%
```

These locations are commonly writable by users and are frequently abused for payload staging.

Example:

```text
schtasks.exe
        ↓
C:\Users\Public\update.ps1
```

This is more suspicious than a documented enterprise task executing a signed binary from `Program Files`.

---

## Hidden or Deceptive Tasks

Attackers may choose task names that imitate legitimate software.

Examples:

```text
WindowsUpdate
UpdateCheck
AdobeUpdate
ChromeUpdate
SystemMaintenance
Telemetry
OneDriveUpdate
```

A legitimate-looking task name is not sufficient evidence of legitimacy.

Investigate:

```text
Task name
+
Author
+
Action
+
Path
+
Trigger
+
Run account
+
Creation time
```

---

## Parent-Process Analysis

Review what launched `schtasks.exe` or PowerShell.

Expected parent processes may include:

- approved administration shells;
- deployment agents;
- enterprise management tooling;
- installers.

Higher-risk parents include:

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

Example:

```text
winword.exe
        ↓
powershell.exe
        ↓
schtasks.exe /create ...
```

This chain should receive immediate scrutiny.

---

## PowerShell Correlation

Review nearby PowerShell activity for:

- encoded commands;
- download cradles;
- `Invoke-WebRequest`;
- `DownloadString`;
- `IEX`;
- Defender modification;
- account manipulation.

Example suspicious sequence:

```text
DET-002
PowerShell download
        ↓
payload written to C:\Users\Public
        ↓
DET-007
scheduled task created
```

Cross-detection correlation substantially increases confidence.

---

## File Investigation

If the task executes a script or binary, collect:

```text
filename
full path
SHA256
file size
creation time
modification time
digital signature
execution status
```

Determine:

- when the file appeared;
- what process created it;
- whether it is signed;
- whether it is common in the environment;
- whether it was downloaded externally;
- whether the task executed it.

---

## Network Correlation

Review network activity around:

- task creation;
- first task execution;
- subsequent task executions.

Useful telemetry includes:

- DNS;
- proxy logs;
- firewall logs;
- EDR network events.

Example:

```text
scheduled task executes
        ↓
powershell.exe starts
        ↓
outbound HTTPS connection
```

This may indicate persistence used to maintain command-and-control access.

---

## Task Scheduler Logs

Where available, review:

```text
Microsoft-Windows-TaskScheduler/Operational
```

Useful events can provide information on:

- task registration;
- task launch;
- action execution;
- task completion;
- errors.

Event IDs can vary by Windows version and collection configuration, so analysts should validate the local environment's telemetry.

---

## Security Event Correlation

Depending on audit configuration, useful Windows Security events may include task creation-related activity.

Correlate process telemetry with:

- account logons;
- privilege use;
- process creation;
- task execution;
- service creation;
- account changes.

Do not rely on a single telemetry source where multiple sources are available.

---

## Remote Scheduled Task Creation

Scheduled tasks can be created remotely.

Investigate whether the task was associated with:

- remote administrative sessions;
- SMB;
- RPC;
- remote PowerShell;
- PsExec-like activity;
- RDP;
- compromised administrative credentials.

Example:

```text
remote authentication
        ↓
schtasks.exe /create
        ↓
task runs payload
```

This may indicate lateral movement.

---

## Persistence Follow-Up

Determine whether the task remains configured after execution.

Review:

- task creation time;
- task last-run time;
- next-run time;
- task modification;
- task deletion.

Attackers may create a task, execute it, and remove it quickly to reduce evidence.

Short-lived tasks can still represent malicious execution.

---

## Privilege Escalation Considerations

A scheduled task may be used to execute with higher privileges than the creating process.

Investigate:

- task principal;
- run level;
- creator privileges;
- whether credentials were supplied;
- whether a privileged account owns the task.

Unauthorized execution as `SYSTEM` should receive high priority.

---

## Defense Evasion Follow-Up

After task creation, look for:

- Defender disablement;
- EDR tampering;
- log clearing;
- PowerShell obfuscation;
- deletion of the task definition;
- payload cleanup.

Example:

```text
scheduled task created
        ↓
payload runs
        ↓
task deleted
        ↓
logs cleared
```

This sequence is strongly suspicious.

---

## Escalation Indicators

Escalate when one or more of the following are present:

- task creation is unauthorized;
- the action launches PowerShell or another interpreter;
- the payload resides in a user-writable directory;
- the task runs at logon or startup;
- the task runs as `SYSTEM`;
- `/RL HIGHEST` is used unexpectedly;
- the parent process is unusual;
- the task name appears deceptive;
- the referenced file is unsigned or unknown;
- a remote source created the task;
- suspicious network activity follows;
- Defender or EDR is modified;
- credential-access activity follows;
- the task appears across multiple endpoints;
- the task is quickly deleted after execution.

---

## False Positives

Potential legitimate causes include:

- software installation;
- enterprise management tooling;
- endpoint deployment;
- backup software;
- patching;
- scheduled maintenance;
- approved administrative automation;
- monitoring agents.

To close as benign, validate:

```text
Who created the task
+
Why it exists
+
What it executes
+
When it runs
+
Which account runs it
+
Whether the activity is approved
```

---

## Suggested Triage Flow

```text
DET-007 Alert
     |
     v
Identify host + user
     |
     v
Review full creation command
     |
     v
Extract task name
     |
     v
Extract action + payload path
     |
     v
Review trigger
     |
     v
Review run account / privilege
     |
     v
Was task creation authorized?
     |
     +---- Yes ----------------------+
     |                               |
     |                      Validate business context
     |
     v
Investigate referenced file/script
     |
     v
Check task execution
     |
     v
Review network activity
     |
     v
Check persistence / defense evasion
     |
     v
Determine benign vs suspicious
```

---

## Analyst Decision

### Benign / Expected

Close as benign when:

- task creation is authorized;
- the creator is expected;
- the task name and purpose are documented;
- the payload is trusted;
- the trigger and run account are appropriate;
- no suspicious follow-on behavior exists.

Document the business justification.

### Suspicious

Escalate when:

- authorization cannot be confirmed;
- the task launches an unusual interpreter;
- the payload is in a user-writable path;
- the task runs at logon or startup unexpectedly;
- the task runs with elevated privileges;
- the parent process is suspicious;
- related endpoint or network alerts exist.

### Confirmed or Probable Compromise

Treat as probable or confirmed compromise when task creation is associated with:

- malicious payload execution;
- persistence;
- command-and-control activity;
- privilege escalation;
- credential dumping;
- defense evasion;
- lateral movement.

Potential response actions may include:

- disable or remove the malicious task;
- isolate affected endpoints;
- terminate malicious processes;
- quarantine associated files;
- block malicious infrastructure;
- restore weakened security controls;
- reset compromised credentials where justified;
- hunt for the same task across the environment;
- preserve forensic evidence;
- escalate according to incident-response procedures.

---

## Evidence to Preserve

Collect and preserve:

- complete task-creation command line;
- task name;
- task action;
- task trigger;
- task run account;
- run level;
- creator user;
- hostname;
- timestamp;
- process ID;
- parent process and PID;
- task XML where available;
- referenced executable/script;
- file hash;
- Task Scheduler operational logs;
- process execution telemetry;
- network activity;
- PowerShell logs;
- EDR alerts;
- task deletion/modification events;
- analyst timeline.

---

## Example Detection Scenario

### Process Event

```text
EventID:
4688

Image:
C:\Windows\System32\schtasks.exe

CommandLine:
schtasks.exe /create /tn UpdateCheck /tr "powershell.exe -WindowStyle Hidden -File C:\Users\Public\update.ps1" /sc onlogon

User:
LAB\test-user

Computer:
WIN11-LAB
```

### Detection Reason

```text
schtasks.exe
        +
/create
        +
PowerShell task action
        +
logon trigger
        =
DET-007 match
```

### Expected Analyst Action

Determine whether the scheduled task was authorized, inspect the task configuration and referenced script, identify whether the task executed, and correlate subsequent endpoint and network activity.

---

## Detection Limitations

DET-007 intentionally focuses on task creation through visible `schtasks.exe` and PowerShell process telemetry.

It may miss:

- tasks created directly through Task Scheduler APIs;
- COM-based task registration;
- WMI-assisted mechanisms;
- activity where command-line telemetry is unavailable;
- malicious modification of an existing task rather than creation of a new one.

It may also generate false positives from legitimate enterprise automation.

Production deployments should combine process telemetry with Task Scheduler operational logs and task-registration telemetry where available.

---

## Detection Engineering Notes

DET-007 adds a dedicated **persistence** use case to the Detection-as-Code portfolio.

Current coverage:

```text
DET-001 — Encoded PowerShell execution
DET-002 — PowerShell download behavior
DET-003 — Repeated authentication failures
DET-004 — Failures followed by successful authentication
DET-005 — Local administrator privilege assignment
DET-006 — Defender protection modification
DET-007 — Scheduled task creation
```

The project now demonstrates:

- single-event behavioral detections;
- temporal authentication correlation;
- privilege-change monitoring;
- defense-evasion monitoring;
- persistence detection.

Positive and negative test fixtures should remain version-controlled so detection changes cannot silently break DET-007 behavior.

---

## Recommended Production Refinement

The initial detector identifies scheduled-task creation broadly.

A production-quality version should increase confidence by combining task creation with contextual risk factors such as:

```text
Task creation
        +
PowerShell/cmd/mshta/rundll32 action
```

or:

```text
Task creation
        +
user-writable payload path
```

or:

```text
Task creation
        +
ONLOGON / ONSTART trigger
```

or:

```text
Task creation
        +
SYSTEM / highest privileges
```

This provides better signal quality than treating all scheduled tasks as equally suspicious.

---

## Final Analyst Principle

> A newly created scheduled task is a persistence opportunity, not a compromise verdict. Its significance depends on who created it, what it executes, when it runs, under which security context, and what behavior follows execution.
