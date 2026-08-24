# DET-008 — Suspicious LSASS Process Access

## Alert Description

This detection identifies process-access activity targeting the Windows Local Security Authority Subsystem Service (`lsass.exe`) with access rights commonly associated with memory inspection.

LSASS is a high-value process because it handles authentication activity and may contain credential material in memory. Adversaries frequently target LSASS to obtain passwords, NTLM hashes, Kerberos material, or other authentication artifacts.

However, legitimate security software, endpoint detection tools, diagnostic utilities, and operating-system components may also access LSASS.

DET-008 should therefore be treated as a **high-priority credential-access signal requiring source-process validation and contextual correlation**, not automatic proof of credential dumping.

---

## Detection Objective

Identify suspicious process access to `lsass.exe`.

The current Detection-as-Code logic is conceptually:

```text
Sysmon Event ID 10
        +
TargetImage = lsass.exe
        +
suspicious GrantedAccess
        =
DET-008 match
```

The initial portfolio logic evaluates access masks such as:

```text
0x1010
0x1410
0x1438
0x1fffff
```

These values should be interpreted as investigative indicators rather than universal proof of malicious intent.

---

## MITRE ATT&CK Mapping

### T1003.001 — OS Credential Dumping: LSASS Memory

Adversaries may attempt to access LSASS process memory to obtain credentials.

### Parent Technique

- **T1003 — OS Credential Dumping**

### Primary Tactic

- Credential Access

Depending on surrounding activity, LSASS access may also support:

- Privilege Escalation
- Lateral Movement
- Defense Evasion

---

## Relevant Telemetry

DET-008 is modeled primarily on:

### Sysmon Event ID 10 — ProcessAccess

This event records one process opening another process with specified access rights.

Important fields may include:

- `SourceImage`
- `SourceProcessId`
- `SourceThreadId`
- `TargetImage`
- `TargetProcessId`
- `GrantedAccess`
- `CallTrace`
- `User`
- `Computer`
- timestamp

Field names can vary depending on the log pipeline or normalization schema.

---

## Initial Triage

When DET-008 triggers, collect and review:

1. Hostname
2. Timestamp
3. Source process
4. Source process path
5. Source PID
6. Target process
7. Target PID
8. Granted access mask
9. Source user
10. Parent process of the source
11. Source file hash
12. Digital signature
13. File prevalence
14. Process command line
15. Related EDR alerts
16. Recent privilege escalation
17. Defender or EDR tampering
18. Follow-on authentication or lateral movement

---

## Key Questions

The analyst should determine:

- What process accessed LSASS?
- Is that process expected to inspect LSASS?
- Is the source binary signed?
- Is the signer trusted?
- Is the executable located in a normal path?
- What parent process launched it?
- What access rights were requested?
- Did the source process create a dump file?
- Was the source process recently downloaded?
- Was Defender or EDR weakened beforehand?
- Did credential-related activity follow?
- Did the account authenticate to additional hosts afterward?
- Is the same behavior present on other endpoints?

---

## Why LSASS Matters

`lsass.exe` is a core Windows security process.

It is involved in:

- local security policy enforcement;
- authentication;
- access tokens;
- Kerberos;
- NTLM;
- credential-related operations.

Because of this role, LSASS is a common target for credential dumping.

A suspicious sequence may resemble:

```text
Initial compromise
        ↓
privilege escalation
        ↓
LSASS access
        ↓
credential extraction
        ↓
lateral movement
```

---

## Sysmon Event ID 10

Sysmon ProcessAccess telemetry helps identify cross-process access.

Example normalized event:

```text
EventID:
10

SourceImage:
C:\Users\Public\diagnostic.exe

TargetImage:
C:\Windows\System32\lsass.exe

GrantedAccess:
0x1010
```

The most important pivots are:

```text
SourceImage
+
TargetImage
+
GrantedAccess
+
process lineage
```

---

## Target Validation

Confirm that the target is actually:

```text
C:\Windows\System32\lsass.exe
```

A process merely containing the string `lsass` in another location should not automatically be treated as the real LSASS process.

Where possible, verify:

- target path;
- process ID;
- Windows service/process context;
- signer information.

---

## Source Process Analysis

The source process is usually the most important field.

Investigate:

```text
SourceImage
```

Examples requiring scrutiny may include:

```text
C:\Users\Public\tool.exe
C:\Temp\dump.exe
C:\Users\<user>\Downloads\unknown.exe
powershell.exe
rundll32.exe
procdump.exe
unknown unsigned binary
```

A legitimate-looking filename should not be trusted without validation.

---

## Legitimate LSASS Access

Some legitimate processes may access LSASS.

Possible categories include:

- endpoint detection and response agents;
- antivirus software;
- credential-protection software;
- Windows security components;
- forensic tools;
- approved diagnostic software.

For each source process, determine:

```text
Known binary?
+
Trusted signer?
+
Expected installation path?
+
Expected behavior on this endpoint?
```

---

## Access Mask Analysis

`GrantedAccess` represents the access rights requested against the target process.

The portfolio detection initially considers values such as:

```text
0x1010
0x1410
0x1438
0x1fffff
```

These access masks can be associated with process memory interaction.

However, access-mask interpretation is context-dependent.

Do not classify an event as malicious solely because one of these values appears.

Validate:

- source process;
- process path;
- signer;
- behavior;
- surrounding telemetry.

---

## Broad Access Rights

A broad access mask such as:

```text
0x1fffff
```

may represent extensive process access.

This should generally receive higher scrutiny when the source is:

- unsigned;
- uncommon;
- user-writable;
- newly downloaded;
- launched by PowerShell;
- associated with other suspicious behavior.

---

## Process Lineage

Review the parent process of the source.

Example suspicious chain:

```text
powershell.exe
        ↓
unknown.exe
        ↓
lsass.exe access
```

Another high-risk chain:

```text
winword.exe
        ↓
powershell.exe
        ↓
credential tool
        ↓
lsass.exe
```

Process ancestry can transform an ambiguous LSASS access event into a much stronger security signal.

---

## Command-Line Analysis

Review the source process command line.

Look for indicators associated with:

- process dumps;
- memory dumps;
- LSASS references;
- credential extraction;
- output file paths;
- mini-dump functions;
- known credential-dumping syntax.

Do not rely on a tool name alone.

Attackers can rename utilities.

---

## Dump File Investigation

Determine whether the process created a file after accessing LSASS.

Potential examples:

```text
lsass.dmp
memory.dmp
debug.dmp
temp.dmp
```

Collect:

```text
filename
full path
SHA256
file size
creation time
creator process
```

A process accessing LSASS and immediately creating a large dump file is substantially more suspicious than LSASS access alone.

---

## User-Writable Paths

Increase priority when the source process runs from:

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
C:\Users\Public\diagnostic.exe
        ↓
lsass.exe
```

User-writable paths are frequently abused for payload staging.

---

## Digital Signature Analysis

Determine:

- whether the binary is signed;
- who signed it;
- whether the signature is valid;
- whether the signer is expected;
- whether the binary matches known enterprise software.

An unsigned binary accessing LSASS should generally receive more scrutiny than a known and trusted security product.

A valid signature does not by itself prove benign behavior.

---

## File Reputation and Prevalence

Review:

- internal prevalence;
- first-seen timestamp;
- hash reputation;
- endpoint distribution;
- software inventory.

Questions include:

- Is this binary common across the organization?
- Did it appear only minutes before the event?
- Is it present on one endpoint only?
- Is the hash known to security tooling?

Low-prevalence LSASS access deserves increased attention.

---

## PowerShell Correlation

Review nearby PowerShell activity.

Relevant DET-001 and DET-002 behaviors include:

```text
Encoded PowerShell
PowerShell download cradle
```

Example suspicious chain:

```text
DET-002
PowerShell downloads executable
        ↓
executable starts
        ↓
DET-008
LSASS access
```

This is significantly stronger evidence than isolated LSASS access.

---

## Defender / EDR Correlation

Review whether endpoint defenses were modified before LSASS access.

Example:

```text
DET-006
Defender weakened
        ↓
DET-008
LSASS accessed
```

This sequence should receive high priority.

Look for:

- Defender exclusions;
- service stopping;
- EDR tampering;
- antivirus disablement;
- AMSI bypass;
- logging changes.

---

## Privilege Analysis

LSASS access may require elevated privileges depending on the access method and system configuration.

Determine:

- whether the source ran as administrator;
- whether the account recently gained local admin rights;
- whether token elevation occurred;
- whether UAC bypass behavior occurred;
- whether privileged group membership changed.

Example correlation:

```text
DET-005
user added to Administrators
        ↓
DET-008
same identity accesses LSASS
```

This is a strong escalation pattern.

---

## Credential-Dumping Follow-Up

After suspicious LSASS access, investigate for indications that credentials were actually used.

Look for:

- new successful logons;
- remote authentication;
- RDP;
- SMB;
- WinRM;
- service creation;
- authentication from unusual hosts;
- lateral movement.

Example:

```text
LSASS access
        ↓
credential obtained
        ↓
4624 on another host
```

---

## Lateral Movement Analysis

Review authentication activity after the event.

Potential indicators include:

- same account authenticating to multiple systems;
- remote service execution;
- administrative-share access;
- RDP sessions;
- WinRM;
- WMI;
- PsExec-like behavior.

Credential dumping often becomes more actionable when followed by lateral movement.

---

## CallTrace Analysis

If Sysmon provides:

```text
CallTrace
```

review it for unusual modules or memory-access patterns.

CallTrace data can help distinguish:

- known security software;
- unusual injected modules;
- abnormal access paths.

Interpretation can be highly environment-specific, so it should support rather than replace process-level analysis.

---

## Known-Tool Considerations

Credential-dumping activity may use:

- dedicated credential-dumping tools;
- memory-dump utilities;
- native APIs;
- renamed binaries;
- custom malware;
- signed tools abused for dumping.

Do not build triage around filenames alone.

Behavior is more reliable than tool naming.

---

## Escalation Indicators

Escalate when one or more of the following are present:

- source process is unsigned;
- source path is user-writable;
- source binary is newly observed;
- broad LSASS access rights are requested;
- source process was downloaded shortly beforehand;
- PowerShell launched the source;
- Defender or EDR was weakened first;
- a dump file is created;
- source process is unknown or deceptive;
- privileged access was recently granted;
- credential-related alerts occur;
- authentication to additional systems follows;
- similar LSASS access appears across multiple endpoints;
- the endpoint is a privileged workstation or sensitive server.

---

## False Positives

Potential legitimate causes include:

- EDR software;
- antivirus;
- endpoint security agents;
- approved forensic acquisition;
- memory diagnostics;
- security assessment tools;
- authorized incident-response tooling.

To close as benign, validate:

```text
Source process
+
Signer
+
Installation path
+
Business purpose
+
Expected behavior
+
No suspicious follow-on activity
```

---

## Suggested Triage Flow

```text
DET-008 Alert
     |
     v
Confirm TargetImage = lsass.exe
     |
     v
Identify SourceImage
     |
     v
Review GrantedAccess
     |
     v
Review signer + hash + path
     |
     v
Review parent process
     |
     v
Is source expected security software?
     |
     +---- Yes ---------------------+
     |                              |
     |                     Validate normal behavior
     |
     v
Check for dump file
     |
     v
Check Defender / EDR changes
     |
     v
Review authentication afterward
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

- the source process is known;
- the signer is trusted;
- the path is expected;
- LSASS access is documented behavior for that software;
- the activity is authorized;
- no suspicious follow-on behavior exists.

Document the validation.

### Suspicious

Escalate when:

- the source is unknown;
- the binary is unsigned;
- the source runs from a temporary or user-writable path;
- the access mask is unusually broad;
- the parent process is suspicious;
- PowerShell or another script interpreter launched the source;
- the activity cannot be explained.

### Confirmed or Probable Compromise

Treat as probable or confirmed compromise when LSASS access is associated with:

- dump-file creation;
- known credential-dumping behavior;
- Defender or EDR tampering;
- privilege escalation;
- malicious PowerShell;
- lateral movement;
- unauthorized successful authentication;
- credential reuse across systems.

Potential response actions may include:

- isolate the affected endpoint;
- terminate malicious processes;
- quarantine associated binaries;
- preserve dump files as evidence;
- reset exposed credentials where justified;
- revoke active sessions;
- investigate privileged-account exposure;
- hunt for credential reuse;
- restore weakened security controls;
- escalate according to the incident-response process.

---

## Evidence to Preserve

Collect and preserve:

- Sysmon Event ID 10 record;
- SourceImage;
- SourceProcessId;
- TargetImage;
- TargetProcessId;
- GrantedAccess;
- CallTrace;
- user;
- hostname;
- timestamp;
- source-process command line;
- parent process;
- source file hash;
- signer information;
- process tree;
- dump files;
- Defender/EDR events;
- PowerShell events;
- authentication events;
- network telemetry;
- related alerts;
- analyst timeline.

---

## Example Detection Scenario

### Process Access Event

```text
EventID:
10

SourceImage:
C:\Users\Public\diagnostic.exe

TargetImage:
C:\Windows\System32\lsass.exe

GrantedAccess:
0x1010

SourceUser:
LAB\test-user

Computer:
WIN11-LAB
```

### Detection Reason

```text
Sysmon Event ID 10
        +
Target = lsass.exe
        +
suspicious access mask
        =
DET-008 match
```

### Expected Analyst Action

Identify and validate the source process, inspect its signer and path, review its process lineage, determine whether a memory dump was created, and correlate the event with privilege changes, defense evasion, authentication, and lateral movement.

---

## Detection Limitations

DET-008 intentionally uses a simplified set of process-access masks for portfolio testing.

It may miss:

- credential dumping using different access rights;
- kernel-assisted credential access;
- direct system calls;
- minidump techniques that produce different telemetry;
- credential theft that does not access LSASS;
- activity where Sysmon ProcessAccess telemetry is unavailable.

It may also alert on legitimate security software.

Production deployments should baseline expected LSASS-accessing processes and combine:

```text
TargetImage
+
GrantedAccess
+
SourceImage
+
Signer
+
process lineage
+
environment-specific allowlisting
```

---

## Detection Engineering Notes

DET-008 adds dedicated **credential-access telemetry** to the Detection-as-Code portfolio.

Current coverage:

```text
DET-001 — Encoded PowerShell execution
DET-002 — PowerShell download behavior
DET-003 — Repeated authentication failures
DET-004 — Failures followed by successful authentication
DET-005 — Local administrator privilege assignment
DET-006 — Defender protection modification
DET-007 — Scheduled task creation
DET-008 — Suspicious LSASS process access
```

The project now demonstrates detection engineering across:

- Execution
- Credential Access
- Persistence
- Privilege Escalation
- Defense Evasion
- Authentication analytics

Positive and negative fixtures should remain version-controlled so future logic changes cannot silently broaden or break DET-008 behavior.

---

## Recommended Production Refinement

The portfolio matcher intentionally uses a small static set of access masks.

A stronger production detector should additionally consider:

```text
SourceImage reputation
+
code signing
+
known security-product allowlist
+
user-writable paths
+
parent process
+
CallTrace
+
dump-file creation
```

This reduces false positives and better separates ordinary endpoint-security behavior from genuine credential-dumping activity.

---

## Final Analyst Principle

> LSASS access is a credential-access opportunity, not a credential-dumping verdict. Its significance depends on which process accessed LSASS, what rights it requested, whether that process is trusted, how it was launched, and whether credential use or lateral movement followed.
