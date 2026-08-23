# DET-001 — Encoded PowerShell Execution

## Alert Description

This detection identifies PowerShell processes executed with encoded command-line parameters such as:

- `-enc`
- `-EncodedCommand`

Encoded PowerShell is not inherently malicious. Administrators, deployment tooling, and automation frameworks may use encoded commands legitimately. However, attackers frequently use encoded PowerShell to obscure command content, reduce readability, bypass simple string-based controls, and conceal malicious execution.

The alert should therefore be treated as an **investigative lead**, not automatic proof of compromise.

---

## Detection Objective

Identify PowerShell execution where the command line contains encoded-command arguments that may represent:

- obfuscated script execution;
- malicious payload delivery;
- defense evasion;
- post-exploitation activity;
- command-and-control execution;
- credential-access tooling;
- staged malware execution.

The goal is to surface encoded PowerShell activity for analyst review and contextual correlation.

---

## MITRE ATT&CK Mapping

### T1059.001 — Command and Scripting Interpreter: PowerShell

Adversaries may abuse PowerShell to execute commands and scripts.

### Related Tactic

- Execution

### Related Behavior

Encoded commands may also support:

- Defense Evasion
- Command and Control
- Credential Access
- Persistence

depending on the decoded content.

---

## Detection Logic

DET-001 looks for:

```text
PowerShell executable
        +
Encoded-command argument
        =
DET-001 match
```

Examples include:

```text
powershell.exe -EncodedCommand <Base64>
```

```text
powershell.exe -enc <Base64>
```

```text
pwsh.exe -EncodedCommand <Base64>
```

The detection is intended to identify the use of encoded command-line execution rather than judge the content as malicious by itself.

---

## Initial Triage

When DET-001 triggers, collect and review:

1. Hostname
2. User account
3. PowerShell process ID
4. Parent process
5. Full command line
6. Encoded payload
7. Decoded command content
8. Child processes
9. Network connections
10. Related PowerShell events
11. Endpoint detection alerts
12. Any persistence or security-control changes

---

## Key Questions

The analyst should determine:

- Is PowerShell usage expected on this endpoint?
- Does this user normally execute PowerShell?
- What launched PowerShell?
- What does the encoded content decode to?
- Does the decoded command retrieve remote content?
- Does it create or execute another process?
- Does it modify security controls?
- Does it create persistence?
- Does it access credentials or sensitive files?
- Are there related network connections?
- Is the activity isolated or occurring across multiple hosts?

---

## High-Risk Parent Processes

Increase investigation priority when encoded PowerShell is launched by unusual or user-facing applications such as:

```text
winword.exe
excel.exe
outlook.exe
powerpnt.exe
mshta.exe
wscript.exe
cscript.exe
rundll32.exe
regsvr32.exe
cmd.exe
```

Example suspicious process chain:

```text
winword.exe
    ↓
powershell.exe -EncodedCommand ...
    ↓
decoded malicious script
```

An Office application spawning encoded PowerShell should generally receive substantially more scrutiny than PowerShell launched from an approved administrative tool.

---

## Decode the Command

PowerShell `-EncodedCommand` content is commonly Base64-encoded UTF-16LE text.

The encoded value should be extracted and decoded in a controlled analysis environment.

### Example

Command line:

```text
powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA
```

The analyst should decode the Base64 value and inspect the resulting command.

### Review the Decoded Content For

- URLs
- IP addresses
- `Invoke-WebRequest`
- `DownloadString`
- `DownloadFile`
- `Invoke-Expression`
- `IEX`
- execution-policy bypass
- Defender modification
- credential-access commands
- registry persistence
- scheduled tasks
- encoded or nested PowerShell
- additional script execution
- file creation or execution
- reconnaissance commands

---

## Suspicious PowerShell Indicators

Common indicators that increase risk include:

```text
-EncodedCommand
-enc
-ExecutionPolicy Bypass
-WindowStyle Hidden
-NoProfile
-Noni
Invoke-Expression
IEX
DownloadString
DownloadFile
Invoke-WebRequest
Start-BitsTransfer
```

Combinations of these arguments are generally more significant than any single keyword.

Example:

```text
powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <Base64>
```

This pattern combines obfuscation with an attempt to reduce user visibility.

---

## Nested Encoding and Obfuscation

The decoded command may itself contain:

- another Base64 payload;
- compressed data;
- character substitution;
- string concatenation;
- environment-variable expansion;
- dynamically constructed commands;
- additional PowerShell invocation.

Example analysis flow:

```text
Encoded PowerShell
      ↓
Base64 decode
      ↓
Second encoded blob
      ↓
Decode again
      ↓
Final script
```

Analysts should continue decoding until the actual executable logic is understood.

---

## Network Correlation

Review network activity near the execution timestamp.

Useful telemetry includes:

- DNS logs;
- proxy logs;
- firewall logs;
- EDR network events;
- TLS inspection;
- web-filter logs.

Look for a sequence such as:

```text
Encoded PowerShell
        ↓
DNS lookup
        ↓
Outbound connection
        ↓
Remote payload retrieval
```

Network activity to an unknown or suspicious destination substantially increases the severity of the event.

---

## Child-Process Investigation

Identify any processes spawned by PowerShell.

Potentially suspicious child processes include:

```text
cmd.exe
rundll32.exe
regsvr32.exe
mshta.exe
wscript.exe
cscript.exe
schtasks.exe
reg.exe
certutil.exe
bitsadmin.exe
```

Example:

```text
powershell.exe -EncodedCommand ...
        ↓
cmd.exe
        ↓
payload.exe
```

Follow-on process creation is often more meaningful than the encoded PowerShell event alone.

---

## File-System Investigation

Determine whether the decoded command:

- created a file;
- downloaded a file;
- wrote a script;
- created a DLL or executable;
- modified a startup location;
- deleted artifacts after execution.

Preserve:

```text
filename
full path
SHA256
creation time
modification time
execution status
```

If a file was created or downloaded, review:

- endpoint prevalence;
- reputation;
- signature status;
- associated alerts;
- whether it executed afterward.

---

## Registry and Persistence Review

If the decoded script modifies the registry or scheduled tasks, investigate for persistence.

Potential areas include:

```text
Run / RunOnce keys
Scheduled Tasks
Services
Startup folders
PowerShell profiles
WMI subscriptions
```

Escalate when encoded PowerShell creates persistent execution mechanisms without a legitimate administrative explanation.

---

## Security-Control Modification

Review the decoded content for attempts to weaken endpoint defenses.

Examples include:

```text
Set-MpPreference
Add-MpPreference
DisableRealtimeMonitoring
AMSI bypass
ETW bypass
Defender exclusions
Firewall modification
```

Attempts to disable or bypass security controls should substantially increase investigation priority.

---

## Credential-Access Indicators

Escalate if the decoded content references:

- LSASS;
- credential dumping;
- SAM;
- SECURITY hive;
- browser credentials;
- tokens;
- password stores;
- authentication material.

Encoded PowerShell used for credential access is a high-priority event.

---

## Escalation Indicators

Escalate when one or more of the following are present:

- PowerShell is launched by Microsoft Office.
- The decoded command contacts unknown external infrastructure.
- The decoded content downloads or executes another payload.
- `IEX` or `Invoke-Expression` is used.
- Security controls are disabled or bypassed.
- Additional layers of obfuscation are present.
- Suspicious child processes are launched.
- Persistence is created.
- Credential-access behavior appears.
- The user does not normally execute PowerShell.
- The event occurs on a sensitive server.
- Similar encoded execution appears across multiple endpoints.
- The command purpose cannot be explained.

---

## False Positives

Legitimate activity may include:

- administrative automation;
- software deployment;
- configuration-management systems;
- endpoint-management tools;
- approved PowerShell scripts;
- enterprise maintenance workflows;
- developer automation.

A known administrator using encoded PowerShell should still be validated rather than automatically closed.

Review:

```text
User
+
Parent process
+
Decoded command
+
Business purpose
+
Host role
+
Follow-on activity
```

---

## Suggested Triage Flow

```text
DET-001 Alert
     |
     v
Identify user + endpoint
     |
     v
Review parent process
     |
     v
Extract encoded command
     |
     v
Decode Base64 content
     |
     v
Understand script behavior
     |
     +---- Approved administrative activity?
     |               |
     |              Yes
     |               |
     |       Validate business context
     |
     v
Check child processes
     |
     v
Check network activity
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

- the decoded command is fully understood;
- the activity belongs to an approved administrative workflow;
- the user or service account is expected;
- the parent process is expected;
- no suspicious follow-on activity exists;
- the command does not introduce unapproved persistence or security-control changes.

Document the business justification.

### Suspicious

Escalate when:

- the decoded command cannot be explained;
- execution originates from an unusual parent;
- the command contacts unfamiliar infrastructure;
- the script downloads or launches additional content;
- the command is heavily obfuscated;
- suspicious child processes appear;
- related endpoint or network alerts exist.

### Confirmed Malicious

Treat as malicious when the decoded content demonstrates attacker behavior such as:

- malware retrieval;
- credential dumping;
- persistence creation;
- defense evasion;
- unauthorized command execution;
- malicious outbound communication.

Potential response actions may include:

- isolate the endpoint;
- terminate malicious processes;
- block malicious domains/IPs;
- quarantine downloaded artifacts;
- disable or reset compromised accounts when justified;
- preserve forensic evidence;
- hunt for the same indicators across the environment;
- escalate according to the incident-response process.

---

## Evidence to Preserve

Collect and preserve:

- complete PowerShell command line;
- encoded payload;
- decoded content;
- process ID;
- parent process and parent PID;
- user account;
- hostname;
- timestamp;
- child processes;
- network connections;
- DNS queries;
- URLs and IP addresses;
- created or downloaded files;
- SHA256 hashes;
- registry changes;
- scheduled tasks;
- EDR alerts;
- related PowerShell events;
- relevant threat-intelligence results.

---

## Example Detection Scenario

### Process Event

```text
Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

CommandLine:
powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA

User:
LAB\test-user

Computer:
WIN11-LAB
```

### Detection Reason

```text
PowerShell executable
        +
Encoded-command argument
        =
DET-001 match
```

### Expected Analyst Action

The analyst should decode the Base64 payload, determine what the command does, inspect the parent process, and correlate any resulting endpoint or network activity.

---

## Detection Limitations

DET-001 intentionally focuses on obvious encoded-command arguments.

It may miss:

- custom obfuscation without `-EncodedCommand`;
- PowerShell invoked through another executable;
- scripts where command-line logging is unavailable;
- encoded content passed indirectly;
- malicious scripts executed from files rather than command-line arguments;
- alternative PowerShell hosts.

It may also alert on legitimate automation.

For this reason, DET-001 should be combined with additional detections and contextual telemetry rather than treated as a standalone compromise verdict.

---

## Detection Engineering Notes

The rule is designed to prioritize interpretability.

The detection intentionally separates:

```text
Executable context
        +
Encoded-command behavior
```

rather than attempting to classify all PowerShell as suspicious.

Positive and negative test events should be maintained alongside the rule so changes to the detection logic can be validated automatically through the Detection-as-Code pipeline.

---

## Final Analyst Principle

> Encoded PowerShell is not malicious by definition. Its significance depends on what the command decodes to, who executed it, what launched it, and what behavior followed.
