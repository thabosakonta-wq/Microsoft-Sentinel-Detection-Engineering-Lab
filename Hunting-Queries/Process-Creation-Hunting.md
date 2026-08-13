# Process Creation Hunting

## Hunting Objective

Identify potentially suspicious process execution using Windows process creation telemetry.

This hunting content focuses on behavioral relationships rather than treating individual process names as inherently malicious.

The objective is to identify:

* Suspicious parent-child process relationships
* PowerShell execution
* Windows command-shell execution
* Scripting-engine activity
* Office-to-command execution
* Browser-to-command execution
* Processes launched from user-writable locations
* Suspicious command-line arguments
* Encoded PowerShell execution
* Download and execution activity
* Unusual administrative activity
* Cross-host process activity
* Potential post-compromise execution

This hunting content complements:

`Detection-Rules/Process-Creation-Monitoring.md`

and

`Detection-Rules/Suspicious-PowerShell.md`

---

## MITRE ATT&CK

Primary techniques:

* **T1059 — Command and Scripting Interpreter**
* **T1059.001 — PowerShell**
* **T1059.003 — Windows Command Shell**
* **T1204.002 — Malicious File**
* **T1105 — Ingress Tool Transfer**
* **T1027 — Obfuscated Files or Information**

Potential execution-related techniques may also include:

* **T1218 — System Binary Proxy Execution**
* **T1218.005 — Mshta**
* **T1218.010 — Regsvr32**
* **T1218.011 — Rundll32**

---

## Data Source

Primary telemetry:

* Windows Security Event Log
* Microsoft Sentinel `SecurityEvent`
* Event ID **4688 — A new process has been created**

Useful fields include:

* `TimeGenerated`
* `Computer`
* `Account`
* `NewProcessName`
* `ProcessCommandLine`
* `ParentProcessName`

Additional telemetry may include:

* Microsoft Defender for Endpoint
* Sysmon
* PowerShell Script Block Logging
* Network telemetry
* File creation telemetry
* Microsoft Defender Antivirus events

---

# Hunt 1 — Process Creation Baseline

Establish a baseline of process execution across monitored endpoints.

```kql
SecurityEvent
| where EventID == 4688
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ProcessCommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

### Hunting Purpose

This provides the foundational process execution dataset.

Analysts can use it to understand:

* Which processes are executing
* Which accounts are executing them
* Which systems are affected
* Which parent processes are involved
* What command-line arguments were supplied

---

# Hunt 2 — PowerShell Process Execution

Identify PowerShell activity for proactive investigation.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ProcessCommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

### Investigation Focus

Determine:

* Whether the PowerShell activity is expected
* Who initiated it
* Which process launched PowerShell
* What command was executed
* Whether external resources were accessed
* Whether additional processes were created

---

# Hunt 3 — Suspicious PowerShell Command Lines

Identify PowerShell executions containing commonly investigated behavioral indicators.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend CommandLine = tolower(tostring(ProcessCommandLine))
| where CommandLine contains "-encodedcommand"
    or CommandLine contains " -enc "
    or CommandLine contains "executionpolicy bypass"
    or CommandLine contains "-noprofile"
    or CommandLine contains "invoke-expression"
    or CommandLine contains "downloadstring"
    or CommandLine contains "net.webclient"
    or CommandLine contains "invoke-webrequest"
    or CommandLine contains "frombase64string"
    or CommandLine contains "start-bitstransfer"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ProcessCommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

### Hunting Purpose

This hunt identifies PowerShell command-line characteristics that warrant additional investigation.

A match is not proof of malicious activity.

---

# Hunt 4 — Office Application Spawning PowerShell

Identify PowerShell launched by Microsoft Office applications.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend ParentProcess = tolower(tostring(ParentProcessName))
| where ParentProcess contains "winword.exe"
    or ParentProcess contains "excel.exe"
    or ParentProcess contains "outlook.exe"
    or ParentProcess contains "powerpnt.exe"
    or ParentProcess contains "msaccess.exe"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ProcessCommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

### Investigation Priority

Office-to-PowerShell execution should receive additional attention when combined with:

* Encoded commands
* Download activity
* External network connections
* Temporary-file execution
* Newly created scripts
* Unusual user accounts

---

# Hunt 5 — Browser Spawning PowerShell

Identify potentially unusual browser-to-PowerShell relationships.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend ParentProcess = tolower(tostring(ParentProcessName))
| where ParentProcess contains "chrome.exe"
    or ParentProcess contains "msedge.exe"
    or ParentProcess contains "firefox.exe"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ProcessCommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

### Investigation Guidance

Browser-to-PowerShell relationships are not automatically malicious.

Determine whether:

* The user intentionally launched a tool
* A browser extension or management application is involved
* The activity followed a download
* The process was launched from a temporary location
* Additional suspicious processes were created

---

# Hunt 6 — Command Shell and Scripting Engines

Identify common command and scripting interpreters.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "cmd.exe"
    or NewProcessName endswith "wscript.exe"
    or NewProcessName endswith "cscript.exe"
    or NewProcessName endswith "mshta.exe"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ProcessCommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

### Investigation Focus

Investigate:

* Parent process
* Command-line arguments
* Script location
* User account
* Network activity
* Child processes

---

# Hunt 7 — Proxy Execution Utilities

Identify potentially suspicious use of Windows utilities frequently investigated during endpoint incidents.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "rundll32.exe"
    or NewProcessName endswith "regsvr32.exe"
    or NewProcessName endswith "mshta.exe"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ProcessCommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

### MITRE ATT&CK Context

These utilities may be associated with **System Binary Proxy Execution**.

Investigate the command line, referenced files, parent process and network activity before determining whether the execution is suspicious.

---

# Hunt 8 — Processes Executing From User-Writable Locations

Identify processes executing from locations commonly writable by users or applications.

```kql
SecurityEvent
| where EventID == 4688
| extend ProcessPath = tolower(tostring(NewProcessName))
| where ProcessPath contains "\\users\\"
    or ProcessPath contains "\\appdata\\"
    or ProcessPath contains "\\temp\\"
    or ProcessPath contains "\\windows\\temp\\"
    or ProcessPath contains "\\downloads\\"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ProcessCommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

### Investigation Guidance

Pay particular attention to:

* Newly created executables
* Random-looking filenames
* Script interpreters
* Temporary directories
* Processes launched shortly after downloads
* Executables launched by Office applications

Execution from a user-writable location is not inherently malicious.

---

# Hunt 9 — Suspicious Parent-Child Process Relationships

Identify unusual parent-child combinations.

```kql
SecurityEvent
| where EventID == 4688
| extend
    ChildProcess = tolower(tostring(NewProcessName)),
    ParentProcess = tolower(tostring(ParentProcessName))
| where
    (ChildProcess contains "powershell.exe"
        and ParentProcess contains "winword.exe")
    or
    (ChildProcess contains "powershell.exe"
        and ParentProcess contains "excel.exe")
    or
    (ChildProcess contains "powershell.exe"
        and ParentProcess contains "outlook.exe")
    or
    (ChildProcess contains "cmd.exe"
        and ParentProcess contains "winword.exe")
    or
    (ChildProcess contains "mshta.exe"
        and ParentProcess contains "winword.exe")
    or
    (ChildProcess contains "powershell.exe"
        and ParentProcess contains "w3wp.exe")
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ProcessCommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

### Hunting Purpose

Parent-child relationships can provide stronger behavioral context than the process name alone.

---

# Hunt 10 — Rare Process Executions

Identify processes with low execution frequency.

```kql
SecurityEvent
| where EventID == 4688
| summarize
    ExecutionCount = count(),
    Hosts = dcount(Computer),
    Accounts = dcount(Account),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by NewProcessName
| where ExecutionCount <= 3
| order by FirstSeen desc
```

### Investigation Guidance

Rare processes should be investigated when they are:

* Newly observed
* Executed by unusual accounts
* Located in user-writable paths
* Associated with suspicious parents
* Associated with suspicious command lines

Rarity alone does not indicate malicious activity.

---

# Hunt 11 — Processes Executed by Unusual Accounts

Identify process activity associated with accounts that may warrant additional review.

```kql
SecurityEvent
| where EventID == 4688
| where isnotempty(Account)
| summarize
    ExecutionCount = count(),
    Processes = make_set(NewProcessName, 30),
    Hosts = make_set(Computer, 30)
    by Account
| order by ExecutionCount desc
```

### Investigation Guidance

Prioritize accounts when:

* A service account launches interactive tools
* A privileged account launches unusual processes
* A newly observed account executes administrative utilities
* The account is not normally associated with the affected endpoint

---

# Hunt 12 — Process Creation Across Multiple Hosts

Identify processes observed across multiple endpoints.

```kql
SecurityEvent
| where EventID == 4688
| summarize
    ExecutionCount = count(),
    HostCount = dcount(Computer),
    Hosts = make_set(Computer, 30),
    Accounts = make_set(Account, 30)
    by NewProcessName
| where HostCount >= 5
| order by HostCount desc
```

### Hunting Purpose

This establishes process prevalence across the environment.

A newly observed process appearing on many endpoints may represent:

* Legitimate software deployment
* Security tooling
* Enterprise management
* A common application
* Malware propagation

The analyst must establish context.

---

# Hunt 13 — PowerShell Download and Execution Chain

Search for PowerShell executions associated with download behavior.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend CommandLine = tolower(tostring(ProcessCommandLine))
| where CommandLine contains "downloadstring"
    or CommandLine contains "invoke-webrequest"
    or CommandLine contains "net.webclient"
    or CommandLine contains "start-bitstransfer"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ProcessCommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

### Investigation Guidance

Correlate the event with:

* Network connections
* DNS queries
* File creation
* Antivirus detections
* Subsequent process creation
* Persistence

---

# Hunt 14 — Encoded PowerShell

Identify PowerShell executions containing encoded command indicators.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend CommandLine = tolower(tostring(ProcessCommandLine))
| where CommandLine contains "-encodedcommand"
    or CommandLine contains " -enc "
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ProcessCommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

### Investigation Guidance

Encoded PowerShell requires command-line decoding and contextual analysis.

Investigate:

* Decoded command content
* Parent process
* Account
* Host
* Network connections
* File creation
* Subsequent child processes

Encoding alone does not prove malicious intent.

---

# Hunt 15 — Process Activity After Successful Authentication

Correlate successful authentication with subsequent process creation.

```kql
let SuccessfulLogons =
    SecurityEvent
    | where EventID == 4624
    | project
        LogonTime = TimeGenerated,
        Account,
        Computer;

let Processes =
    SecurityEvent
    | where EventID == 4688
    | project
        ProcessTime = TimeGenerated,
        Account,
        Computer,
        NewProcessName,
        ProcessCommandLine,
        ParentProcessName;

SuccessfulLogons
| join kind=inner Processes on Account, Computer
| where ProcessTime between (LogonTime .. LogonTime + 30m)
| project
    LogonTime,
    ProcessTime,
    Account,
    Computer,
    NewProcessName,
    ProcessCommandLine,
    ParentProcessName
| order by LogonTime desc
```

### Investigation Priority

Increase priority when the post-authentication process is:

* PowerShell
* cmd.exe
* mshta.exe
* rundll32.exe
* regsvr32.exe
* An executable from a temporary directory
* A previously unseen process

---

# Correlation Strategy

Process hunting should not be performed in isolation.

Correlate process creation with:

## Authentication

Look for:

* Failed authentication
* Successful authentication
* Privileged authentication
* New source systems
* Remote logons

## PowerShell

Look for:

* Encoded commands
* Execution-policy bypass
* Download activity
* Base64 decoding
* `Invoke-Expression`

## Network

Look for:

* New outbound connections
* External IP addresses
* Suspicious destinations
* DNS lookups
* Remote administration traffic

## File Activity

Look for:

* Newly created executables
* Scripts
* DLLs
* Temporary files
* Downloaded content

## Persistence

Look for:

* Scheduled tasks
* New services
* Registry Run keys
* Startup items
* New user accounts

---

# Example Suspicious Execution Chain

A potentially suspicious sequence could resemble:

```text
User Authentication
       |
       v
WINWORD.EXE
       |
       v
PowerShell
       |
       +---- EncodedCommand
       |
       +---- DownloadString
       |
       v
Executable Created
       |
       v
New Process
       |
       v
Persistence
```

This sequence represents a stronger investigative signal than any individual event.

---

# False Positive Considerations

Legitimate process creation can result from:

* System administration
* Software installation
* Software updates
* Endpoint management
* Security tooling
* Scheduled tasks
* Automation
* Configuration management
* Developer activity
* IT support

Common legitimate PowerShell activity should not automatically be treated as malicious.

---

# Tuning Recommendations

Production implementations should consider:

* Approved administrative accounts
* Approved management servers
* Software deployment systems
* Endpoint security products
* Known automation scripts
* Developer workstations
* Approved PowerShell automation
* Known parent-child relationships

Reference tables and allowlists can reduce repeated false positives.

Avoid broad exclusions such as excluding all PowerShell activity.

---

# Severity Guidance

## Low

* Common process
* Known account
* Known endpoint
* Expected administrative activity

## Medium

* Unusual process
* Rare execution
* Unexpected parent process
* User-writable execution path

## High

* Office-to-PowerShell execution
* Encoded PowerShell
* Download-and-execute behavior
* Suspicious proxy execution utility
* Process activity following unusual authentication

## Critical

Consider critical escalation when process activity is correlated with:

* Confirmed credential compromise
* Persistence
* Lateral movement
* Malicious payload execution
* Command-and-control activity
* Security-tool tampering

---

# Analyst Investigation Workflow

When suspicious process creation is identified:

1. Identify the endpoint.
2. Identify the executing account.
3. Identify the process.
4. Review the complete command line.
5. Identify the parent process.
6. Identify any child processes.
7. Review the executable path.
8. Determine whether the process is known.
9. Search for the process across other hosts.
10. Review authentication activity.
11. Review PowerShell activity.
12. Review network connections.
13. Review file creation.
14. Search for persistence.
15. Determine whether the activity is legitimate or suspicious.
16. Document findings.
17. Escalate or contain according to incident-response procedures.

---

# Investigation Questions

Analysts should ask:

* Who executed the process?
* On which endpoint?
* When did execution occur?
* What launched the process?
* What command-line arguments were supplied?
* Where was the executable located?
* Is the executable normally present?
* Has this process appeared elsewhere?
* Was the account recently authenticated?
* Were there preceding failed logons?
* Did the process access the network?
* Did it create files?
* Did it spawn additional processes?
* Did it establish persistence?
* Did it interact with security tooling?

---

# Hunting Limitations

Event ID 4688 provides useful process creation information but visibility depends on Windows audit configuration.

Detection quality may improve when combined with:

* Command-line auditing
* Sysmon
* Microsoft Defender for Endpoint
* PowerShell Script Block Logging
* Network telemetry
* DNS telemetry
* File telemetry

Some process relationships may not be fully visible using Security Event 4688 alone.

---

# Validation

Testing should be performed only in an authorized lab environment.

Recommended validation scenarios:

* Normal PowerShell administration
* PowerShell launched from `cmd.exe`
* Encoded PowerShell
* Execution-policy bypass
* Office-to-PowerShell execution
* Suspicious temporary-directory execution
* Legitimate software installation
* Scheduled administrative scripts

For each scenario document:

* Expected result
* Actual result
* Hunting query
* Detection value
* False-positive assessment
* Required tuning

---

# Detection Engineering Relationship

This hunting content complements:

`Detection-Rules/Process-Creation-Monitoring.md`

and

`Detection-Rules/Suspicious-PowerShell.md`

The workflow is:

```text
Windows Process Creation
          |
          v
Process Creation Detection
          |
          v
Suspicious PowerShell Detection
          |
          v
Threat Hunting
          |
          v
Correlation
          |
          v
Investigation
          |
          v
Response / SOAR
```

Detection rules provide focused alerting.

Threat hunting provides broader proactive analysis and helps identify activity that may not meet the threshold of an individual detection rule.

---

# SOC Analyst Notes

Process names should not be treated as malicious or benign in isolation.

The strongest process-hunting signal usually comes from the combination of:

* Process
* Parent process
* Child process
* Command line
* Account
* Endpoint
* Execution path
* Authentication context
* Network activity
* File activity
* Persistence

Behavioral context is therefore more valuable than a simple executable-name blacklist.

---

# Portfolio Purpose

This hunting artifact demonstrates practical SOC threat-hunting methodology using Windows process creation telemetry and Microsoft Sentinel.

It demonstrates the ability to:

* Analyze process creation events
* Investigate parent-child relationships
* Hunt PowerShell execution
* Identify suspicious command-line behavior
* Identify execution from user-writable locations
* Investigate proxy execution utilities
* Correlate process activity with authentication
* Consider false positives
* Apply MITRE ATT&CK
* Develop investigation pivots
* Connect detection engineering with threat hunting and response

The presence of suspicious process activity does not by itself confirm compromise.

The analyst must establish intent, context, scope and supporting evidence.
