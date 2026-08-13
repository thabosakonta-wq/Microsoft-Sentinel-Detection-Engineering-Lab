# Process Creation Monitoring

## Detection Objective

Monitor Windows process creation events to identify potentially suspicious process execution, command-line activity, and parent-child process relationships using Microsoft Sentinel.

The detection uses Windows Security Event ID **4688 — A new process has been created** to provide visibility into process execution and identify characteristics that may warrant investigation.

---

## MITRE ATT&CK

Primary techniques represented by this detection include:

* **T1059 — Command and Scripting Interpreter**
* **T1059.001 — PowerShell**
* **T1059.003 — Windows Command Shell**
* **T1218 — System Binary Proxy Execution**

> **Note:** The presence of a mapped technique does not indicate that malicious activity was observed.

Event ID 4688 provides process creation telemetry. It should not be interpreted as direct evidence of **T1057 — Process Discovery**, which describes an adversary discovering running processes.

---

## Data Source

* Windows Security Event Log
* Event ID: **4688 — A new process has been created**
* Microsoft Sentinel `SecurityEvent`

Important fields include:

* `TimeGenerated`
* `Computer`
* `Account`
* `NewProcessName`
* `CommandLine`
* `ParentProcessName`

---

## Detection Architecture

The detection uses multiple analytical layers:

1. **Baseline process visibility**
2. **Suspicious process identification**
3. **Suspicious parent-child relationships**
4. **Command-line analysis**
5. **Unusual execution paths**
6. **Time-window aggregation**
7. **Analyst investigation and contextual validation**

This approach avoids treating every process creation event as malicious.

---

## Baseline Process Visibility

The following query provides broad visibility into process creation activity.

```kql
SecurityEvent
| where EventID == 4688
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    CommandLine,
    ParentProcessName
| order by TimeGenerated desc
```

### Purpose

This baseline query is useful for:

* Process investigation
* Incident timelines
* Threat hunting
* Detection development
* Establishing normal process behaviour
* Investigating suspicious execution chains

---

## Suspicious Process Execution Detection

The following query identifies commonly abused command and scripting interpreters.

```kql
SecurityEvent
| where EventID == 4688
| extend
    ProcessName = tolower(tostring(NewProcessName)),
    ParentProcess = tolower(tostring(ParentProcessName)),
    CmdLine = tostring(CommandLine)
| where ProcessName matches regex @"(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil)\.exe$"
| project
    TimeGenerated,
    Computer,
    Account,
    ProcessName,
    ParentProcess,
    CmdLine
| order by TimeGenerated desc
```

### Detection Purpose

The query highlights processes frequently associated with command execution, scripting, or proxy execution.

These processes are **not inherently malicious**.

The result requires contextual investigation.

---

## Suspicious PowerShell Execution

PowerShell deserves separate analysis because legitimate administrative activity and malicious post-compromise activity can both generate PowerShell process events.

```kql
SecurityEvent
| where EventID == 4688
| extend
    ProcessName = tolower(tostring(NewProcessName)),
    ParentProcess = tolower(tostring(ParentProcessName)),
    CmdLine = tostring(CommandLine)
| where ProcessName endswith @"\powershell.exe"
    or ProcessName endswith @"\pwsh.exe"
| extend
    SuspiciousIndicator =
        case(
            CmdLine contains "-enc", "EncodedCommand",
            CmdLine contains "-encodedcommand", "EncodedCommand",
            CmdLine contains "downloadstring", "DownloadString",
            CmdLine contains "invoke-webrequest", "InvokeWebRequest",
            CmdLine contains "iex", "InvokeExpression",
            CmdLine contains "frombase64string", "Base64",
            CmdLine contains "bypass", "ExecutionPolicyBypass",
            CmdLine contains "hidden", "HiddenWindow",
            "None"
        )
| project
    TimeGenerated,
    Computer,
    Account,
    ProcessName,
    ParentProcess,
    CmdLine,
    SuspiciousIndicator
| where SuspiciousIndicator != "None"
| order by TimeGenerated desc
```

### Important Detection Note

The indicators above are **heuristics** rather than proof of malicious PowerShell.

For example:

* `-EncodedCommand` can be used by legitimate automation.
* `Invoke-WebRequest` can be used by administrators.
* `-ExecutionPolicy Bypass` can occur in legitimate deployment tooling.

Additional context is required before classifying the activity as malicious.

---

## Suspicious Parent-Child Process Relationships

Parent-child relationships can provide important execution context.

The following query identifies potentially unusual relationships involving Office applications, scripting engines, and command interpreters.

```kql
SecurityEvent
| where EventID == 4688
| extend
    ProcessName = tolower(tostring(NewProcessName)),
    ParentProcess = tolower(tostring(ParentProcessName)),
    CmdLine = tostring(CommandLine)
| where
    (
        ParentProcess contains "winword.exe"
        or ParentProcess contains "excel.exe"
        or ParentProcess contains "outlook.exe"
        or ParentProcess contains "powerpnt.exe"
    )
    and
    (
        ProcessName contains "powershell.exe"
        or ProcessName contains "pwsh.exe"
        or ProcessName contains "cmd.exe"
        or ProcessName contains "wscript.exe"
        or ProcessName contains "cscript.exe"
        or ProcessName contains "mshta.exe"
    )
| project
    TimeGenerated,
    Computer,
    Account,
    ParentProcess,
    ProcessName,
    CmdLine
| order by TimeGenerated desc
```

### Investigation Value

Office applications spawning command interpreters may warrant investigation because malicious documents can be used to initiate execution chains.

However, legitimate enterprise automation can produce similar relationships.

---

## Suspicious Execution Paths

Executables launched from unusual user-writable locations can warrant additional investigation.

```kql
SecurityEvent
| where EventID == 4688
| extend
    ProcessPath = tolower(tostring(NewProcessName)),
    CmdLine = tostring(CommandLine)
| where
    ProcessPath contains @"\users\"
    or ProcessPath contains @"\appdata\"
    or ProcessPath contains @"\temp\"
    or ProcessPath contains @"\windows\temp\"
    or ProcessPath contains @"\downloads\"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ParentProcessName,
    CmdLine
| order by TimeGenerated desc
```

### Detection Rationale

Execution from locations such as:

* User profile directories
* `%AppData%`
* `%Temp%`
* `%Downloads%`

may be suspicious when combined with other indicators.

The location alone should not be considered malicious.

---

## Encoded and Obfuscated Command-Line Detection

Command-line obfuscation can be an important investigation signal.

```kql
SecurityEvent
| where EventID == 4688
| extend
    CmdLine = tostring(CommandLine),
    ProcessName = tostring(NewProcessName)
| where
    CmdLine contains "-enc"
    or CmdLine contains "-encodedcommand"
    or CmdLine contains "frombase64string"
    or CmdLine contains "IEX("
    or CmdLine contains "Invoke-Expression"
| project
    TimeGenerated,
    Computer,
    Account,
    ProcessName,
    ParentProcessName,
    CmdLine
| order by TimeGenerated desc
```

### Detection Consideration

Obfuscation indicators should be combined with:

* Parent process
* User account
* Host
* Network activity
* File activity
* Authentication events
* Endpoint security alerts

before assigning high confidence.

---

## Process Frequency Analysis

Repeated process creation within a short period can identify abnormal execution patterns.

```kql
SecurityEvent
| where EventID == 4688
| extend
    ProcessName = tostring(NewProcessName)
| summarize
    ProcessCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by
    TimeWindow = bin(TimeGenerated, 15m),
    Computer,
    Account,
    ProcessName
| where ProcessCount >= 10
| project
    TimeWindow,
    Computer,
    Account,
    ProcessName,
    ProcessCount,
    FirstSeen,
    LastSeen
| order by ProcessCount desc
```

### Purpose

This can identify:

* Process storms
* Repeated scripting execution
* Automated execution loops
* Suspicious command execution
* Potential malware activity

Thresholds should be tuned against normal endpoint behaviour.

---

## Detection Logic

The detection should prioritize process executions containing one or more contextual indicators:

| Indicator                         | Investigative Value |
| --------------------------------- | ------------------- |
| PowerShell execution              | Medium              |
| Encoded PowerShell                | High                |
| Office → PowerShell               | High                |
| Office → CMD                      | High                |
| Office → scripting engine         | High                |
| Execution from `%Temp%`           | Medium              |
| Execution from `%AppData%`        | Medium              |
| Unknown executable                | Medium              |
| Suspicious command-line arguments | High                |
| Repeated process creation         | Medium              |
| Unusual administrative account    | High                |

These values are investigative priorities rather than automatic classifications.

---

## Analyst Investigation

When suspicious process activity is identified, investigate:

### Process

* Process name
* Process path
* File reputation
* Process frequency
* Whether the executable is expected

### Command Line

Review:

* Arguments
* Encoded content
* URLs
* File paths
* Script names
* Download operations
* Execution-policy modifications
* Obfuscation

### Parent Process

Determine:

* Which process launched the activity
* Whether the parent-child relationship is expected
* Whether an Office application initiated execution
* Whether a scripting engine initiated the process

### Account

Determine:

* User identity
* Privileged status
* Whether the account normally performs the activity
* Whether the account is a service account

### Endpoint

Review:

* Hostname
* User activity
* Other process events
* Endpoint security alerts
* Network connections
* Recent authentication activity

---

## Correlation Opportunities

Process creation should be correlated with other telemetry where available.

Useful correlations include:

### Authentication

Correlate with:

* Event ID `4624`
* Event ID `4625`

This can identify whether suspicious process activity occurred after unusual authentication.

### PowerShell

Correlate process creation with:

* PowerShell logging
* Script Block Logging
* Module logging
* PowerShell operational events

### Network

Correlate with:

* Outbound connections
* DNS activity
* Suspicious destinations
* Download activity

### Endpoint Security

Correlate with:

* Microsoft Defender alerts
* Malware detections
* EDR telemetry
* File reputation

---

## False Positive Considerations

Process creation is normal Windows activity.

Legitimate examples include:

* Windows system processes
* Software applications
* Administrative tools
* Security software
* Software installation
* Scheduled tasks
* Enterprise deployment tools
* IT automation
* Legitimate PowerShell administration

Potential false-positive sources include:

* Software deployment platforms
* Configuration-management tools
* Backup software
* Monitoring agents
* Security products
* System administrators

Allowlisting should be performed carefully and preferably using stable contextual attributes rather than simply excluding process names.

---

## Severity

**Baseline Severity: Informational / Medium**

Increase severity when multiple suspicious indicators occur together.

### Higher-priority conditions

* Office application spawning PowerShell
* Encoded PowerShell combined with network activity
* Execution from a user-writable directory
* Unknown executable with suspicious command-line arguments
* Suspicious process launched by a privileged account
* Process creation following unusual authentication
* Correlation with endpoint security alerts
* Repeated suspicious execution on multiple endpoints

---

## Response Guidance

When suspicious process creation is confirmed:

1. Identify the process.
2. Identify the parent process.
3. Identify the executing account.
4. Review the command line.
5. Examine the executable path.
6. Review related process events.
7. Correlate authentication telemetry.
8. Review network activity.
9. Investigate potential persistence mechanisms.
10. Determine whether containment is required.
11. Document the investigation and conclusion.

---

## Detection Tuning

This detection should be tuned using representative enterprise telemetry.

Potential tuning strategies include:

* Known administrative tools
* Approved software paths
* Known deployment accounts
* Trusted parent-child relationships
* Enterprise automation platforms
* Security-product processes

Avoid broad exclusions such as:

```text
Exclude all PowerShell
Exclude all CMD
Exclude all administrative accounts
```

Such exclusions can significantly reduce detection coverage.

Prefer contextual suppression based on:

* Host
* Account
* Parent process
* Command-line pattern
* Software path
* Approved administrative workflow

---

## Detection Limitations

The effectiveness of Event ID 4688 monitoring depends on telemetry configuration.

Potential limitations include:

* Command-line auditing not being enabled
* Missing process creation events
* Incomplete Sentinel ingestion
* Inconsistent endpoint logging
* Legitimate software generating noisy process activity
* Obfuscated command lines
* Processes executed through alternative mechanisms
* Limited visibility into process ancestry

Additional Windows auditing and endpoint telemetry can improve detection fidelity.

---

## Validation Scenarios

The detection should be validated using controlled and authorised test scenarios.

### Scenario 1 — Normal Process Creation

A standard Windows application creates a child process.

**Expected result:**

The baseline process visibility query should capture the event without automatically classifying it as malicious.

### Scenario 2 — PowerShell Execution

A controlled PowerShell process is launched.

**Expected result:**

The PowerShell detection should identify the process for investigation.

### Scenario 3 — Encoded PowerShell

A controlled test generates an encoded PowerShell command.

**Expected result:**

The encoded-command heuristic should identify the activity.

### Scenario 4 — Office Child Process

A controlled test generates an Office application spawning a command interpreter.

**Expected result:**

The parent-child detection should identify the relationship.

### Scenario 5 — User-Writable Path

A controlled executable is launched from a temporary or user-writable directory.

**Expected result:**

The execution-path detection should identify the event.

---

## Detection Status

**Status:** Active Detection Design

**Detection Type:** Process Execution / Command-Line / Parent-Child Analysis

**Primary Event:** Windows Security Event ID `4688`

**Analytical Window:** 15 minutes for frequency-based analysis

**Default Severity:** Informational / Medium

---

## Portfolio Note

This detection demonstrates how Windows process creation telemetry can be transformed into actionable security analytics using Microsoft Sentinel and KQL.

The implementation demonstrates:

* Process execution monitoring
* Command-line analysis
* Parent-child process analysis
* Suspicious execution-path detection
* PowerShell monitoring
* Obfuscation detection
* Frequency-based analysis
* False-positive analysis
* Detection tuning
* Investigation methodology
* ATT&CK-aligned detection engineering

The documented detections are intended to demonstrate security monitoring methodology and do not claim that confirmed malicious activity was observed in the laboratory environment.
