# PowerShell Threat Hunting

## Hunting Objective

Identify potentially suspicious PowerShell activity that may indicate command execution, script abuse, obfuscation, payload retrieval, persistence, or post-compromise activity.

This hunting content complements the **Suspicious PowerShell Detection** rule and **Process Creation Hunting** query.

The objective is to proactively identify PowerShell behaviours that may require investigation even when an individual event does not trigger a detection.

---

## MITRE ATT&CK

- **T1059.001 — PowerShell**
- **T1059 — Command and Scripting Interpreter**
- **T1105 — Ingress Tool Transfer**
- **T1027 — Obfuscated Files or Information**
- **T1053 — Scheduled Task/Job**
- **T1547 — Boot or Logon Autostart Execution**

---

## Data Sources

### Primary Telemetry

- Windows Security Event Log
- Microsoft Sentinel `SecurityEvent`
- Event ID **4688 — A new process has been created**

### Additional Telemetry

- Microsoft Defender for Endpoint
- PowerShell Script Block Logging
- PowerShell Module Logging
- Microsoft Defender Antivirus
- Sysmon
- Network telemetry
- DNS telemetry

---

# Hunt 1 — PowerShell Execution Baseline

Establish the normal volume of PowerShell execution across monitored systems.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| summarize
    ExecutionCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Accounts = make_set(Account, 20),
    Computers = make_set(Computer, 20)
    by NewProcessName
| order by ExecutionCount desc
```

### Hunting Purpose

This query establishes a baseline for PowerShell activity.

Investigate:

- Hosts with unusually high PowerShell activity
- Accounts executing PowerShell frequently
- PowerShell activity on systems where it is uncommon
- Unexpected PowerShell versions
- Administrative versus standard-user execution

---

# Hunt 2 — Encoded PowerShell

Identify PowerShell executions containing encoded command parameters.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend CommandLineLower = tolower(ProcessCommandLine)
| where CommandLineLower contains "-encodedcommand"
    or CommandLineLower contains " -enc "
    or CommandLineLower contains "/encodedcommand"
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

Encoded PowerShell can be used to obscure command content.

Investigate:

- The encoded command
- The initiating process
- The executing account
- The destination host
- Network activity
- Files created by the process
- Subsequent child processes

Encoded PowerShell is not automatically malicious and may occur in legitimate automation.

---

# Hunt 3 — Execution Policy Bypass

Identify PowerShell executions attempting to bypass execution policy restrictions.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend CommandLineLower = tolower(ProcessCommandLine)
| where CommandLineLower contains "-executionpolicy bypass"
    or CommandLineLower contains "-ep bypass"
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

Execution-policy bypass may indicate an attempt to execute PowerShell content outside normal policy restrictions.

Investigate the command together with:

- Parent process
- User account
- Script path
- Network connections
- Download activity
- Child processes
- Persistence mechanisms

---

# Hunt 4 — PowerShell Download and Execution Activity

Search for PowerShell commands associated with downloading or retrieving content.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend CommandLineLower = tolower(ProcessCommandLine)
| where CommandLineLower contains "downloadstring"
    or CommandLineLower contains "downloadfile"
    or CommandLineLower contains "invoke-webrequest"
    or CommandLineLower contains "invoke-restmethod"
    or CommandLineLower contains "net.webclient"
    or CommandLineLower contains "start-bitstransfer"
    or CommandLineLower contains "curl "
    or CommandLineLower contains "wget "
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

PowerShell can be used to retrieve scripts, tools, or payloads from remote locations.

Investigate:

- URLs
- IP addresses
- Domains
- Downloaded filenames
- Destination paths
- File hashes
- Subsequent execution
- Network reputation

---

# Hunt 5 — PowerShell Obfuscation Indicators

Search for command-line patterns commonly associated with PowerShell obfuscation.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend CommandLineLower = tolower(ProcessCommandLine)
| where CommandLineLower contains "frombase64string"
    or CommandLineLower contains "replace("
    or CommandLineLower contains "char("
    or CommandLineLower contains "invoke-expression"
    or CommandLineLower contains "iex "
    or CommandLineLower contains "set-alias"
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

Obfuscation can make malicious PowerShell commands more difficult to detect.

Potential indicators include:

- Base64 decoding
- String replacement
- Character reconstruction
- `Invoke-Expression`
- Alias manipulation
- Highly unusual command-line structures

These indicators should be investigated in context.

---

# Hunt 6 — Suspicious PowerShell Parent Processes

Identify PowerShell launched by unusual parent processes.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend ParentLower = tolower(ParentProcessName)
| where ParentLower contains "winword.exe"
    or ParentLower contains "excel.exe"
    or ParentLower contains "outlook.exe"
    or ParentLower contains "mshta.exe"
    or ParentLower contains "wscript.exe"
    or ParentLower contains "cscript.exe"
    or ParentLower contains "rundll32.exe"
    or ParentLower contains "regsvr32.exe"
    or ParentLower contains "w3wp.exe"
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

Unexpected parent-child relationships can provide important behavioural context.

Particular attention should be given to:

```text
WINWORD.EXE
    |
    └── powershell.exe
```

or:

```text
EXCEL.EXE
    |
    └── powershell.exe
```

These relationships do not automatically indicate compromise but should be investigated when unexpected.

---

# Hunt 7 — Office Application → PowerShell

Specifically identify Office applications spawning PowerShell.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend ParentLower = tolower(ParentProcessName)
| where ParentLower contains "winword.exe"
    or ParentLower contains "excel.exe"
    or ParentLower contains "powerpnt.exe"
    or ParentLower contains "outlook.exe"
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

Office-to-PowerShell execution may be associated with malicious documents and script execution.

Correlate with:

- Email telemetry
- File creation
- Document names
- User activity
- Network connections
- Child processes
- Endpoint alerts

---

# Hunt 8 — Browser → PowerShell

Identify PowerShell processes launched by browser-related processes.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend ParentLower = tolower(ParentProcessName)
| where ParentLower contains "chrome.exe"
    or ParentLower contains "msedge.exe"
    or ParentLower contains "firefox.exe"
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

Browser-to-PowerShell execution is uncommon in many environments.

Investigate:

- Browser extensions
- Downloaded files
- User activity
- URLs
- PowerShell command line
- Child processes
- Endpoint security alerts

---

# Hunt 9 — PowerShell from Temporary Directories

Identify PowerShell execution associated with temporary or unusual paths.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend CommandLineLower = tolower(ProcessCommandLine)
| where CommandLineLower contains "\\temp\\"
    or CommandLineLower contains "\\tmp\\"
    or CommandLineLower contains "\\appdata\\local\\temp\\"
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

Execution involving temporary directories can be associated with:

- Downloaded payloads
- Installer activity
- Malware execution
- User-generated scripts
- Application update mechanisms

Temporary paths should therefore be treated as contextual indicators rather than proof of malicious activity.

---

# Hunt 10 — PowerShell Child Process Analysis

Identify processes launched by PowerShell.

```kql
SecurityEvent
| where EventID == 4688
| where ParentProcessName endswith "powershell.exe"
    or ParentProcessName endswith "pwsh.exe"
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

PowerShell spawning additional processes can provide important evidence of execution chains.

Investigate child processes such as:

- `cmd.exe`
- `rundll32.exe`
- `mshta.exe`
- `regsvr32.exe`
- `certutil.exe`
- `bitsadmin.exe`
- Other unexpected executables

Example:

```text
powershell.exe
      |
      └── cmd.exe
             |
             └── suspicious.exe
```

---

# Hunt 11 — PowerShell Activity by Account

Identify accounts generating significant PowerShell activity.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| summarize
    ExecutionCount = count(),
    Computers = dcount(Computer),
    Hosts = make_set(Computer, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Account
| order by ExecutionCount desc
```

### Hunting Purpose

Identify:

- Accounts with unusually high PowerShell activity
- Privileged accounts
- Service accounts
- Accounts executing PowerShell on unusual hosts
- Recently observed PowerShell users

Account context should be compared with expected administrative responsibilities.

---

# Hunt 12 — PowerShell Activity by Host

Identify hosts generating unusual PowerShell activity.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| summarize
    ExecutionCount = count(),
    Accounts = dcount(Account),
    Users = make_set(Account, 20),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Computer
| order by ExecutionCount desc
```

### Hunting Purpose

Hosts with unusually high PowerShell activity may require further investigation.

Pay particular attention to:

- Domain controllers
- Servers
- Application servers
- Security infrastructure
- Critical business systems

---

# Hunt 13 — PowerShell Activity Over Time

Identify unusual spikes in PowerShell execution.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| summarize
    ExecutionCount = count(),
    Accounts = dcount(Account),
    Computers = dcount(Computer)
    by bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

### Hunting Purpose

This query can identify sudden increases in PowerShell execution.

Investigate spikes that coincide with:

- Security incidents
- Software deployments
- Maintenance windows
- Authentication anomalies
- Network anomalies
- Endpoint alerts

---

# Hunt 14 — PowerShell with NoProfile

Identify PowerShell executions using `-NoProfile`.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend CommandLineLower = tolower(ProcessCommandLine)
| where CommandLineLower contains "-noprofile"
    or CommandLineLower contains " -nop "
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

`-NoProfile` is commonly used in automation and administration, but it can also be used to reduce environmental dependencies during malicious execution.

Investigate this indicator alongside:

- Encoded commands
- Execution-policy bypass
- Downloads
- Obfuscation
- Suspicious parents

---

# Hunt 15 — High-Risk PowerShell Combination

Identify PowerShell executions containing multiple suspicious characteristics.

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend CommandLineLower = tolower(ProcessCommandLine)
| extend
    Encoded = CommandLineLower contains "-encodedcommand"
        or CommandLineLower contains " -enc ",
    PolicyBypass = CommandLineLower contains "-executionpolicy bypass"
        or CommandLineLower contains "-ep bypass",
    DownloadActivity = CommandLineLower contains "downloadstring"
        or CommandLineLower contains "downloadfile"
        or CommandLineLower contains "invoke-webrequest"
        or CommandLineLower contains "net.webclient"
        or CommandLineLower contains "start-bitstransfer",
    Obfuscation = CommandLineLower contains "frombase64string"
        or CommandLineLower contains "invoke-expression"
        or CommandLineLower contains "iex ",
    NoProfile = CommandLineLower contains "-noprofile"
        or CommandLineLower contains " -nop "
| extend SuspicionScore =
      toint(Encoded)
    + toint(PolicyBypass)
    + toint(DownloadActivity)
    + toint(Obfuscation)
    + toint(NoProfile)
| where SuspicionScore >= 2
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    ProcessCommandLine,
    ParentProcessName,
    Encoded,
    PolicyBypass,
    DownloadActivity,
    Obfuscation,
    NoProfile,
    SuspicionScore
| order by SuspicionScore desc, TimeGenerated desc
```

### Hunting Purpose

Multiple independent indicators provide stronger context than a single keyword.

For example:

```text
EncodedCommand
        +
ExecutionPolicy Bypass
        +
DownloadString
```

should receive substantially more attention than an ordinary PowerShell administrative command.

---

# Investigation Workflow

When suspicious PowerShell activity is identified:

### 1. Identify the Endpoint

Determine:

- Hostname
- IP address
- Asset type
- Business criticality
- Operating system

### 2. Identify the Account

Determine:

- Username
- Privilege level
- Administrative role
- Service account status
- Whether the activity was expected

### 3. Review the Complete Command Line

Look for:

- Encoded commands
- URLs
- IP addresses
- Script paths
- Base64 content
- Obfuscation
- Download activity
- Credential-related commands

### 4. Identify the Parent Process

Determine what launched PowerShell.

Examples:

- `explorer.exe`
- `cmd.exe`
- `winword.exe`
- `excel.exe`
- `outlook.exe`
- `mshta.exe`
- Browser processes
- Unknown executables

### 5. Identify Child Processes

Determine whether PowerShell spawned:

- Command interpreters
- Script engines
- System utilities
- Download tools
- Unknown executables

### 6. Review Network Activity

Investigate:

- Destination IPs
- Domains
- URLs
- DNS requests
- Download locations
- External connections

### 7. Review File Activity

Look for:

- New scripts
- Executables
- DLLs
- Temporary files
- Archive files
- Files written to unusual directories

### 8. Search for Persistence

Review for:

- Scheduled tasks
- Services
- Registry Run keys
- Startup folders
- WMI persistence
- Other autorun mechanisms

### 9. Correlate Security Telemetry

Correlate PowerShell activity with:

- Authentication events
- Process creation
- Defender alerts
- Sysmon events
- DNS activity
- Firewall activity
- Endpoint telemetry

### 10. Determine the Outcome

Classify the activity as:

- Benign
- Expected administrative activity
- Suspicious
- Confirmed malicious
- Requires additional investigation

---

# False Positive Considerations

PowerShell is a legitimate administrative and automation technology.

Potential legitimate activity includes:

- System administration
- Software deployment
- Configuration management
- Endpoint management
- Security tooling
- Scheduled scripts
- Infrastructure automation
- Microsoft management tools
- Software installation
- IT support activity

Avoid treating a single PowerShell indicator as proof of compromise.

Detection quality improves when the following are incorporated:

- Approved administrative accounts
- Approved management systems
- Known automation scripts
- Known software deployment platforms
- Expected maintenance windows
- Asset criticality
- Parent-child relationships

---

# Severity Guidance

## Low

Examples:

- Normal PowerShell administration
- Approved automation
- Known management activity

## Medium

Examples:

- Unusual PowerShell execution
- `-NoProfile`
- PowerShell from an unexpected account
- PowerShell on an unusual host

## High

Examples:

- Encoded PowerShell
- Execution-policy bypass
- Suspicious parent process
- External download activity
- Obfuscation combined with execution

## Critical

Consider the highest severity when multiple high-risk behaviours occur together, particularly when combined with:

- Credential access
- Persistence
- Lateral movement
- Known malicious infrastructure
- Confirmed malware
- Security-tool tampering

Severity should always reflect the complete investigation context.

---

# Validation

Detection validation should be performed only in an authorised lab environment.

Recommended test cases:

### Test 1 — Normal PowerShell

Expected result:

- PowerShell execution is visible
- No high-risk classification

### Test 2 — Encoded Command

Expected result:

- Hunt 2 identifies the execution

### Test 3 — Execution Policy Bypass

Expected result:

- Hunt 3 identifies the execution

### Test 4 — Download Activity

Expected result:

- Hunt 4 identifies suspicious download patterns

### Test 5 — Suspicious Parent

Expected result:

- Hunt 6 identifies the parent-child relationship

### Test 6 — Multiple Indicators

Expected result:

- Hunt 15 produces a higher suspicion score

Each test should document:

- Test scenario
- Expected result
- Actual result
- Detection status
- False-positive assessment
- Tuning requirement

---

# Detection Engineering Considerations

A mature PowerShell hunting capability should combine process telemetry with richer endpoint telemetry.

Recommended enhancements include:

- PowerShell Script Block Logging
- PowerShell Module Logging
- Sysmon process telemetry
- Microsoft Defender for Endpoint
- Network telemetry
- DNS telemetry
- File creation telemetry
- User and Entity Behaviour Analytics
- Asset criticality
- Threat intelligence

Where available, full script content is generally more valuable than process command-line analysis alone.

---

# Analyst Decision Framework

A useful investigation model is:

```text
PowerShell Execution
        |
        v
Is the execution expected?
        |
   +----+----+
   |         |
  YES        NO
   |         |
   v         v
Close /    Review
Document   Context
             |
             v
     Suspicious Indicators?
             |
        +----+----+
        |         |
       NO        YES
        |         |
        v         v
   Continue     Correlate
   Monitoring   Telemetry
                   |
                   v
            Multiple Indicators?
                   |
              +----+----+
              |         |
             NO        YES
              |         |
              v         v
         Investigate   Escalate
```

---

# Expected Outcome

These hunting queries provide a structured approach to identifying suspicious PowerShell activity across monitored Windows systems.

The hunting capability supports:

- Baseline analysis
- Behavioural analysis
- Command-line analysis
- Parent-child process analysis
- Obfuscation detection
- Download detection
- Account analysis
- Host analysis
- Correlation
- Incident investigation

The queries are intended to support analyst investigation rather than automatically classify every PowerShell execution as malicious.

---

# Portfolio Note

This hunting capability demonstrates practical SOC and Microsoft Sentinel detection-engineering methodology.

The implementation demonstrates:

- KQL query development
- Windows process telemetry analysis
- PowerShell threat hunting
- MITRE ATT&CK mapping
- Behavioural detection
- Command-line analysis
- Parent-child process analysis
- False-positive analysis
- Investigation workflows
- Detection validation
- Severity assessment

The project demonstrates an understanding that effective SOC detection requires contextual analysis rather than simple keyword matching.

---

# Related Project Components

This hunting query complements:

- `Detection-Rules/Suspicious-PowerShell.md`
- `Detection-Rules/Process-Creation-Monitoring.md`
- `Hunting-Queries/Failed-Authentication-Hunting.md`
- `Hunting-Queries/Process-Creation-Hunting.md`
- `Playbooks/Automated-Host-Isolation.md`

Together these components demonstrate an end-to-end workflow:

```text
Telemetry
    |
    v
Detection Engineering
    |
    v
Threat Hunting
    |
    v
Investigation
    |
    v
SOAR Response
    |
    v
Incident Documentation
```

---

## Disclaimer

The presence of a PowerShell hunting result does not by itself indicate malicious activity.

All findings should be validated against organisational context, approved administrative activity, endpoint telemetry, network evidence, and other available security data.
