# Process Creation Monitoring

## Detection Objective

Monitor Windows process creation events to identify potentially suspicious processes and command-line activity using Microsoft Sentinel.

## MITRE ATT&CK

- **T1057 — Process Discovery**
- **T1059 — Command and Scripting Interpreter**

## Data Source

- Windows Security Event Log
- Event ID: **4688 — A new process has been created**

## KQL Detection

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

Detection Logic

The query collects Windows process creation events and exposes the process name, command line, parent process and associated account for investigation.

This provides visibility into:

Newly created processes
Process command lines
Parent-child process relationships
User accounts initiating processes
Potentially suspicious execution chains
Analyst Investigation

When suspicious process activity is identified, investigate:

The process name.
The command line.
The parent process.
The user account.
The endpoint.
The timing of the activity.
Whether the process is associated with known legitimate software.
Whether additional related processes were created.
Suspicious Indicators

Analysts should pay particular attention to:

PowerShell launched by unusual parent processes.
Command shells spawned by Office applications.
Processes executing from unusual directories.
Unexpected administrative accounts.
Obfuscated command lines.
Unknown executables.
Unusual parent-child relationships.
False Positive Considerations

Process creation is normal Windows activity.

Legitimate examples include:

Windows system processes
Software applications
Administrative tools
Security software
Software installation
Scheduled tasks

The detection therefore provides telemetry for investigation rather than automatically classifying every process as malicious.

Severity

Informational / Medium

Severity should be increased when suspicious process characteristics or additional indicators are identified.

Response

When suspicious process creation is confirmed:

Identify the process.
Identify the parent process.
Identify the executing account.
Review the command line.
Examine related process events.
Investigate persistence mechanisms.
Review network activity where relevant.
Determine whether containment is required.
Document the investigation.
Detection Engineering Notes

This detection establishes baseline process-creation visibility in Microsoft Sentinel and provides the foundation for more targeted endpoint detections.