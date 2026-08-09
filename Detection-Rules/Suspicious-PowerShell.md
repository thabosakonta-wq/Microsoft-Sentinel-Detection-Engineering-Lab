# Suspicious PowerShell Execution Detection

## Detection Objective

Detect potentially suspicious PowerShell execution on Windows endpoints using Microsoft Sentinel and Windows Security Event ID 4688 process creation telemetry.

## MITRE ATT&CK

- **T1059.001 — PowerShell**

## Data Source

- Windows Security Event Log
- Event ID: **4688 — A new process has been created**

## KQL Detection

```kql
SecurityEvent
| where EventID == 4688
| where CommandLine contains "powershell"
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    CommandLine,
    ParentProcessName
| order by TimeGenerated desc

Detection Logic

The query identifies process creation events where the command line contains powershell.

The following fields are retained for analyst investigation:

Timestamp
Computer
User account
New process
Command line
Parent process
Analyst Investigation

When an alert is generated, the analyst should investigate:

The PowerShell command executed.
The user account responsible for execution.
The parent process.
The originating endpoint.
Whether the activity was expected or authorised.
Whether encoded or obfuscated PowerShell was used.
Whether additional suspicious processes were created.
False Positive Considerations

PowerShell is a legitimate Windows administration and automation tool.

Potential legitimate activity includes:

System administration
Software deployment
IT automation
Configuration management
Security administration

Therefore, the detection should not automatically classify every PowerShell event as malicious.

Severity

Medium

Severity should be increased when additional suspicious indicators are present, such as:

Encoded commands
Obfuscation
Unusual parent processes
Unexpected user accounts
Execution from unusual locations
Suspicious network activity
Response

If suspicious PowerShell activity is confirmed:

Investigate the endpoint.
Identify the executing account.
Review related process creation events.
Review network activity.
Check for persistence mechanisms.
Determine whether containment is required.
Document the investigation.
Detection Engineering Notes

This rule demonstrates the use of Windows process creation telemetry to identify PowerShell activity and provides a foundation for more advanced PowerShell threat detections.