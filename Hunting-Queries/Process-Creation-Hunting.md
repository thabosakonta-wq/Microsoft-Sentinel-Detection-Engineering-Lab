# Process Creation Hunting Query

## Objective

Identify suspicious process creation activity that may indicate execution of PowerShell, command interpreters, scripting engines, or other potentially suspicious processes.

## KQL Query

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
## Investigation Focus

Review process creation events for:

- PowerShell execution
- Command prompt execution
- Scripting engines
- Unusual executable paths
- Suspicious command-line arguments
- Processes launched from temporary directories
- Unexpected parent-child process relationships
- Processes executed by unusual accounts

## Analyst Workflow

1. Identify the suspicious process.
2. Review the process command line.
3. Identify the parent process.
4. Identify the account that executed the process.
5. Review the executable path.
6. Determine whether the execution was expected.
7. Correlate the event with other security telemetry.
8. Determine whether the activity is legitimate or suspicious.

## MITRE ATT&CK

- **T1059 - Command and Scripting Interpreter**
- **T1059.001 - PowerShell**
- **T1059.003 - Windows Command Shell**

## False Positive Considerations

Process creation events may result from:

- Normal administrative activity
- Software installation
- System maintenance
- Automated scripts
- Scheduled tasks
- Legitimate PowerShell administration
- Security software activity

## Expected Outcome

The query provides process creation telemetry that can be used to identify potentially suspicious execution and support endpoint investigation.

## Data Source

Windows Security Event Log / Microsoft Sentinel `SecurityEvent`.

## Portfolio Note

This hunting query demonstrates the use of process creation telemetry to identify suspicious execution patterns and support endpoint threat hunting.