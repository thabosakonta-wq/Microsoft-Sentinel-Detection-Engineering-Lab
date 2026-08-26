# Suspicious PowerShell Hunting Query

## Objective

Identify potentially suspicious PowerShell activity that may indicate command execution, script abuse, encoded commands, or other attacker behavior.

## KQL Query

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
    or FileName =~ "pwsh.exe"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

## Investigation Focus

Review PowerShell executions for:

- Encoded or obfuscated commands
- Download activity
- Execution of scripts from unusual locations
- Suspicious parent processes
- Commands involving credential access
- Commands involving persistence mechanisms
- Administrative PowerShell activity inconsistent with the user's role

## Analyst Workflow

1. Identify the PowerShell process.
2. Review the complete command line.
3. Examine the initiating process.
4. Identify the associated user account.
5. Check the device involved.
6. Correlate the activity with other endpoint or authentication events.
7. Determine whether the activity is legitimate administrative activity or potentially malicious.

## MITRE ATT&CK

T1059.001 - Command and Scripting Interpreter: PowerShell

## Expected Outcome

The query provides an initial hunting dataset for PowerShell execution and allows analysts to investigate potentially suspicious command-line activity.

## Data Source

Microsoft Defender for Endpoint / Microsoft Defender XDR DeviceProcessEvents.

## Portfolio Note

This query demonstrates proactive threat hunting rather than relying solely on alert-driven investigation.
