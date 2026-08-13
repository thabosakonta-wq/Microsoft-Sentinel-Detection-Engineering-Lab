# Suspicious PowerShell Detection

## Detection Objective

Detect potentially suspicious PowerShell execution using Microsoft Sentinel and Windows process creation telemetry.

The detection focuses on command-line behaviours and execution characteristics that may indicate:

- Command and scripting abuse
- Obfuscated PowerShell execution
- Encoded commands
- Execution-policy bypass
- Script download and execution
- Suspicious parent-child process relationships
- Potential post-compromise activity

This detection is intended to identify activity requiring analyst investigation rather than automatically classify PowerShell activity as malicious.

---

## MITRE ATT&CK

- **T1059.001 — PowerShell**
- **T1059 — Command and Scripting Interpreter**
- **T1105 — Ingress Tool Transfer**
- **T1027 — Obfuscated Files or Information**

---

## Data Source

- Windows Security Event Log
- Event ID: **4688 — A new process has been created**
- Microsoft Sentinel `SecurityEvent`
- Windows process command-line telemetry

---

## KQL Detection

```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
    or NewProcessName endswith "pwsh.exe"
| extend CommandLineLower = tolower(CommandLine)
| extend SuspiciousIndicators = case(
    CommandLineLower contains "-encodedcommand", "EncodedCommand",
    CommandLineLower contains " -enc ", "EncodedCommand",
    CommandLineLower contains "executionpolicy bypass", "ExecutionPolicyBypass",
    CommandLineLower contains " -nop", "NoProfile",
    CommandLineLower contains " -noprofile", "NoProfile",
    CommandLineLower contains "invoke-expression", "InvokeExpression",
    CommandLineLower contains " iex ", "InvokeExpression",
    CommandLineLower contains "downloadstring", "DownloadString",
    CommandLineLower contains "net.webclient", "WebClient",
    CommandLineLower contains "invoke-webrequest", "WebRequest",
    CommandLineLower contains "wget ", "WebRequest",
    CommandLineLower contains "curl ", "WebRequest",
    CommandLineLower contains "frombase64string", "Base64Decode",
    CommandLineLower contains "start-bitstransfer", "BITSDownload",
    "PowerShellExecution"
)
| project
    TimeGenerated,
    Computer,
    Account,
    NewProcessName,
    CommandLine,
    ParentProcessName,
    SuspiciousIndicators
| order by TimeGenerated desc