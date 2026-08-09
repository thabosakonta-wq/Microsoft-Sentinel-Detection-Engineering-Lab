# Microsoft Sentinel Detection Engineering Lab

A practical Microsoft Sentinel detection engineering and threat hunting portfolio demonstrating KQL-based security detections, proactive threat hunting, MITRE ATT&CK mapping, and structured SOC investigation workflows.

---

## Project Overview

This project demonstrates the development and documentation of security monitoring and threat-hunting content for Windows security telemetry in a Microsoft Sentinel environment.

The portfolio focuses on identifying and investigating:

- Windows authentication failures
- Potential brute-force and password-spraying activity
- Process creation and execution activity
- PowerShell execution
- Command and scripting activity
- Suspicious command-line behaviour
- Parent-child process relationships
- MITRE ATT&CK techniques
- Potential false positives
- SOC investigation workflows

The objective is to demonstrate practical SOC analyst and detection engineering methodology rather than simply presenting isolated KQL queries.

---

## Objectives

The project demonstrates the ability to:

- Develop KQL-based security detection rules
- Create proactive threat-hunting queries
- Analyse Windows authentication telemetry
- Monitor Windows process creation events
- Investigate PowerShell activity
- Analyse command-line execution
- Identify potentially suspicious execution patterns
- Map detection coverage to MITRE ATT&CK
- Apply structured SOC investigation workflows
- Document detection logic
- Identify potential false positives
- Communicate security findings in an analyst-oriented format

---

## Detection Engineering

The project currently contains three detection rules.

### 1. Failed Logon Detection

**Windows Event ID:** `4625`

Detects failed Windows authentication attempts that may require investigation.

Investigation areas include:

- Repeated authentication failures
- Potential brute-force activity
- Potential password spraying
- Suspicious source addresses
- Account-related anomalies
- Authentication abuse

**File:**

`Detection-Rules/Failed-Logon-Detection.md`

---

### 2. Process Creation Monitoring

**Windows Event ID:** `4688`

Monitors Windows process creation telemetry to identify potentially suspicious execution.

Investigation areas include:

- New process execution
- Process command lines
- Parent-child process relationships
- Unusual executable paths
- PowerShell execution
- Command interpreters
- Suspicious processes
- Processes executed by unusual accounts

**File:**

`Detection-Rules/Process-Creation-Monitoring.md`

---

### 3. Suspicious PowerShell Detection

Monitors PowerShell execution and command-line activity that may warrant further investigation.

Investigation areas include:

- PowerShell execution
- Suspicious command-line arguments
- Encoded or unusual execution patterns
- Potential post-compromise activity
- Administrative PowerShell activity
- False-positive validation

**File:**

`Detection-Rules/Suspicious-PowerShell.md`

---

## Threat Hunting

The project also contains proactive threat-hunting queries designed to investigate security telemetry beyond predefined alerts.

### 1. Failed Authentication Hunting

**Windows Event ID:** `4625`

Investigates authentication failures for patterns associated with:

- Brute-force activity
- Password spraying
- Credential misuse
- Multiple accounts targeted from a common source
- Unusual authentication times
- Suspicious logon types
- Authentication failures followed by successful logons

**File:**

`Hunting-Queries/Failed-Authentication-Hunting.md`

---

### 2. Process Creation Hunting

**Windows Event ID:** `4688`

Investigates process creation telemetry for potentially suspicious execution.

Investigation areas include:

- PowerShell execution
- Command prompt execution
- Scripting engines
- Suspicious command-line arguments
- Unusual executable paths
- Temporary directory execution
- Unexpected parent-child relationships
- Processes launched by unusual accounts

**File:**

`Hunting-Queries/Process-Creation-Hunting.md`

---

### 3. Suspicious PowerShell Hunting

Provides proactive hunting for PowerShell activity that may warrant further investigation.

Investigation areas include:

- PowerShell execution
- Suspicious command-line activity
- Unusual execution patterns
- Potentially encoded commands
- Administrative versus suspicious activity
- Correlation with other endpoint telemetry

**File:**

`Hunting-Queries/Suspicious-PowerShell-Hunting.md`

---

## MITRE ATT&CK Coverage

The current detection and hunting content is mapped to the following MITRE ATT&CK techniques:

| Technique | Name | Project Coverage |
|---|---|---|
| T1059 | Command and Scripting Interpreter | PowerShell and process creation monitoring |
| T1059.001 | PowerShell | PowerShell detection and hunting |
| T1059.003 | Windows Command Shell | Process creation monitoring and hunting |
| T1110 | Brute Force | Failed authentication detection and hunting |
| T1110.003 | Password Spraying | Failed authentication detection and hunting |

These mappings describe the techniques represented by the detection and hunting content.

They **do not imply that malicious activity was actually observed**.

**Mapping file:**

`MITRE-Mapping/Detection-Mapping.md`

---

## SOC Investigation Workflow

The detection and hunting content supports a structured analyst workflow.

### Investigation Process

1. Identify the security event or suspicious activity.
2. Identify the affected host, account, process, or source.
3. Review relevant timestamps and frequency.
4. Examine authentication or process information.
5. Review command-line information where available.
6. Examine parent-child process relationships where applicable.
7. Correlate related security telemetry.
8. Determine whether the activity is expected or suspicious.
9. Consider potential false positives.
10. Map relevant activity to MITRE ATT&CK.
11. Document the analyst assessment and conclusion.

This workflow is intended to demonstrate the analytical process used by a SOC analyst when investigating security telemetry.

---

## False Positive Considerations

Detection engineering requires consideration of legitimate activity.

Potential false positives include:

### Authentication

- Incorrect passwords
- Expired credentials
- Cached credentials
- Service accounts
- User error
- Misconfigured applications

### Process Creation

- Normal administrative activity
- Software installation
- System maintenance
- Automated scripts
- Scheduled tasks
- Legitimate PowerShell administration
- Security software activity

A detection should therefore be investigated in context rather than treated as proof of malicious activity.

---

## Data Sources

The project primarily uses Windows security telemetry represented through Microsoft Sentinel.

Examples include:

- Windows Security Event Log
- Event ID `4625` — Failed Logon
- Event ID `4688` — Process Creation
- Microsoft Sentinel `SecurityEvent`
- Process command-line telemetry
- Authentication telemetry

---

## Technologies and Concepts

- Microsoft Sentinel
- Kusto Query Language (KQL)
- Windows Security Event Logs
- Windows authentication telemetry
- Process creation telemetry
- PowerShell
- Windows Command Shell
- MITRE ATT&CK
- Threat hunting
- Detection engineering
- SOC investigation methodology
- False-positive analysis
- Security monitoring
- Analyst-oriented technical documentation

---

## Repository Structure

```text
Microsoft-Sentinel-Detection-Engineering-Lab/
│
├── Detection-Rules/
│   ├── Failed-Logon-Detection.md
│   ├── Process-Creation-Monitoring.md
│   └── Suspicious-PowerShell.md
│
├── Hunting-Queries/
│   ├── Failed-Authentication-Hunting.md
│   ├── Process-Creation-Hunting.md
│   └── Suspicious-PowerShell-Hunting.md
│
├── MITRE-Mapping/
│   └── Detection-Mapping.md
│
├── README.md
└── LICENSE

Skills Demonstrated

This portfolio demonstrates practical exposure to:

Security detection development
KQL query development
Threat hunting
Windows security telemetry analysis
Authentication investigation
Process execution analysis
PowerShell security monitoring
Command-line analysis
MITRE ATT&CK mapping
SOC investigation methodology
Detection documentation
False-positive analysis
Analyst-oriented technical communication
Lab Scope

This repository represents a detection engineering and threat-hunting portfolio/lab.

The documented detections and hunting queries demonstrate security monitoring concepts, analytical methodology, and detection engineering practices.

The project does not claim that the documented techniques represent confirmed malicious activity.

Current Project Coverage
Area	Status
Detection Rules	Complete
Threat Hunting Queries	Complete
MITRE ATT&CK Mapping	Complete
SOC Investigation Workflow	Documented
False Positive Considerations	Documented
Repository Documentation	Complete
GitHub Repository	Published
Future Development

Potential future extensions include:

SOC incident case studies
Investigation timelines
Additional detection rules
Additional threat-hunting scenarios
Microsoft Sentinel analytics-rule documentation
Detection tuning
False-positive analysis
Security investigation evidence
Incident response documentation
Detection validation scenarios
Security monitoring architecture documentation
KQL query optimisation
Additional MITRE ATT&CK coverage
Portfolio Disclaimer

This repository is a technical portfolio and lab environment.

The detection rules, hunting queries, and MITRE ATT&CK mappings are intended to demonstrate security monitoring and analytical methodology.

The presence of a detection or MITRE ATT&CK mapping does not indicate that malicious activity was actually observed.

Author

Thabo Sakonta

Cybersecurity / SOC / Detection Engineering Portfolio

Project: Microsoft Sentinel Detection Engineering Lab