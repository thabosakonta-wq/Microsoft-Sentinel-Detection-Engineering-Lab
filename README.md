# Microsoft Sentinel Detection Engineering Lab

A practical Microsoft Sentinel detection engineering and threat hunting portfolio demonstrating KQL-based security detections, proactive threat hunting, MITRE ATT&CK mapping, and structured SOC investigation workflows.

## Project Overview

This project demonstrates the development and documentation of security monitoring and threat-hunting content for Windows security telemetry in a Microsoft Sentinel environment.

The portfolio focuses on identifying and investigating:

* Windows authentication failures
* Potential brute-force and password-spraying activity
* Suspicious process execution
* PowerShell activity
* Command and scripting activity
* Suspicious parent-child process relationships
* Authentication and endpoint anomalies
* Potential false positives requiring analyst validation

The project is designed to demonstrate practical SOC analyst and detection engineering skills rather than simply presenting isolated KQL queries.

---

## Objectives

The objectives of this lab are to:

* Develop KQL-based security detection rules
* Create proactive threat-hunting queries
* Analyse Windows authentication telemetry
* Monitor Windows process creation events
* Investigate PowerShell execution
* Identify potentially suspicious command-line activity
* Map detection coverage to MITRE ATT&CK
* Apply structured SOC investigation workflows
* Document detection logic and analyst considerations
* Identify potential false-positive conditions
* Demonstrate analyst-oriented technical communication

---

## Detection Engineering

The `Detection-Rules` directory contains the following detection content.

### Failed Logon Detection

**File:** `Detection-Rules/Failed-Logon-Detection.md`

Monitors Windows Security Event ID **4625**, representing failed logon attempts.

Investigation areas include:

* Repeated authentication failures
* Potential brute-force activity
* Authentication abuse
* Suspicious source addresses
* Account-related anomalies
* Authentication patterns requiring further investigation

**MITRE ATT&CK:**

* T1110 - Brute Force
* T1110.003 - Password Spraying

---

### Process Creation Monitoring

**File:** `Detection-Rules/Process-Creation-Monitoring.md`

Monitors Windows Security Event ID **4688** for process creation activity.

Investigation areas include:

* New process execution
* Process command lines
* Parent-child process relationships
* Unusual executable paths
* Suspicious process activity
* Processes executed by unusual accounts

**MITRE ATT&CK:**

* T1059 - Command and Scripting Interpreter
* T1059.001 - PowerShell
* T1059.003 - Windows Command Shell

---

### Suspicious PowerShell Detection

**File:** `Detection-Rules/Suspicious-PowerShell.md`

Identifies PowerShell activity that may warrant further investigation.

Investigation areas include:

* PowerShell execution
* Suspicious command-line arguments
* Encoded or unusual execution patterns
* Potential post-compromise activity
* Legitimate administrative activity requiring analyst validation

**MITRE ATT&CK:**

* T1059.001 - PowerShell

---

## Threat Hunting

The `Hunting-Queries` directory contains proactive hunting queries designed to investigate security telemetry beyond predefined detections.

### Failed Authentication Hunting

**File:** `Hunting-Queries/Failed-Authentication-Hunting.md`

Investigates Windows Event ID **4625** authentication failures for patterns associated with:

* Brute-force activity
* Password spraying
* Credential misuse
* Multiple accounts targeted from a common source
* Unusual authentication times
* Suspicious logon types
* Authentication failures followed by successful logons

---

### Process Creation Hunting

**File:** `Hunting-Queries/Process-Creation-Hunting.md`

Investigates Windows Event ID **4688** process creation telemetry for:

* PowerShell execution
* Command prompt execution
* Scripting engines
* Suspicious command-line arguments
* Unusual executable paths
* Temporary-directory execution
* Unexpected parent-child process relationships
* Processes launched by unusual accounts

---

### Suspicious PowerShell Hunting

**File:** `Hunting-Queries/Suspicious-PowerShell-Hunting.md`

Provides proactive hunting for PowerShell activity that may require further investigation.

The hunting approach considers:

* PowerShell execution patterns
* Command-line characteristics
* Suspicious arguments
* Encoded or unusual activity
* User and host context
* Legitimate administrative activity
* Correlation with other security telemetry

---

## MITRE ATT&CK Coverage

The current project maps detection and hunting content to the following MITRE ATT&CK techniques:

| Technique | Name                              | Project Coverage                            |
| --------- | --------------------------------- | ------------------------------------------- |
| T1059     | Command and Scripting Interpreter | PowerShell and process creation monitoring  |
| T1059.001 | PowerShell                        | PowerShell detection and hunting            |
| T1059.003 | Windows Command Shell             | Process creation monitoring and hunting     |
| T1110     | Brute Force                       | Failed authentication detection and hunting |
| T1110.003 | Password Spraying                 | Failed authentication detection and hunting |

These mappings describe the techniques represented by the detection content. They **do not imply that real malicious activity was observed**.

---

## SOC Investigation Workflow

The detection and hunting content supports a structured analyst workflow:

1. Identify the security event or suspicious activity.
2. Identify the affected host, account, process, or source.
3. Review timestamps and activity frequency.
4. Examine available authentication or command-line information.
5. Review parent-child process relationships where applicable.
6. Correlate related security telemetry.
7. Determine whether the activity is expected or suspicious.
8. Consider potential false-positive explanations.
9. Map relevant activity to MITRE ATT&CK.
10. Document the investigation conclusion.

This workflow is intended to demonstrate an analyst mindset rather than simply query execution.

---

## False-Positive Considerations

Detection engineering requires distinguishing suspicious activity from legitimate administrative or system activity.

Potential false-positive sources include:

* Incorrect passwords
* Expired credentials
* Cached credentials
* Service accounts
* Scheduled tasks
* Software installation
* System maintenance
* Legitimate PowerShell administration
* Automated scripts
* Security software
* Normal user activity

The documented detections therefore require analyst validation and contextual investigation.

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
```

---

## Technologies and Concepts

This portfolio uses or demonstrates concepts including:

* Microsoft Sentinel
* Kusto Query Language (KQL)
* Windows Security Event Logs
* Windows authentication telemetry
* Process creation telemetry
* PowerShell
* Windows Command Shell
* MITRE ATT&CK
* Threat hunting
* Detection engineering
* SOC investigation workflows
* False-positive analysis
* Security monitoring
* Analyst documentation

---

## Skills Demonstrated

This project demonstrates practical exposure to:

* Security detection development
* KQL query development
* Threat hunting
* Windows security telemetry analysis
* Authentication investigation
* Process execution analysis
* PowerShell security monitoring
* Command-line analysis
* MITRE ATT&CK mapping
* SOC investigation methodology
* Detection documentation
* False-positive assessment
* Analyst-oriented technical communication

---

## Lab Scope

This repository represents a **detection engineering and threat-hunting portfolio/lab**.

The documented detections and hunting queries are designed to demonstrate security monitoring concepts, analytical methodology, and SOC investigation practices.

The presence of a detection rule, hunting query, or MITRE ATT&CK mapping does **not** indicate that malicious activity was actually observed.

Where appropriate, the portfolio distinguishes between:

* Detection logic
* Hunting logic
* Investigation methodology
* Expected legitimate activity
* Potentially suspicious activity
* Analyst validation requirements

---

## Future Development

Planned extensions include:

* SOC incident case studies
* Investigation timelines
* Additional detection rules
* Additional hunting scenarios
* Sentinel analytics-rule documentation
* Security investigation evidence
* Detection tuning
* False-positive analysis
* Incident investigation documentation
* Detection validation exercises
* Security monitoring architecture documentation
* Investigation screenshots and supporting evidence

---

## Portfolio Purpose

This repository is intended to demonstrate practical cybersecurity skills relevant to:

* SOC Analyst roles
* Junior Detection Engineer roles
* Security Monitoring roles
* Microsoft Sentinel Analyst roles
* Threat Hunting roles
* Cybersecurity Analyst roles

The emphasis is on **detection logic, investigation methodology, telemetry analysis, and analyst reasoning**.

---

## Author

**Thabo Sakonta**

### Project

**Microsoft Sentinel Detection Engineering Lab**

---

## Disclaimer

This is an educational and professional portfolio project.

The detections and hunting queries are intended for defensive security monitoring, threat hunting, and SOC investigation purposes.

They should be validated and adapted to the specific Microsoft Sentinel workspace, data connectors, Windows telemetry configuration, and operational requirements of a production environment.
