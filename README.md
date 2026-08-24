# Microsoft Sentinel Detection Engineering Lab

A practical Microsoft Sentinel detection engineering and threat hunting portfolio demonstrating **KQL-based security detections, proactive threat hunting, Windows telemetry analysis, MITRE ATT&CK mapping, SOC investigation workflows, detection tuning, incident classification, and SOAR automation concepts.**

The portfolio follows an end-to-end SOC workflow:

**Detection → Threat Hunting → Investigation → Correlation → Classification → MITRE ATT&CK → Response**

---

## Portfolio at a Glance

| Area | Coverage |
|------|----------|
| SIEM | Microsoft Sentinel |
| Query Language | Kusto Query Language (KQL) |
| Endpoint Telemetry | Windows Security Events |
| Authentication | Event ID 4625 |
| Process Monitoring | Event ID 4688 |
| PowerShell | Detection + Hunting |
| Threat Hunting | 5 hunting scenarios |
| Detection Engineering | 3 detection rules |
| MITRE ATT&CK | T1059, T1059.001, T1059.003, T1110, T1110.003 |
| Investigation | Structured SOC workflow |
| Alert Tuning | Failed-logon tuning |
| Case Study | Simulated suspicious PowerShell investigation |
| SOAR | Automated host-isolation design |
| Endpoint Response | Microsoft Defender for Endpoint concept |
| Documentation | Investigation reports + Markdown |

The objective is to demonstrate practical SOC analyst and detection engineering methodology rather than simply presenting isolated KQL queries.

---

## Objectives

The project demonstrates the ability to:

* Develop KQL-based security detection rules
* Create proactive threat-hunting queries
* Analyse Windows authentication telemetry
* Monitor Windows process creation events
* Investigate PowerShell activity
* Analyse command-line execution
* Investigate network connection activity
* Identify potentially suspicious execution patterns
* Correlate endpoint and authentication telemetry
* Map detection coverage to MITRE ATT&CK
* Apply structured SOC investigation workflows
* Tune detections and consider false positives
* Classify security events based on available evidence
* Document investigation findings
* Design SOAR-based response workflows
* Communicate security findings in an analyst-oriented format

---

## Detection Engineering

The project currently contains three dedicated detection rules, supported by five proactive hunting queries, structured investigation reports, a simulated SOC incident case study, MITRE ATT&CK mapping, and a documented SOAR containment design.

### 1. Failed Logon Detection

**Windows Event ID:** `4625`

Detects failed Windows authentication attempts that may require investigation.

Investigation areas include:

* Repeated authentication failures
* Potential brute-force activity
* Potential password spraying
* Suspicious source addresses
* Account-related anomalies
* Authentication abuse
* Unusual authentication patterns

**File:**

`Detection-Rules/Failed-Logon-Detection.md`

---

### 2. Process Creation Monitoring

**Windows Event ID:** `4688`

Monitors Windows process creation telemetry to identify potentially suspicious execution.

Investigation areas include:

* New process execution
* Process command lines where available
* Parent-child process relationships
* Unusual executable paths
* PowerShell execution
* Command interpreters
* Suspicious processes
* Processes executed by unusual accounts

**File:**

`Detection-Rules/Process-Creation-Monitoring.md`

---

### 3. Suspicious PowerShell Detection

Monitors PowerShell execution and command-line activity that may warrant further investigation.

Investigation areas include:

* PowerShell execution
* Suspicious command-line arguments
* Encoded or unusual execution patterns
* Potential post-compromise activity
* Administrative PowerShell activity
* Download and execution indicators
* False-positive validation

**File:**

`Detection-Rules/Suspicious-PowerShell.md`

---

## Threat Hunting

The project contains proactive threat-hunting queries designed to investigate security telemetry beyond predefined alerts.

### 1. Failed Authentication Hunting

**Windows Event ID:** `4625`

Investigates authentication failures for patterns associated with:

* Brute-force activity
* Password spraying
* Credential misuse
* Multiple accounts targeted from a common source
* Unusual authentication times
* Suspicious logon types
* Authentication failures followed by successful logons

**File:**

`Hunting-Queries/Failed-Authentication-Hunting.md`

---

### 2. Network Connection Hunting

Investigates network connection telemetry for potentially suspicious communications and endpoint activity.

Investigation areas include:

* Unusual remote connections
* Unexpected destination addresses
* Suspicious ports
* Unusual outbound communication
* Repeated connections
* Potential command-and-control indicators
* Correlation with process execution
* Network activity associated with suspicious PowerShell

**File:**

`Hunting-Queries/Network-Connection-Hunting.md`

---

### 3. PowerShell Hunting

Investigates PowerShell activity and command-line telemetry for potentially suspicious execution.

Investigation areas include:

* PowerShell execution
* Suspicious command-line arguments
* Encoded commands
* Execution policy bypass
* Download and execution activity
* Scripting behaviour
* Parent-child process relationships
* Correlation with authentication and network activity

**File:**

`Hunting-Queries/PowerShell-Hunting.md`

---

### 4. Process Creation Hunting

**Windows Event ID:** `4688`

Investigates process creation telemetry for potentially suspicious execution.

Investigation areas include:

* PowerShell execution
* Command prompt execution
* Scripting engines
* Suspicious command-line arguments
* Unusual executable paths
* Temporary directory execution
* Unexpected parent-child relationships
* Processes launched by unusual accounts

**File:**

`Hunting-Queries/Process-Creation-Hunting.md`

---

### 5. Suspicious PowerShell Hunting

Provides proactive hunting for PowerShell activity that may warrant further investigation.

Investigation areas include:

* PowerShell execution
* Suspicious command-line activity
* Unusual execution patterns
* Potentially encoded commands
* Administrative versus suspicious activity
* Correlation with other endpoint telemetry

**File:**

`Hunting-Queries/Suspicious-PowerShell-Hunting.md`

---

## MITRE ATT&CK Coverage

The portfolio maps selected detection and hunting scenarios to relevant MITRE ATT&CK techniques.

| Technique | Name | Portfolio Coverage |
|-----------|------|--------------------|
| T1059 | Command and Scripting Interpreter | Process and command execution monitoring |
| T1059.001 | PowerShell | PowerShell detection and hunting |
| T1059.003 | Windows Command Shell | Process creation monitoring and hunting |
| T1110 | Brute Force | Failed authentication detection and hunting |
| T1110.003 | Password Spraying | Authentication pattern analysis |

These mappings represent the analytical and detection coverage implemented in the lab.

They **do not indicate that malicious activity was observed or that a real-world intrusion occurred**.

**Mapping:** `MITRE-Mapping/Detection-Mapping.md`

---

## SOC Investigation Workflow

The detection and hunting content supports a structured analyst workflow designed to demonstrate how a SOC analyst progresses from an initial security signal to an evidence-based assessment and response recommendation.

### Investigation Process

1. Identify the security event or suspicious activity.
2. Validate the alert and determine whether it is actionable.
3. Identify the affected host, account, process, or source.
4. Establish the investigation timeframe and scope.
5. Review relevant timestamps, frequency, and event context.
6. Examine authentication or process information.
7. Review command-line information where available.
8. Examine parent-child process relationships where applicable.
9. Correlate related endpoint, authentication, and network telemetry.
10. Preserve and document relevant investigation evidence.
11. Conduct additional threat hunting where required.
12. Determine whether the activity is expected, suspicious, or malicious based on available evidence.
13. Consider potential false positives and environmental context.
14. Map relevant activity to MITRE ATT&CK.
15. Assess severity, scope, and potential impact.
16. Document the analyst assessment and conclusion.
17. Recommend appropriate response, remediation, monitoring, or containment actions.
18. Escalate the incident when required.

```

## SOC Incident Case Studies

The repository includes simulated SOC incident case studies designed to demonstrate end-to-end investigation methodology.

### Suspicious PowerShell Investigation

A comprehensive simulated SOC investigation covering:

* Alert validation
* PowerShell analysis
* Command-line investigation
* Process tree analysis
* Authentication correlation
* Network connection analysis
* Threat hunting
* MITRE ATT&CK mapping
* False-positive assessment
* Evidence-based classification
* Analyst verdict
* Recommended response
* SOAR containment considerations

**Case Study:**

`SOC-Incident-Case-Studies/Suspicious-PowerShell-Investigation.md`

> **Simulation Notice:** This is a simulated Home Lab investigation. It does not represent a confirmed real-world compromise.

---

## Investigation Reports

The repository also contains structured investigation documentation demonstrating alert analysis, detection tuning, and incident investigation methodology.

### Failed Logon Alert Tuning

Documents investigation and tuning considerations for failed authentication alerts.

**File:**

`Investigation-Reports/Failed-Logon-Alert-Tuning.md`

---

### Suspicious PowerShell Incident

Documents a structured investigation into suspicious PowerShell activity.

**File:**

`Investigation-Reports/Suspicious-PowerShell-Incident.md`

> **Simulation Notice:** Investigation content is intended to demonstrate SOC investigation methodology and does not represent a confirmed real-world compromise.

---

## SOAR and Automated Response

The repository includes a documented SOAR playbook design demonstrating how a Microsoft Sentinel incident could trigger automated endpoint containment.

### Automated Host Isolation

The playbook design covers:

* Microsoft Sentinel incident triggering
* Suspicious PowerShell detection
* Host identification
* Endpoint isolation considerations
* Microsoft Defender for Endpoint integration
* Critical-server guardrails
* Analyst review
* Automated containment workflow

**File:**

`Playbooks/Automated-Host-Isolation.md`

The playbook is a documented design concept.

It does **not** claim that live endpoint isolation was performed as part of this portfolio.

---

## False Positive Considerations

Detection engineering requires consideration of legitimate activity.

Potential false positives include:

### Authentication

* Incorrect passwords
* Expired credentials
* Cached credentials
* Service accounts
* User error
* Misconfigured applications

### Process Creation

* Normal administrative activity
* Software installation
* System maintenance
* Automated scripts
* Scheduled tasks
* Legitimate PowerShell administration
* Security software activity

### PowerShell

* Legitimate administration
* Software deployment
* IT automation
* Configuration management
* Security tooling
* Administrative scripts

### Network Activity

* Legitimate software updates
* Web browsing
* Cloud services
* Security tools
* Management systems
* Monitoring infrastructure

A detection should therefore be investigated in context rather than treated as proof of malicious activity.

---

## Data Sources

The project primarily uses Windows and Microsoft security telemetry represented through Microsoft Sentinel.

Examples include:

* Windows Security Event Log
* Event ID `4625` — Failed Logon
* Event ID `4688` — Process Creation
* Microsoft Sentinel / Log Analytics SecurityEvent table
* Process command-line telemetry
* Authentication telemetry
* Network connection telemetry
* PowerShell execution telemetry

The exact telemetry source may vary depending on the detection or hunting scenario.

---

* Expanded detection validation scenarios

Detection and hunting content is designed for validation against representative Windows security telemetry and simulated Home Lab scenarios.

Validation considerations include:

* Expected event generation
* KQL syntax and query validation
* Detection logic review
* Threshold and aggregation analysis
* False-positive assessment
* Investigation-context requirements
* MITRE ATT&CK alignment
* Analyst triage workflow
* Potential response actions

The portfolio distinguishes between:

1. Detection logic
2. Threat-hunting logic
3. Simulated investigation evidence
4. Production response concepts

Detection validation is intended to demonstrate analytical and engineering methodology rather than claim production deployment.

The project does not claim that the detections were deployed in a production Microsoft Sentinel environment.

## Technologies and Concepts

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
* SOC investigation methodology
* False-positive analysis
* Security monitoring
* Network investigation
* Incident investigation
* Incident classification
* Evidence-based investigation
* Analyst-oriented technical documentation
* SOAR playbook design
* Endpoint containment concepts

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
│   ├── Network-Connection-Hunting.md
│   ├── PowerShell-Hunting.md
│   ├── Process-Creation-Hunting.md
│   └── Suspicious-PowerShell-Hunting.md
│
├── Investigation-Reports/
│   ├── Failed-Logon-Alert-Tuning.md
│   └── Suspicious-PowerShell-Incident.md
│
├── SOC-Incident-Case-Studies/
│   └── Suspicious-PowerShell-Investigation.md
│
├── Playbooks/
│   └── Automated-Host-Isolation.md
│
├── MITRE-Mapping/
│   └── Detection-Mapping.md
│
├── README.md
└── LICENSE
```

---

## Skills Demonstrated

This portfolio demonstrates practical exposure to:

* Security detection development
* KQL query development
* Threat hunting
* Windows security telemetry analysis
* Authentication investigation
* Process execution analysis
* PowerShell security monitoring
* Command-line analysis
* Network connection analysis
* MITRE ATT&CK mapping
* SOC investigation methodology
* Detection documentation
* Detection tuning
* False-positive analysis
* Incident classification
* Evidence-based investigation
* Analyst-oriented technical communication
* SOAR playbook design
* Automated endpoint containment concepts

---

## Lab Scope

This repository represents a detection engineering and threat-hunting portfolio/lab.

The documented detections, hunting queries, investigation workflows, investigation reports, SOC case studies, MITRE mappings, and SOAR playbook design demonstrate security monitoring concepts, analytical methodology, and detection engineering practices.

The project does not claim that the documented techniques represent confirmed malicious activity.

The Suspicious PowerShell case study is explicitly a simulated Home Lab investigation.

The automated host isolation playbook is a documented SOAR design demonstrating how Microsoft Sentinel and Microsoft Defender for Endpoint could be integrated for automated containment.

It does **not** claim that live endpoint isolation was performed as part of this portfolio.

---

## Current Project Coverage

| Area | Status |
| ---- | ------ |
| Detection Rules | Complete |
| Threat Hunting Queries | Complete |
| MITRE ATT&CK Mapping | Complete |
| Investigation Reports | Complete |
| SOC Incident Case Studies | Complete |
| SOAR Playbooks | Complete |
| Repository Documentation | Complete |
| GitHub Repository | Published |

---

## Future Development

Potential future extensions include:

* Additional SOC incident case studies
* Investigation timelines
* Additional detection rules
* Additional threat-hunting scenarios
* Microsoft Sentinel analytics-rule documentation
* Detection tuning
* False-positive analysis
* Security investigation evidence
* Incident response documentation
* Detection validation scenarios
* Security monitoring architecture documentation
* KQL query optimisation
* Additional MITRE ATT&CK coverage
* Additional SOAR automation scenarios
* Automated alert enrichment
* Incident severity and risk scoring
* Additional network investigation scenarios
* Endpoint telemetry correlation

---

## Portfolio Disclaimer

This repository is a technical portfolio and lab environment.

The detection rules, hunting queries, investigation workflows, investigation reports, SOAR playbook design, and MITRE ATT&CK mappings are intended to demonstrate security monitoring and analytical methodology.

The presence of a detection or MITRE ATT&CK mapping does not indicate that malicious activity was actually observed.

The SOC incident case study is simulated and is intended solely to demonstrate investigation methodology.

---

## Author

**Thabo Sakonta**

Cybersecurity / SOC / Detection Engineering Portfolio

**Project:** Microsoft Sentinel Detection Engineering Lab