# Simulated SOC Incident Case Study — Suspicious PowerShell Investigation

## Case Study Overview

This case study documents a simulated Security Operations Center (SOC) investigation involving potentially suspicious PowerShell activity within a Windows endpoint environment.

The investigation is designed to demonstrate an analyst workflow from initial detection through evidence collection, contextual analysis, threat hunting, MITRE ATT&CK mapping, classification, and recommended response.

> **Important:** This is a simulated Home Lab investigation created for cybersecurity portfolio and learning purposes. The activity described in this document does not represent a confirmed real-world compromise.

---

## 1. Investigation Objective

The objective of this investigation is to determine whether suspicious PowerShell execution represents:

* Legitimate administrative activity
* Benign automation
* Security tooling
* User activity
* Potentially malicious execution
* A precursor to additional suspicious activity

The investigation demonstrates how a SOC analyst should avoid treating a single detection as proof of compromise and instead correlate multiple pieces of telemetry.

---

## 2. Investigation Scenario

A Microsoft Sentinel detection identifies potentially suspicious PowerShell execution on a Windows endpoint.

The detection is associated with command-line characteristics that may require further investigation.

Potential indicators include:

* PowerShell execution
* Encoded command-line parameters
* Execution-policy modification or bypass
* No-profile execution
* Script execution
* Download-related commands
* Web request functionality
* Base64 decoding
* Suspicious parent-child process relationships

The initial alert is therefore treated as a **potentially suspicious event**, rather than confirmed malicious activity.

---

## 3. Initial Alert

### Alert Type

**Suspicious PowerShell Activity**

### Severity

**Medium — requires investigation**

### Detection Source

Microsoft Sentinel detection engineering content.

### Relevant Detection

```text
Detection-Rules/Suspicious-PowerShell.md
```

### Related Hunting Content

```text
Hunting-Queries/PowerShell-Hunting.md
Hunting-Queries/Suspicious-PowerShell-Hunting.md
Hunting-Queries/Process-Creation-Hunting.md
Hunting-Queries/Network-Connection-Hunting.md
```

---

## 4. Initial Analyst Assessment

The initial detection contains indicators that can occur during both legitimate administration and malicious activity.

The analyst therefore performs contextual investigation before assigning a final verdict.

The initial questions are:

1. Which endpoint generated the activity?
2. Which account executed PowerShell?
3. What was the parent process?
4. What command line was executed?
5. Was encoded PowerShell used?
6. Was execution policy modified?
7. Did PowerShell create another process?
8. Did the process establish network connections?
9. Were additional security events generated?
10. Is the activity consistent with expected administrative behaviour?

---

## 5. Investigation Scope

The investigation focuses on the following telemetry:

| Evidence Area        | Purpose                                                  |
| -------------------- | -------------------------------------------------------- |
| PowerShell execution | Identify suspicious scripting activity                   |
| Process creation     | Establish execution context                              |
| Command line         | Identify suspicious parameters                           |
| Parent process       | Determine process ancestry                               |
| Authentication       | Identify executing account                               |
| Network connections  | Determine whether execution resulted in communication    |
| DNS / web activity   | Identify potentially suspicious destinations             |
| MITRE ATT&CK         | Classify relevant behaviour                              |
| False positives      | Determine whether legitimate activity explains the event |

---

## 6. PowerShell Investigation

The analyst first reviews PowerShell telemetry.

Relevant indicators include:

```text
-EncodedCommand
-ExecutionPolicy Bypass
-NoProfile
-WindowStyle Hidden
-IEX
Invoke-Expression
DownloadString
Net.WebClient
Invoke-WebRequest
FromBase64String
Start-BitsTransfer
```

These indicators should not automatically be considered malicious.

For example, legitimate administrators, deployment tools, software installers, and automation frameworks may use PowerShell with unusual parameters.

The analyst therefore evaluates the indicators in context.

---

## 7. Command-Line Analysis

Command-line analysis is performed to determine the intent of the PowerShell execution.

Questions include:

* Was the command encoded?
* Was a script downloaded?
* Was content decoded?
* Was another process launched?
* Was PowerShell used to modify the environment?
* Was a remote resource accessed?
* Were suspicious strings present?
* Did the command attempt to hide execution?

A suspicious command-line pattern increases investigative priority but does not independently establish malicious intent.

---

## 8. Process Creation Correlation

The analyst correlates the PowerShell activity with Windows process creation telemetry.

Relevant telemetry may include:

```text
Windows Security Event ID 4688
```

The analyst examines:

* New process name
* Process ID
* Parent process
* Parent process ID
* Command line
* Account
* Timestamp
* Executable path

### Parent-Child Analysis

The analyst investigates whether PowerShell was launched by an expected parent process.

Examples of potentially interesting relationships include:

```text
winword.exe
    └── powershell.exe
```

```text
excel.exe
    └── powershell.exe
```

```text
outlook.exe
    └── powershell.exe
```

or:

```text
powershell.exe
    └── cmd.exe
```

or:

```text
powershell.exe
    └── rundll32.exe
```

These relationships require contextual investigation.

A suspicious parent-child relationship should be treated as an investigative signal rather than automatic proof of compromise.

---

## 9. Authentication Context

The analyst determines which account executed the PowerShell process.

Relevant questions include:

* Is the account a normal user?
* Is it an administrator?
* Is it a service account?
* Is the account expected to administer the endpoint?
* Was the account recently authenticated?
* Were there failed authentication attempts?
* Was the account used from an unusual source?

The investigation may correlate with:

```text
Windows Event ID 4625
```

for failed authentication activity.

Where relevant, successful authentication events can also be reviewed to determine whether suspicious activity followed authentication anomalies.

---

## 10. Network Connection Correlation

The investigation then moves from endpoint execution to network activity.

The analyst determines whether the PowerShell process established network communication.

Relevant hunting content:

```text
Hunting-Queries/Network-Connection-Hunting.md
```

Potential telemetry sources include:

```text
DeviceNetworkEvents
CommonSecurityLog
Sysmon
Firewall logs
Proxy logs
DNS logs
```

The analyst investigates:

* Remote IP
* Remote port
* Remote URL
* Protocol
* Timestamp
* Initiating process
* Initiating process command line
* Account
* Destination frequency

---

## 11. Network Investigation Questions

The analyst asks:

1. Did PowerShell initiate an outbound connection?
2. Was the destination internal or external?
3. Was the destination previously observed?
4. Was the destination rare for the endpoint?
5. Was the destination associated with expected software?
6. Was the destination contacted repeatedly?
7. Was the connection encrypted?
8. Was DNS resolution involved?
9. Did the connection occur immediately after PowerShell execution?
10. Was data transfer observed?

A network connection alone does not establish malicious activity.

The destination, timing, process context, and frequency must be considered together.

---

## 12. Network Behaviour Assessment

The analyst compares the observed network activity with expected endpoint behaviour.

Potentially interesting combinations include:

```text
PowerShell
    +
Encoded command
    +
External network connection
```

or:

```text
PowerShell
    +
Download-related command
    +
External destination
```

or:

```text
PowerShell
    +
Suspicious child process
    +
External network communication
```

These combinations increase investigative priority because multiple independent indicators support the same hypothesis.

---

## 13. Threat Hunting Correlation

The analyst expands the investigation beyond the original alert.

### PowerShell Hunting

```text
Hunting-Queries/PowerShell-Hunting.md
```

Used to identify related PowerShell activity.

### Suspicious PowerShell Hunting

```text
Hunting-Queries/Suspicious-PowerShell-Hunting.md
```

Used to identify behavioural indicators associated with suspicious scripting.

### Process Creation Hunting

```text
Hunting-Queries/Process-Creation-Hunting.md
```

Used to identify related process execution.

### Network Connection Hunting

```text
Hunting-Queries/Network-Connection-Hunting.md
```

Used to identify related network communication.

The purpose of this correlation is to determine whether the alert represents an isolated event or part of a broader activity pattern.

---

## 14. Investigation Timeline

The following timeline represents the structure an analyst would use to document the investigation.

| Sequence | Investigation Event                              |
| -------- | ------------------------------------------------ |
| T+00     | Suspicious PowerShell alert generated            |
| T+05     | Analyst validates alert details                  |
| T+10     | PowerShell command line reviewed                 |
| T+15     | Parent-child process relationship investigated   |
| T+20     | Executing account reviewed                       |
| T+25     | Authentication telemetry reviewed                |
| T+30     | Related process creation activity investigated   |
| T+35     | Network connection telemetry investigated        |
| T+40     | Related PowerShell and network hunting performed |
| T+50     | MITRE ATT&CK techniques assessed                 |
| T+60     | False-positive analysis completed                |
| T+65     | Analyst verdict documented                       |

> The timeline is a simulated investigation structure and does not represent timestamps from a real incident.

---

## 15. MITRE ATT&CK Mapping

The investigation may involve the following MITRE ATT&CK techniques depending on the evidence observed.

| Technique | Name                              | Investigative Relevance            |
| --------- | --------------------------------- | ---------------------------------- |
| T1059     | Command and Scripting Interpreter | Command execution                  |
| T1059.001 | PowerShell                        | PowerShell-based execution         |
| T1059.003 | Windows Command Shell             | Command shell activity             |
| T1105     | Ingress Tool Transfer             | Potential remote file transfer     |
| T1071.001 | Web Protocols                     | Potential HTTP/HTTPS communication |
| T1071.004 | DNS                               | DNS-based communication            |
| T1573     | Encrypted Channel                 | Potential encrypted communication  |
| T1027     | Obfuscated Files or Information   | Encoded or obfuscated content      |

These mappings are investigative references.

They **do not indicate that the corresponding techniques were confirmed**.

---

## 16. False-Positive Assessment

Potential legitimate explanations include:

### System Administration

An administrator may intentionally use:

```text
-ExecutionPolicy Bypass
-NoProfile
```

during troubleshooting or automation.

### Software Deployment

Deployment systems may execute PowerShell scripts automatically.

### Security Tools

Security products may generate PowerShell processes as part of legitimate security operations.

### Automation

Configuration-management and monitoring systems may execute scripts remotely.

### Developer Activity

Developers may use PowerShell for development, testing, or automation.

The analyst must therefore establish whether the activity was expected for the user, endpoint, application, and time period.

---

## 17. Evidence-Based Classification

The analyst should classify the investigation using evidence rather than assumptions.

### Benign

Use when:

* Activity is expected
* User and process context are legitimate
* Network activity is expected
* No additional suspicious indicators are identified

### Suspicious

Use when:

* Multiple indicators are present
* Activity cannot be explained by normal business activity
* Additional suspicious process or network behaviour is observed
* Further investigation is required

### Malicious / Confirmed

Use only when sufficient evidence supports malicious activity.

Examples could include:

* Confirmed malicious payload
* Known malicious infrastructure
* Confirmed unauthorized execution
* Corroborating endpoint and network evidence
* Confirmed compromise indicators

---

## 18. Simulated Analyst Verdict

### Verdict

**Suspicious — Requires Further Investigation**

### Confidence

**Medium**

### Rationale

The simulated investigation demonstrates a combination of potentially suspicious PowerShell, process, and network indicators.

However, because this is a Home Lab scenario and does not contain real incident evidence, the activity cannot legitimately be classified as a confirmed compromise.

The appropriate analyst response is therefore to classify the activity as suspicious pending additional evidence.

---

## 19. Recommended Response

If this were a real SOC investigation, recommended actions could include:

1. Preserve relevant endpoint telemetry.
2. Identify the affected user and endpoint.
3. Review the complete PowerShell command line.
4. Investigate the parent and child processes.
5. Review related authentication activity.
6. Investigate network destinations.
7. Search for the same indicators across other endpoints.
8. Determine whether the destination infrastructure is legitimate.
9. Check for additional execution or persistence activity.
10. Escalate if evidence supports compromise.

If malicious activity were confirmed, containment actions could include endpoint isolation and account security controls in accordance with organisational incident-response procedures.

---

## 20. Automated Response Consideration

The repository includes an automated host-isolation playbook:

```text
Playbooks/Automated-Host-Isolation.md
```

This demonstrates how a suspicious PowerShell detection could potentially trigger an automated containment workflow.

Automation should include appropriate safeguards.

Examples include:

* Critical-server exclusions
* Analyst review
* Confidence thresholds
* Incident severity checks
* Allow-listed administrative activity
* Approval controls

Automated containment should not be treated as a substitute for investigation.

---

## 21. Lessons Learned

This case study demonstrates several important SOC principles.

### Detection Alone Is Not Enough

A detection identifies activity requiring investigation. It does not automatically prove compromise.

### Context Matters

The same PowerShell command can be legitimate in one context and suspicious in another.

### Correlation Improves Confidence

PowerShell, process, authentication, and network telemetry become more useful when correlated.

### Threat Hunting Expands Visibility

A SOC analyst should search beyond the original alert to identify related activity.

### MITRE ATT&CK Provides Classification

ATT&CK mappings help describe observed or investigated behaviour but should not be used as proof of compromise.

### False Positives Must Be Considered

Effective detection engineering requires balancing detection coverage with operational accuracy.

---

## 22. Investigation Methodology

The overall workflow used in this case study is:

```text
Detection
   │
   ▼
Alert Validation
   │
   ▼
Endpoint Identification
   │
   ▼
User / Account Analysis
   │
   ▼
PowerShell Analysis
   │
   ▼
Command-Line Analysis
   │
   ▼
Process Tree Analysis
   │
   ▼
Authentication Correlation
   │
   ▼
Network Correlation
   │
   ▼
Threat Hunting
   │
   ▼
MITRE ATT&CK Mapping
   │
   ▼
False-Positive Assessment
   │
   ▼
Analyst Verdict
   │
   ▼
Recommended Response
```

This workflow represents the intended analytical methodology demonstrated by the Home Lab.

---

## 23. Related Portfolio Components

This case study connects the following repository components:

### Detection Engineering

```text
Detection-Rules/Suspicious-PowerShell.md
Detection-Rules/Process-Creation-Monitoring.md
Detection-Rules/Failed-Logon-Detection.md
```

### Threat Hunting

```text
Hunting-Queries/PowerShell-Hunting.md
Hunting-Queries/Suspicious-PowerShell-Hunting.md
Hunting-Queries/Process-Creation-Hunting.md
Hunting-Queries/Failed-Authentication-Hunting.md
Hunting-Queries/Network-Connection-Hunting.md
```

### Investigation Reports

```text
Investigation-Reports/Failed-Logon-Alert-Tuning.md
Investigation-Reports/Suspicious-PowerShell-Incident.md
```

### MITRE ATT&CK

```text
MITRE-Mapping/Detection-Mapping.md
```

### SOAR / Response

```text
Playbooks/Automated-Host-Isolation.md
```

---

## 24. Home Lab Classification

**Lab Type:**

Simulated SOC Investigation / Detection Engineering Home Lab

**Primary Domain:**

Security Operations Center

**Secondary Domains:**

* Detection Engineering
* Threat Hunting
* Endpoint Security
* Network Security
* Incident Response
* MITRE ATT&CK
* SOAR

**Environment:**

Windows / Microsoft Sentinel-oriented security monitoring laboratory.

**Evidence Type:**

Simulated investigation methodology and detection telemetry scenarios.

---

## 25. Portfolio Value

This case study demonstrates practical exposure to:

* SOC alert triage
* Security event analysis
* PowerShell investigation
* Process analysis
* Command-line analysis
* Authentication correlation
* Network investigation
* Threat hunting
* MITRE ATT&CK mapping
* False-positive analysis
* Incident classification
* Response recommendations
* Security documentation
* Analyst communication
* Detection engineering methodology

The case study is designed to demonstrate how multiple security-monitoring capabilities can be combined into an analyst-driven investigation.

---

## 26. Disclaimer

This document is a simulated cybersecurity Home Lab case study.

It is intended to demonstrate:

* Security monitoring methodology
* Detection engineering
* Threat hunting
* Investigation methodology
* Analyst reasoning
* MITRE ATT&CK classification
* Incident-response concepts

It does not claim that a real compromise occurred.

All investigation events, timelines, verdicts, and scenarios described as simulated are for educational and portfolio purposes.

---

## Author

**Thabo Sakonta**

Cybersecurity / SOC / Detection Engineering Portfolio

**Project:** Microsoft Sentinel Detection Engineering Lab
