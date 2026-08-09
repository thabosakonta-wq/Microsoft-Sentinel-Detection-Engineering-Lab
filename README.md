# Microsoft Sentinel Detection Engineering Lab

## Overview

This repository demonstrates Microsoft Sentinel detection engineering using Kusto Query Language (KQL), threat hunting, MITRE ATT&CK mapping, and SOC investigation workflows.

The project focuses on developing practical detections for suspicious Windows activity and documenting the associated analyst investigation process.

## Objectives

- Develop KQL-based security detections
- Perform threat hunting using Microsoft Sentinel
- Map detections to MITRE ATT&CK
- Document SOC investigation workflows
- Develop repeatable analyst response procedures
- Demonstrate detection engineering skills

## Skills Demonstrated

- Microsoft Sentinel
- Kusto Query Language (KQL)
- Detection Engineering
- Threat Hunting
- Windows Security Event Analysis
- MITRE ATT&CK
- SOC Investigation
- Security Monitoring
- Incident Response

## Detection Coverage

| Detection | Windows Event | MITRE ATT&CK |
|---|---:|---|
| Suspicious PowerShell | 4688 | T1059.001 |
| Failed Logon Activity | 4625 | T1110 |
| Suspicious Process Creation | 4688 | T1057 |
| Persistence Activity | Various | T1547 |

## Repository Structure

```text
Detection-Rules/
Hunting-Queries/
Investigation-Reports/
MITRE-Mapping/
Playbooks/
Screenshots/

Tools
Microsoft Sentinel
Azure Log Analytics
Kusto Query Language
Windows Security Events
Sysmon
MITRE ATT&CK
Author

Thabo Sakonta

Microsoft Certified Security Operations Analyst (SC-200)

GitHub: https://github.com/thabosakonta-wq

LinkedIn: https://www.linkedin.com/in/thabo-sakonta-377a3748

Disclaimer

This repository is an educational cybersecurity portfolio project demonstrating defensive security monitoring, threat hunting, and detection engineering techniques.