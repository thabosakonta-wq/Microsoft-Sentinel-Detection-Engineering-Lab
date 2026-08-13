# SOC Incident Investigation & Alert Tuning: Failed Logon Loop

## 1. Incident Overview
* **Incident ID:** INC-2026-0813B
* **Severity:** 🟡 Medium
* **Status:** Closed (Resolved / Alert Tuned)
* **Target Host:** `SQL-PROD-01.local`
* **Impacted User:** `SVC_BackupAdmin`
* **Assigned Analyst:** Thabo
* **MITRE ATT&CK Tactic:** Credential Access ([TA0006](https://mitre.org))
* **MITRE ATT&CK Technique:** Brute Force ([T1110](https://mitre.org))

---

## 2. Detection Trigger & Alert Context
The incident triggered via a custom Microsoft Sentinel Analytics Rule designed to detect high-frequency failed logon events on critical assets.

### Triggered KQL Detection Rule
```kusto
// References: Detection-Rules/Failed-Logon-Detection.md
SecurityEvent
| where EventID == 4625
| summarize FailureCount = count() by TimeGenerated = bin(TimeGenerated, 5m), Account, Computer, SubStatus, LogonType
| where FailureCount > 30
```

---

## 3. Timeline of Events

| Timestamp (UTC) | Source Component | Event / Action Description |
| :--- | :--- | :--- |
| `2026-08-13 20:00:00` | Microsoft Sentinel | Alert Triggered: High volume of failed logons detected on `SQL-PROD-01`. |
| `2026-08-13 20:05:00` | SOC Analyst | Analyst initiated triage and cross-referenced active network changes. |
| `2026-08-13 20:12:00` | Active Directory | Confirmed account `SVC_BackupAdmin` is locked out due to continuous bad password attempts. |
| `2026-08-13 20:25:00` | SysAdmin Team | Confirmed a password rotation occurred at 19:55 UTC, but a legacy scheduled backup script was not updated. |
| `2026-08-13 20:40:00` | SOC Analyst | Closed incident as a False Positive and initiated an analytics rule exclusion to filter out system noise. |

---

## 4. Deep-Dive Analyst Investigation

### Step 1: Baseline Analysis
The analyst queried the environment using the corresponding hunting query (`Hunting-Queries/Failed-Authentication-Hunting.md`) to extract specific `SubStatus` codes and trends over time:

```kusto
SecurityEvent
| where EventID == 4625 and Computer == "SQL-PROD-01.local"
| summarize count() by TargetUserName, SubStatus, LogonType
```

### Step 2: Findings & Diagnostics
* **Target Account:** `SVC_BackupAdmin`
* **Logon Type:** `0` (Batch/Scheduled Task execution attempt)
* **SubStatus Code:** `0xc000006a` (User name correct but password is incorrect)
* **Frequency:** Exactly 120 attempts every 5 minutes.

The strict periodic interval and specific account name pointed heavily away from human threat-actor behavior (which typically searches laterally or checks varied username lists) and pointed towards an automated application authentication loop.

---

## 5. Verdict & Detection Tuning Action
* **Verdict:** False Positive (FP) — Misconfigured Administrative System Task
* **Root Cause:** The enterprise domain service account password was rotated according to corporate compliance policy. However, the automated backup task running on `SQL-PROD-01` was caching the legacy credentials, causing a persistent authentication failure loop.

### Detection Engineering Tuning (Optimization)
To prevent future alert fatigue caused by service account password rotations, the original detection rule was modified. We implemented a KQL filter to exclude high-privilege service accounts running batch processes while maintaining active tracking on actual interactive user logons:

```kusto
// Tuned Analytics Rule Logic
SecurityEvent
| where EventID == 4625
// Filter out legitimate batch service accounts known to cycle passwords
| where not(TargetUserName startswith "SVC_" and LogonType == 0)
| summarize FailureCount = count() by TimeGenerated = bin(TimeGenerated, 5m), TargetUserName, Computer, LogonType
| where FailureCount > 30
```
