# SOAR Playbook: Automated Endpoint Isolation via Microsoft Defender for Endpoint

## 1. Playbook Overview
* **Playbook Name:** `Automated-Host-Isolation`
* **Trigger Event:** Microsoft Sentinel Incident Creation
* **Target Alert:** `Suspicious Encoded PowerShell Process Detected`
* **Integration Connectors:** Microsoft Sentinel, Microsoft Entra ID, Microsoft Defender for Endpoint
* **Objective:** Drastically minimize attacker dwell time by automatically isolating an endpoint showing verified Command and Control (C2) callback behaviors.

---

## 2. Workflow Logic Architecture

The automated logic flow is structured sequentially to prevent false-positive impacts on critical infrastructure while ensuring rapid containment on standard workstations.

```text
[Sentinel Incident Trigger] 
            │
            ▼
[Extract Host & Account Entities]
            │
            ▼
[Condition Check: Is Host Critical Server?]
       ├───> YES ───> [Send PagerDuty/Teams Alert to On-Call Engineer] ───> [End]
       │
       └───> NO ────> [Call MDE API: Isolate Machine]
                             │
                             ▼
                      [Post Update to Sentinel Incident Timeline]
                             │
                             ▼
                      [Close Teams/Slack Alert Block with Status]
```

---

## 3. Detailed Component Steps

### Step 1: Incident Trigger & Context Enrichment
* **Trigger:** Playbook executes automatically when an incident containing the analytics rule `Suspicious PowerShell Detection` is generated.
* **Entity Extraction:** The workflow parses the Sentinel JSON payload to isolate dynamic variables:
  * `HostName` (e.g., `WKSTN-042`)
  * `AccountName` (e.g., `Thabo.Admin`)
  * `IncidentID`

### Step 2: Critical Asset Protection (Guardrail)
To ensure the automated logic does not accidentally isolate a production domain controller or critical database instance, a lookup step queries an Azure Key Vault or asset inventory table.
* **Condition:** If `HostName` contains `DC` or `PROD`, automation pauses. An urgent high-priority ticket escalates to human analysts.

### Step 3: Enforcement Action via Defender for Endpoint API
If the asset is verified as a standard corporate workstation, the playbook invokes the Microsoft Defender for Endpoint connector:
* **API Action:** `Post /api/machines/{id}/isolate`
* **Parameters Applied:**
  * **Isolation Type:** Full isolation (blocks all network traffic except to the Defender security cloud).
  * **Comment:** "Automated containment initiated by Sentinel Playbook: Automated-Host-Isolation due to INC-2026-0813A."

### Step 4: Incident Timeline Enrichment & Auditing
The playbook authenticates back to Microsoft Sentinel to append an operational audit log directly inside the incident timeline:
```text
[SOAR Automation Log]: Endpoint WKSTN-042 has been successfully isolated from the corporate network via Defender for Endpoint API. Isolation confirmed at 21:05 UTC.
```

---

## 4. Playbook Benefits & Metrics Impact
* **Dwell Time Reduction:** Lowers containment response latency from an average analyst triage time of 15–20 minutes down to **sub-30 seconds**.
* **Alert Fatigue Mitigation:** Reduces manual repetitive tasks for Tier-1 analysts, shifting resources toward deeper root-cause investigations.
