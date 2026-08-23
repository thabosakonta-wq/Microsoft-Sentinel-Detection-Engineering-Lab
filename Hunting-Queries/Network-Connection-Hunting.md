# Network Connection Threat Hunting

## Hunting Objective

Identify potentially suspicious network connection activity that may indicate:

* Command and control communication
* Malware beaconing
* Ingress tool transfer
* Suspicious outbound connections
* Unusual external destinations
* Connections to public IP addresses
* Rare destination ports
* Repeated connections to the same destination
* High-volume outbound communication
* Suspicious process-to-network relationships
* Potential data staging or exfiltration activity
* Network activity associated with suspicious PowerShell execution
* Connections originating from unusual processes
* Communication involving unexpected hosts or accounts

This hunting content complements the endpoint-focused detection and hunting capabilities within this Microsoft Sentinel Detection Engineering Lab.

The objective is to identify network behaviours that may require investigation even when an individual connection does not independently trigger a security alert.

---

## MITRE ATT&CK

This hunting content supports investigation of techniques including:

* **T1071 - Application Layer Protocol**
* **T1071.001 - Web Protocols**
* **T1071.004 - DNS**
* **T1095 - Non-Application Layer Protocol**
* **T1105 - Ingress Tool Transfer**
* **T1041 - Exfiltration Over C2 Channel**
* **T1021 - Remote Services**
* **T1568 - Dynamic Resolution**
* **T1573 - Encrypted Channel**
* **T1059.001 - PowerShell**
* **T1027 - Obfuscated Files or Information**

MITRE ATT&CK mappings are investigative references and should not be interpreted as proof that a technique occurred.

---

## Data Sources

### Primary Telemetry

Potential Microsoft Sentinel data sources include:

* `DeviceNetworkEvents`
* `CommonSecurityLog`
* `SecurityEvent`
* `Sysmon`
* Firewall logs
* Proxy logs
* DNS logs
* Network security appliance logs

### Microsoft Defender for Endpoint

Where available, `DeviceNetworkEvents` can provide useful endpoint network telemetry including:

* Device name
* Timestamp
* Remote IP
* Remote port
* Remote URL
* Initiating process
* Initiating process command line
* Account
* Protocol
* Action type

### Windows Security Telemetry

Windows Security Event ID `4688` can provide process creation context.

This can be correlated with network telemetry to determine whether a suspicious process subsequently established network communication.

### Sysmon

Sysmon Event ID `3` can provide network connection telemetry when network connection logging is enabled.

### Important Telemetry Note

The KQL examples in this document primarily use `DeviceNetworkEvents`.

The availability and field names of network telemetry depend on the Microsoft Sentinel data connectors and data sources configured in the environment.

These queries should therefore be validated against the actual schema available in the target workspace before being deployed as production analytics rules.

---

# Hunt 1 - Network Connection Baseline

## Objective

Establish the normal volume of network connections across monitored endpoints.

```kql
DeviceNetworkEvents
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName
| order by ConnectionCount desc
```

## Analyst Considerations

Use this query to establish a baseline for:

* Highly active endpoints
* Low-activity endpoints
* Connection volume
* Monitoring coverage
* Historical activity periods

A high connection count does not independently indicate malicious activity.

---

# Hunt 2 - External/Public IP Connections

## Objective

Identify connections to public IP addresses that may warrant further investigation.

```kql
DeviceNetworkEvents
| where isnotempty(RemoteIP)
| where RemoteIPType == "Public"
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Devices = make_set(DeviceName, 20),
    Processes = make_set(InitiatingProcessFileName, 20)
    by RemoteIP
| order by ConnectionCount desc
```

## Analyst Considerations

Investigate:

* Unknown external destinations
* Newly observed IP addresses
* Rare destinations
* Connections from sensitive endpoints
* Connections initiated by unusual processes

Validate the destination against approved infrastructure, business services and known security tooling before classifying activity as suspicious.

---

# Hunt 3 - Rare Destination Ports

## Objective

Identify unusual destination ports that may warrant investigation.

```kql
DeviceNetworkEvents
| where isnotempty(RemotePort)
| summarize
    ConnectionCount = count(),
    Devices = dcount(DeviceName),
    Processes = make_set(InitiatingProcessFileName, 20)
    by RemotePort
| order by ConnectionCount asc
```

## Analyst Considerations

Rare ports may represent:

* Legitimate applications
* Administrative services
* Development environments
* Security tools
* Remote management
* Custom application protocols

Rare does not mean malicious.

The analyst should correlate the port with the destination, process, user, host role and timing.

---

# Hunt 4 - Repeated Connections and Potential Beaconing

## Objective

Identify repeated connections from endpoints to the same remote destination.

```kql
DeviceNetworkEvents
| where isnotempty(RemoteIP)
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Devices = make_set(DeviceName, 20),
    Processes = make_set(InitiatingProcessFileName, 20)
    by RemoteIP, RemotePort
| where ConnectionCount >= 20
| order by ConnectionCount desc
```

## Analyst Considerations

Repeated connections may be consistent with:

* Software update services
* Monitoring agents
* Browser activity
* Cloud services
* API communication
* Malware beaconing

Potential beaconing becomes more interesting when repeated communication is combined with:

* Consistent timing
* Rare destinations
* Suspicious processes
* Unknown infrastructure
* Unusual user accounts

---

# Hunt 5 - Suspicious Remote URLs

## Objective

Identify network activity involving remote URLs that may warrant investigation.

```kql
DeviceNetworkEvents
| where isnotempty(RemoteUrl)
| where RemoteUrl contains "."
| project
    Timestamp,
    DeviceName,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccountName
| order by Timestamp desc
```

## Analyst Considerations

Review:

* Newly observed domains
* Suspicious domain names
* Unusual URL paths
* Download-related activity
* Connections initiated by scripting engines
* Connections from unexpected processes

Domain reputation and organizational allowlists should be considered before classification.

---

# Hunt 6 - PowerShell Network Activity

## Objective

Identify network connections initiated by PowerShell.

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe")
| project
    Timestamp,
    DeviceName,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    Protocol,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccountName,
    ActionType
| order by Timestamp desc
```

## Analyst Considerations

PowerShell network activity can be legitimate administrative activity.

Increase investigative priority when network communication is associated with:

* `EncodedCommand`
* `DownloadString`
* `Invoke-WebRequest`
* `WebClient`
* `Start-BitsTransfer`
* `FromBase64String`
* Execution policy bypass
* Unexpected administrative accounts
* Suspicious parent processes

This hunt should be correlated with the project's PowerShell detection and hunting content.

---

# Hunt 7 - Command Shell Network Activity

## Objective

Identify network activity associated with Windows command interpreters.

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("cmd.exe", "command.com")
| project
    Timestamp,
    DeviceName,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    Protocol,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccountName
| order by Timestamp desc
```

## Analyst Considerations

Investigate command-shell network activity when it is associated with:

* Unusual user accounts
* Temporary directories
* Script execution
* Suspicious parent processes
* Unexpected external destinations
* Other indicators of compromise

---

# Hunt 8 - Suspicious Process-to-Network Relationships

## Objective

Identify network activity associated with processes that may warrant additional endpoint investigation.

```kql
DeviceNetworkEvents
| where isnotempty(InitiatingProcessFileName)
| summarize
    ConnectionCount = count(),
    RemoteIPs = make_set(RemoteIP, 20),
    RemoteURLs = make_set(RemoteUrl, 20),
    RemotePorts = make_set(RemotePort, 20)
    by DeviceName, InitiatingProcessFileName
| order by ConnectionCount desc
```

## Analyst Considerations

Review processes that:

* Rarely communicate externally
* Operate from unusual directories
* Have unexpected network access
* Communicate with unusual destinations
* Are associated with scripting activity

The process path and parent process should be reviewed where available.

---

# Hunt 9 - High-Volume Outbound Activity

## Objective

Identify endpoints generating unusually high numbers of network connections.

```kql
DeviceNetworkEvents
| summarize
    ConnectionCount = count(),
    UniqueDestinations = dcount(RemoteIP),
    UniquePorts = dcount(RemotePort),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName
| order by ConnectionCount desc
```

## Analyst Considerations

High-volume network activity can occur on:

* Servers
* Browsers
* Proxy systems
* Security tools
* Monitoring systems
* Software update infrastructure

Potentially suspicious activity should be evaluated against the normal role and baseline of the endpoint.

---

# Hunt 10 - Potential Command and Control Indicators

## Objective

Identify network activity combining multiple indicators that may justify deeper investigation.

```kql
DeviceNetworkEvents
| where isnotempty(RemoteIP)
| where RemoteIPType == "Public"
| where InitiatingProcessFileName in~ (
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe"
)
| project
    Timestamp,
    DeviceName,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    Protocol,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccountName
| order by Timestamp desc
```

## Analyst Considerations

This is an investigation query rather than proof of C2.

Prioritize events where multiple contextual indicators exist:

* Public destination
* Scripting process
* Unusual destination
* Suspicious command line
* Rare process
* Repeated communication
* Unexpected account

---

# Hunt 11 - Potential Ingress Tool Transfer

## Objective

Identify network activity that may be associated with downloading tools or files.

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (
    "powershell.exe",
    "pwsh.exe",
    "bitsadmin.exe",
    "curl.exe",
    "wget.exe"
)
| project
    Timestamp,
    DeviceName,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccountName
| order by Timestamp desc
```

## Analyst Considerations

Investigate:

* Downloads initiated from unexpected endpoints
* Tool transfer to sensitive systems
* Suspicious URLs
* Temporary-directory execution
* Download activity followed by process creation

Correlate network events with process creation and file activity where available.

---

# Hunt 12 - Potential Exfiltration Indicators

## Objective

Identify network activity that may warrant investigation for potential data transfer.

```kql
DeviceNetworkEvents
| where isnotempty(RemoteIP)
| where RemoteIPType == "Public"
| summarize
    ConnectionCount = count(),
    Devices = make_set(DeviceName, 20),
    Processes = make_set(InitiatingProcessFileName, 20),
    URLs = make_set(RemoteUrl, 20),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by RemoteIP, RemotePort
| order by ConnectionCount desc
```

## Analyst Considerations

Network connection telemetry alone may not provide sufficient evidence to establish data exfiltration.

Additional evidence may include:

* File access
* Archive creation
* Large data transfers
* Cloud storage activity
* Unusual destinations
* Compression utilities
* Suspicious processes

This hunt should therefore be treated as an investigation starting point.

---

# Hunt 13 - Process and Network Correlation

## Objective

Correlate process execution context with network activity.

```kql
DeviceNetworkEvents
| where isnotempty(InitiatingProcessFileName)
| project
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    Protocol
| order by Timestamp desc
```

## Analyst Workflow

For suspicious results:

1. Identify the endpoint.
2. Identify the initiating process.
3. Review the process command line.
4. Identify the user or account.
5. Identify the remote destination.
6. Determine whether the destination is expected.
7. Review the destination port.
8. Check whether communication is repeated.
9. Correlate with process creation telemetry.
10. Correlate with authentication activity.
11. Review PowerShell or scripting activity.
12. Determine whether the activity is legitimate or suspicious.
13. Document the investigation.

---

# Network Hunting Investigation Workflow

Network activity should be investigated using contextual correlation rather than isolated indicators.

## Step 1 - Identify the Endpoint

Determine:

* Device name
* Device role
* User
* Business function
* Criticality

## Step 2 - Identify the Process

Determine:

* Process name
* Process path
* Parent process
* Command line
* User context

## Step 3 - Identify the Destination

Determine:

* Remote IP
* Remote URL
* Destination port
* Protocol
* Public/private classification
* Known organizational service

## Step 4 - Establish Frequency

Determine:

* First observed time
* Last observed time
* Connection count
* Repetition interval
* Number of affected endpoints

## Step 5 - Correlate Endpoint Telemetry

Correlate network activity with:

* Windows Event ID 4688
* PowerShell activity
* Authentication events
* File activity
* Security alerts
* Other endpoint telemetry

## Step 6 - Assess Legitimacy

Determine whether the activity is:

* Expected
* Administrative
* Application-related
* Security-tool related
* Unknown
* Suspicious

## Step 7 - Determine Investigation Priority

Consider:

* Destination reputation
* Process reputation
* User context
* Endpoint criticality
* Persistence of activity
* Other correlated indicators

## Step 8 - Document the Result

Record:

* Investigation scope
* Evidence reviewed
* Relevant timestamps
* Affected systems
* Indicators
* MITRE ATT&CK techniques
* False-positive assessment
* Analyst conclusion
* Recommended action

---

# False Positive Considerations

Network hunting can generate significant legitimate activity.

Potential false positives include:

### Browsers

* Web browsing
* Search engines
* Content delivery networks
* Advertising services
* Cloud applications

### Operating System Services

* Windows updates
* Microsoft services
* Certificate validation
* Time synchronization
* DNS resolution

### Security Tools

* Endpoint protection
* Vulnerability scanners
* Monitoring agents
* Patch-management systems

### Business Applications

* SaaS applications
* APIs
* Remote management
* Cloud platforms
* Software update services

### Administrative Activity

* PowerShell administration
* Remote management
* System maintenance
* Software deployment

Network detections should therefore be tuned using:

* Known-good destinations
* Approved applications
* Expected process behaviour
* Device roles
* Service accounts
* Organizational baselines

---

# Detection Tuning Considerations

Potential tuning strategies include:

* Excluding known trusted destinations
* Allowlisting approved administrative tools
* Creating baselines per device role
* Creating baselines per user group
* Filtering expected security-tool traffic
* Using connection frequency thresholds
* Combining multiple indicators
* Correlating network and process telemetry
* Correlating network and authentication telemetry

Tuning should reduce unnecessary alert volume without removing meaningful security coverage.

---

# MITRE ATT&CK Mapping

| Technique | Name                            | Hunting Relevance                                                 |
| --------- | ------------------------------- | ----------------------------------------------------------------- |
| T1071     | Application Layer Protocol      | Investigating network application protocols                       |
| T1071.001 | Web Protocols                   | HTTP/HTTPS-related network activity                               |
| T1071.004 | DNS                             | DNS-related communication                                         |
| T1095     | Non-Application Layer Protocol  | Network communication outside common application protocols        |
| T1105     | Ingress Tool Transfer           | Potential tool/file downloads                                     |
| T1041     | Exfiltration Over C2 Channel    | Potential outbound data transfer investigation                    |
| T1021     | Remote Services                 | Remote network service activity                                   |
| T1568     | Dynamic Resolution              | Potential dynamically resolved infrastructure                     |
| T1573     | Encrypted Channel               | Potential encrypted communications                                |
| T1059.001 | PowerShell                      | PowerShell-initiated network activity                             |
| T1027     | Obfuscated Files or Information | Obfuscated command activity correlated with network communication |

These mappings represent potential investigative coverage.

They do not indicate that malicious activity was observed.

---

# Recommended Investigation Evidence

When documenting a network investigation, collect relevant evidence such as:

* Timestamp
* Device name
* User/account
* Remote IP
* Remote URL
* Destination port
* Protocol
* Initiating process
* Process path
* Parent process
* Command line
* Authentication events
* Related security alerts
* Destination reputation
* Connection frequency
* First/last observed timestamps

Sensitive information should be redacted before publishing portfolio material.

---

# Analyst Assessment Template

```text
Investigation ID:
Date:
Analyst:

Alert/Hunt:
Affected Device:
User/Account:

Remote IP:
Remote URL:
Remote Port:
Protocol:

Initiating Process:
Process Path:
Parent Process:
Command Line:

First Observed:
Last Observed:
Connection Count:

Related Events:
Related Alerts:

MITRE ATT&CK:

False Positive Assessment:

Analyst Verdict:
[ ] Benign
[ ] Suspicious
[ ] Malicious
[ ] Inconclusive

Recommended Action:

Notes:
```

---

# Portfolio Scope

This document is part of the Microsoft Sentinel Detection Engineering Lab portfolio.

The hunting queries demonstrate:

* Network threat hunting
* Endpoint network telemetry analysis
* KQL development
* Process-to-network correlation
* PowerShell network investigation
* C2 investigation methodology
* Ingress tool transfer investigation
* Exfiltration investigation
* MITRE ATT&CK mapping
* False-positive analysis
* Detection tuning
* SOC investigation methodology

---

# Important Lab Disclaimer

This repository is a technical portfolio and laboratory environment.

The queries and investigative scenarios are designed to demonstrate security monitoring, threat hunting and SOC analytical methodology.

The presence of a hunting query or MITRE ATT&CK mapping does **not** indicate that malicious activity was observed.

KQL examples should be validated against the actual schema and telemetry available in the target Microsoft Sentinel environment before being used operationally.

---

# Related Project Components

This hunting content complements:

* `Detection-Rules/Failed-Logon-Detection.md`
* `Detection-Rules/Process-Creation-Monitoring.md`
* `Detection-Rules/Suspicious-PowerShell.md`
* `Hunting-Queries/Failed-Authentication-Hunting.md`
* `Hunting-Queries/Process-Creation-Hunting.md`
* `Hunting-Queries/PowerShell-Hunting.md`
* `Hunting-Queries/Suspicious-PowerShell-Hunting.md`
* `Investigation-Reports/Suspicious-PowerShell-Incident.md`
* `MITRE-Mapping/Detection-Mapping.md`
* `Playbooks/Automated-Host-Isolation.md`

---

# Author

**Thabo Sakonta**

Cybersecurity / SOC / Detection Engineering Portfolio

**Project:** Microsoft Sentinel Detection Engineering Lab
