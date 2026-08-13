# Failed Authentication Hunting

## Hunting Objective

Identify suspicious authentication activity that may indicate:

* Brute-force attacks
* Password spraying
* Credential stuffing
* Repeated authentication failures
* Account targeting
* Suspicious source systems
* Successful authentication following repeated failures

This hunting content complements the **Failed Logon Detection** rule.

The purpose of threat hunting is to proactively identify suspicious authentication patterns that may not generate an individual detection alert.

---

## MITRE ATT&CK

* **T1110 — Brute Force**
* **T1110.001 — Password Guessing**
* **T1110.003 — Password Spraying**
* **T1078 — Valid Accounts**

---

## Data Sources

Primary telemetry:

* Windows Security Event Log
* Microsoft Sentinel `SecurityEvent`
* Event ID **4625 — An account failed to log on**
* Event ID **4624 — An account was successfully logged on**

Additional telemetry may include:

* Microsoft Defender for Endpoint
* Microsoft Entra ID sign-in logs
* VPN authentication logs
* Firewall logs
* Identity provider logs

---

# Hunt 1 — Authentication Failure Overview

Establish a baseline of failed authentication activity.

```kql
SecurityEvent
| where EventID == 4625
| summarize
    FailureCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Computer, Account
| order by FailureCount desc
```

### Hunting Purpose

Identify accounts and systems experiencing unusually high authentication failure volumes.

Investigate:

* Repeated failures
* Service accounts
* Administrative accounts
* Unusual destination systems
* Authentication activity outside normal operating patterns

---

# Hunt 2 — Top Source IP Addresses

Identify source addresses generating large numbers of authentication failures.

```kql
SecurityEvent
| where EventID == 4625
| extend SourceIP = tostring(IpAddress)
| where isnotempty(SourceIP)
| summarize
    FailureCount = count(),
    TargetAccounts = dcount(Account),
    TargetSystems = dcount(Computer),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP
| order by FailureCount desc
```

### Hunting Purpose

A source IP repeatedly targeting one account may indicate brute-force activity.

A source IP targeting many accounts may indicate password spraying or credential attacks.

---

# Hunt 3 — Password Spray Detection

Identify sources attempting authentication against multiple accounts within a short time period.

```kql
SecurityEvent
| where EventID == 4625
| extend SourceIP = tostring(IpAddress)
| where isnotempty(SourceIP)
| summarize
    FailureCount = count(),
    TargetAccounts = dcount(Account),
    Accounts = make_set(Account, 20),
    TargetSystems = dcount(Computer),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, bin(TimeGenerated, 15m)
| where TargetAccounts >= 5
| order by TargetAccounts desc, FailureCount desc
```

### Investigation Guidance

Password spraying commonly involves a small number of password attempts against multiple accounts.

Investigate:

* Source IP reputation
* Targeted accounts
* Authentication protocol
* Logon type
* Whether any authentication subsequently succeeded
* Whether the source is an approved administrative system
* Whether the activity occurred across multiple endpoints

---

# Hunt 4 — Brute Force Against Individual Accounts

Identify accounts experiencing repeated authentication failures.

```kql
SecurityEvent
| where EventID == 4625
| summarize
    FailureCount = count(),
    SourceIPs = make_set(IpAddress, 20),
    SourceCount = dcount(IpAddress),
    TargetSystems = make_set(Computer, 20)
    by Account, bin(TimeGenerated, 15m)
| where FailureCount >= 10
| order by FailureCount desc
```

### Hunting Purpose

Repeated failures against a single account may indicate:

* Password guessing
* Credential attacks
* Automated authentication attempts
* Service-account misuse

Thresholds should be tuned to the environment.

---

# Hunt 5 — Failed Authentication Followed by Success

Identify potentially suspicious successful authentication following a failed authentication attempt.

```kql
let FailedLogons =
    SecurityEvent
    | where EventID == 4625
    | project
        FailureTime = TimeGenerated,
        Account,
        FailureComputer = Computer,
        FailureSourceIP = tostring(IpAddress);

let SuccessfulLogons =
    SecurityEvent
    | where EventID == 4624
    | project
        SuccessTime = TimeGenerated,
        Account,
        SuccessComputer = Computer,
        SuccessSourceIP = tostring(IpAddress);

FailedLogons
| join kind=inner SuccessfulLogons on Account
| where SuccessTime between (FailureTime .. FailureTime + 30m)
| project
    FailureTime,
    SuccessTime,
    Account,
    FailureComputer,
    SuccessComputer,
    FailureSourceIP,
    SuccessSourceIP
| order by FailureTime desc
```

### Investigation Priority

Increase investigative priority when:

* Multiple failures precede the success
* The source IP is unusual
* The account is privileged
* The destination system is critical
* The source is external
* The successful authentication is followed by suspicious process activity

A successful authentication does not by itself prove compromise.

---

# Hunt 6 — Multiple Accounts From One Source

Identify authentication activity where a single source attempts access to multiple accounts.

```kql
SecurityEvent
| where EventID in (4624, 4625)
| extend SourceIP = tostring(IpAddress)
| where isnotempty(SourceIP)
| summarize
    AuthenticationAttempts = count(),
    FailedAttempts = countif(EventID == 4625),
    SuccessfulAttempts = countif(EventID == 4624),
    Accounts = make_set(Account, 30),
    AccountCount = dcount(Account)
    by SourceIP, bin(TimeGenerated, 30m)
| where AccountCount >= 5
| order by AuthenticationAttempts desc
```

### Hunting Purpose

This can expose:

* Password spraying
* Credential stuffing
* Compromised administrative systems
* Automated authentication tools

---

# Hunt 7 — Privileged Account Authentication Failures

Prioritize failed authentication involving administrative accounts.

```kql
SecurityEvent
| where EventID == 4625
| where Account contains "admin"
    or Account contains "administrator"
| summarize
    FailureCount = count(),
    SourceIPs = make_set(IpAddress, 20),
    Computers = make_set(Computer, 20)
    by Account
| order by FailureCount desc
```

### Tuning Consideration

Account-name matching is only a basic hunting technique.

A production implementation should use an approved privileged-account reference list containing:

* Domain administrators
* Server administrators
* Security administrators
* Service accounts
* Break-glass accounts

---

# Hunt 8 — Authentication Failures by Logon Type

Analyze the logon type associated with authentication failures.

```kql
SecurityEvent
| where EventID == 4625
| summarize
    FailureCount = count()
    by LogonType, FailureReason
| order by FailureCount desc
```

### Investigation Guidance

Logon type provides additional context about the authentication attempt.

Investigate unusual combinations of:

* Account
* Logon type
* Source
* Destination
* Failure reason
* Time of activity

---

# Hunt 9 — External Source Authentication Activity

Identify authentication failures originating from non-private IPv4 addresses.

```kql
SecurityEvent
| where EventID == 4625
| extend SourceIP = tostring(IpAddress)
| where isnotempty(SourceIP)
| where not(ipv4_is_private(SourceIP))
| summarize
    FailureCount = count(),
    TargetAccounts = dcount(Account),
    Accounts = make_set(Account, 20),
    TargetSystems = dcount(Computer)
    by SourceIP
| order by FailureCount desc
```

### Investigation Guidance

Validate:

* Whether remote access is expected
* VPN usage
* Firewall exposure
* Source location
* IP reputation
* Authentication method
* Whether successful authentication occurred

This query should be interpreted carefully because IPv6 and other address formats may require additional handling.

---

# Hunt 10 — Authentication Activity Against Multiple Hosts

Identify sources targeting multiple systems.

```kql
SecurityEvent
| where EventID == 4625
| extend SourceIP = tostring(IpAddress)
| where isnotempty(SourceIP)
| summarize
    FailureCount = count(),
    TargetSystems = dcount(Computer),
    Systems = make_set(Computer, 30),
    Accounts = make_set(Account, 30)
    by SourceIP, bin(TimeGenerated, 30m)
| where TargetSystems >= 3
| order by TargetSystems desc, FailureCount desc
```

### Hunting Purpose

This may identify:

* Password spraying
* Lateral authentication attempts
* Automated credential attacks
* Compromised internal systems

---

# Investigation Correlation

Authentication hunting becomes significantly more valuable when correlated with other telemetry.

## Process Creation

Look for:

* `powershell.exe`
* `pwsh.exe`
* `cmd.exe`
* `wscript.exe`
* `cscript.exe`
* `rundll32.exe`
* `regsvr32.exe`
* `mshta.exe`
* Unknown executables

## Network Activity

Investigate:

* New outbound connections
* Remote administration protocols
* Unusual destination IPs
* External authentication sources
* Potential command-and-control communication

## File Activity

Investigate:

* Newly created executables
* Scripts
* Temporary files
* Archive files
* Files created immediately after successful authentication

## Persistence

Look for:

* Scheduled tasks
* Services
* Registry Run keys
* Startup folders
* Newly created accounts

## PowerShell

Correlate authentication activity with:

* Encoded commands
* Execution-policy bypass
* Download activity
* `Invoke-Expression`
* `DownloadString`
* `Net.WebClient`

---

# Example Attack Chain

A potentially suspicious sequence may resemble:

```text
External Source
      |
      v
Multiple Failed Authentication Attempts
      |
      v
Successful Authentication
      |
      v
PowerShell Execution
      |
      v
Payload Download
      |
      v
Persistence
```

This sequence should receive significantly more investigative attention than an isolated failed authentication event.

The analyst should correlate timestamps, accounts, source systems, destination systems and process activity.

---

# False Positive Considerations

Authentication failures can be caused by legitimate activity.

Common sources include:

* Incorrect passwords
* Expired passwords
* Locked accounts
* Service accounts
* Scheduled tasks
* Applications using outdated credentials
* Mapped drives
* VPN reconnect attempts
* Automated management systems
* Monitoring platforms

Before escalation, establish whether the activity is expected.

---

# Tuning Recommendations

Production deployments should consider:

* Approved administrative IP ranges
* VPN infrastructure
* Domain controllers
* Monitoring systems
* Service accounts
* Automated management platforms
* Known vulnerability scanners
* Backup systems
* Application servers

Reference tables can be used to reduce repeated false positives.

Thresholds should be adjusted according to:

* Environment size
* Authentication volume
* User population
* Server population
* Normal administrative activity
* Service-account behaviour

---

# Severity Guidance

## Low

Examples:

* Small number of failures
* Known internal source
* Known user
* Expected administrative activity

## Medium

Examples:

* Repeated failures
* Multiple targeted accounts
* Unusual source
* Unexpected authentication pattern

## High

Examples:

* Password-spray pattern
* Brute-force activity against privileged accounts
* External authentication attacks
* Failed attempts followed by successful authentication
* Authentication followed by suspicious process execution

## Critical

Consider critical escalation when authentication activity is correlated with strong evidence of compromise, such as:

* Successful privileged authentication
* Suspicious PowerShell execution
* Credential theft
* Persistence
* Lateral movement
* Confirmed malicious payload execution

---

# Analyst Workflow

When this hunt identifies suspicious activity:

1. Identify the source system or IP.
2. Identify targeted accounts.
3. Identify affected systems.
4. Determine the authentication type.
5. Establish the relevant time window.
6. Determine whether authentication succeeded.
7. Review the successful session.
8. Review process creation telemetry.
9. Review PowerShell activity.
10. Review network connections.
11. Review file creation.
12. Search for persistence.
13. Check for lateral movement.
14. Determine whether additional systems are affected.
15. Document findings.
16. Escalate or contain according to incident-response procedures.

---

# Hunting Limitations

This hunting content assumes Windows Security Event telemetry is available and correctly configured.

Hunting quality depends on:

* Event collection configuration
* Command-line auditing
* Network telemetry
* Identity logging
* Time synchronization
* Account normalization
* Source IP visibility

Some authentication scenarios may not appear in `SecurityEvent`.

For cloud authentication, analysts should also use appropriate identity telemetry such as Microsoft Entra ID sign-in logs.

---

# Validation

Testing should be performed only in an authorized lab environment.

Recommended validation scenarios:

* Repeated incorrect password attempts
* Multiple accounts targeted from one source
* Successful authentication after failed attempts
* Administrative account failures
* Internal authentication failures
* Remote authentication attempts

Each scenario should record:

* Expected result
* Actual result
* Query result
* Detection/hunting value
* False-positive assessment
* Required tuning

---

# Detection Engineering Relationship

This hunt complements:

`Detection-Rules/Failed-Logon-Detection.md`

The relationship is:

```text
Failed Authentication Telemetry
            |
            v
Failed Logon Detection
            |
            v
Threat Hunting
            |
            v
Correlation
            |
            v
Investigation
            |
            v
Response / SOAR
```

The detection provides targeted alerting.

The hunting layer provides proactive investigation and broader behavioural analysis.

---

# SOC Analyst Notes

Authentication failures should rarely be evaluated in isolation.

The strongest investigative signal is often the relationship between:

* Source
* Account
* Destination
* Time
* Authentication type
* Failure frequency
* Successful authentication
* Process activity
* Network activity
* Persistence

This approach helps distinguish normal authentication noise from potentially malicious credential activity.

---

# Portfolio Purpose

This hunting query demonstrates practical SOC threat-hunting methodology using Microsoft Sentinel and Windows Security telemetry.

It demonstrates the ability to:

* Query authentication telemetry
* Identify brute-force patterns
* Identify password-spray behaviour
* Correlate failures with successful authentication
* Prioritize privileged accounts
* Analyze source systems
* Consider false positives
* Apply MITRE ATT&CK
* Develop investigation pivots
* Connect detection engineering with threat hunting

The presence of suspicious authentication activity does not by itself confirm compromise.

The analyst must establish intent, context, scope and supporting evidence.
