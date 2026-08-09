# Failed Logon Detection

## Detection Objective

Detect repeated failed authentication attempts on Windows endpoints using Microsoft Sentinel and Windows Security Event ID 4625.

## MITRE ATT&CK

- **T1110 — Brute Force**

## Data Source

- Windows Security Event Log
- Event ID: **4625 — An account failed to log on**

## KQL Detection

```kql
SecurityEvent
| where EventID == 4625
| summarize
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by Computer, Account
| where FailedAttempts >= 5
| project
    Computer,
    Account,
    FailedAttempts,
    FirstAttempt,
    LastAttempt
| order by FailedAttempts desc

# Failed Logon Detection

## Detection Objective

Detect repeated failed authentication attempts on Windows endpoints using Microsoft Sentinel and Windows Security Event ID 4625.

## MITRE ATT&CK

- **T1110 — Brute Force**

## Data Source

- Windows Security Event Log
- Event ID: **4625 — An account failed to log on**

## KQL Detection

```kql
SecurityEvent
| where EventID == 4625
| summarize
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by Computer, Account
| where FailedAttempts >= 5
| project
    Computer,
    Account,
    FailedAttempts,
    FirstAttempt,
    LastAttempt
| order by FailedAttempts desc

Detection Logic

The query identifies accounts experiencing five or more failed authentication attempts within the available query time range.

This can indicate:

Brute-force activity
Password spraying
Credential guessing
Misconfigured applications
Expired credentials
User error
Analyst Investigation

When the detection triggers, investigate:

The affected account.
The endpoint generating the events.
The number of failed attempts.
The time period of the activity.
The source workstation or IP address where available.
Whether a successful logon occurred after the failures.
Whether multiple accounts were targeted.
False Positive Considerations

Failed authentication does not automatically indicate malicious activity.

Common legitimate causes include:

Incorrect passwords
Cached credentials
Expired passwords
Service-account configuration issues
Applications using outdated credentials
Severity

Medium

Increase severity when:

Multiple accounts are targeted.
A large number of failures occur rapidly.
Authentication originates from an unusual endpoint.
Failed attempts are followed by a successful authentication.
The activity occurs outside normal working patterns.
Response

If suspicious authentication activity is confirmed:

Identify the affected account.
Identify the originating endpoint.
Review related authentication events.
Determine whether successful authentication occurred.
Investigate for additional suspicious activity.
Consider account protection or containment measures.
Document the incident.
Detection Engineering Notes

This detection demonstrates how Windows authentication telemetry can be used to identify potential brute-force and password-spraying activity within a Microsoft Sentinel environment.

