# Failed Authentication Hunting Query

## Objective

Identify repeated Windows authentication failures that may indicate brute-force activity, password spraying, credential misuse, or account configuration problems.

## KQL Query

```kql
SecurityEvent
| where EventID == 4625
| project
    TimeGenerated,
    Computer,
    Account,
    IpAddress,
    LogonType,
    FailureReason,
    SubStatus
| order by TimeGenerated desc
```
## Investigation Focus

Review authentication failures for:

- Repeated failures against the same account
- Multiple accounts targeted from the same source
- Unusual source IP addresses
- Unusual authentication times
- Suspicious logon types
- Authentication failures followed by successful logons

## Analyst Workflow

1. Identify the affected account.
2. Identify the originating computer or IP address.
3. Review the number and frequency of failures.
4. Determine the logon type.
5. Check whether other accounts were targeted.
6. Correlate with successful authentication events.
7. Determine whether the activity is legitimate or suspicious.

## MITRE ATT&CK

- **T1110 - Brute Force**
- **T1110.003 - Password Spraying**

## False Positive Considerations

Authentication failures may result from:

- Incorrect passwords
- Expired credentials
- Cached credentials
- Service accounts
- Misconfigured applications
- Normal user error

## Expected Outcome

The query provides authentication telemetry that can be used to identify patterns consistent with brute-force or password-spraying activity.

## Data Source

Windows Security Event Log / Microsoft Sentinel `SecurityEvent`.

## Portfolio Note

This hunting query demonstrates proactive investigation of authentication telemetry rather than relying exclusively on predefined alerts.

