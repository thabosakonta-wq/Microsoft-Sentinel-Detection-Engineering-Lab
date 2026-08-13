# Failed Logon Detection

## Detection Objective

Detect repeated Windows authentication failures that may indicate brute-force attacks, password spraying, credential guessing, or other suspicious authentication activity.

The detection uses Windows Security Event ID **4625** and applies time-window aggregation to distinguish concentrated authentication failures from isolated or routine user errors.

---

## MITRE ATT&CK

* **T1110 — Brute Force**
* **T1110.003 — Password Spraying**

---

## Data Source

* Windows Security Event Log
* Microsoft Sentinel `SecurityEvent`
* Event ID: **4625 — An account failed to log on**

---

## Detection Logic

The detection analyses failed authentication events in **15-minute windows**.

Two patterns are particularly important:

### Brute Force

A high number of failed authentication attempts against the same account may indicate credential guessing or brute-force activity.

### Password Spraying

A single source generating failed authentication attempts against multiple accounts may indicate password spraying.

The detection therefore preserves:

* Computer
* Account
* Source IP
* Failed-attempt count
* Number of targeted accounts
* First observed attempt
* Last observed attempt

---

## KQL Detection — Failed Authentication Aggregation

```kql
SecurityEvent
| where EventID == 4625
| extend
    TargetAccount = tostring(TargetUserName),
    SourceIP = tostring(IpAddress),
    LogonTypeValue = tostring(LogonType)
| where isnotempty(Computer)
| summarize
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    TargetAccounts = dcount(TargetAccount),
    Accounts = make_set(TargetAccount, 20),
    SourceIPs = make_set(SourceIP, 20),
    LogonTypes = make_set(LogonTypeValue, 10)
    by
    TimeWindow = bin(TimeGenerated, 15m),
    Computer
| where FailedAttempts >= 5
| project
    TimeWindow,
    Computer,
    FailedAttempts,
    TargetAccounts,
    Accounts,
    SourceIPs,
    LogonTypes,
    FirstAttempt,
    LastAttempt
| order by FailedAttempts desc
```

---

## Brute-Force Detection

The following logic focuses on repeated failures against the same account.

```kql
SecurityEvent
| where EventID == 4625
| extend
    TargetAccount = tostring(TargetUserName),
    SourceIP = tostring(IpAddress)
| where isnotempty(TargetAccount)
| summarize
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    SourceIPs = make_set(SourceIP, 20)
    by
    TimeWindow = bin(TimeGenerated, 15m),
    Computer,
    TargetAccount
| where FailedAttempts >= 5
| project
    TimeWindow,
    Computer,
    TargetAccount,
    FailedAttempts,
    SourceIPs,
    FirstAttempt,
    LastAttempt
| order by FailedAttempts desc
```

### Detection Interpretation

A high number of failures against one account within a short period can indicate:

* Password guessing
* Brute-force authentication
* Automated credential attacks
* Misconfigured applications
* Repeated use of an expired password

The result should be investigated in context rather than automatically classified as malicious.

---

## Password-Spray Detection

Password spraying differs from traditional brute force because the attacker may attempt authentication against multiple accounts rather than repeatedly targeting one account.

```kql
SecurityEvent
| where EventID == 4625
| extend
    TargetAccount = tostring(TargetUserName),
    SourceIP = tostring(IpAddress)
| where isnotempty(TargetAccount)
| where isnotempty(SourceIP)
| summarize
    FailedAttempts = count(),
    TargetAccounts = dcount(TargetAccount),
    Accounts = make_set(TargetAccount, 50),
    Computers = make_set(Computer, 20),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by
    TimeWindow = bin(TimeGenerated, 15m),
    SourceIP
| where TargetAccounts >= 5
| project
    TimeWindow,
    SourceIP,
    FailedAttempts,
    TargetAccounts,
    Accounts,
    Computers,
    FirstAttempt,
    LastAttempt
| order by TargetAccounts desc, FailedAttempts desc
```

### Detection Interpretation

A source generating failures against multiple accounts within a short period may indicate:

* Password spraying
* Credential attacks
* Automated authentication attempts
* Compromised internal systems attempting lateral movement

The `TargetAccounts` threshold should be tuned according to the environment.

---

## Threshold Tuning

The initial thresholds are intentionally conservative examples:

| Detection Pattern        | Initial Threshold | Window     |
| ------------------------ | ----------------: | ---------- |
| Repeated failures        |               ≥ 5 | 15 minutes |
| Same-account brute force |               ≥ 5 | 15 minutes |
| Password spraying        |      ≥ 5 accounts | 15 minutes |

These thresholds should not be considered universal values.

A production environment should tune thresholds using historical authentication telemetry.

Factors to consider include:

* Organisation size
* Number of users
* Service-account activity
* Authentication architecture
* VPN infrastructure
* Domain controllers
* Application behaviour
* Normal administrative activity
* Remote-access patterns

---

## Investigation Workflow

When the detection triggers, investigate the following:

### 1. Identify the Account

Determine:

* Username
* Account type
* Privileged status
* Whether the account is active
* Whether the account belongs to a service or application

### 2. Identify the Source

Review:

* Source IP
* Source hostname
* Computer
* Authentication origin
* Internal versus external source

### 3. Examine Timing

Determine:

* First failed attempt
* Last failed attempt
* Number of attempts
* Attack duration
* Whether activity occurred during normal working hours

### 4. Determine the Attack Pattern

Establish whether the activity represents:

* Repeated attempts against one account
* Attempts against multiple accounts
* Multiple accounts from one source
* Multiple sources targeting one account

### 5. Search for Successful Authentication

A successful authentication following repeated failures can significantly increase investigative priority.

Review Event ID:

* **4624 — An account was successfully logged on**

Correlate the successful authentication with:

* Account
* Computer
* Source IP
* Timestamp
* Logon type

### 6. Correlate Additional Telemetry

Where available, correlate with:

* Process creation
* PowerShell activity
* Endpoint alerts
* Network connections
* Privileged account activity
* Other authentication events

---

## False Positive Considerations

Failed authentication does not automatically indicate malicious activity.

Common legitimate causes include:

* Incorrect passwords
* Expired passwords
* Cached credentials
* Service-account configuration issues
* Applications using outdated credentials
* Scheduled tasks using old credentials
* Automated enterprise applications
* User error
* Network authentication issues

Detection results should therefore be assessed in context.

---

## Severity

**Default Severity: Medium**

Consider increasing severity when one or more of the following conditions are present:

* Multiple accounts are targeted.
* A large number of failures occur rapidly.
* The source is unusual or previously unseen.
* Authentication originates from an unexpected endpoint.
* The source is external when internal authentication is expected.
* Failed attempts are followed by successful authentication.
* A privileged account is targeted.
* The activity is correlated with endpoint or network security alerts.
* The activity occurs outside expected authentication patterns.

---

## Response Guidance

If suspicious authentication activity is confirmed:

1. Identify the affected account.
2. Identify the originating source.
3. Determine whether authentication succeeded.
4. Review related Event ID `4624` events.
5. Investigate endpoint and network telemetry.
6. Determine whether additional accounts were targeted.
7. Assess whether the account or source system may be compromised.
8. Apply appropriate account-protection or containment measures according to organisational procedures.
9. Document the investigation and conclusion.

---

## Detection Engineering Considerations

This detection demonstrates several practical detection-engineering concepts:

* Time-window aggregation using `bin()`
* Threshold-based detection
* Distinction between brute force and password spraying
* Source and account cardinality
* Detection tuning
* Contextual investigation
* False-positive analysis
* Severity assessment
* Authentication-event correlation

The thresholds should be validated against representative telemetry before being deployed as production analytics rules.

---

## Detection Limitations

The detection depends on the quality and availability of Windows authentication telemetry.

Potential limitations include:

* Missing source-IP information
* Incomplete Event ID `4625` ingestion
* Differences in Windows authentication configurations
* Service-account noise
* NAT or proxy infrastructure obscuring the original source
* Legitimate authentication bursts
* Thresholds that are too low or too high for the environment

Additional enrichment and correlation should therefore be considered before treating an alert as confirmed malicious activity.

---

## Validation Scenarios

The detection should be validated against controlled scenarios such as:

### Scenario 1 — Normal User Error

A user enters an incorrect password several times.

**Expected result:**
The activity may trigger the basic threshold but should be assessed as a potential false positive.

### Scenario 2 — Repeated Account Targeting

Multiple failed attempts are generated against one account within 15 minutes.

**Expected result:**
The brute-force detection should identify the activity.

### Scenario 3 — Multiple Account Targeting

A single source generates failed authentication attempts against several accounts within 15 minutes.

**Expected result:**
The password-spray detection should identify the activity.

### Scenario 4 — Failure Followed by Success

Multiple failed authentication attempts are followed by a successful Event ID `4624`.

**Expected result:**
The authentication sequence should receive increased investigative priority.

---

## Detection Status

**Status:** Active Detection Design

**Detection Type:** Authentication Anomaly / Brute Force / Password Spraying

**Primary Event:** Windows Security Event ID `4625`

**Recommended Frequency:** 15-minute analytical window

**Default Severity:** Medium

---

## Portfolio Note

This detection demonstrates how Windows authentication telemetry can be transformed into actionable security analytics using Microsoft Sentinel and KQL.

The detection is designed to demonstrate detection engineering methodology and does not claim that confirmed malicious authentication activity was observed in the laboratory environment.
