#### Identifies accounts who have failed to logon to the domain multiple times in a row, followed by a successful authentication within a short time frame. Multiple failed attempts followed by a success can be an indication of a brute force attempt or possible mis-configuration of a service account within an environment.
#### The lookback is set to 2h and the authentication window and threshold are set to 1h and 5, meaning we need to see a minimum of 5 failures followed by a success for an account within 1 hour to surface an alert.

## Mitre Att&Ck (Credential Access)
### T1110 - Brute Force

#### Query: 
```KQL
// Parameters
let lookbackPeriod = 2h;
let authenticationWindow = 1h;
let failureThreshold = 5;
// Filter logon events within the lookback period
let logonEvents = IdentityLogonEvents
    | where TimeGenerated >= ago(lookbackPeriod)
    | project
        TimeGenerated,AccountUpn, AccountSid, AccountName, IPAddress, DeviceName, Logonstatus = iff(ActionType == "LogonSuccess", "LogonSuccess", "LogonFailed");
// Identify failure sequences
let failureSequences = logonEvents
    | where Logonstatus == "LogonFailed"
    | summarize
        FailureCount = count(),
        StartTime = min(TimeGenerated),
        EndTime = max(TimeGenerated)
        by AccountUpn, AccountSid, bin(TimeGenerated, authenticationWindow)
    | where FailureCount >= failureThreshold;
// Identify success events
let successEvents = logonEvents
    | where Logonstatus == "LogonSuccess";
// Join failure sequences with success events within the same time window
failureSequences
| join kind=inner (
    successEvents
    | project SuccessTime = TimeGenerated, AccountUpn, AccountSid, AccountName, IPAddress, DeviceName
    )
    on AccountUpn, AccountSid
| extend endAuthenticationWindow = StartTime + authenticationWindow
| where SuccessTime between (StartTime .. endAuthenticationWindow)
| project AccountUpn, AccountSid, FailureCount, StartTime, EndTime, SuccessTime, AccountName, IPAddress, DeviceName
| order by SuccessTime desc
```
