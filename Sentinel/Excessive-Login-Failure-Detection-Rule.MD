//Detection Query for mostly Domain Activity and User activity.
//This Detection Rule identifies user accounts which has over 5 Windows logon failures with wrong password over the previous 10 mins.

//Mitre ATT&CK (Credential Access)
//T1110 - Brute Force

Query: 
// Define the threshold for excessive logon failures
let failureThreshold = 5;
// Get logon failure events in the any days specified
IdentityLogonEvents
| where TimeGenerated >= ago(5m)
| where ActionType == "LogonFailed"
| where FailureReason == "WrongPassword"
| summarize FailureCount = count()
    by
    AccountName,
    Application,
    AccountDomain,
    AccountUpn,
    FailureReason,
    AccountDisplayName,
    IPAddress, DeviceName, DestinationDeviceName, DestinationIPAddress
    | where FailureCount >= failureThreshold
| order by FailureCount desc
