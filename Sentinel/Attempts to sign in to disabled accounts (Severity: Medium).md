#### Identifies failed attempts to sign in to disabled accounts in Active Directory
## MITRE ATT&CK (Initial Access)
### T1078- Valid Accounts
#### Query:
```KQL
IdentityLogonEvents
| where FailureReason == "AccountDisabled" and LogonType == "Failed logon"
| summarize FailedAttempts = count() by AccountName, AccountUpn, Application, IPAddress, DeviceName, DestinationDeviceName, DestinationIPAddress, DestinationPort, Protocol, bin(TimeGenerated, 1h)
| where FailedAttempts >= 5
| project AccountName, FailedAttempts, TimeGenerated, Application, IPAddress, DeviceName, DestinationDeviceName, DestinationIPAddress, DestinationPort, Protocol
| sort by TimeGenerated desc
```
