#### This query identifies accounts that were created or deleted by users other than the defined list of approved user principal names using the IdentityDirectoryEvents.
## MITRE ATT&CK (Initial Access)
### T1078-Valid Account
#### Query:
```KQL
let approvedUsers = dynamic(["User1", "User2", "User3"]); // Specify the list of users that are allowed to create and delete the user account
IdentityDirectoryEvents
| where ActionType  in ("User Account Created", "Device Account Created", "Account Deleted Changed", "Account Deleted")
| where not(AccountUpn  in (approvedUsers))
| project TimeGenerated, AccountUpn, TargetAccountUpn, ActionType, Application, AccountDomain, AccountName, Device
```
