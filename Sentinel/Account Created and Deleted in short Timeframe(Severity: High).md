#### Look for accounts created and then deleted in under 24 hours. Attackers may create an account for their use, and then remove the account when no longer needed.
## MITRE ATT&CK
### Initial Access
### T1078-Valid Accounts

#### Query:
```KQL
let AccountCreationEvents = 
    IdentityDirectoryEvents
    | where ActionType == "User Account Created"
    | project AccountName, CreationTime = TimeGenerated;
let AccountDeletionEvents = 
    IdentityDirectoryEvents
    | where ActionType == " Account deleted"
    | project AccountName, DeletionTime = TimeGenerated;
AccountCreationEvents
| join kind=inner (AccountDeletionEvents) on AccountName
| extend TimeDifference = DeletionTime-CreationTime
| where TimeDifference <= 1d
| project AccountName, CreationTime, DeletionTime
| order by CreationTime desc
```

