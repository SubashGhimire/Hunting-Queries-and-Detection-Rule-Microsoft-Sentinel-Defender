#### This query identifies if any users are added to any privilege group that you want to keep an eye on. This query will help identify any user who is not suppose to be added on the list of privillege group. 
## Mitre Att&ck (Persistence)
### T1098- Account Manipulation
#### Query:
```KQL
IdentityDirectoryEvents
| where ActionType == "Group Membership changed"
| extend ToGroup = tostring(AdditionalFields.["TO.GROUP"])
| extend FromGroup = tostring(AdditionalFields.["FROM.GROUP"])
| where ToGroup in ('Security-Group', 'IT-Admin-Group')     // Specify the privilege group that you want to monitor
| project TimeGenerated, Actor=AccountName, UserAdded=TargetAccountUpn, ToGroup, FromGroup
```
