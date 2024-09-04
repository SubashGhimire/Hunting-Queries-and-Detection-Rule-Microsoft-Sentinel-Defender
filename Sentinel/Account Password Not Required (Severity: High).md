#### This query identifies if any user is created by enabling Account Password Not Required changed. 
#### Which means if this is enabled i.e if it is changed form False to True that user does not have to enter the password for authentication.
## Mitre Att&ck (Persistence)
### T1098- Account Manipulation

#### Query:
```KQL
IdentityDirectoryEvents
| where ActionType == "Account Password Not Required changed"
| extend PreviousState = tostring(parse_json(AdditionalFields)['FROM Account Password Not Required'])
| extend CurrentState = tostring(parse_json(AdditionalFields)['TO Account Password Not Required'])
| extend Actor = tostring(AdditionalFields.["ACTOR.ACCOUNT"])
| where PreviousState == "False" and CurrentState == "True"
| project TimeGenerated, AccountName, TargetAccountUpn, Actor, PreviousState, CurrentState, AdditionalFields
| order by TimeGenerated desc
```
