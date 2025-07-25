## 🔍 KQL Description
#### This query is used to:
#### 1.Monitor changes to users' Authenticator app registrations.
#### 2.Detect unauthorized device additions or removals.
#### 3.Support incident response and forensic investigations.
#### 4.Ensure compliance with MFA policies.
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Persistence / Defense Evasion
#### Goal: Adversaries may manipulate MFA device registrations to bypass authentication or maintain access.
#### Technique: Modify Authentication Process (T1556.006 - Modify Authentication Process: MFA)
#### Attackers may add their own device to a user's account or remove legitimate devices to control authentication.
### Query:
```KQL
//Azure Log Analytics query to parse modified StrongAuthenticationPhoneAppDetail
let DeviceChanges = AuditLogs
| where OperationName == "Update user"  and TargetResources contains "StrongAuthenticationPhoneAppDetail"
| extend Target = tostring(TargetResources[0].userPrincipalName)
| extend Actor = case(isempty(parse_json(InitiatedBy.user).userPrincipalName),tostring(parse_json(InitiatedBy.app).displayName) ,tostring(parse_json(InitiatedBy.user).userPrincipalName))
| mvexpand ModifiedProperties = parse_json(TargetResources[0].modifiedProperties)
| where ModifiedProperties.displayName == "StrongAuthenticationPhoneAppDetail" 
| project TimeGenerated,Actor,Target,TargetResources,ModifiedProperties,Id;
let OldValues= DeviceChanges
| extend  OldValue = parse_json(tostring(ModifiedProperties.oldValue))
| mv-apply OldValue on (extend Old_DeviceName=tostring(OldValue.DeviceName),Old_DeviceToken=tostring(OldValue.DeviceToken) | sort by tostring(Old_DeviceToken));
let NewValues= DeviceChanges
| extend NewValue = parse_json(tostring(ModifiedProperties.newValue))
| mv-apply NewValue on (extend New_DeviceName=tostring(NewValue.DeviceName),New_DeviceToken=tostring(NewValue.DeviceToken) | sort by tostring(New_DeviceToken));
let RemovedDevices = DeviceChanges
| join kind=inner OldValues  on Id
| join kind=leftouter  NewValues on Id,$left.Old_DeviceToken==$right.New_DeviceToken,$left.Old_DeviceName==$right.New_DeviceName
| extend Action = strcat("Removed Authenticator App Device (Name: ", Old_DeviceName , ", Token: ", Old_DeviceToken , ") from Strong Authentication");
let AddedDevices = DeviceChanges
| join kind=inner NewValues  on Id
| join kind=leftouter OldValues on Id,$left.New_DeviceToken==$right.Old_DeviceToken,$left.New_DeviceName==$right.Old_DeviceName
| extend Action = strcat("Added Authenticator App Device (Name: ", New_DeviceName , ", Token: ", New_DeviceToken , ") to Strong Authentication");
union RemovedDevices,AddedDevices
| where Old_DeviceToken != New_DeviceToken
| project TimeGenerated,Action,Actor,Target,Old_DeviceName,Old_DeviceToken,New_DeviceName,New_DeviceToken
| distinct *
```
