## 🔍 KQL Description
#### This query is used to:
#### 1.Audit MFA configuration changes across the organization.
#### 2.Detect unauthorized or suspicious changes to authentication methods.
#### 3.Support incident response by identifying who made the change and when.
#### 4.Ensure compliance with security policies requiring strong authentication.
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Persistence / Defense Evasion
#### Goal: Adversaries may alter authentication methods to maintain access or avoid detection.
#### Technique: Modify Authentication Process (T1556.006 - Modify Authentication Process: MFA)
#### Attackers may change or remove MFA methods to weaken account security or ensure persistent access.
### Query:
```KQL
let AuthenticationMethods = dynamic(["TwoWayVoiceMobile","TwoWaySms","TwoWayVoiceOffice","TwoWayVoiceOtherMobile","TwoWaySmsOtherMobile","OneWaySms","PhoneAppNotification","PhoneAppOTP"]);
let AuthenticationMethodChanges = AuditLogs
| where OperationName == "Update user" and TargetResources contains "StrongAuthenticationMethod"
| extend Target = tostring(TargetResources[0].userPrincipalName)
| extend Actor = case(isempty(parse_json(InitiatedBy.user).userPrincipalName),tostring(parse_json(InitiatedBy.app).displayName) ,tostring(parse_json(InitiatedBy.user).userPrincipalName))
| mvexpand ModifiedProperties = parse_json(TargetResources[0].modifiedProperties)
| where ModifiedProperties.displayName ==  "StrongAuthenticationMethod"
| project TimeGenerated,Actor,Target,TargetResources,ModifiedProperties,Id;
let OldValues = AuthenticationMethodChanges
| extend OldValue = parse_json(tostring(ModifiedProperties.oldValue))
| mv-apply OldValue on (extend Old_MethodType=tostring(OldValue.MethodType),Old_Default=tostring(OldValue.Default) | sort by Old_MethodType);
let NewValues = AuthenticationMethodChanges
| extend NewValue = parse_json(tostring(ModifiedProperties.newValue))
| mv-apply NewValue on (extend New_MethodType=tostring(NewValue.MethodType),New_Default=tostring(NewValue.Default) | sort by New_MethodType);
let RemovedMethods = AuthenticationMethodChanges
| join kind=inner OldValues on Id
| join kind=leftouter  NewValues  on Id,$left.Old_MethodType==$right.New_MethodType
| project TimeGenerated,Id,ModifiedProperties,Actor,Target,Old_MethodType,New_MethodType
| where Old_MethodType != New_MethodType
| extend Action = strcat("Removed (" , AuthenticationMethods[toint(Old_MethodType)], ") from Authentication Methods.")
| extend ChangedValue = "Method Removed";
let AddedMethods = AuthenticationMethodChanges
| join kind=inner NewValues on Id
| join kind=leftouter  OldValues  on Id,$left.New_MethodType==$right.Old_MethodType
| project TimeGenerated,Id,ModifiedProperties,Actor,Target,Old_MethodType,New_MethodType
| where Old_MethodType != New_MethodType
| extend Action = strcat("Added (" , AuthenticationMethods[toint(New_MethodType)], ") as Authentication Method.") 
| extend ChangedValue = "Method Added";
let DefaultMethodChanges = AuthenticationMethodChanges
| join kind=inner OldValues on Id
| join kind=inner NewValues on Id
| where Old_Default != New_Default and Old_MethodType == New_MethodType and New_Default == "true"
| join kind=inner OldValues on Id | where Old_Default1 == "true" and Old_MethodType1 != New_MethodType | extend Old_MethodType = Old_MethodType1
| extend Action = strcat("Default Authentication Method was changed to (" , AuthenticationMethods[toint(New_MethodType)], ").")
| extend ChangedValue = "Default Method";
union RemovedMethods,AddedMethods,DefaultMethodChanges
| project TimeGenerated,Action,Actor,Target,ChangedValue,OldValue=case(isempty(Old_MethodType), "",strcat(Old_MethodType,": ", AuthenticationMethods[toint(Old_MethodType)])),NewValue=case(isempty( New_MethodType),"", strcat(New_MethodType,": ", AuthenticationMethods[toint(New_MethodType)]))
| distinct *
```
