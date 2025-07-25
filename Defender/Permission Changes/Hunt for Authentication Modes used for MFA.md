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
AuditLogs
| where OperationName == "Update user" and TargetResources contains "StrongAuthenticationUserDetails"
| extend Target = TargetResources[0].userPrincipalName
| extend Actor = parse_json(InitiatedBy.user).userPrincipalName
| mv-expand   ModifiedProperties = parse_json(TargetResources[0].modifiedProperties)
| where ModifiedProperties.displayName == "StrongAuthenticationUserDetails"
| extend NewValue = parse_json(replace_string(replace_string(tostring(ModifiedProperties.newValue),"[",""),"]",""))
| extend OldValue = parse_json(replace_string(replace_string(tostring(ModifiedProperties.oldValue),"[",""),"]",""))
| mv-expand NewValue
| mv-expand OldValue
| where (tostring(bag_keys(OldValue)) == tostring(bag_keys(NewValue))) or (isempty(OldValue) and tostring(NewValue) !contains ":null") or (isempty(NewValue) and tostring(OldValue) !contains ":null") 
| extend ChangedValue = tostring(bag_keys(NewValue)[0])
| extend OldValue = tostring(parse_json(OldValue)[ChangedValue])
| extend NewValue = tostring(parse_json(NewValue)[ChangedValue])
| extend OldValue = case(ChangedValue == "PhoneNumber" or ChangedValue == "AlternativePhoneNumber", replace_strings(OldValue,dynamic([' ','(',')']), dynamic(['','',''])), OldValue )
| extend NewValue = case(ChangedValue == "PhoneNumber" or ChangedValue == "AlternativePhoneNumber", replace_strings(NewValue,dynamic([' ','(',')']), dynamic(['','',''])), NewValue )
| where tostring(OldValue) != tostring(NewValue)
| extend Action = case(isempty(OldValue), strcat("Added new ",ChangedValue, " to Strong Authentication."),isempty(NewValue),strcat("Removed existing ",ChangedValue, " from Strong Authentication."),strcat("Changed ",ChangedValue," in Strong Authentication."))
| project TimeGenerated,Action,Actor,Target,ChangedValue,OldValue,NewValue
```
