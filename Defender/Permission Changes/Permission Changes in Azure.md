## 🔍 KQL Description
#### This query helps security teams:
#### 1.Track changes to privileged roles and group memberships.
#### 2.Identify potential unauthorized privilege escalation.
#### 3.Support compliance and audit requirements.
#### 4.Correlate identity changes with suspicious activity or alerts.
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Privilege Escalation / Persistence
#### Goal: Adversaries may attempt to gain elevated access or maintain persistence by modifying role or group memberships.
#### Technique: (T1078.004 - Valid Accounts: Privileged Accounts, T1098 - Account Manipulation)
#### Attackers may add themselves or others to privileged roles or groups to gain elevated access.
### Query:
```KQL
AuditLogs
| where OperationName in (
    "Add member to role", 
    "Remove member from role", 
    "Add eligible member to role", 
    "Remove eligible member from role", 
    "Update role membership", 
    "Update user",
    "Add member to group", 
    "Remove member from group"
)
| where Category contains "RoleManagement"
| where Result == "success"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName), TargetUser, TargetResources, AdditionalDetails, Category
| order by TimeGenerated desc
```
