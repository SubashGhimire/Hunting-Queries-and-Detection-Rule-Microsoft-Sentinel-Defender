### This KQL can be used to detect any Role Changes made to the Azure Tenants accounts. 
## Changes like 
#### "Add member to role"  
#### "Remove member from role" 
#### "Add eligible member to role" 
#### "Remove eligible member from role" 
#### "Update role membership" 
#### "Update user" 
#### "Add member to group"
#### "Remove member from group"

#### Query:
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
