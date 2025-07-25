## 🔍 KQL Description
#### This query is used to:
#### 1.Identify privileged accounts in the environment.
#### 2.Assess exposure risk by focusing on identities with elevated permissions.
#### 3.Support attack surface reduction by auditing role assignments.
#### 4.Enable proactive threat hunting for potential misuse of admin privileges.
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Privilege Escalation / Persistence
#### Goal: Adversaries may target or abuse privileged accounts to gain elevated access or maintain persistence.
#### Technique: Valid Accounts (T1078.002 - Domain Accounts / T1078.003 - Cloud Accounts)
#### Attackers may use legitimate accounts with administrative roles to perform malicious actions while evading detection.
### Query:
```KQL
ExposureGraphNodes
| where set_has_element(Categories, "identity")
| extend AccountUPN = NodeProperties.rawData.accountUpn
| extend AdminRoles = NodeProperties.rawData.assignedRoles
| extend NumberofRoles = array_length(AdminRoles)
| where NumberofRoles > 0
```
