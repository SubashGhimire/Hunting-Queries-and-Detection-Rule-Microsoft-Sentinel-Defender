## 🔍 KQL Description
#### The goal is to audit the state of service accounts in the environment. This helps in:
#### 1.Identifying unused or stale service accounts (especially if disabled).
#### 2.Ensuring only necessary service accounts are active, reducing the attack surface.
#### 3.Supporting compliance and security posture assessments.
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Persistence / Defense Evasion
#### Goal: Adversaries may use service accounts to maintain access or avoid detection.
#### Technique: Valid Accounts (T1078.002 - Domain Accounts / T1078.003 - Cloud Accounts)
#### Attackers may use legitimate service accounts to persist in the environment or move laterally without triggering alerts.
### Query:
```KQL
IdentityInfo
| distinct Type, IsAccountEnabled, AccountName
| summarize TotalServiceAccounts = countif(Type == "ServiceAccount"),
            TotalEnabledAccounts = countif(Type =="ServiceAccount" and  IsAccountEnabled == 1),
            TotalDisabledAccounts = countif(Type =="ServiceAccount" and IsAccountEnabled == 0)
```
