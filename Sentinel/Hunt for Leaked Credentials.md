## 🔍 KQL Description
#### This KQL query searches the ExposureGraphNodes table in Microsoft Defender XDR or Sentinel to identify user accounts whose credentials have been leaked. It focuses on nodes categorized as "identity" and labeled as "user", then extracts detailed identity-related properties such as:
##### •	Display name, UPN, email address
##### •	Account status (enabled/disabled)
##### •	Job title, department, phone, address
##### •	Source provider (e.g., Azure AD, on-prem AD)
##### •	Account creation time
##### •	Whether the account's credentials have been leaked
##### •	The query filters and enriches this data, and presents it in a clean, readable format for hunting or triage.
## 🧩 MITRE ATT&CK Mapping
#### Tactic: Credential Access (TA0006)
#### Technique: Unsecured Credentials (T1552)
### Query:
```KQL
ExposureGraphNodes
| where set_has_element(Categories, "identity")
| where NodeLabel == "user"
| extend properties = parse_json(NodeProperties)
| extend DisplayName = properties.rawData.accountDisplayName
| extend EnabledAccount = properties.rawData.accountEnabled
| extend Name = properties.rawData.accountName
| extend UPN = properties.rawData.accountUpn
| extend AccountCreated = properties.rawData.createdDateTime
| extend Email = properties.rawData.emailAddress
| extend Department = properties.rawData.department
| extend JobTitle = properties.rawData.jobTitle
| extend Address = properties.rawData.address
| extend Mobile = properties.rawData.phone
| extend AccountType = properties.rawData.userAccountControl
| extend SourceProvider = properties.rawData.primaryProvider
| extend Leakedcredentials = properties.rawData.hasLeakedCredentials == true 
| project NodeId, NodeName, DisplayName, EnabledAccount, Name, UPN, AccountCreated, Email, Department, JobTitle, Address, Mobile, AccountType, SourceProvider, Leakedcredentials
```


