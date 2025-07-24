## 🔍 KQL Description
#### The objective of this KQL script is to monitor for unauthorized or suspicious changes to the OneDrive configuration, including personal usage of onedrive which could indicate:
#### 1. Abuse of OneDrive for data exfiltration
#### 2. Persistence mechanisms using cloud sync
#### 3. User profile hijacking or manipulation
#### This is especially useful for identifying:
#### 1. Insider threats
#### 2. Compromised servers
#### 3. Automated exfiltration scripts
## 🧩 MITRE ATT&CK Mapping
#### Tactic: Persistence
#### Goal: The adversary is trying to maintain their foothold.
#### Technique: Registry Run Keys / Startup Folder, T1020 – Automated Exfiltration
#### Although this specific key isn't a startup key, attackers may use registry modifications to configure or abuse applications like OneDrive for persistence or exfiltration.
#### If OneDrive is being configured to automatically sync stolen data, this falls under automated exfiltration.
### Query:
```KQL
DeviceRegistryEvents 
| where TimeGenerated >= ago(90d)
| where ActionType == "RegistryKeyCreated" or ActionType == "RegistryValueSet"
| where RegistryKey has "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\OneDrive\\Personal"
```
