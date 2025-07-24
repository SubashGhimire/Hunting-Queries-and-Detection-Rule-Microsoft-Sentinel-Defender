## 🔍 KQL Description
#### The objective of this KQL script is to detect commands executed via the Run dialog, which is often used by attackers or malicious scripts to launch tools like PowerShell, cmd, or malicious payloads—especially in ClickFix-style attacks, where users are tricked into running commands.
## 🧩 MITRE ATT&CK Mapping
#### Tactic: Execution
#### Goal: Run unauthorized or malicious code on the system.
#### Technique: T1059 – Command and Scripting Interpreter
#### Sub-techniques - T1059.001 – PowerShell, T1059.003 – Windows Command Shell
### Query:
```KQL
DeviceRegistryEvents
| where RegistryKey contains "Runmru"
| where notempty(RegistryValueData)
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueData, ActionType
```
