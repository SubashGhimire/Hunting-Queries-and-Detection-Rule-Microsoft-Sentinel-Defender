## 🔍 KQL Description
This query is used to:
#### Detect obfuscated or stealthy PowerShell execution.
#### 1.Identify potential malware or attacker activity using renamed or embedded PowerShell.
#### 2.Correlate execution with user sessions for attribution.
#### 3.Support threat hunting and incident response.
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Execution / Defense Evasion
#### Goal: Adversaries use PowerShell with obfuscation or renamed binaries to execute malicious code while avoiding detection.
#### Technique: Command and Scripting Interpreter (T1059.001 - PowerShell)
#### PowerShell is a powerful tool often abused by attackers for payload delivery, lateral movement, and persistence.
### Query:
```KQL
DeviceProcessEvents
| where ProcessCommandLine !contains "powershell" // Usually in ProcessCommandLine the actual powershell filename is seen, we are filtering out the default powershell name
| where ProcessCommandLine !contains "pwsh"  //Another default name for powershell, the idea is see other user generated script.
| where ProcessCommandLine !contains "AppxUpgradeUwp.exe" // This powersell script is for lastpass password manager that we use that's why its filter out
| where ProcessCommandLine contains "-NoProfile" or ProcessCommandLine contains "-ExecutionPolicy" or ProcessCommandLine contains "Invoke-Expression"
| join kind=inner (DeviceLogonEvents) on DeviceId
| where AccountName != "system"
| distinct DeviceName, FileName, ActionType, ProcessVersionInfoOriginalFileName, ProcessCommandLine, ProcessRemoteSessionIP, AccountName, AccountDomain
```
