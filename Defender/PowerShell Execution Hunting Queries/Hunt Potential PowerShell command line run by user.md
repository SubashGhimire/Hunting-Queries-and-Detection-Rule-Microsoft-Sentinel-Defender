## 🔍 KQL Description
This query is used to:
#### Monitor PowerShell usage across endpoints.
#### 1.Detect suspicious or unauthorized script execution.
#### 2.Investigate potential lateral movement or remote access.
#### 3.Support threat hunting and incident response.
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Execution / Defense Evasion
#### Goal: Adversaries often use PowerShell to execute malicious code while evading detection.
#### Technique: Command and Scripting Interpreter (T1059.001 - PowerShell)
#### PowerShell is frequently used by attackers due to its powerful capabilities and native presence on Windows systems
### Query:
```KQL
DeviceEvents
| where ActionType == "PowerShellCommand"
| where InitiatingProcessFileName == "powershell.exe"
| where InitiatingProcessAccountName != "system"
| where ProcessCommandLine != "" and InitiatingProcessCommandLine != ""
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, AccountDomain,AccountName, FileName, ActionType, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP, FolderPath, InitiatingProcessFolderPath, IsInitiatingProcessRemoteSession, InitiatingProcessAccountUpn, InitiatingProcessVersionInfoOriginalFileName, InitiatingProcessCommandLine
```
