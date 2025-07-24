## 🔍 KQL Description
#### The objective of this KQL script is to detect To suspicious command-line activity (especially file downloads using curl) that was triggered by a browser, which may indicate:
#### 1. Malicious JavaScript or HTML triggering command execution
#### 2. User tricked into clicking a link that launches a command
#### 3. Initial access or payload download in a phishing or drive-by attack
## 🧩 MITRE ATT&CK Mapping
#### Tactic: Execution
#### Goal: Run unauthorized or malicious code on the system.
#### Technique: T1059 – Command and Scripting Interpreter
#### Sub-techniques - T1059.001 – PowerShell, T1059.003 – Windows Command Shell
### Query:
```KQL
let MonitoredCommands = dynamic(["powershell","pwsh","regsvr32","bitsadmin","certutil", "mshta", "cmd"]);
let BrowserList = dynamic(["chrome","msedge","firefox","brave"]);
DeviceProcessEvents
| where TimeGenerated >= ago(7d)
| where FileName has_any(MonitoredCommands) and InitiatingProcessFileName has_any(BrowserList)
| extend CommandLine = tostring(InitiatingProcessCommandLine)
| where (FileName == "cmd.exe" and CommandLine contains "curl")
```
