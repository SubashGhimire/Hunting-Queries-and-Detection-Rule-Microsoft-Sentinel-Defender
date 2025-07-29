## 🔍 KQL Description
#### This query is used to:
#### 1.Detect installation of a potentially unwanted or suspicious application (e.g., a sponsored version of FileZilla).
#### 2.Correlate installation with network activity, especially to public IPs, which could indicate:
#### 3.Telemetry or beaconing
#### 4.Data exfiltration
#### 5.Command and control (C2) behavior
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Execution (TA0002), Command and Control (TA0011)
#### Technique: User Execution (T1204), Application Layer Protocol (T1071)
#### Sub-Technique: T1071.001 (Web Protocols), T1204.002 (Malicious File)
### Query:
```KQL
// Identify application events
let application_events = 
DeviceProcessEvents
| where TimeGenerated >= ago(30d)
| where ActionType in ("Install", "FileCreated", "FileModified")
    or ProcessCommandLine contains "msiexec"
    or ProcessCommandLine has_any ("install", "setup", "update", "installer", ".msi", ".exe")
| where FileName has_any ("FileZilla_3.69.1_win64_sponsored2-setup.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessAccountName, FileName, ProcessCommandLine, FolderPath, ActionType, InitiatingProcessAccountUpn, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, ProcessId;
// Find network connections related to the application processes
application_events
| join kind=inner ( 
    DeviceNetworkEvents
    | where RemoteIPType == "Public"  // Filter for public IPs
    | project NetworkTimestamp = TimeGenerated, DeviceName, InitiatingProcessId, RemoteIP, RemoteUrl, RemotePort, Protocol
) on $left.ProcessId == $right.InitiatingProcessId and $left.DeviceName == $right.DeviceName
| project TimeGenerated, NetworkTimestamp, DeviceName, AccountName, InitiatingProcessAccountName, FileName, ProcessCommandLine, FolderPath, ActionType, InitiatingProcessAccountUpn, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemoteUrl, RemotePort, Protocol
| sort by TimeGenerated desc
```
