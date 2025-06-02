## KQL Description
#### This query is designed to hunt for potential data exfiltration from Windows Server devices by detecting file write activity followed by network connections to the internet using common file transfer tools like curl.exe, ftp.exe, powershell.exe, certutil.exe, etc.
## 🎯 MITRE ATT&CK Mapping
#### 🛠️ Tactic: Exfilteration (TA0010)
#### 📌 Techniques:T1048 – Exfiltration Over Alternative Protocol
### Query:
```KQL
let OS_info = DeviceInfo
| where OSPlatform contains "Windows Server"
| project DeviceName;
let exfilTools = dynamic(["curl.exe", "ftp.exe", "powershell.exe", "certutil.exe", "bitsadmin.exe", "winscp.exe"]);
let fileWrites = DeviceFileEvents
| where ActionType in ("FileCreated", "FileModified")
| project FileWriteTime = Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessFileName;
let netConnections = DeviceNetworkEvents
| where RemoteUrl != "" and RemotePort in (21, 22, 80, 443)
| project NetConnectTime = Timestamp, DeviceName, RemoteUrl, RemotePort, InitiatingProcessId, InitiatingProcessCommandLine, InitiatingProcessFileName;
fileWrites
| join kind=inner (netConnections) on DeviceName, InitiatingProcessId
| where abs(datetime_diff("minute", FileWriteTime, NetConnectTime)) <= 5
| where DeviceName in (OS_info)
| where InitiatingProcessFileName in~ (exfilTools)
| project FileWriteTime, NetConnectTime, DeviceName, FileName, FolderPath, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
```
