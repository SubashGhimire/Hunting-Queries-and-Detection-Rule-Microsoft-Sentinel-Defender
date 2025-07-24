## 🔍 KQL Description
#### The objective of this KQL script is to detect suspicious file write and network activity that may indicate data exfiltration from a Windows Server using known tools like curl, ftp, or powershell.
#### This is especially useful for identifying:
#### 1. Insider threats
#### 2. Compromised servers
#### 3. Automated exfiltration scripts
## 🧩 MITRE ATT&CK Mapping
#### Tactic: Exfiltration
#### Goal: The adversary is trying to steal data from your environment.
#### Technique: T1048 – Exfiltration Over Alternative Protocol, T1041 – Exfiltration Over C2 Channel
#### Using tools like ftp.exe, certutil.exe, or winscp.exe to send data out.
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
