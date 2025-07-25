## 🔍 KQL Description
#### The query is used to:
#### 1.Detect remote access activity via RDP.
#### 2.Identify potential unauthorized access or lateral movement.
#### 3.Audit remote administration practices.
#### 4.Correlate with other indicators of compromise (IOCs).
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Lateral Movement / Initial Access
#### Goal: Adversaries may use RDP to move between systems or gain initial access.
#### Technique: Remote Services (T1021.001 - Remote Desktop Protocol)
#### Attackers may use RDP to access systems remotely, often after credential theft or brute-force attacks.
### Query:
```KQL
DeviceNetworkEvents
| where RemotePort == 3389  // RDP typically uses port 3389
| where ActionType == "ConnectionSuccess"  // Successful connections
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, ReportId, DeviceId, RemoteUrl
| sort by Timestamp desc
```
