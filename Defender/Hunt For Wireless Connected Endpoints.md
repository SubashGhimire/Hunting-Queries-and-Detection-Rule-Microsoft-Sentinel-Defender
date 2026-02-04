## 🔍 KQL Description
#### This query is designed to:
#### 1.List Wi-Fi-connected devices and their network configurations.
#### 2.Identify public IP addresses in use.
#### 4.Provide visibility into network adapter details, including vendor and status.
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Discovery (TA0007)
#### Technique: System Network Configuration Discovery (T1016)
#### Sub-Technique: T1016.001 (Internet Connection Discovery)
### Query:
```KQL
let WifiDevices =
DeviceNetworkInfo
| where NetworkAdapterType contains "Wireless" or NetworkAdapterName  has_any ("Wi-Fi", "Wireless")
| project DeviceId, DeviceName, NetworkAdapterName, NetworkAdapterStatus, NetworkAdapterVendor;
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| join kind=inner WifiDevices on DeviceId
| summarize
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated),
    ConnectionCount=count()
    by DeviceName, DeviceId, RemoteIP, NetworkAdapterName, NetworkAdapterStatus, NetworkAdapterVendor
| order by LastSeen desc
```
