## 🔍 KQL Description
#### This query is used to:
#### 1.Identify devices connected to Wi-Fi networks with public IP addresses.
#### 2.Correlate those connections with network events (e.g., outbound connections).
#### 3.Determine geolocation of both local and remote IPs.
#### 4.Provide process-level context (e.g., which process initiated the connection).
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Command and Control (TA0011)
#### Technique: Application Layer Protocol (T1071) or Exfiltration Over C2 Channel (T1041)
#### Sub-Technique: T1071.001 (Web Protocols), T1071.002 (DNS), etc.
### Query:
```KQL
DeviceNetworkInfo
| extend Network_Name = tostring(parse_json(ConnectedNetworks)[0]["Name"])
| where isnotempty(Network_Name) and NetworkAdapterType has "Wireless80211"
| extend IP_info = (todynamic(parse_json(IPAddresses)))
| mv-expand IP_info
| extend Ip_Received = tostring(parse_json(IP_info).IPAddress),
           IP_Type = tostring(parse_json(IP_info).AddressType)
| where IP_Type has "Public"
| extend Network_IP_Location = tostring(geo_info_from_ip_address(Ip_Received).country), tostring(IP_info)
| join kind=inner (DeviceNetworkEvents) on $left.Ip_Received == $right.LocalIP
| extend Remote_IP_Location = tostring(geo_info_from_ip_address(RemoteIP).country)
| summarize by DeviceName, Network_Name, NetworkAdapterType,LocalIP, Network_IP_Location, IP_Type, RemoteIP,Remote_IP_Location, RemotePort, RemoteUrl, ActionType, Protocol,InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessIntegrityLevel
```
