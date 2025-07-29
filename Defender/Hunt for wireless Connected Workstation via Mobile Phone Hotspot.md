## 🔍 KQL Description
#### This query is likely used to:
#### 1.Detect unauthorized or risky Wi-Fi connections, especially to mobile hotspots.
#### 2.Identify devices bypassing corporate network controls by routing traffic through personal phones.
#### 3.Provide geolocation context for the IP address in use.
#### 4.Gather network adapter metadata for further investigation.
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Defense Evasion (TA0005), Command and Control (TA0011)
#### Technique: AProxy (T1090), Exfiltration Over Alternative Protocol (T1048)
#### Sub-Technique: T1090.001 (Internal Proxy), T1048.003 (Exfiltration Over Unsecured Network Protocol)
### Query:
```KQL
DeviceNetworkInfo
| extend Network_Name = tostring(parse_json(ConnectedNetworks)[0]["Name"])
| where isnotempty(Network_Name) and NetworkAdapterType has "Wireless80211"
| extend IP_info = (todynamic(parse_json(IPAddresses)))
| mv-expand IP_info
| extend Ip_Received = tostring(parse_json(IP_info).IPAddress)
| extend IP_Type = tostring(parse_json(IP_info).AddressType)
| extend geo_ip = todynamic(geo_info_from_ip_address(Ip_Received).country)
| where (Network_Name contains "Android" or Network_Name  contains "Xiaomi"  or Network_Name  contains "Nokia" or Network_Name  contains "Iphone")
| mv-expand geo_ip
| summarize  by  Network_Name, DefaultGateways, DnsAddresses,DeviceName, Ip_Received,IP_Type, tostring(geo_ip), NetworkAdapterName, NetworkAdapterStatus, NetworkAdapterType, NetworkAdapterVendor
```
