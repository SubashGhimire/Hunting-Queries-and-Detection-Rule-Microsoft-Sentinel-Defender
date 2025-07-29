## 🔍 KQL Description
#### This query is designed to:
#### 1.Inventory Wi-Fi-connected devices and their network configurations.
#### 2.Identify public IP addresses in use.
#### 3.Geolocate those IPs to detect anomalies (e.g., a device showing a public IP from an unexpected country).
#### 4.Provide visibility into network adapter details, including vendor and status.
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Discovery (TA0007)
#### Technique: System Network Configuration Discovery (T1016)
#### Sub-Technique: T1016.001 (Internet Connection Discovery)
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
| mv-expand geo_ip
| summarize  by  Network_Name, DefaultGateways, DnsAddresses,DeviceName, Ip_Received,IP_Type, tostring(geo_ip), NetworkAdapterName, NetworkAdapterStatus, NetworkAdapterType, NetworkAdapterVendor
```
