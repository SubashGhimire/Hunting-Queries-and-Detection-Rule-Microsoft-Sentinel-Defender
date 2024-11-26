#### This KQL query identifies potentially suspicious inbound connection attempts to internet-facing devices in the last 2 hours. It achieves this by filtering and correlating data from two tables: DeviceInfo (device metadata) and DeviceNetworkEvents (network activity).
#### This query identifies suspicious external connection attempts to internet-facing devices:
Helps pinpoint external threats (e.g., potential attackers) based on their activity (3+ attempts from the same IP).
Provides geographical context for the source of threats, aiding in analysis and incident response.
Focuses on actionable data by correlating network activity with device metadata, ensuring only relevant devices are considered.

#### Query:
```KQL
let InternetFacingDevice = 
DeviceInfo
| where Timestamp > ago(2h)
| where IsInternetFacing
| summarize arg_max(Timestamp, *) by DeviceId, DeviceName
| project DeviceId, DeviceName;
DeviceNetworkEvents
| where DeviceId has_any(InternetFacingDevice)
| where ActionType == "InboundConnectionAttempt"
| where not(ipv4_is_private(RemoteIP))  // Only external public IPs
| extend IPLocation = geo_info_from_ip_address(RemoteIP)
| summarize Connections = count(), Ports = make_set(RemotePort) by RemoteIP, tostring(IPLocation.country), DeviceId
| where Connections >= 3  // Only show IPs with >= 3 attempts
// Join DeviceInfo table with DeviceNetworkEvents
| join kind=inner (InternetFacingDevice) on DeviceId
| project DeviceName, DeviceId, RemoteIP, Ports, Connections, IPLocation_country
| sort by Connections desc
```
