#### This query helps see if there is unusual amount of DNS queries.
#### Query:
```KQL
IdentityQueryEvents
| where TimeGenerated > ago(1d)
| where ActionType == "DNS query"
| summarize queryCount = count()
    by
    QueryTarget,
    bin(TimeGenerated, 1h),
    DeviceName,
    IPAddress,
    Port,
    DestinationDeviceName,
    DestinationIPAddress,
    DestinationPort
| where queryCount > 100 // Example threshold for unusual volume
| order by queryCount desc
| project
    TimeGenerated,
    QueryTarget,
    queryCount,
    DeviceName,
    IPAddress,
    Port,
    DestinationDeviceName,
    DestinationIPAddress,
    DestinationPort
```
