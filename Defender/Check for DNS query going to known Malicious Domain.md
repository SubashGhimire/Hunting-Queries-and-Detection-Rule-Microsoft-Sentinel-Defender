####  This query Looks any DNS query traffic going to any known malicious domain by looking at the ThreatIngelligenceIndicator database that is ingested into sentinel/Defender via Data Connector.

```KQL
IdentityQueryEvents
| where TimeGenerated > ago(1d)
| where isnotempty(QueryTarget)  // Ensure we have non-empty QueryTarget values
| join kind=inner (
    ThreatIntelligenceIndicator 
    | where TimeGenerated > ago(1d)
    | where isnotempty(DomainName)  // Ensure we have non-empty DomainName values
    | project DomainName, Description, ConfidenceScore, ThreatType, ThreatSeverity, FileHashType, FileHashValue, Url
) on $left.QueryTarget == $right.DomainName
| project TimeGenerated, DeviceName, QueryTarget, Description, IPAddress, Port, DestinationDeviceName, DestinationIPAddress, DestinationPort
```

