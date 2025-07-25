#### This query identifies the devices with missing Recommended Security Updates on the devices onboarded on Defender.
#### Query:
```KQL
DeviceTvmSoftwareVulnerabilities
| join kind=inner (
    DeviceTvmSoftwareVulnerabilitiesKB
    | project CveId
) on CveId
| project DeviceName, CveId, RecommendedSecurityUpdateId
| summarize MissingKBs = make_set(RecommendedSecurityUpdateId) by DeviceName
| where array_length(MissingKBs) > 0
```
