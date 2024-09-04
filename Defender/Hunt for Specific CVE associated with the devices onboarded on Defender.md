#### This Query looks for Specific CVE specified in the query and lists out all the onboarded devices that has the CVE specified. In defender, in Threat Analytics  you can see the latest known vulnerability details. The idea of this query is to find out if any latest discovered vulnerability is exposed to the devices that are in your environment.
#### Query:
```KQL
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2024-38063"
| join kind=leftouter (DeviceInfo | project DeviceName, OnboardingStatus, DeviceId) on DeviceId
| where OnboardingStatus == "Onboarded"  // Filter for Onboarded devices
| project DeviceName, DeviceId, OnboardingStatus, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, RecommendedSecurityUpdateId, OSPlatform
| distinct DeviceName, DeviceId, OnboardingStatus, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, RecommendedSecurityUpdateId, OSPlatform
```
