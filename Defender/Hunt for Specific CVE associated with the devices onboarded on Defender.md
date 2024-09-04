#### In defender, in Threat Analytics you can see the latest known vulnerability details. With this Query you can check if latest vulnerability from the Threat Analytics list are vulnerable to the onboarded devices in your environment. To summarize, idea of this query is to find out if any latest discovered vulnerability is vulnerable to the devices that are in your environment.
#### Query:
```KQL
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2024-38063" \\ Specify the specific CVEID that you want to check
| join kind=leftouter (DeviceInfo | project DeviceName, OnboardingStatus, DeviceId) on DeviceId
| where OnboardingStatus == "Onboarded"  // Filter for Onboarded devices
| distinct DeviceName, DeviceId, OnboardingStatus, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, RecommendedSecurityUpdateId, OSPlatform
```
