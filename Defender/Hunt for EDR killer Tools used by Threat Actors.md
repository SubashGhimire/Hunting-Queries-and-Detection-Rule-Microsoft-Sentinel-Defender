## 🔍 KQL Description
#### The goal is to detect potential execution or presence of EDRKiller or similar tools in the environment by matching known malicious hashes against telemetry from Defender for Endpoint.
#### This helps security analysts:
#### 1.Identify compromised endpoints.
#### 2.Investigate how the tool was delivered or executed.
#### 3.Take remediation actions.
## 🧩 MITRE ATT&CK Mapping
#### Tactic: Defense Evasion
#### Technique: Technique: Impair Defenses (T1562)
##### Sub-techniques:
##### 1.Disable or Modify Tools (T1562.001) – EDRKiller disables EDR/AV tools.
##### 2.Indicator Removal on Host (T1070) – May remove logs or indicators.
### Query:
```KQL
let IOC_EDRkiller = externaldata(Indicator_Type:string, Data:string, Note:string)
[h'https://raw.githubusercontent.com/SubashGhimire/Hunting-Queries-and-Detection-Rule-Microsoft-Sentinel-Defender/refs/heads/main/IOC/06082025-edrkiller-iocs.csv'];
let EDRKillerTool =
IOC_EDRkiller
| where Indicator_Type == "sha256"
| project Data;
let DeviceProcess =
DeviceProcessEvents
| where Timestamp >= ago(90d)
| where SHA256 has_any (EDRKillerTool);
let DeviceFile = DeviceFileEvents
| where TimeGenerated >= ago(90d)
| where SHA256 has_any (EDRKillerTool);
let DeviceEvent = DeviceEvents
| where TimeGenerated >= ago(90d)
| where SHA256 has_any (EDRKillerTool);
union DeviceProcess,DeviceFile, DeviceEvent
```
