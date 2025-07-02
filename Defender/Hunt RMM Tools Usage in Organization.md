## 🔍 KQL Description
#### The objective of this KQL script is to detect suspicious activities related to Remote Monitoring and Management (RMM) tools by querying various data sources. 
#### It identifies processes, file signatures, network connections, and firewall logs associated with known RMM tools and domains, helping to uncover potential security threats.
#### The list of RMM tools are provided in the IOC Folder with name IOC_RMM where the KQL checks if the list of RMM Tools from the IOC_RMM is present in the organization.
## 🧩 MITRE ATT&CK Mapping
#### Tactic: Command and Control(TA0011)
#### Technique: Remote Access Tools(T1219)
### Query:
```KQL
let IOC_RMM = externaldata(Type:string, Value:string, Source:string)
[h'https://raw.githubusercontent.com/SubashGhimire/Hunting-Queries-and-Detection-Rule-Microsoft-Sentinel-Defender/refs/heads/main/IOC/IOC_RMM.csv'];
let RmmTool =
IOC_RMM
| where Type == "RmmToolName"
| project Value;
let DigitalSignature =
IOC_RMM
| where Type == "File Signature"
| project Value;
let URLDomain =
IOC_RMM
| where Type == "domain"
| project Value;
let DeviceProcess =
DeviceProcessEvents
| where Timestamp >= ago(90d)
| where ProcessVersionInfoCompanyName has_any(RmmTool) or ProcessVersionInfoProductName has_any (RmmTool);
let FileCertificateevents =
DeviceFileCertificateInfo
| where Timestamp >= ago(90d)
| where Signer has_any(DigitalSignature);
let DeviceNetworkConnection = 
DeviceNetworkEvents
| where Timestamp >= ago(90d)
| where RemoteUrl has_any (URLDomain);
let FirewallNetworkConnection = CommonSecurityLog
| where TimeGenerated >= ago(90d)
| where DeviceAction == "pass"
| where DestinationHostName has_any (URLDomain);
union DeviceProcess, FileCertificateevents, DeviceNetworkConnection, FirewallNetworkConnection
```
