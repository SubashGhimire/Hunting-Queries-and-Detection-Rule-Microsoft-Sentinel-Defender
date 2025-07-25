## 🔍 KQL Description
#### This query is used to:
#### 1.Identify potentially suspicious signed binaries in the environment.
#### 2.Detect abuse of code signing certificates by threat actors.
#### 3.Support threat hunting and malware analysis.
#### 4.Reduce false positives by excluding known good vendors.
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Defense Evasion
#### Goal: Adversaries may use signed binaries to bypass security controls.
#### Technique: Signed Binary Proxy Execution (T1218)
#### Attackers may use signed, trusted binaries to execute malicious payloads, leveraging the trust associated with digital signatures.
### Query:
```KQL
DeviceFileCertificateInfo
| join kind=inner (DeviceFileEvents) on SHA1
//| extend VT_hash = iff(isnotempty(SHA1), strcat("https://www.virustotal.com/gui/file/", SHA1), SHA1)
| summarize count() by Signer
| where Signer !contains "Google "
| where not(Signer has_any("Intel", "fortinet", ".net", "citrix", "microsoft", "HP Inc.", "adobe", "cisco", 
                           "Avaya Inc.", "Zoom Video Communications, Inc.", "zscaler", "oracle", 
                           "Advanced Micro Devices Inc.", "Lenovo", "Hewlett-Packard Company", 
                           "RingCentral", "Symantec", "Mozilla", "Dell Technologies Inc."))
| sort by count_
```
