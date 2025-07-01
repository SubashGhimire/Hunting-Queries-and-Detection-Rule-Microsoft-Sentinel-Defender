## 🔍 KQL Description
#### This query identifies delivered inbound emails flagged for malware, phishing, or spam, and correlates them with URL click events to find instances where users clicked on potentially malicious links.
## 🧩 MITRE ATT&CK Mapping
#### Tactic: Initial Access (TA0001)
#### Technique: Phishing (T1566)
##### Sub-Technique(T1566.001)
### Query:
```KQL
EmailEvents_CL
| where (DetectionMethods_s has "Malware" or DetectionMethods_s has "Phish" or DetectionMethods_s has "Spam")
| where (ThreatTypes_s has "Malware" or ThreatTypes_s has "Phish" or ThreatTypes_s has "Spam") and EmailDirection_s == "Inbound"
| where DeliveryAction_s contains "Delivered"
| join kind=inner UrlClickEvents_CL on NetworkMessageId_g
| where (ActionType_s != "" or ActionType_s != "ClickBlocked")
| where (ActionType_s == "ClickAllowed" or  IsClickedThrough_b != "false")
```
