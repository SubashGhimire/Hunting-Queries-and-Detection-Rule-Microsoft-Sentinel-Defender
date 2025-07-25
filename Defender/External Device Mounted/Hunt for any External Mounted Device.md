## 🔍 KQL Description
#### The goal is to monitor USB drive usage on a specific device. This can help in:
#### 1.Detecting unauthorized data exfiltration attempts
#### 2.Auditing physical device access
#### 3.Investigating insider threats or policy violations
#### 4.Tracking removable media usage for compliance
## 🧩 MITRE ATT&CK Mapping
#### Tactic: Exfiltration
#### Goal: The adversary is trying to steal data from your environment.
#### Technique: Exfiltration Over Physical Medium (T1052.001)
#### Adversaries may exfiltrate data by copying it to a physical medium such as a USB drive.
### Query:
```KQL
DeviceEvents
| where ActionType == "UsbDriveMounted"
| where DeviceName contains "Name of the Device" //put the name of the device in the double qoute to see if any external drive is mounted.
//| project Timestamp, DeviceName, DeviceId, ReportId, InitiatingProcessAccountName, AdditionalFields, ActionType
```
