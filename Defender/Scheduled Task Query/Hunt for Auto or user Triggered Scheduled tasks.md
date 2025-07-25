#### This query analyzes process events on specific devices in your network to identify actions involving svchost.exe or schtasks.exe. These executables are commonly associated with scheduled tasks, either system-initiated or user-triggered. 
#### This query can be helpfull in a situation where you want to see or hunt for any unexpected or suspicious scheduled task running automatically on the devices that you want to check. This query can also help in a situation where defender detected a suspicious scheduled task running on the organizations devices.

#### Query:
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName == "svchost.exe" // Common for scheduled tasks 
 or InitiatingProcessFileName == "schtasks.exe" //If the task is directly triggered by the user
| where DeviceName in ("adc", "sgf", "ert", "poi")
| order by Timestamp desc
```
