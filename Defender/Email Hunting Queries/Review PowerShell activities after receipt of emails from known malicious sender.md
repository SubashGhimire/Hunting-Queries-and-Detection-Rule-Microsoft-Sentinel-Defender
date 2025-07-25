#### This query helps review any powershell activities in the user's workstations after a known malicious sender sends a mass malicious e-mails in the organization.

#### Query :
```KQL
//Define new table for emails from specific sender
let EmailsFromBadSender=EmailEvents_CL
| where SenderFromAddress_s =~ "MaliciousSender@example.com"
| project TimeEmail = Timestamp_t, Subject_s, SenderFromAddress_s, AccountName = tostring(split(RecipientEmailAddress_s, "@")[0]);
//Merge emails from sender with process-related events on devices
EmailsFromBadSender
| join (
DeviceProcessEvents
//Look for PowerShell activity
| where FileName =~ "powershell.exe"
//Add line below to check only events initiated by Outlook
//| where InitiatingProcessParentFileName =~ "outlook.exe"
| project TimeProc = Timestamp, AccountName, DeviceName, InitiatingProcessParentFileName, InitiatingProcessFileName, FileName, ProcessCommandLine
) on AccountName
//Check only PowerShell activities within 30 minutes of receipt of an email
| where (TimeProc - TimeEmail) between (0min.. 30min)
```
