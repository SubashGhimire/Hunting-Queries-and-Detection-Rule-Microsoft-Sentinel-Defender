#### This query hunts for any files shared by the malicious sender on the devices of the users. In other words it checks if the file shared by malicious sender is downloaded, saved or present on the devices of the user's.

#### Query:
```KQL 
EmailAttachmentInfo_CL
| where SenderFromAddress_s =~ "MaliciousSender@example.com"
// Get emails with attachments identified by a SHA-256
| where isnotempty(SHA256_s)
| extend SHA256 = SHA256_s // Standardize the column name for the join
| join (
// Check devices for any activity involving the attachments
    DeviceFileEvents
    | project FileName, SHA256, DeviceName, DeviceId
) on SHA256 
| project Timestamp_t, FileName, SHA256, DeviceName, DeviceId, NetworkMessageId_g, SenderFromAddress_s, RecipientEmailAddress_s
``` 

