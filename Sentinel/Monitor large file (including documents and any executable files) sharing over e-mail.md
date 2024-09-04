#### You can create a detection rule to identify any suspicious file being shared over the e-mails. 
#### This query identifies any files being shared over the e-mails. Filetypes like .exe, bat etc..
## Mitre Attack Technique: Data Transfer Size Limits (T1030) 
#### Query:
```KQL
// Define the size threshold (e.g., 10 MB)
let sizeThreshold = 10 * 1024 * 1024;  // 10 MB in bytes
// Define suspicious file types
let suspiciousFileTypes = pack_array(".exe", ".bat", ".cmd", ".com", ".scr", ".pif", ".cpl", ".dll", ".sys", ".js", ".vbs");
// Query to monitor large attachments and suspicious file types
EmailAttachmentInfo_CL
| where FileSize_d > sizeThreshold or FileType_s in (suspiciousFileTypes)
| project TimeGenerated, TenantId, SenderFromAddress_s, RecipientEmailAddress_s, FileName_s, FileType_s, FileSize_d, SHA256_s, NetworkMessageId_g, ReportId_s
| extend Description = strcat("Suspicious attachment detected: ", FileName_s, " (", FileType_s, ") with size ", tostring(FileSize_d / 1024 / 1024), " MB")
| summarize Count = count() by TenantId, SenderFromAddress_s, RecipientEmailAddress_s, FileSize_d, FileType_s, bin(TimeGenerated, 1h)
```
