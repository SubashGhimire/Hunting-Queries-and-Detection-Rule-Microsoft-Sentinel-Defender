#### This query helps identify logon attempts on any device within 30 minutes of receiving an email categorized as malware inside the organization.
#### Query:

```KQL
//Define new table for malicious emails
let MaliciousEmails=EmailEvents_CL
//List emails detected as malware, getting only pertinent columns
| where (ThreatTypes_s has "Malware" or ThreatTypes_s has "Phish" or ThreatTypes_s has "Spam") and EmailDirection_s == "Inbound"
| project TimeEmail = Timestamp_t, Subject_s, SenderFromAddress_s, AccountName = tostring(split(RecipientEmailAddress_s, "@")[0]);
MaliciousEmails
| join (
//Merge malicious emails with logon events to find logons by recipients
IdentityLogonEvents
| project LogonTime = Timestamp, AccountName, DeviceName
) on AccountName
//Check only logons within 30 minutes of receipt of an email
| where (LogonTime - TimeEmail) between (0min.. 30min)
| take 10
```
