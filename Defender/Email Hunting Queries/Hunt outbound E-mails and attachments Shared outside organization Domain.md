#### To identify e-mails sent or forwarded outbound i.e outside of the organization e-mail domain:
#### Query:
```KQL
let Lookback = ago(1d);
let AllEmailActivity = 
EmailEvents_CL
| where TimeGenerated >= Lookback 
| where DeliveryAction_s == "Delivered"
| where EmailDirection_s == "Outbound"
;
AllEmailActivity 
```

#### Now join the AllemailActivity data to the EmailAttachmentinfo Table to match if any outbound e-mail being sent from the organization e-mail domain with attachments:

#### Final Query:
```KQL
let Lookback = ago(1d);
let AllEmailActivity = 
EmailEvents_CL
| where TimeGenerated >= Lookback 
| where DeliveryAction_s == "Delivered"
| where EmailDirection_s == "Outbound";
let EmailWithAttachments = 
    AllEmailActivity
    | join kind=inner (
        EmailAttachmentInfo_CL
        | where TimeGenerated >= Lookback
    ) on NetworkMessageId_g  // Assuming NetworkMessageId_g exists in both tables
;
EmailWithAttachments
| project TimeGenerated, SenderFromAddress_s, RecipientEmailAddress_s, FileType_s, FileName_s, FileSize_d
```

##### Note: Table names for the query shown above can be different in different organization. Adjust the table name and its schema's according to the organization enviornment.
