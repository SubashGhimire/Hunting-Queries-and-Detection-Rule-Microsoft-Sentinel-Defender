#### Let's say your organization is monitoring email traffic for potential phishing attacks. 
#### You are specifically concerned about attackers who might spoof email addresses to look like they are from microsoft, a well-known company.
#### Attackers might use domains like "microsoft-azure.com" or "support-microsoft.net" to trick recipients into thinking the emails are legitimate. This KQl can help you identify those fake URL Domains

#### Query:
```KQL
EmailEvents_CL
| join EmailEvents_CL on NetworkMessageId_g
| where EmailDirection_s == "Inbound"
| where LatestDeliveryAction_s == "Delivered"
| where SenderFromDomain_s contains "microsoft"
| where SenderFromDomain_s !endswith "microsoft.com" 
```

