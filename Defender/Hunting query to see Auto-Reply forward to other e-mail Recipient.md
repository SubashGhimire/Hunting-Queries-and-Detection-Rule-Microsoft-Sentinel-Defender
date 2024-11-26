#### This Query Lists out all the Auto reply configured inside the organization's user's e-mails to sent to outbound recepient. In other words, it looks for Auto reply e-mails sent to the Recipent outside of the organization domain.
#### Query
```KQL
EmailEvents_CL
// add your automatic replies cases in your languages
| where Subject_s startswith "Automatic reply:"
| where DeliveryAction_s has "Delivered" and EmailDirection_s has "Outbound"
| extend Username = split(RecipientEmailAddress_s, "@")[0], Domain = tostring(split(RecipientEmailAddress_s, "@")[1])
| extend DomainParts = split(RecipientEmailAddress_s, ".")
| extend DomainExtensions = tostring(DomainParts[-1])
| distinct  SenderFromAddress_s, SenderMailFromDomain_s, SenderIPv4_s, RecipientEmailAddress_s, DomainExtensions, Domain, Subject_s, EmailDirection_s, DeliveryAction_s, DeliveryLocation_s, ThreatTypes_s
```
