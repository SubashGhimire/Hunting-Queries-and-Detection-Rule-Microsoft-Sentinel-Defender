#### Identifies when an account is enabled with a default password and the password is not set by the user within 48 hours.
## Mitre Att&ck (Persistence)
### T1098: Account Manipulation
#### This Detection rule is mostly for the organization that has Windows server 2012 or below as Domain Controller cause you can enable blank password option while creating any user account.
#### Query: 
```KQL
// Get events where users are enabled
let userEnabledEvents = IdentityDirectoryEvents
    | where ActionType == "Account enabled"
    | project EnabledTime = TimeGenerated, AccountUpn, AccountSid;
// Get events where passwords are set
let passwordSetEvents = IdentityDirectoryEvents
    | where ActionType == "Account Password changed"
    | project PasswordSetTime = TimeGenerated, AccountUpn, AccountSid;
// Join enabled events with password set events
let enabledWithoutPasswordSet = userEnabledEvents
    | join kind=leftouter (passwordSetEvents) on AccountSid
    | extend TimeDifference = datetime_diff("hour", PasswordSetTime, EnabledTime)
    | where isnull(PasswordSetTime) or TimeDifference > 48
    | project AccountUpn, EnabledTime, PasswordSetTime, TimeDifference
    | order by EnabledTime desc;
enabledWithoutPasswordSet
```
