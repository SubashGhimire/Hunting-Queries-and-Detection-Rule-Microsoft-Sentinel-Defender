#### Hunting query to see Log on events inside organization domain
#### Query:
```KQL
let Lookback = ago(1d);
let Signins = 
IdentityLogonEvents
| where TimeGenerated > Lookback
| distinct AccountDisplayName, AccountUpn, DeviceName, DestinationDeviceName, ActionType, AccountDomain, Application
;
Signins 
```
