#### This query searches for any user logged In to GlobalProtect outside of Canada. 
#### Query:
```KQL
GlobalProtect_CL
| where PanOSSourceRegion != "CA"     //Specify the country achronym according to your requirement. 
| where isnotnull(PanOSSourceRegion) and PanOSSourceRegion != ""
```
