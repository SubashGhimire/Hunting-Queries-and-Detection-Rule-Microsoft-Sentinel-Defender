#### This query gives you lists of security incidents that are coming after hours meaning after workimh hours like 8-5. 
#### Set your Date and Time in the query according to your requirement. Please note that the time zone may affect the created time depending on which timezone your Sentinel or defender tenant is setup.
#### Query:
```KQL
SecurityIncident
|where hourofday(CreatedTime) >= 21 or hourofday(CreatedTime) < 12  // Filter incidents happening after 5:00 PM or before 9:00 AM
```
