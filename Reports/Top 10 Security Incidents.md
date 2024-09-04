#### This query lists out top 10 security incidents. You can specify the time and date range on the query itself or on the Sentinel/Defender to list out the TOP 10 Security Incident.
#### Query
```KQL
SecurityIncident
| summarize ["Number of Incidents"] = count(), ["Incidents List"]= make_list(IncidentNumber) by Title, Severity
| top 10 by ['Number of Incidents'] desc
| project-reorder ['Number of Incidents'], Severity, Title
```
