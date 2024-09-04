#### Gives you Incident Report of 2 weeks with severity level "High"
#### Query
```KQL
SecurityIncident
| where TimeGenerated >= ago(14d)
| extend AssignedTo = tostring(parse_json(Owner)['assignedTo'])  // Adjust if extraction is needed
| project IncidentNumber, Title, Description, Severity, Status, TimeGenerated, ClosedTime, Classification, ClassificationReason, ClassificationComment, AdditionalData, RelatedAnalyticRuleIds, AssignedTo
| order by TimeGenerated desc
HighSeverityCount = 
CALCULATE(
    COUNTROWS(Query1),
    Severity[SeverityLevel] = "High"
```