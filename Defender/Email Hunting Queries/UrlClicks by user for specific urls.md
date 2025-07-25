#### This Query helps identify users clicking in the specific urls shared to them via e-mail. This hunting query is beneficial to identify which users clicked on any phishing url shared by malicous actor.
#### Query:
```KQL
let urls = dynamic(["https://www.emaze.com/@ALIZRTIZR/ems", "https://lists.mcgill.ca/scripts/wa.exe?SUBED1=CHB_PERMANENT_MDS&A=1"]);
EmailUrlInfo_CL
| where Url_s in (urls)
| join kind=inner (
    UrlClickEvents_CL
    | where Url_s  in (urls)
    | project ClickTimestamp = TimeGenerated, ClickedUrl = Url_s, AccountUpn_s
) on $left.RecipientEmailAddress_s == $right.AccountUpn_s
| project RecipientEmailAddress_s, Url_s, ClickTimestamp, ClickedUrl
```
