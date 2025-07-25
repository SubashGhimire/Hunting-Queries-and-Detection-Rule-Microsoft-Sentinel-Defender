#### This KQL query is designed to track and summarize email activities related to a specific sender, focusing on instances where recipients clicked on URLs within those emails.
#### It Corelates the all three tables to list out the user's who clicked on the url's send by the specific Sender specified in the Query.

#### Query:
```KQL
let EmailEvents = EmailEvents_CL
    | where EmailDirection_s in("Inbound", "Intra-org")
    | where SenderFromAddress_s == "Ryan.Raynolds@deadpool.ca"  // Replace with the specific sender's email
    | project
        NetworkMessageId_g,
        SenderFromAddress_s,
        RecipientEmailAddress_s,
        Subject_s,
        DeliveryAction_s,
        EmailDirection_s,
        TimeGenerated;
let EmailUrls = EmailUrlInfo_CL
    | project
        NetworkMessageId_g,
        SenderFromAddress_s,
        RecipientEmailAddress_s,
        Url_s,
        UrlDomain_s;   
let UrlClicks = UrlClickEvents_CL
    | project
        NetworkMessageId_g,
        AccountUpn_s,
        Url_s,
        ActionType_s,
        Workload_s,
        UrlChain_s,
        TimeGenerated;
EmailEvents
| join kind=inner (EmailUrls) on NetworkMessageId_g
| join kind=inner (UrlClicks) on NetworkMessageId_g
| extend UserClicking = iif(ActionType_s contains "ClickAllowed", "Yes", "No")
| where UserClicking == "Yes"  // Filter to only show emails where users clicked the URLs
| project
    SenderFromAddress_s,
    RecipientEmailAddress_s,
    UserClicking,
    Url_s,
    Workload_s,
    UrlDomain_s,
    AccountUpn_s,
    TimeGenerated
| summarize 
    ClickedUsers = make_set(AccountUpn_s),  // List of users who clicked
    CountOfClickedUsers = dcount(AccountUpn_s)  // Count of users who clicked
    by 
    SenderFromAddress_s, 
    RecipientEmailAddress_s, 
    Url_s, 
    Workload_s, 
    UrlDomain_s, 
    TimeGenerated
```

##### Explanation:
##### KQL BreakDown:

1. EmailEvents:
let EmailEvents = EmailEvents_CL
    | where EmailDirection_s in("Inbound", "Intra-org")
    | where SenderFromAddress_s == "Ryan.Raynolds@deadpool.ca"
    | project
        NetworkMessageId_g,
        SenderFromAddress_s,
        RecipientEmailAddress_s,
        Subject_s,
        DeliveryAction_s,
        EmailDirection_s,
        TimeGenerated;
Purpose: Filters and selects specific columns from the EmailEvents_CL table.
Filtering: Only emails with EmailDirection_s of "Inbound" or "Intra-org" from the sender "Ryan.Raynolds@deadpool.ca" are selected.
Projection: Columns like NetworkMessageId_g, SenderFromAddress_s, RecipientEmailAddress_s, and others are chosen for further processing.

2. EmailUrls:
let EmailUrls = EmailUrlInfo_CL
    | project
        NetworkMessageId_g,
        SenderFromAddress_s,
        RecipientEmailAddress_s,
        Url_s,
        UrlDomain_s;
Purpose: Extracts URL-related data from the EmailUrlInfo_CL table.
Projection: Selects NetworkMessageId_g, SenderFromAddress_s, RecipientEmailAddress_s, Url_s, and UrlDomain_s for linking with email events.

3. URLClicks:
let UrlClicks = UrlClickEvents_CL
    | project
        NetworkMessageId_g,
        AccountUpn_s,
        Url_s,
        ActionType_s,
        Workload_s,
        UrlChain_s,
        TimeGenerated;
Purpose: Captures URL click event data from the UrlClickEvents_CL table.
Projection: Selects NetworkMessageId_g, AccountUpn_s, Url_s, and other relevant columns.

4. Join Operations:
EmailEvents
| join kind=inner (EmailUrls) on NetworkMessageId_g
| join kind=inner (UrlClicks) on NetworkMessageId_g
Purpose: Joins the three tables (EmailEvents, EmailUrls, and UrlClicks) based on the NetworkMessageId_g to link emails with their associated URLs and click events.
Join Type: Inner joins are used, meaning only records that exist in all three tables are included.

5. User Click Filtering:
| extend UserClicking = iif(ActionType_s contains "ClickAllowed", "Yes", "No")
| where UserClicking == "Yes"
UserClicking: Creates a new column UserClicking that is "Yes" if the ActionType_s contains "ClickAllowed", indicating that the user clicked on the URL.
Filtering: Only keeps rows where users clicked on the URLs (UserClicking == "Yes")

6. Final Project and Summarization:
| project
    SenderFromAddress_s,
    RecipientEmailAddress_s,
    UserClicking,
    Url_s,
    Workload_s,
    UrlDomain_s,
    AccountUpn_s,
    TimeGenerated
| summarize 
    ClickedUsers = make_set(AccountUpn_s),  
    CountOfClickedUsers = dcount(AccountUpn_s)  
    by 
    SenderFromAddress_s, 
    RecipientEmailAddress_s, 
    Url_s, 
    Workload_s, 
    UrlDomain_s, 
    TimeGenerated

Projection: Selects relevant columns including sender, recipient, URL details, and user information.
Summarization:
ClickedUsers: Creates a set of unique users (AccountUpn_s) who clicked on the URLs.
CountOfClickedUsers: Counts the number of unique users who clicked.
Group By: The summarization groups results by sender, recipient, URL, workload, URL domain, and the time the email was generated

7. Overall Purpose of the query:
This query identifies which users clicked on URLs in emails sent from a specific sender (Ryan.Raynolds@deadpool.ca), summarizes how many users clicked on each URL, and lists the users who did so. 
It helps to identify the list of user's who clicked on the phishing e-mail URL  link coming from the compromised Business Account.
