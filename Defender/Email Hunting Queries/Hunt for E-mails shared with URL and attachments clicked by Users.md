#### This KQL query is designed to identify and analyze user interactions with URLs embedded in emails, specifically focusing on emails that are either inbound or intra-organizational (within the organization). 
#### The goal is to determine which users clicked on URLs within these emails and to provide a summary of this activity.
#### Query: 

```KQL
let EmailEvents = EmailEvents_CL
    | where EmailDirection_s in("Inbound", "Intra-org")
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
| where UserClicking == "Yes"  // Filter to show only emails where users clicked the URLs
| summarize 
    ClickedUsers = make_set(AccountUpn_s),  // List of users who clicked
    CountOfClickedUsers = dcount(AccountUpn_s)  // Count of distinct users who clicked
    by 
    SenderFromAddress_s, 
    RecipientEmailAddress_s,
    Subject_s, 
    Url_s, 
    Workload_s, 
    UrlDomain_s, 
    TimeGenerated
| project
    SenderFromAddress_s,
    RecipientEmailAddress_s,
    Subject_s,
    Url_s,
    Workload_s,
    UrlDomain_s,
    ClickedUsers,
    CountOfClickedUsers,
    TimeGenerated
| extend MailMessage_0_Sender = SenderFromAddress_s
| extend MailMessage_0_Recipient = RecipientEmailAddress_s
| extend MailMessage_0_Urls = Url_s
| extend Account_0_Name = ClickedUsers
```
##### Explanation: 

##### Key Steps in the Query:

1.	Filter and Select Data from Email Events (EmailEvents_CL):
a.	The query starts by filtering the EmailEvents_CL table to include only emails with a direction of either "Inbound" (coming from outside the organization) or "Intra-org" (sent within the organization).
b.	It then selects (projects) relevant columns, such as the unique email identifier (NetworkMessageId_g), sender's email address (SenderFromAddress_s), recipient's email address (RecipientEmailAddress_s), subject of the email (Subject_s), and the time the event was generated (TimeGenerated).
2.	Extract URL Information from Emails (EmailUrlInfo_CL):
a.	The EmailUrlInfo_CL table is used to gather information about URLs found in the emails. This includes the URL itself (Url_s), the domain of the URL (UrlDomain_s), and the corresponding sender and recipient email addresses.
3.	Analyze URL Click Events (UrlClickEvents_CL):
a.	The UrlClickEvents_CL table is queried to identify user interactions with the URLs. It includes data on the user account that clicked the URL (AccountUpn_s), the action taken (ActionType_s), the workload or platform used (e.g., email, Teams) (Workload_s), and the time of the event.
4.	Join the Tables:
a.	The query performs inner joins on the NetworkMessageId_g field to combine data from the EmailEvents_CL, EmailUrlInfo_CL, and UrlClickEvents_CL tables. This ensures that only records with matching email and URL data across all three tables are included.
5.	Identify User Clicks:
a.	The extend UserClicking = iif(ActionType_s contains "ClickAllowed", "Yes", "No") step creates a new column, UserClicking, that indicates whether the user clicked on the URL. If the ActionType_s field contains "ClickAllowed," the UserClicking value is set to "Yes."
6.	Filter for Clicked URLs:
a.	The query then filters the results to include only those records where UserClicking is "Yes," meaning the URLs were clicked by users.
7.	Summarize the Results:
a.	The summarize function groups the results by key fields, including the sender's email, recipient's email, email subject, URL, workload, URL domain, and the time the event was generated.
b.	It creates two summary columns:
8.		ClickedUsers uses the make_set(AccountUpn_s) function to create a list of unique users who clicked on the URLs.
9.		CountOfClickedUsers uses the dcount(AccountUpn_s) function to count the number of distinct users who clicked on the URLs.
10.	Project the Final Output:
a.	The final output of the query includes the sender's and recipient's email addresses, the subject of the email, the URL, the workload (platform), the URL domain, the list of users who clicked on the URLs, the count of distinct users who clicked, and the time the event was generated.
11.	Objective of the Query:
12.	The primary objective of this query is to track and analyze user interactions with URLs in emails, particularly those that were clicked on by recipients. By summarizing this information, the query helps in identifying:
a.	Which emails contained URLs that were clicked on.
b.	The list of users who clicked on these URLs.
c.	The total number of distinct users who clicked on each URL.
13.	This analysis is particularly useful in security contexts, where understanding user behavior regarding potentially risky links can help in identifying phishing attacks or other malicious activities.
