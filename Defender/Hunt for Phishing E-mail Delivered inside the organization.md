#### If You want to hunt for the e-mails delivered which is categorized as “Phishing” on the organization e-mail domain then run this query
#### Query:
```KQL
EmailEvents_CL
| where EmailDirection_s == "Inbound"
| join EmailUrlInfo_CL on NetworkMessageId_g
| where UrlLocation_s in ("Attachment", “Body”) // To see Suspicious e-mail from Attachment or Body of the e-mail. //You can look for different Urllocation according to your need.
| where DeliveryAction_s == "Delivered"
| where ThreatTypes_s contains "phish"
| summarize Count=count() by UrlDomain_s
| sort by Count desc
```
#### Once you get the list of UrlDomains that were cayagorised as phishing you can cross check these urldomains in virus total running the below python Script:
```PYTHON
import requests
API_KEY = "Put Your Virus Total API KEY"  
url = "https://www.virustotal.com/vtapi/v2/url/report"

def check_domain(domain):
    params = {"apikey": API_KEY, "resource": domain}
    response = requests.get(url, params=params)
    return response.json()
```
#### Example usage
domains = ["www.healthevidence.org", "belmontbusinessmedia.emlnk9.com", "soinsintermediaire.us15.list-manage.com", "content.app-us1.com", "www.facebook.com", "soinsintermediaires.com", "www.instagram.com", "www.linkedin.com", "mailchi.mp"] # Replace with your list of domains
for domain in domains:
    report = check_domain(domain)
    print(f"Domain: {domain}, Report: {report}")


#### After you run the script you'll get the report from virusTotal and see if any security vendor has flagged or reported them as malicious. 
