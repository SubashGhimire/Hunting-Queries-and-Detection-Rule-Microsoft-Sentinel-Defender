#### This Query is designed to have visibility of the web traffic ports that's coming inside and going outside of 
#### the network which were used for exploits by the threat actors in the past by comparing with the updated list of ports that has been used by the threat actors from the git hub https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/suspicious_ports_list.csv
#### The idea of this Hunting Query is to hunt if any of the ports is being used by the threat actors to exploit the organizations applications.

#### Query:
```KQL
let Suspicious_Ports = externaldata(
    dest_port: int,
    metadata_comment: string,
    metadata_confidence: string, 
    metatada_category: string,
    metadata_detection_type: string
)
[
    @"https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/suspicious_ports_list.csv"
]
with (format="csv", ignoreFirstRecord=True)
| where isnotempty(dest_port);  // Filter out rows with empty or invalid dest_port
CommonSecurityLog
| where TimeGenerated >= ago(1h)
| where DeviceAction in ("accept", "pass", "close") 
| join kind=inner (Suspicious_Ports) on $left.DestinationPort == $right.dest_port
| project TimeGenerated, DeviceName, DestinationPort, DeviceProduct, Activity, ApplicationProtocol, DeviceInboundInterface, DeviceOutboundInterface, DestinationIP, SourceTranslatedAddress, SourceTranslatedPort, metadata_comment, metadata_confidence, metatada_category, metadata_detection_type, Computer
| order by TimeGenerated desc
```
#### Explanation 
#### This KQL (Kusto Query Language) query is designed to detect network traffic involving suspicious ports by joining security logs with an external list of ports flagged as suspicious. Here's a step-by-step explanation:
##### 1. Defining the Suspicious Ports List
```KQL
let Suspicious_Ports = externaldata(
    dest_port: int,
    metadata_comment: string,
    metadata_confidence: string, 
    metatada_category: string,
    metadata_detection_type: string
)
[
    @"https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/suspicious_ports_list.csv"
]
with (format="csv", ignoreFirstRecord=True)
| where isnotempty(dest_port);
```
##### Purpose: Load a list of suspicious Windows service names from an external CSV file hosted online.
##### Details:
##### The CSV file contains details about suspicious services, such as:
##### service_name: Name of the service.
##### service_path: File path of the service.
##### metadata_*: Additional information, like the tool category, severity, comments, and references.
##### externaldata: Reads the file in CSV format and treats it like a table.
##### ignoreFirstRecord=True: Ignores the header row of the CSV file.

##### 2. Querying the Security Logs
```CommonSecurityLog
| where TimeGenerated >= ago(1h)
| where DeviceAction in ("accept", "pass", "close")
```
##### Purpose: Fetch security logs from the CommonSecurityLog table, which contains firewall or security appliance logs.
##### TimeGenerated >= ago(1h): Filters logs from the past hour.
##### DeviceAction in ("accept", "pass", "close"): Focuses on specific actions indicating allowed or terminated connections.

##### 3. Joining Security Logs with the Suspicious Ports List
```KQL
| join kind=inner (Suspicious_Ports) on $left.DestinationPort == $right.dest_port
```
##### Purpose: Match the security log entries with the suspicious ports list.
##### join kind=inner: Retains only logs where a match is found between:
##### DestinationPort from the security logs.
##### dest_port from the suspicious ports list.
##### This identifies traffic involving the flagged suspicious ports.

##### 4. Selecting Relevant Fields
```KQL
| project TimeGenerated, DeviceName, DestinationPort, DeviceProduct, Activity, ApplicationProtocol, DeviceInboundInterface, DeviceOutboundInterface, DestinationIP, SourceTranslatedAddress, SourceTranslatedPort, metadata_comment, metadata_confidence, metatada_category, metadata_detection_type, Computer
```
##### Purpose: Choose the fields to include in the results:
##### Security log details (e.g., TimeGenerated, DeviceName, DestinationPort, DestinationIP, ApplicationProtocol).
##### Metadata from the suspicious ports list (e.g., metadata_comment, metadata_confidence, metatada_category, metadata_detection_type).
##### Device-related information (e.g., Computer, DeviceInboundInterface, DeviceOutboundInterface).

##### 5. Sorting Results.
```KQL
| order by TimeGenerated desc
```
##### Purpose: Sort the results by the timestamp (TimeGenerated) in descending order to show the most recent events first.

#### What This Query Does
##### Loads a suspicious ports list from an external CSV file.
##### Filters recent security log events from the CommonSecurityLog table (last 1 hour, with specific actions).
##### Matches the DestinationPort in the logs against the suspicious ports list.
##### Outputs detailed information about the matched events, including metadata about the flagged ports.
##### Sorts the results so you can quickly analyze the most recent activity.

#### Why This Query is Useful
##### Purpose: Detect potential threats by identifying network traffic targeting or originating from known suspicious ports.
##### Applications: This can help in threat hunting, incident response, or monitoring unusual activity in the network. The metadata provides additional context about why the port is suspicious (e.g., confidence level, detection category).
