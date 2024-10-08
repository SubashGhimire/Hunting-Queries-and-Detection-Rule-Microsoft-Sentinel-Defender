#### This KQL (Kusto Query Language) query is helps to detect the installation of new Chromium browser extensions on Microsoft Defender for Endpoint (MDE) devices. Specifically, it aims to identify when a new extension file (with a ".crx" extension) is created in the "Webstore Downloads" folder. 
#### This is relevant for detecting malicious activities, such as the deployment of a fake extension to gather information.

#### Query:
```KQL
DeviceFileEvents
| where ActionType == "FileCreated"
| where FolderPath contains "Webstore Downloads" and FileName endswith ".crx"
| extend ExtensionId = extract(@"(?i)Downloads[\\/]|Webstore Downloads[\\/](.+?)_\d+\.crx", 1, FolderPath)
```

##### Once you get the result downlaod the .crx file to analyze it on virustotal or any other threat feed to check if it is a fake or malicious extension.
