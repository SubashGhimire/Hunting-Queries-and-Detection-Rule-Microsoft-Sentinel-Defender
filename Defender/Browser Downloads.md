#### This query idetifies any files being downlaoded from borwsers like Internet Explorer, Edge, Chrome and firefox. This query can be used as hunting query to identify any suspicious file being downloaded from device borwser, after an incident alert triggred in the defender or can be used just to hunt for any suspicious files being downlaoded on devices.

#### Query:
```KQL
DeviceFileEvents 
| where Timestamp > ago(7d)
| where FolderPath !has "$Recycle.Bin"
| where 
    // Edge
     InitiatingProcessFileName == "msedge.exe"
     or
     InitiatingProcessFolderPath endswith @"windows\system32\browser_broker.exe" 
    // Internet Explorer x64
    or InitiatingProcessFolderPath endswith @"program files\internet explorer\iexplore.exe"
    // Internet Explorer x32
    or InitiatingProcessFolderPath endswith @"program files (x86)\internet explorer\iexplore.exe"
    // Chrome
    or (InitiatingProcessFileName =~ "chrome.exe" and FileName endswith "crdownload")
    // Firefox
    or (InitiatingProcessFileName =~ "firefox.exe" and (FileName !endswith ".js" or FolderPath !has "profile"))
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath
```
