## 🔍 KQL Description
#### The objective of this KQL script is to detect commands executed via the Run dialog, which is often used by attackers or malicious scripts to launch tools like PowerShell, cmd, or malicious payloads—especially in ClickFix-style attacks, where users are tricked into running commands.
## 🧩 MITRE ATT&CK Mapping
#### Tactic: Execution
#### Goal: Run unauthorized or malicious code on the system.
#### Technique: T1059 – Command and Scripting Interpreter
#### Sub-techniques - T1059.001 – PowerShell, T1059.003 – Windows Command Shell
### Query:
```KQL
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where InitiatingProcessFileName =~ "explorer.exe"
| where RegistryKey has @"\CurrentVersion\Explorer\RunMRU"
| where RegistryValueData has "✅" or (RegistryValueData has_any ("powershell", "mshta", "curl", "msiexec", "cmd") and (RegistryValueData has_any ("verify", "http", "https", "-W Hidden",  "-eC",  "-o",  "vbscript", "E:jscript", "ssh", "Invoke-Expression", "DownloadString", "DownloadFile", "FromBase64String", "System.IO.Compression", "System.IO.MemoryStream", "iex", "iex(", "Invoke-WebRequest", "iwr", "Get-ADDomainController")) or RegistryValueData matches regex @"[-/–][Ee^]{1,2}[NnCcOoDdEeMmAa^]*\s[A-Za-z0-9+/=]{15,}")
```
