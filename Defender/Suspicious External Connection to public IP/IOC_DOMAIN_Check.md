## 🔍 KQL Description
#### This query is used to:
#### 1.Correlate threat intelligence with actual telemetry from your environment.
#### 2.Identify compromised devices or accounts interacting with known malicious infrastructure.
#### 3.Support incident response and containment.
#### 4.Enable proactive threat hunting across multiple data sources..
## 🧩 MITRE ATT&CK Mapping
#### Tactic:
#### Command and Control (TA0011)
#### Execution (TA0002)
#### Defense Evasion (TA0005)
#### Impact (TA0040)
#### Technique:
#### T1071 - Application Layer Protocol (e.g., HTTP/S communication with malicious domains)
#### T1105 - Ingress Tool Transfer (malicious file downloads)
#### T1059 - Command and Scripting Interpreter (malicious script execution)
#### T1036 - Masquerading (renamed binaries or scripts)
### Query:
```KQL
let IOC_Domains = dynamic(["wearychallengeraise.com", "goclouder.com", "bundlehulu.com", "anallyticsnodde.com","roundedbullets.com", "summerartcamp.net", "downloadessays.net", "joinushealth.com", "healthherofit.com", "worryfreetransport.com", "radiotimesignal.com", "fastfilebackup.com", "cyclingonlineshop.com", "luxuryfitnesslabs.com", "purvoyage.com", "93f4f4.bobbyweisman.com/kakfgar", 
"bobbyweisman.com", "bobbyweisman.com/index.html", "6f4922f4.bobbyweisman.com/brake", "tool.municipiodechepo.org/id", "tool.municipiodechepo.org", "OneStart.ai", "gridnodeessentials.com", "prisorta.com",
"manage.kugglipkutanitola.website",
  "robot.gsixk.com",
  "service.ghostbuffer.com",
  "www.webvps.name",
  "www.webvps2.name",
  "www.yutubuview.com",
  "suv.ghostbuffer.com",
  "info.ghostbuffer.com",
  "yutubuview.com",
  "micorsofts.net",
  "bocstore.net",
  "www.micrsofts.com", "ignifugacionsarguix.com"
 ]);
let IOC_md5 = dynamic([
  "8a0822abd87620f1ffff1534b518f54b",
  "7146dc9c01b91654640d940c38561966",
  "58364f594684b88dc8cad52d0aa452db",
  "237f686ad93a2907f6bc3d54ac432e44",
  "76751a2c282915765dce7574706d23f3",
  "d7648000cfdbe7f66f860df04fbb3bb0",
  "fd0d852b6080f9278bccca71cafc4c36",
  "184a38bd8791e029d818a60dfe82728e",
  "e76d2a7de117f877d273f6d5aec82dd6",
  "4592ed905a8b0866804055d8fca112ab",
  "b122d6d27d79f8eebba70c8dbf521eab",
  "cd07f72d0b7725445bf8a8b73169dbb0",
  "5d888876a0e085fa962ac782c776cc8c",
  "b9622171ab39e97d56815b0baffe6d98",
  "1ae096772c5be43fbf3dbfcb783aa77d",
  "665ce9fd6ad9df8da508725c1d6fe75e",
  "12dfe40b7a370b0b962902d0b2627c93",
  "0549eb3153b50c3f0a5ae7e0a5a38aed",
  "ed443cb7e8da89a5dcc4c78da2350c5b",
  "9f94f8c4d7445044279c91db599ccab1",
  "161a99a1d73ea19a030aa47bac1003e0",
  "16a643242223234b79f66034f4064534",
  "e5502c7d2ea8a42106feb95c103e0e08"
]);
let IOC_SHA256 = dynamic(["ddbce3dde4bd92f12c8df61ea4a8c5b2daed133af994f9228cffe006390a4bb0",
  "f83271cf968f0bf6c084d75f09b4c40c94ac31f730b94685253870ad5366e8f4",
  "7f55d5cabf2e29b33164e5b70f00cca2e96991a177be1686a8aa6a3871f54d92",
  "3840c5983afbd28b6035a96f451793be264a001948205ef41d3d0b4778058690",
  "3fc7a941b12a7f6408f1a93aa5bb5ef31e0bc148174d4fd99752d630974ccd9f",
  "c00dd87c3829b92146cfa594a49970065d2984d8499f04cf9d3d0433f7282bc5",
  "58e253f99eb42b408926b161f9995e9f171edc31736298be019df8bc54daa0f3",
  "32f38cec311f7e9d0500daee31ecee1fb4731f0cb5a071f6a41521ac8b3d448c",
  "7f0544a5bd5990caf79896e2890d4e035d026b6be8ed7a32e263be34f0b842e2",
  "5b6a092a3b87097ec1b812632d8896b039a21eb4d05fa53abb21716fa6871bea",
  "69f37c68d714384b8b2e4e84583a8f0dc819f98877bd911f1ecda3fb8bedec3a",
  "e3da9577db59cf92f3d1ffcb2826fe63e5022efe95951fbca0c7ad6185b51c60",
  "3b4c756d1542ed59fb53e200a248422fab11d52b4ff2bbdeb0c907014df3e866",
  "c47dcfe3ff29ff8ee4c4f65f98dc0039c78c659aa3f0f03bcce1413fd870a821",
  "e94fdcf6383465a178c303eee95d1399e94a85213f3d27fd7cd7157f4a96752a",
  "d7e40c5f824c88234bfbc400fb956d7ca6ecab1655ad5cacd6f5a5c4d85e58ee",
  "54858a9aa1735efbae3e165369c108bb7279def34514626b2530014e3bd353a9",
  "7ac8b655e682119ee652e95fe562db855b343d4ee0c5d47032dfa9fcca018d02",
  "727e43966a5345fa5975660e6e9e1c000d450dc2c5c9ef125506125580a127e0",
  "f02a39bbd3f72aa443d554a2880da8aa15685ce6949dfbe5e84dda98917167e8",
  "95a6906b8f7c529f9280a458804f85c5257c57a0cddd190f8bea52ffe23fa644",
  "92c5deef41e29457cb0d13ee955a48685dc01907eb96d310a40490b4c804ef05",
  "2a45fbaa45883f8df1d022d0f8ac4a81f0deeb7708d609dd24333aa633a22b50"
]);
let IOC_IP = dynamic(["3.161.213.45", "3.161.213.48", "3.161.213.28", "3.161.213.120", 
"45.32.59.24",
"91.193.103.136",
"139.180.144.254",
  "139.180.199.98",
  "202.182.96.114",
  "207.148.110.33",
  "45.32.54.173",
  "45.76.98.74",
  "45.77.46.125",
  "139.180.144.254",
  "158.247.198.67",
  "185.243.42.103",
  "202.182.96.114", 
"89.44.193.109",
  "89.44.193.12",
  "89.44.193.95",
  "180.178.39.26",
  "180.178.39.26",
  "59.188.133.112",
  "59.188.133.112",
  "64.44.206.10"
 ]);
let FirewallLogs = CommonSecurityLog
| where DeviceVendor == "Fortinet"
| where DestinationHostName has_any (IOC_Domains)
| where DestinationIP has_any (IOC_IP);
let DeviceNetworklogs = DeviceNetworkEvents
| where RemoteUrl has_any (IOC_Domains)  
| where RemoteIP  has_any (IOC_IP)
| where ActionType == "ConnectionSuccess";
let DeviceEvents = DeviceEvents
| where SHA256 has_any (IOC_SHA256)
| where MD5 has_any (IOC_md5);
let Devicefile = DeviceFileEvents
| where SHA256 has_any (IOC_SHA256)
| where MD5 has_any (IOC_md5);
let Deviceprocess = DeviceProcessEvents
| where SHA256 has_any (IOC_SHA256)
| where MD5 has_any (IOC_md5);
FirewallLogs
| union DeviceNetworklogs, DeviceEvents, Devicefile, Deviceprocess
| sort by TimeGenerated desc 
```
