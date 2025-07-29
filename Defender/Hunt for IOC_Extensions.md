## 🔍 KQL Description
#### This query helps security analysts:
#### 1.Identify devices with potentially malicious or unwanted browser extensions.
#### 2.Detect outbound connections to known adware or tracking domains.
#### 3.Correlate extension presence with network behavior for deeper threat hunting.
## 🧩 MITRE ATT&CK Mapping
#### Tactic:Persistence (TA0003), Command and Control (TA0011)
#### Technique: Browser Extensions (T1176), Application Layer Protocol (T1071)
### Query:
```KQL
let ioc = dynamic(["kgmeffmlnkfnjpgmdndccklfigfhajen","Emoji keyboard online",
"dpdibkjjgbaadnnjhkmmnenkmbnhpobj", "Free Weather Forecast",
"gaiceihehajjahakcglkhmdbbdclbnlf", "Video Speed Controller ",
"mlgbkfnjdmaoldgagamcnommbbnhfnhf", "Unlock Discord",
"eckokfcjbjbgjifpcbdmengnabecdakp" ,"Dark Theme",
"mgbhdehiapbjamfgekfpebmhmnmcmemg", "Volume Max",
"cbajickflblmpjodnjoldpiicfmecmif", "Unblock TikTok",
"pdbfcnhlobhoahcamoefbfodpmklgmjm"
"eokjikchkppnkdipbiggnmlkahcdkikp", "Color Picker", "Eyedropper"
"ihbiedpeaicgipncdnnkikeehnjiddck", "Weather",
"jjdajogomggcjifnjgkpghcijgkbcjdi", "Unlock TikTok",
"mmcnmppeeghenglmidpmjkaiamcacmgm", "Volume Booster",
"ojdkklpgpacpicaobnhankbalkkgaafp", "Web Sound Equalizer",
"lodeighbngipjjedfelnboplhgediclp", "Header Value",
"hkjagicdaogfgdifaklcgajmgefjllmd", "Flash Player",
"gflkbgebojohihfnnplhbdakoipdbpdm", "Youtube Unblocked",
"kpilmncnoafddjpnbhepaiilgkdcieaf", "SearchGPT",
"caibdnkmpnjhjdfnomfhijhmebigcelo", "Unlock Discord",
"admitab.com",
"edmitab.com",
"click.videocontrolls.com",
"c.undiscord.com",
"click.darktheme.net",
"c.jermikro.com",
"c.untwitter.com",
"c.unyoutube.net",
"admitclick.net",
"addmitad.com",
"abmitab.com",
"admitlink.net"]);
let BrowsersExtensions = DeviceTvmBrowserExtensions 
| where ExtensionId has_any (ioc) or ExtensionName has_any (ioc);
let Firewalllogs = CommonSecurityLog
| where DestinationHostName has_any (ioc)
| where DestinationHostName !contains "weather";
BrowsersExtensions
| union Firewalllogs
| sort by TimeGenerated desc
```
