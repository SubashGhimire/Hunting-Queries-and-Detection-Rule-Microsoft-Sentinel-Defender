## Onboarding Devices
#### This Query Hunts for Devices that are not Onboarded on Defender by searching for devices that matches the rgex which contains any alphabets or numbers or hyphens as device name and specific domain name of your organization.

#### Query:
``` KQL
DeviceInfo
| where OnboardingStatus != "Onboarded"  // Exclude onboarded devices
| where OSPlatform contains "Windows10" or OSPlatform contains "Windows11"  // Windows 10 or 11 OS
| where (DeviceName matches regex "^[a-zA-Z0-9-]+\\.abc07\\.qqqq\\.qc\\.ca$" )  // Matches domain name abc07 
| where DeviceType == "Workstation"  // Device type is workstation
| where Vendor contains "HP"  // Vendor contains "HP"
| distinct DeviceId, DeviceName, OSPlatform, DeviceType, OnboardingStatus, Vendor  // Only distinct based on these columns
``` 
### Explanation

#### This KQL query is used to identify distinct devices that are not onboarded, run either Windows 10 or Windows 11, belong to a specific domain, are workstations, and are made by the vendor HP.

#### Here’s a detailed breakdown:

#### DeviceInfo | where OnboardingStatus != "Onboarded":

##### This first filter excludes devices that are already "Onboarded," focusing only on those that haven't completed the onboarding process.

#### where OSPlatform contains "Windows10" or OSPlatform contains "Windows11":

##### The query is looking for devices that are running either Windows 10 or Windows 11 operating systems. The contains ensures that even if there are additional versions (e.g., Windows10 Enterprise), those will still match.

#### where (DeviceName matches regex "^[a-zA-Z0-9-]+\\.abc07\\.qqqq\\.qc\\.ca$"):

##### This part uses a regular expression (regex) to match devices whose names end with the domain abc07.qqqq.qc.ca. The regex ensures that device names consist of alphanumeric characters or hyphens followed by the specific domain. 

#### where DeviceType == "Workstation":

##### The query only includes devices that are classified as "Workstation." This means devices like desktop or laptop computers, excluding servers, mobile devices, etc.

#### where Vendor contains "HP":

##### This filter narrows down the results to devices made by HP, based on the "Vendor" field.

#### distinct DeviceId, DeviceName, OSPlatform, DeviceType, OnboardingStatus, Vendor:

##### Finally, it retrieves distinct records based on the specified columns: DeviceId, DeviceName, OSPlatform, DeviceType, OnboardingStatus, and Vendor. This ensures that duplicate records with the same values in these fields are removed, showing only unique devices.
### Summary:
#### This query helps you find distinct HP workstations running Windows 10 or 11 that have not been onboarded, belong to the specific domain abc07.qqqq.qc.ca, and filters out other devices based on these criteria.
