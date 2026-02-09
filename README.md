<img width="1024" height="559" alt="image" src="https://github.com/user-attachments/assets/e3845234-6177-46a4-9030-580f9b441138" />


# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/JacksonUsoro/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the ‘DeviceFileEvents’ table for any fields that contained ‘tor.exe’ or ‘firefox.exe’ and discovered that user ‘employee2’ downloaded the tor browser and installed it. There is also evidence of a text file called ‘torshoppinglist.txt’ created ‘2026-02-05T15:26:41.1147086Z’. 

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "employee2"
| where FileName contains "firefox" or FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1142" height="605" alt="image" src="https://github.com/user-attachments/assets/f1acc33f-23a4-46fe-9117-c6138aaa29c2" />


---

### 2. Searched the `DeviceProcessEvents` Table

On February 5, 2026, the user employee2 executed a portable Tor Browser installer from their downloads folder on the device threat-hunt-lab. The use of the /S command-line switch indicates a silent installation attempt, likely intended to bypass standard web filtering and establish an anonymized connection....

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, Account = AccountName, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessVersionInfoFileDescription, Command = ProcessCommandLine

```
<img width="1749" height="76" alt="image" src="https://github.com/user-attachments/assets/68466c18-21b5-4a72-9e7d-20b873057374" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for indications that user ‘employee2” actually opened the tor browser. This action was done at this exact time stamp: “ 2026-02-05T15:09:20.9788182Z” 

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"
| where FileName has_any("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc

```
<img width="2108" height="745" alt="image" src="https://github.com/user-attachments/assets/f86ffd50-99d1-4b97-ba2e-13a470d5aaa4" />

There were several subsequent instances of “tor.exe” and “firefox.exe”, 23 in total.


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Utilized the DeviceNetworkEvents table for evidence that the tor browser was used to establish a connection using any of the known ports.

At 10:11 AM, the tor.exe process successfully established an outbound connection via port 9001, a common default port for Tor relays and directory authorities. This verifies that “employee2” has moved past installation and has successfully initialized an encrypted tunnel to the Tor network.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "employee2"
| project Timestamp, ActionType, RemotePort, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp, RemotePort desc

```
<img width="1142" height="752" alt="image" src="https://github.com/user-attachments/assets/b3fae484-7ede-4941-8474-d2f811c2b722" />


---

## Chronological Event Timeline 

<img width="657" height="1015" alt="image" src="https://github.com/user-attachments/assets/1ea044e6-fd4a-4e72-9aab-7b44854c6ee3" />

---
## Investigation Notes

Intent: The use of the silent install switch (/S) and a portable version of the software indicates a deliberate attempt to circumvent organizational software restriction policies.

Verification: The ConnectionSuccess events on port 9001 are a high-fidelity indicator of a successful Tor circuit establishment.

#### Data Exfiltration Risk: The creation of torshoppinglist.txt after establishing a Tor connection suggests the user was actively browsing and potentially transacting or recording information while anonymized.
---

## Summary

#### On February 5, 2026, the user employee2 downloaded a portable version of the Tor Browser and performed a silent installation (using the /S switch) to bypass standard security visibility. Following the installation, the user launched the browser, which successfully initialized the Tor proxy (tor.exe) and established several outbound encrypted connections to the Tor network via remote port 9001 and port 443. The session concluded with the user creating a document titled torshoppinglist.txt in their Documents folder, confirming active use of the unauthorized software.
---

### Response Taken

TOR usage was confirmed on endpoint “threat-hunt-lab” by user ‘employee2’. The device was isolated and the user's direct manager was notified.

---
