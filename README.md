<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorised TOR Usage
- [Scenario Creation](https://github.com/sever-ali/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyse related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents for ANY file that had the string “tor” in it and discovered what looks like the user “s_ali” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop at 2026-04-05T17:16:52.9273805Z. These events began at: 2026-04-05T17:01:15.7698993Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "sever-mde-test"
| where InitiatingProcessAccountName == "s_ali"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-04-05T17:01:15.7698993Z)
| order by Timestamp desc
| project DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1133" height="450" alt="Screenshot 2026-04-07 at 15 46 55" src="https://github.com/user-attachments/assets/10a1071c-0630-4b32-b3fb-3e69e63b7985" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows”. Based on the logs returned at 18:03 on April 6th, an employee on the “sever-mde-test” device ran the file   tor-browser-windows-x86_64-portable-15.0.8.exe from their Downloads folder, using a command that triggered a silent installation

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "sever-mde-test"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

<img width="1158" height="193" alt="Screenshot 2026-04-07 at 15 48 31" src="https://github.com/user-attachments/assets/9d95d308-4d39-4a2f-b9e1-e874493f2046" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “s_ali” actually opened the tor browser. There was evidence that they did open it at 2026-04-05T17:03:47.7833944Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "sever-mde-test"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

<img width="1138" height="444" alt="Screenshot 2026-04-07 at 15 49 35" src="https://github.com/user-attachments/assets/216a0d8f-430f-4208-a655-bdb7f84f128a" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

 At 2026-04-05T17:04:02.9584499Z, user “s_ali” on “sever-mde-test” device successfully established a connection to the remote IP address 136.244.82.118 on port 9001. The connection was initiated by the process tor.exe located in the folder: c:\users\s_ali\desktop\tor browser\browser\torbrowser\tor\tor.exe, there were a couple other connections over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "sever-mde-test"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

<img width="1139" height="444" alt="Screenshot 2026-04-07 at 15 50 47" src="https://github.com/user-attachments/assets/8785fc8f-4e87-4ef4-850d-731db817ac8c" />

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
