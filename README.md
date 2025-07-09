![image](https://github.com/user-attachments/assets/ec707989-5b14-4c96-b9c8-b9faf61cf0b9)



# Threat Hunting Report: The Credential Stuffing Nightmare(T1110.004)


## Platforms and Languages Leveraged
- Log Analytics Workspace (Microsoft Azure)
- Microsoft Sentinel
- Windows 10 Virtual Machine
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

Following a highly publicized data breach at the social media giant Tweeter, leadership at Instagratification—a fast-growing competitor in the social networking space—is on high alert. Intelligence reports suggest that thousands of credentials were leaked, and many users are known to reuse the same usernames and passwords across platforms. With a significant overlap in user bases between Tweeter and Instagratification, executives are increasingly concerned about the possibility of a credential stuffing attack targeting their platform.

This concern is compounded by two critical factors:

-Immature Cybersecurity Posture: As a relatively new company, Instagratification’s security program is still maturing, with limited detection and response capabilities.

-High-Value User Data: The platform stores a wealth of sensitive user data, including Personally Identifiable Information (PII), geolocation history, private messages, shared media, and even linked financial information for ad and commerce features.As the cybersecurity consultant of Instagratification, You are brought in by upper management, tasked with launching a targeted threat hunt.


### 🔍 Your Objective:

-Identify any Indicators of Compromise (IOCs) related to credential stuffing activity, such as failed login attempts from known malicious IPs, abnormal authentication patterns, or signs of lateral movement within compromised accounts.

Recommend detection rules, mitigation strategies, and incident response steps to contain any confirmed intrusions and harden defenses against future attacks.

This proactive investigation could be the difference between maintaining user trust—or becoming the next headline.

---

## Steps Taken

### 1. Searched the `DeviceLogonEvents` Table

Searched for any IOCs that indicated a Brute Force attack was being launched against the social media platform Instagratification. I found that 2 RemoteIP addresses had an abnormally large amount of failed logon attempts(>7) to Instagratifications Accounts.

**Query used to locate events:**

```kql
DeviceLogonEvents
| summarize  FailedLogonAttempts = count() by RemoteIP
| where FailedLogonAttempts between (7 .. 1000 )
| order by FailedLogonAttempts desc 
```
![image](https://github.com/user-attachments/assets/1658f285-750f-4e0c-86c7-34ec66dfa516)



>

---

### 2. Searched the `DeviceLogonEvents` Table

Searched for any Successful Logon Attempts from the Remote IPs with abnormally high amount of failed Logon attempts using the same DeviceLogonEvents Table.This would determine if any threat actors were able to successfully logoon to Instagratifications accounts. It was determined that the RemoteIP 47.196.45.190 was able to succesfully login 6 times.

**Query used to locate event:**

```kql

DeviceLogonEvents
| where AccountDomain contains "HackAttack"
| where ActionType == "LogonSuccess"
| summarize SuccessfulLogonAttempts = count() by RemoteIP, DeviceName, DeviceId, AccountName
```
![image](https://github.com/user-attachments/assets/cd0fd5f0-9d4c-4413-80eb-f170235beaa8)



---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "cavsin6" actually opened the TOR browser. There was evidence that they did open it at `2025-05-13T03:38:45.3540808Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "cavsin6"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/424ad370-0ba1-4133-984c-b70bf1abad0b)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-05-13T03:39:22.7727634Z`, an employee on the "cavsin6" device successfully established a connection to the remote IP address `89.58.34.5` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\cavsin6\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "cavsin6"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/54efe016-f4c3-4793-88a1-e39b2d9becd4)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-05-13T03:30:42.2139604Z`
- **Event:** The user "cavsin6" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\cavsin6\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-05-13T03:37:33.6557737Z`
- **Event:** The user "cavsin6" executed the file `tor-browser-windows-x86_64-portable-14.5.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.1.exe /S`
- **File Path:** `C:\Users\cavsin6\Downloads\tor-browser-windows-x86_64-portable-14.5.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-05-13T03:38:45.3540808Z`
- **Event:** User "cavsin6" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\cavsin6\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-05-13T03:39:22.7727634Z`
- **Event:** A network connection to IP `89.58.34.53` on port `9001` by user "cavsin6" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\cavsin6\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-05-13T03:39:38.6507791Z` - Connected to `167.114.103.133` on port `443`.
  - `2025-05-13T03:39:22.7727634Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "cavsin6" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-05-13T04:48:32.7489945Z`
- **Event:** The user "cavsin6" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\cavsin6\Desktop\tor-shopping-list.txt`

---

## Summary

The user "cavsin6" on the "cavsin6" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `cavsin6` by the user `cavsin6`. The device was isolated, and the user's direct manager was notified.

---
