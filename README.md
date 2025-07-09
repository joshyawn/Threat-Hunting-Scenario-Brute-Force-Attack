![image](https://github.com/user-attachments/assets/ec707989-5b14-4c96-b9c8-b9faf61cf0b9)



# Threat Hunting Report: The Credential Stuffing Nightmare(T1110.004)


## Platforms and Languages Leveraged
- Log Analytics Workspace (Microsoft Azure)
- Microsoft Sentinel
- Windows 10 Virtual Machine
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

Following a highly publicized data breach at the social media giant Tweeter, leadership at Instagratification—a fast-growing child company in the social networking space—is on high alert. Intelligence reports suggest that hundreds of employee credentials were leaked, and many employees are known to have accounts for both companies simultaneously. It is of great concern that employees of the company reuse their login credentials across platforms. Executives are increasingly concerned about the possibility of a credential stuffing attack targeting their Instagratification platform.

This concern is compounded by two critical factors:

-Immature Cybersecurity Posture: As a relatively new company, Instagratification’s security program is still maturing, with limited detection and response capabilities.

-High-Value User Data: The platform stores a wealth of sensitive user data, including Personally Identifiable Information (PII), geolocation history, private messages, shared media, and even linked financial information for ad and commerce features. As the cybersecurity consultant of Instagratification, You are brought in by upper management, tasked with launching a targeted threat hunt.


### 🔍 Your Objective:

-Identify any Indicators of Compromise (IOCs) related to credential stuffing activity, such as failed login attempts from known malicious IPs, abnormal authentication patterns, or signs of lateral movement within compromised accounts.

Recommend detection rules, mitigation strategies, and incident response steps to contain any confirmed intrusions and harden defenses against future attacks.

This proactive investigation could be the difference between maintaining user trust—or becoming the next headline.

---

## Steps Taken

### 1. Searched the `DeviceLogonEvents` Table

Searched for any IOCs that indicated a Brute Force attack was being launched against the social media platform Instagratification. I found that 2 RemoteIP addresses had an abnormally large amount of failed logon attempts(>7) to Instagratifications servers.

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

Searched for any Successful Logon Attempts from the Remote IPs with abnormally high amount of failed Logon attempts using the same DeviceLogonEvents Table.This would determine if any threat actors were able to successfully logoon to Instagratifications servers. It was determined that the RemoteIP 47.196.45.190 was able to succesfully login 6 times. The first successful login by the threat actor being on 2025-06-13T21:43:15.9216213Z. The results of this query also showed that the threat actor with the RemoteIP 47.196.45.190 was only able to login successfully to this system.

**Query used to locate event:**

```kql

DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where RemoteIP == "47.196.45.190" or RemoteIP == "10.0.0.8"
| project ActionType, DeviceName, DeviceId, AccountName, Timestamp, RemoteIP
```
![image](https://github.com/user-attachments/assets/f5d98a3d-5ac5-46bd-b37d-d4d6c3c2cfc3)




---

### 3. Searched the `DeviceEvents` Table

Searched for more more information on what occurred after the threat actor was able to exploit the vulnerable server. On host hackattack, within the same session, DPAPI was accessed repeatedly by a process that also spawned multiple named‑pipe events, which is a classic precursor to dumping browser‑saved passwords, cookies, and Windows Credential Manager entries. This action could have potentially extended the threat from a single server to full credential harvesting and long‑term persistence.

The action type ProcessCreatedUsingWmiQuery was discovered indicating the threat actor was trying to use Living off the land techniques to escalate the threat.

**Query used to locate events:**

```kql
DeviceEvents
| where DeviceName contains "HackAttack"
```
![image](https://github.com/user-attachments/assets/2f051a8e-89d2-44f2-9d73-29a123d118d8)



---

### 4. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for post-login execution, which revealed a handful of powershell.exe and cmd.exe invocations on host hackattack within two minutes of the successful logon from 47.196.45.190; the commands lacked signed scripts or administrative switches, and no instances of mimikatz.exe or rundll32.exe were detected. All command-line data has been preserved for forensic review, and these processes have been correlated with corresponding DPAPI-related events to confirm no credential-dumping payloads were launched.
**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "HackAttack"
| where FileName has_any ("mimikatz.exe", "powershell.exe", "rundll32.exe", "cmd.exe")
```
![image](https://github.com/user-attachments/assets/36b4b384-0f4d-4160-8be4-6a5586be7ff1)



---

---

## Summary

The threat actor conducted a credential stuffing attack (T1110.004) against Instagratification accounts, resulting in multiple failed logon attempts and eventual successful authentication from the IP 47.196.45.190. After gaining access, the attacker initiated suspicious activity on the endpoint, including DpapiAccessed and NamedPipeEvent actions observed on the host hackattack.

This indicates an attempt to extract DPAPI-protected secrets, commonly used to harvest browser-stored credentials, cookies, or Credential Manager entries (T1555.004).

However, no evidence of lateral movement, privilege escalation, or the use of any high-value credentials was found following the DPAPI access. Post-attack telemetry showed no new logons, remote access, or process execution linked to privilege abuse. This suggests that while the intrusion was technically successful in breaching the user account and accessing the endpoint, the system did not contain credentials of significant value, limiting the attack's scope and impact.

---

## Response Taken

In response to the incident, the compromised account was immediately locked and a company-wide password reset was enforced to mitigate potential reuse of exposed credentials. The affected server (hackattack) was isolated from the network to contain any post-compromise activity, and the malicious IP address (47.196.45.190) was blocked at both the firewall and identity provider level. The affected server was fully reimaged and thoroughly tested to ensure complete remediation. All access vectors previously exploited by the threat actor were eliminated, confirming that no further unauthorized presence remained on the system. Additionally, enhanced detection rules were deployed to monitor for similar credential stuffing patterns, and preventative controls such as MFA enforcement and login throttling were implemented to reduce the risk of future attacks. Privileged access was separated from daily-use accounts to minimize exposure in the event of credential compromise. Admin accounts now require MFA as well and are restricted to hardened jump boxes.

---
