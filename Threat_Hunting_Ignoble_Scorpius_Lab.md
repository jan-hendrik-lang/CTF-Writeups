# **Writeup: Ignoble Scorpius Lab**

## **Level**
Insane

## **Scenario**

Your organization has fallen victim to a sophisticated ransomware attack involving **BlackSuit Ransomware**, attributed to the financially motivated threat actor group **Ignoble Scorpius**. This attack has encrypted critical files, causing significant operational disruptions. A ransom note has been deployed, demanding payment in cryptocurrency. Although the attackers have not indicated any data theft, they are using the encrypted files to pressure the organization into meeting their demands.

As part of the **Incident Response (IR) team**, your main priorities are to **contain and mitigate the attack, identify the attack vector, and assess the full scope of the compromise**. Additionally, analyzing the **Tactics, Techniques, and Procedures (TTPs)** of Ignoble Scorpius will enhance defenses and prevent future intrusions.

### **Network Diagram**
Below is a network infrastructure diagram, showing key systems and segments.

### **Reference Labs**
Want to dive deeper into the ransomware used by threat actors? Analyze the full sample and uncover its secrets in the **BlackSuit Ransomware Lab**.

---
## **Initial Access**

### **Question 1**
Identifying the source IP address of the attacker's machine is crucial for determining the attack's origin and tracking unauthorized access. What IP address was used for initial access to the DMZ machine (**RDP Gateway**), and what is the **SID** of the user account used to log in?

```bash
index=* host=WS3 sourcetype="XmlWinEventLog" EventCode=4624 LogonType=10
```

- **host=WS3**: The DMZ ws3.corp.local (**RD Gateway Server**)
- **sourcetype="XmlWinEventLog"**: Windows Event Log data for different systems
- **EventCode=4624**: Indicates a **successful login**
- **LogonType=10**: Represents an **RDP session**

References:
- [Windows Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Splunk Windows Add-On](https://docs.splunk.com/Documentation/WindowsAddOn/8.1.2/User/SourcetypesandCIMdatamodelinfo)

**Answer:** `18.156.176.108, S-1-5-21-337128598-2364711288-4282874372-500`

---
### **Question 2**
Determining the initial access **timestamp** and the attacker's **entry method** is essential for incident scoping and investigation. At what exact **timestamp** did the attacker gain **initial access** to the **DMZ machine**?

```bash
index=* host="ws3" sourcetype="xmlwineventlog" EventCode=4624 LogonType=10
| table _time, EventData_Xml
```

**Answer:** `2025-01-29 11:15`

---
### **Question 3**
To accurately classify and analyze the attacker's **initial access method** on the DMZ machine, consider how the use of **compromised credentials** could have facilitated unauthorized access. Mapping this activity to a standardized framework for **detection engineering** and **threat hunting** is essential. What is the **MITRE ATT&CK technique ID** associated with this **initial access method**?

- **Attack Method:** RDP using **compromised credentials**
- **Reference:** [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)

**Answer:** `T1078`

---
### **Question 4**
The attacker initially attempted to access the **foothold machine** via **RDP** but lacked sufficient privileges to establish a **graphical session**. The first **compromised account** used in these **failed RDP attempts** was unable to gain interactive access. However, the attacker later switched to **another compromised account**, which was successfully authenticated and allowed further movement.

**What timestamp did the attacker successfully pivot from the DMZ to the internal domain?**

```bash
index=* sourcetype="xmlwineventlog" EventCode=4624 LogonType=3 src_ip="10.10.3.254" host!=WS3
| sort _time
```

- **LogonType=3**: Indicates **lateral movement** with a **network logon** (e.g., SMB, WinRM, PsExec)
- **Source IP**: Host **WS3**
- **Excluding host WS3**: Because it's originating from this host

Reference:
- [Windows Event 4624 - Lateral Movement](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=4624)

**Answer:** `2025-01-29 11:23`

---
### **Question 5**
Identifying the **compromised account** and its **SID** is key to understanding the attacker's privileges at this stage. **Which account** did the attacker use during **initial access** to deploy the **beacon** on the **foothold machine**, and what is its **SID**?

```bash
index=* sourcetype="xmlwineventlog" EventCode=4688 host=WS1 user = gnunez
| table _time, host, Account_Name, Security_ID, NewProcessName, ParentProcessName, ProcessID
| sort _time
```

**Answer:** `S-1-5-21-337128598-2364711288-4282874372-500`

---
## **Execution**

### **Question 6**
During the attack, the adversary **deployed an initial payload** that served as the main executable within the compromised infrastructure. **What is the full path** of this first deployed **payload**?

```bash
index=* sourcetype="xmlwineventlog" EventCode=4688 user = gnunez host=WS1
```

- **EventCode=4688**: Indicates **Process Execution**

**Answer:** `C:\Users\gnunez\Downloads\Sys.exe`

---
### **Question 7**
The **payload deployed** in Q6 creates a **child process** that loads **DLL modules**. **What is the process ID** of this child process, and **which DLL** is the first one loaded by it?

1. Look for different processes spawned from the **malicious process**:

```bash
index=* source="xmlwineventlog:security"  EventCode=4688
ParentProcessName="C:\Users\gnunez\Downloads\Sys.exe"
| table _time, ProcessID, NewProcessName, ParentProcessName
```

2. Look in **Sysmon** for different **DLLs** loaded by the extracted **PIDs**:

```bash
index=* source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=7 process_id=1916 | table _time, ProcessID, Image, ImageLoaded
```

**Answer:** `1916, mscoree.dll`

---
### **Question 8**
Understanding **PowerShell patterns** for **lateral movement** aids in identifying the **C2 framework module** used and enhances **detection engineering** by mapping the **TTPs** leveraged by threat actors. **Which C2 framework module was used for lateral movement to the File Server (FS), Backup, and App Server?**

**Answer:** ``
---

