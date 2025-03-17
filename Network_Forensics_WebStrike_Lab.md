# WebStrike Lab - Network Forensics Writeup

## Level
Too Easy

---

## Scenario
A suspicious file was identified on a company web server, triggering alarms within the intranet. The Development team flagged the anomaly, suspecting potential malicious activity. To address the issue, the network team captured critical network traffic and prepared a PCAP file for analysis. Our task is to analyze the provided PCAP file to uncover how the file appeared and determine the extent of unauthorized activity.

---

## Questions & Answers

### **Q1: From which city did the attack originate?**
**Answer:** Tianjin

#### **Analysis:**
Using Wireshark, we filtered HTTP traffic and identified the attacker's IP address. We performed a geo-IP lookup, revealing that the source of the attack originated from **Tianjin, China**.

---

### **Q2: What is the attacker's User-Agent?**
**Answer:** Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

#### **Analysis:**
Filtering HTTP requests in Wireshark (`http.request`), we located requests made by the attacker. Inspecting the request headers provided us with the attacker's **User-Agent**, confirming the use of **Firefox 115.0 on Linux**.

---

### **Q3: What is the name of the malicious web shell that was successfully uploaded?**
**Answer:** image.jpg.php

#### **Analysis:**
Monitoring file upload requests, we identified a suspicious filename: **`image.jpg.php`**. This is a common technique where an attacker disguises a PHP web shell using a double extension to bypass weak security filters.

---

### **Q4: Which directory is used by the website to store the uploaded files?**
**Answer:** `/reviews/uploads/`

#### **Analysis:**
Looking at HTTP POST requests in Wireshark, we found that the uploaded files were stored in **`/reviews/uploads/`**, which was likely exploited due to poor validation checks on file uploads.

---

### **Q5: Which port, opened on the attacker's machine, was targeted by the malicious web shell for establishing unauthorized outbound communication?**
**Answer:** 8080

#### **Analysis:**
Checking **TCP connections** initiated from the compromised server, we discovered an outbound connection to the attacker's IP on port **8080**, indicating an active reverse shell or command-and-control (C2) session.

---

### **Q6: Which file was the attacker attempting to exfiltrate?**
**Answer:** `passwd`

#### **Analysis:**
By examining HTTP and FTP data streams, we noticed a request attempting to download **`/etc/passwd`**, a critical file that contains user account information. The attacker likely aimed to enumerate user accounts for privilege escalation.

---

## **Conclusion & Mitigation Steps**
1. **User-Agent Filtering:** Implement WAF rules to block suspicious User-Agents commonly used by attackers.
2. **File Upload Restrictions:** Enforce stricter validation on file uploads to prevent execution of disguised scripts.
3. **Network Monitoring:** Regularly monitor traffic for suspicious outbound connections (e.g., port 8080 activity).
4. **Access Control:** Restrict access to sensitive files like `/etc/passwd` to prevent unauthorized data exfiltration.

---

## **References**
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [CyberDefenders WebStrike Lab](https://cyberdefenders.org/blueteam-ctf-challenges/webstrike/)
