
**Summary – Detecting AD Lateral Movement**

---

### 1. Overview  
The “Detecting AD Lateral Movement” room teaches how attackers move laterally in an Active Directory (AD) environment using built‑in Windows protocols (SMB, PsExec, RDP) and how defenders can spot the associated log artifacts in Windows Event Logs and Splunk.

---

### 2. Learning Objectives  
- Detect AD discovery commands via **process creation (Sysmon Event 1)** and **PowerShell Script Block logging (Event 4104)**.  
- Identify SMB‑based lateral movement by spotting admin‑share (C$, ADMIN$, IPC$) access patterns (Event 5140).  
- Detect PsExec usage through **service installation (Event 7045)**, **named pipe creation (Sysmon Event 17)**, and correlate source‑side **Event 4648** and destination‑side logs.  
- Detect RDP lateral movement via **Logon Type 10 (RemoteInteractive)** in **Event 4624**, and trace multi‑hop chains by correlating Logon IDs and **mstsc.exe** process creation.  
- Correlate artifacts across source and destination machines to reconstruct an attacker’s path.

---

### 3. Prerequisites  
- Knowledge of AD architecture, authentication protocols, and Windows Event Log structure.  
- Familiarity with initial‑access detection techniques.  
- Understanding of Windows Event Viewer, relevant Event IDs, and Splunk basics (SPL queries, filtering, stats).

---

### 4. Walkthrough Tasks & Key Findings  

#### Task 1 – Environment Setup  
- Start the provided Splunk VM (IP 10.49.136.31).  
- All investigations use the `index=win` dataset; the final challenge uses `index=challenge`.

#### Task 2 – Discovery & Reconnaissance  
- Attackers first run AD discovery commands (e.g., `nltest /domain_trusts`, `net user /domain`, PowerShell `Get‑ADUser`).  
- Detection:  
  - **Sysmon Event 1** – filter `CommandLine` for known discovery strings.  
  - **PowerShell Event 4104** – search `Message` for cmdlets like `Get‑ADUser`.  
- Example answer: the first discovery command observed was `nltest  /domain_trusts`; the full PowerShell command used to enumerate users was `Import-Module ActiveDirectory; Get-ADUser -Filter * -Properties MemberOf | Select-Object Name, SamAccountName`.

#### Task 3 – Lateral‑Movement Basics  
- Lateral movement follows an **authenticate‑then‑execute** pattern.  
- Two‑sided logging: source machine (e.g., **Event 4648** when alternate credentials are supplied) and destination machine (e.g., **Event 4624**, **Event 5140**).  
- Logon Types:  
  - **3** – Network logon (SMB, PsExec).  
  - **10** – RemoteInteractive (RDP).  
  - **7** – Unlock/Reconnect (RDP reconnection).  

#### Task 4 – Detecting SMB Lateral Movement  
- Admin shares (C$, ADMIN$, IPC$) are accessed via SMB.  
- Detection:  
  - **Event 5140** – “A network share object was accessed”.  
  - Query for `Share_Name` containing `ADMIN$` or `C$`.  
- Example outcomes:  
  - Account `luke.sullivan` used the admin shares.  
  - The actual user at the keyboard on the source workstation was `michelle.smith`.  
- Correlate with **Event 4648** (explicit credential use) and **Sysmon Event 1** on the source host to see the `net use` command line.

#### Task 5 – Detecting PsExec Lateral Movement  
- PsExec combines SMB admin‑share access with remote service installation.  
- Signature artifacts:  
  - **Event 7045** (System log) – new service installed (`PSEXESVC.exe`).  
  - **Sysmon Event 17** – named pipes created by the service.  
  - **Sysmon Event 1** (on destination) where `ParentImage` is the PsExec service → reveals the remote command executed.  
  - **Event 5145** – detailed file‑share access showing the copied binary and pipe names.  
- Source‑side evidence: **Sysmon Event 1** with `Image=*PsExec*` showing the exact command line.  
- Example answers:  
  - Destination host: `THM-SQL-SRV`.  
  - First PsExec command: `C:\Tools\PsExec.exe  -accepteula \\THM-SQL-SRV cmd /c "hostname & whoami & ipconfig"`.

#### Task 6 – Detecting RDP Lateral Movement  
- Primary artifact: **Event 4624** with **Logon_Type 10** (RemoteInteractive).  
- NLA generates a preceding **Logon_Type 3** event (Network) a few seconds earlier; treat it as part of the same RDP session.  
- Chain tracing:  
  1. Identify the Logon ID from the discovery command on the Domain Controller.  
  2. Locate the corresponding **Event 4624** (Logon_Type 10) to get the source IP.  
  3. Map the source IP to a hostname via a machine‑account logon (user ending with `$`).  
  4. On the source host, find **mstsc.exe** process creation (Sysmon Event 1) to confirm outbound RDP.  
  5. Repeat correlation to uncover earlier hops.  
- Example answers:  
  - Source IP of the RDP session landing on the DC: `10.5.30.120`.  
  - Original IP where the RDP chain began: `10.5.50.12`.

#### Task 7 – Investigation Challenge (index=challenge)  
- A suspicious service `svcupdate` was installed on `THM-SHR-SRV`.  
- Using the same detection steps (Event 7045, Event 5140, Event 4648, Sysmon Event 1) the investigators uncovered:  
  - Service binary full path: `%SystemRoot%\svcupdate.exe`.  
  - ADMIN$ share accessed by account `ryan.chen`.  
  - Source IP of the lateral movement: `10.5.50.15`.  
  - First remote command executed: `"cmd" /c "hostname & whoami & ipconfig"`.  
  - Originating host: `THM-HR-WS`.

#### Task 8 – Conclusion & Takeaways  
- **Discovery** commands in process‑creation logs are often the first clue of an upcoming lateral move.  
- **Event 4624** alone cannot differentiate legitimate admin activity from abuse; context (source host, account, time, target pattern) is essential.  
- **Logon Type 10** = RDP; **Type 3** = SMB/PsExec (requires additional artifacts).  
- **Event 4648** links the *initiating* user to the *target* credentials, but does **not** fire for Pass‑the‑Hash/Ticket.  
- Admin‑share access from unexpected sources (Event 5140) is a strong indicator of SMB movement.  
- **PsExec** leaves a unique footprint: service installation (Event 7045), named pipes (Sysmon 17), and remote command execution via the service binary.  
- **RDP chaining** can be traced by matching Logon IDs across hops and locating `mstsc.exe` on intermediate hosts.  
- Hardening measures (password hygiene, least‑privilege groups, network segmentation, disabling unnecessary RDP) reduce the chance that a single stolen credential enables widespread lateral movement.

---

### 5. Final Note  
The room equips defenders with SPL queries and a methodology to hunt for SMB, PsExec, and RDP lateral movement, and to reconstruct the full attacker path by correlating source‑side and destination‑side logs.
