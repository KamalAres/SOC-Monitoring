
**Detailed Summary – Detecting AD Credential Attacks (TryHackMe “Premium” Room)**  

---

## 1. Overview  

The lab focuses on five credential‑access techniques that let an attacker move from a foothold to full domain control:

| Technique | What it targets | How it works | Typical privilege needed |
|-----------|----------------|--------------|--------------------------|
| **Kerberoasting** | Service accounts with SPNs | Requests Kerberos service tickets (TGS) and cracks the RC4‑encrypted ticket offline | Any domain user |
| **AS‑REP Roasting** | User accounts with *pre‑authentication disabled* | Requests a TGT; the DC returns an AS‑REP encrypted with the account’s password hash, which can be cracked offline | None (only need the username) |
| **LSASS Dumping** | LSASS memory on a compromised endpoint | Reads LSASS process memory to harvest NTLM hashes, Kerberos tickets, plaintext passwords (if WDigest enabled) | Local admin / SYSTEM |
| **DCSync** | AD replication protocol (DRSUAPI) | Impersonates a DC and pulls every password hash via replication rights | Domain Admin / Enterprise Admin (or any account granted replication rights) |
| **NTDS.dit Extraction** | The AD database file on a DC | Copies the AD database (and SYSTEM hive) via shadow copies or the IFM (Install‑From‑Media) feature | Local admin on the DC (or Domain Admin) |

These attacks exploit AD’s authentication and replication infrastructure directly, leaving distinct artifacts in various logs.

---

## 2. Learning Objectives  

1. **Kerberoasting** – Detect anomalous TGS requests that use RC4 encryption.  
2. **AS‑REP Roasting** – Identify TGT requests for accounts with pre‑authentication disabled.  
3. **LSASS Dumping** – Spot suspicious process‑access events that read LSASS memory.  
4. **DCSync** – Detect unauthorized AD replication requests.  
5. **NTDS.dit Extraction** – Detect process‑creation and file‑write events that indicate database extraction.  
6. Correlate artifacts across host and DC logs to trace an attacker’s escalation path.

---

## 3. Prerequisites  

| Area | Required knowledge |
|------|-------------------|
| **Active Directory basics** | Domains, OUs, groups, Kerberos/NTLM flow |
| **Windows logging** | Security log channels, key Event IDs |
| **AD monitoring** | Kerberos ticket flow, Event 4768 (TGT) and 4769 (TGS) |
| **Splunk basics** | SPL syntax, `stats`, `bin`, `table`, etc. |

---

## 4. Detection Details per Technique  

### 4.1 Kerberoasting  

* **Key Event** – **4769** (Kerberos Service Ticket Requested).  
* **Signal** – `Ticket_Encryption_Type=0x17` (RC4) in an environment that normally uses AES‑256 (`0x12`).  
* **Important fields**  

| Field | Meaning |
|-------|---------|
| `Service_Name` | SPN being requested (e.g., `svc-sql`) |
| `Ticket_Encryption_Type` | 0x12 = AES, 0x17 = RC4 (suspicious) |
| `Account_Name` | Requesting user (potential attacker) |
| `Client_Address` | Source IP (often IPv6‑mapped IPv4, like `::ffff:10.5.90.1`) |

* **Basic SPL query (index = task2)**  

```spl
index=task2 EventCode=4769 Ticket_Encryption_Type=0x17 
    Service_Name!="*$" Service_Name!="krbtgt"
| table _time, Account_Name, Service_Name, Ticket_Encryption_Type, Client_Address
| sort _time
```

* **Triaging** – Count distinct `Service_Name`s per `Account_Name` to see how many service accounts were targeted:

```spl
index=task2 EventCode=4769 Ticket_Encryption_Type=0x17 
    Service_Name!="*$" Service_Name!="krbtgt"
| stats dc(Service_Name) as targeted_services count by Account_Name, Client_Address
```

* **Evasion note** – Tools can request tickets with AES (e.g., **Orpheus**), so a **volume‑based** rule is needed:

```spl
index=task2 EventCode=4769 Service_Name!="*$" Service_Name!="krbtgt"
| bin _time span=5m
| stats dc(Service_Name) as unique_spns count by Account_Name, Client_Address, _time
| where unique_spns > 5        // threshold tuned to environment
```

---

### 4.2 AS‑REP Roasting  

* **Key Event** – **4768** (Kerberos TGT Request).  
* **Signal** – `Pre_Authentication_Type=0` (pre‑auth disabled). No subsequent 4769 or 4624 events for that account.  
* **Relevant fields**  

| Field | Meaning |
|-------|---------|
| `Pre_Authentication_Type` | 0 = no pre‑auth, 2 = encrypted timestamp |
| `Ticket_Encryption_Type` | Often RC4 (`0x17`) when pre‑auth is disabled |
| `Account_Name` | Target user |
| `Client_Address` | Source IP |

* **Detecting the Roasting attempt (index = task3)**  

```spl
index=task3 EventCode=4768 Pre_Authentication_Type=0
| table _time, Account_Name, Ticket_Encryption_Type, Client_Address
```

* **Confirm lack of follow‑up events** (replace `{ACCOUNT_NAME}`):

```spl
index=task3 (EventCode=4624 OR EventCode=4769) 
| search Account_Name="{ACCOUNT_NAME}"
| table _time, EventCode, Account_Name, Client_Address
```

If no results appear, the TGT was likely requested **solely for offline cracking**.

---

### 4.3 LSASS Dumping  

* **Log source** – **Sysmon Event 10** (ProcessAccess).  
* **Key fields**  

| Field | Meaning |
|-------|---------|
| `SourceImage` | Full path of the process that accessed LSASS |
| `SourceUser` | Account running the process (SYSTEM vs. domain user) |
| `TargetImage` | Should be `*\\lsass.exe` |
| `GrantedAccess` | Hex mask – `0x0010` (PROCESS_VM_READ) is the critical bit; `0x1010` or `0x1FFFFF` indicate full dump tools |
| `CallTrace` | DLL chain – Known DLLs (`dbgcore.dll`, `dbghelp.dll`) = MiniDump API; `UNKNOWN` offsets = injection‑based dumping |

* **Baseline query (index = task4)**  

```spl
index=task4 EventCode=10 TargetImage="*\\lsass.exe"
| stats count by SourceImage, GrantedAccess
```

* **Investigate a suspicious process (replace `{SUSPICIOUS_PROCESS}`)**  

```spl
index=task4 EventCode=10 TargetImage="*\\lsass.exe" SourceImage={SUSPICIOUS_PROCESS}
| table _time, SourceImage, SourceUser, GrantedAccess, CallTrace
```

* **Interpretation**  

  * **Legitimate** – `csrss.exe`, `WerFault.exe`, `svchost.exe` with low access masks (`0x1000`, `0x1010`).  
  * **Malicious** – Tools like `mimikatz.exe`, `procdump.exe`, `dllhost.exe` with `0x1FFFFF` or `0x1010` and a CallTrace showing `UNKNOWN` offsets (injection) or known MiniDump DLLs.

---

### 4.4 DCSync  

* **Log source** – **Security Event 4662** (Directory Service Access). Requires:  

  1. **Audit Directory Service Access** enabled via GPO.  
  2. **SACL** on the domain partition to audit replication rights.  

* **Signal** – Event 4662 where `Access_Mask=0x100` (Control Access) and the raw event text contains the replication GUID **`1131f6ad`** (DS‑Replication‑Get‑Changes‑All). Filter out machine accounts (`user!="*$"`).  

* **Detection query (index = task5)**  

```spl
index=task5 EventCode=4662 "1131f6ad" user!="*$"
| table _time, user, Access_Mask, Properties
| sort _time
```

* **Correlate to source IP** – Use the `Logon_ID` from the 4662 event and match to a 4624 logon event:

```spl
# Get Logon_ID
index=task5 EventCode=4662 Access_Mask=0x100 user={COMPROMISED_USER} "1131f6ad"
| table _time, host, user, Logon_ID

# Find the matching logon
index=task5 EventCode=4624 Logon_ID={LOGON_ID}
| table _time, host, user, Source_Network_Address, Logon_Type
```

* **Normal vs. malicious** – In multi‑DC environments, 4662 with the GUID is normal when the **user** ends with `$` (a DC). A **human** account (or service account) performing the same operation indicates DCSync.

---

### 4.5 NTDS.dit Extraction  

* **Log source** – **Sysmon Event 1** (Process Creation) and **Event 11** (File Creation). Windows Security 4688 can be used if Sysmon isn’t present.  

* **Two common extraction paths**

  1. **IFM (ntdsutil.exe)** – `ntdsutil.exe` with `ifm` and `create` arguments.  
  2. **Shadow copy (vssadmin.exe)** – `vssadmin.exe` with `create shadow` followed by copy commands targeting `ntds.dit` and the `SYSTEM` hive.

* **Detecting ntdsutil usage (index = task6)**  

```spl
index=task6 EventCode=1 Image="*\\ntdsutil.exe"
| table _time, host, User, ParentImage, Image, CommandLine
```

* **Confirm file creation**  

```spl
index=task6 EventCode=11 TargetFilename="*ntds.dit" Image="*\\ntdsutil.exe"
| table _time, Image, TargetFilename
```

* **Detecting shadow‑copy creation**  

```spl
index=task6 EventCode=1 Image="*\\vssadmin.exe" CommandLine="*create shadow*"
| table _time, host, User, ParentImage, Image, CommandLine
```

* **Detecting copies from the shadow volume**  

```spl
index=task6 EventCode=1 CommandLine="*HarddiskVolumeShadowCopy*" 
    (CommandLine="*ntds*" OR CommandLine="*SYSTEM*")
| table _time, host, User, ParentImage, Image, CommandLine
```

* **Noise vs. signal** – Shadow‑copy creation alone can be legitimate (backups). The **follow‑up copy** of `ntds.dit`/`SYSTEM` indicates credential theft.

---

## 5. Comparative Cheat‑Sheet  

| Technique | Primary Log Source | Event ID(s) | Detection Indicator(s) | Required Privilege |
|-----------|-------------------|------------|------------------------|--------------------|
| **Kerberoasting** | DC Security Log | 4769 | `Ticket_Encryption_Type=0x17` (RC4) + many SPNs from one account | Any domain user |
| **AS‑REP Roasting** | DC Security Log | 4768 | `Pre_Authentication_Type=0` and no follow‑up 4769/4624 | None (only need username) |
| **LSASS Dumping** | Endpoint Sysmon | 10 (ProcessAccess) | `TargetImage=*\\lsass.exe`, `GrantedAccess` includes 0x0010, suspicious `SourceImage`/`CallTrace` | Local admin / SYSTEM |
| **DCSync** | DC Security Log | 4662 (Directory Service Access) | `Access_Mask=0x100` + GUID `1131f6ad`, non‑machine `user` | Domain Admin / Enterprise Admin (or any replication right) |
| **NTDS.dit Extraction** | DC Sysmon / 4688 | 1 (Process Creation), 11 (File Creation) | Execution of `ntdsutil.exe` with IFM or `vssadmin.exe` with `create shadow` + copy of `ntds.dit`/`SYSTEM` | Local admin on DC (or Domain Admin) |

---

## 6. Key Takeaways  

1. **Context is everything** – An RC4 ticket in an AES‑only environment, a non‑DC account performing replication, or a high‑privilege access mask on LSASS from an unexpected process are the real red flags.  
2. **Logging must be pre‑configured** –  
   * DCSync detection needs **Directory Service Access auditing** *and* a **SACL** on the domain partition.  
   * LSASS dumping detection requires **Sysmon** with a ProcessAccess rule targeting `lsass.exe`.  
3. **Evasion paths exist** – Attackers can use AES tickets for Kerberoasting (Orpheus) or legitimate backup tools for shadow‑copy creation. Complement static signatures with **volume‑based** or **behavioral** baselines.  
4. **Correlation across sources** – Mapping a LSASS dump (endpoint) to the originating user, then linking that user to a Kerberoasting or DCSync event (DC) builds a clear escalation timeline.  
5. **Real‑world relevance** – The notes cite several recent intrusions (BlackSuit ransomware, SolarWinds/Apt29, Scattered Spider) that employed these exact techniques, confirming they are actively used in the wild.  

---

### Suggested Next Steps for a SOC  

1. **Deploy the SPL queries** above in scheduled Splunk alerts, adjusting thresholds (e.g., number of distinct SPNs per 5 min) to match your environment’s baseline.  
2. **Verify that required audit settings are enabled** (Directory Service Access, Sysmon ProcessAccess).  
3. **Create a “known good” whitelist** of legitimate processes that legitimately access LSASS (`csrss.exe`, `WerFault.exe`, `svchost.exe`) and exclude them from alerts.  
4. **Implement a correlation dashboard** that ties together events from the five techniques, highlighting accounts that appear in multiple stages.  
5. **Test detection with Red‑Team tools** (Rubeus, Impacket, Mimikatz, secretsdump.py) to ensure alerts fire without excessive false positives.  

---
