
**Detailed Summary – “Monitoring Active Directory” Lab Notes**

---

### 1. Why Monitor Active Directory (AD)?
- AD is the core identity store for most enterprises; every ransomware, data breach, or domain compromise involves AD.
- AD generates **thousands of events per hour** (authentication, group changes, service tickets, failed logins).  
- The challenge: **separating malicious activity from normal noise**.

---

### 2. Learning Objectives
1. Identify AD‑related protocols and distinguish domain vs. local authentication.  
2. Interpret key AD Event IDs for authentication, account lifecycle, group changes, and directory services.  
3. Build baseline activity patterns and detect anomalies using **stack counting**.  
4. Configure audit policies to capture critical AD events.  
5. Query AD logs in Splunk to investigate user activity.

---

### 3. Prerequisite Knowledge
- **Active Directory basics** – domains, OUs, Kerberos/NTLM.  
- **Windows Event Logs** – especially IDs 4624, 4625.  
- **Splunk SPL** – writing and refining search queries.

---

### 4. AD Traffic Protocols
| Protocol | Port(s) | Primary Use |
|----------|---------|-------------|
| **Kerberos** | 88 | Default AD authentication (ticket requests). |
| **LDAP** | 389, 636, 3268, 3269 | Directory queries/modifications. |
| **SMB** | 445 (139 legacy) | File sharing, remote admin. |
| **RDP** | 3380 | Interactive remote desktop. |
| **NetBIOS/LLMNR** | 137, 138, 5355 | Legacy name resolution fallback. |

*All AD activity flows through these protocols, each generating log entries.*

---

### 5. Domain vs. Local Users
| User Type | Credentials Stored | Where Authentication Events Appear |
|-----------|--------------------|-----------------------------------|
| **Domain user** | `NTDS.dit` on DC | Domain Controller (central view). |
| **Local user** | `SAM` on the local machine | Only on the local workstation. |

*Implication:* For cross‑system investigations we rely on DC logs for domain users; local‑only accounts appear only on the host where the login occurs.

---

### 6. Authentication Event Flow

#### Kerberos (Ticket‑Based)
1. **TGT request** – Event **4768** on DC.  
2. **TGS request** – Event **4769** on DC.  
3. **Session creation** – Event **4624** on target server.  

*Failed pre‑authentication:* Event **4771** (DC).  
*Encryption types:*  
- `0x12` → AES‑256 (modern).  
- `0x17` → RC4‑HMAC (legacy).

#### NTLM (Legacy)
1. DC validates credentials – Event **4776** (DC).  
2. Session created on target – Event **4624** (target, with `Authentication_Package=NTLM`).

*Typical NTLM triggers:* IP‑based file share access, legacy apps, cross‑forest trusts.

---

### 7. Account‑Lifecycle Events
| Event ID | Action |
|----------|--------|
| **4720** | Account creation |
| **4722** | Account enabled |
| **4724** | Password reset attempt |
| **4725** | Account disabled |
| **4740** | Account locked out |

These events form a predictable baseline (HR onboarding → IT creation, password resets, off‑boarding).

---

### 8. Group‑Membership Events
| Event ID | Scope | Meaning |
|----------|-------|---------|
| **4728** | Global security group | Member added (domain‑wide). |
| **4732** | Domain‑local security group | Member added (machine‑level). |
| **4756** | Universal security group | Member added (forest‑wide). |

*Monitoring privileged groups (Domain Admins, Enterprise Admins, local Administrators) is critical.*

---

### 9. Directory Service Changes – Event 5136
- Captures **attribute‑level** modifications (e.g., `userAccountControl`, `servicePrincipalName`, `scriptPath`, `member`, `displayName`).  
- Useful for detecting:
  - Logon script changes.  
  - Unauthorized SPN alterations.  
  - Unexpected group membership changes.

#### GPO Modifications (via 5136)
- Filter with `Class="groupPolicyContainer"` to see who modified a GPO, which GPO (`DN`), and what attribute changed (`LDAP_Display_Name`, `Value`).  
- Note: 5136 logs only AD‑stored metadata, not the actual policy settings inside SYSVOL.

---

### 10. Logon Events (4624/4625)
- **4624** – Successful logon.  
- **4625** – Failed logon.  
- **LogonType** field identifies the context:
  - `2` – Interactive (keyboard).  
  - `3` – Network (file share, WMI).  
  - `4` – Batch.  
  - `5` – Service.  
  - `7` – Unlock.  
  - `10` – RemoteInteractive (RDP).

*Typical environment:* Type 3 dominates; Types 2 and 10 are comparatively low volume.

---

### 11. Volume & Normal‑vs‑Anomalous Activity
- Large environments (≈500 users) routinely see:
  - **TGS (4769)**: 50 k–100 k events/day.  
  - **TGT (4768)**: 5 k–10 k events/day.  
  - **Logons (4624)**: Varies by server role.  
- **Computer accounts** (ending with `$`) generate **70‑80 %** of Kerberos traffic. Filtering them out focuses analysis on human activity.

#### Service Name Patterns (from 4769)
| Pattern | Represents |
|---------|------------|
| `krbtgt` | TGT renewal |
| `cifs/<host>` | File share |
| `ldap/<host>` | Directory query |
| `http/<host>` | Web request |
| `MSSQLSvc/<host>` | SQL Server |
| `HOST/<host>` | Generic host service |

*Deviations from these patterns merit investigation.*

---

### 12. Anomaly Detection – Stack Counting
- **Technique:** Count occurrences of a field, sort descending, then examine the **low‑frequency tail**.  
- Example (on Event 4769, excluding computer accounts):
  ```spl
  index=* EventCode=4769 NOT Account_Name="*$*"
  | stats count by Account_Name
  | sort -count
  ```
- **Interpretation:**  
  - **Top values** = normal, frequent activity.  
  - **Bottom values** = rare accounts/services/IPs → potential anomalies.

- Stack counting can be applied to any field: `Account_Name`, `Client_Address`, `Service_Name`, `Ticket_Encryption_Type`.

---

### 13. Time‑Based Context
| Activity | Expected Time Window |
|----------|----------------------|
| Regular user logins | Business hours (≈8 am‑6 pm) |
| Backup service accounts | Overnight (midnight‑4 am) |
| Batch jobs | Scheduled windows |
| Admin accounts | Maintenance windows / admin workstations |

*Out‑of‑window activity should be flagged.*

---

### 14. Auditing Configuration – Minimum Settings
| Category | Sub‑category | Setting (Success + Failure) | Events Produced |
|----------|--------------|------------------------------|-----------------|
| Account Logon | Credential Validation | ✓ | 4776 (NTLM) |
| Account Logon | Kerberos Authentication Service | ✓ | 4768, 4771 |
| Account Logon | Kerberos Service Ticket Operations | ✓ | 4769 |
| Account Management | User Account Management | ✓ | 4720, 4722, 4724, 4725 |
| Account Management | Security Group Management | ✓ | 4728, 4732, 4756 |
| DS Access | Directory Service Changes | ✓ | 5136 |
| Logon/Logoff | Logon | ✓ | 4624, 4625 |
| Object Access | File Share | ✓ | 5140 |

*Without these, critical AD data may be missing.*

#### Verifying Settings
- Show all audit policies:  
  ```cmd
  auditpol /get /category:*
  ```
- Show a specific sub‑category (e.g., Kerberos Service Ticket Operations):  
  ```cmd
  auditpol /get /subcategory:"Kerberos Service Ticket Operations"
  ```

Both commands should report **Success and Failure** for the categories above.

---

### 15. Practical Investigation Example (New Employee Onboarding)
Using Splunk queries, the lab demonstrated how to verify a newly created user:

| Question | Answer |
|----------|--------|
| **New account name** | `nathan.brooks` |
| **Creator of the account** | `adm-luke.sullivan` |
| **Group added to** | `Marketing` |
| **Source IP of first TGT request** | `10.5.50.12` |

The steps involved:
1. Search `EventCode=4720` to locate the account‑creation event.  
2. Join with `Subject_Account_Name` to see the creator.  
3. Use `EventCode=4728/4732/4756` to find group membership.  
4. Filter `EventCode=4768` for the new account’s first TGT request to capture the client IP.

---

### 16. Key Takeaways
1. **AD protocols (Kerberos, LDAP, SMB, RDP, NetBIOS/LLMNR)** drive the event landscape.  
2. **Authentication events** reside on Domain Controllers; **logon sessions** appear on target hosts.  
3. Proper **audit policy configuration** is essential; many useful events are off by default.  
4. Expect **high daily volumes**—focus on **stack counting** and rare‑value analysis to surface anomalies.  
5. Correlate **sequences of events** (e.g., TGT → TGS → logon) to reconstruct attacker behavior.  

--- 

*End of detailed summary.*
