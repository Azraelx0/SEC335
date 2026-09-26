# Phishing, Credential Abuse, and Initial Access

## Phishing as Initial Access

**Initial Access (MITRE TA0001)** answers one question: how does the attacker get in? Two techniques dominate real intrusions: **Phishing (T1566)** and **Valid Accounts (T1078)**.

Phishing is often called a "last resort" in pen testing, not because it fails, but because it's the noisiest and most detectable option:
- Email filters may catch it
- Security awareness training may cause employees to report it
- The SOC may catch the resulting C2 callback

But it's still the most effective vector because it bypasses the perimeter entirely. Firewalls don't block email, and IDS/IPS can't read intent. When a user clicks "Enable Content" on a malicious doc, the macro runs inside the trust boundary, under the user's own privileges and access.

### Choosing an Initial Access Method

A pen tester weighs noise level, detection risk, scope of access, speed, ethical/legal risk, and effectiveness. Phishing is high-noise and high-detection but very effective. It's the "last resort" you reach for when simpler technical approaches are exhausted, or when the goal is specifically to demonstrate human risk.

---

## Weaponizing Office Macros

### How VBA Macros Enable Code Execution

Office macros use **VBA (Visual Basic for Applications)**, a full scripting language inside documents. VBA can:
- Run commands via the Windows shell
- Create COM objects (FileSystemObject, WScript.Shell, MSXML2.XMLHTTP)
- Download files, modify the registry, create scheduled tasks/services, query WMI

The key enabler is the **AutoOpen / Document_Open** macro, which runs automatically when the doc opens. The user opens what looks legit, and the macro runs silently.

### The Lab Macro Pattern (used by real actors like Emotet, QakBot, IcedID)

1. **HTTP Download** – uses MSXML2.XMLHTTP to grab a payload from a remote server
2. **File System Interaction** – uses Scripting.FileSystemObject to write the payload to disk
3. **Execution** – uses Shell to run the downloaded file, which pulls and runs the final payload (a Meterpreter reverse HTTPS shell)

This maps to **T1105 (Ingress Tool Transfer)** – downloading tools into the compromised environment.

### Why reverse_https Instead of reverse_tcp?

- **TLS encryption:** HTTPS is encrypted end-to-end, so monitors can't see the Meterpreter protocol. Looks like normal browsing.
- **Firewall bypass:** Port 443 is almost always allowed outbound. Port 4444 (reverse_tcp) is trivially blocked.
- **Blends in:** an HTTPS callback looks like a user browsing a site.
- **WAF/IDS evasion:** many appliances deep-inspect HTTP but not TLS-encrypted HTTPS.

---

## Stolen Credentials: The Most Common Vector

**Valid Accounts (T1078)** often ranks *above* phishing as the most common initial access technique. Mandiant, CrowdStrike, and Microsoft all confirm stolen creds are the dominant method for both nation-state and criminal actors.

### Where Stolen Credentials Come From

- **Dark web marketplaces** – forums selling "logs" (full dumps from infostealer malware)
- **Data brokers** – aggregated breach data, sometimes sold legally
- **Infostealer malware** – Raccoon, Vidar, Lumma harvest saved browser creds, cookies, wallets
- **Public breaches** – leaked databases (LinkedIn, Adobe, etc.)
- **Credential stuffing** – reusing known username/password pairs across services
- **Password spraying** – trying common passwords across many accounts

### How They Provide Direct Access (no phishing needed)

- **RDP (T1021.001):** stolen creds = direct graphical login if RDP is exposed
- **VPN / Remote Access (T1133):** creds against VPN concentrators, Citrix gateways, etc.
- **SMB / Open Shares (T1021.002):** if port 445 is exposed, creds get you into shares (including ADMIN$ and C$)
- **Cloud Services (T1078.004):** creds for Azure AD, AWS, etc., which often bridge to on-prem

Real-world: Mandiant's M-Trends 2026 confirms Valid Accounts are the most observed initial access vector. **Initial Access Brokers (IABs)** sell access — from ~$50 for a domain user to $10,000+ for domain admin at a Fortune 500.

---

## PSExec: Lateral Movement, Not Initial Access (Usually)

**PSExec (MITRE S0029)** is a **Lateral Movement** tool. It works by connecting to a remote system's SMB shares and creating a Windows service.

Techniques: T1021.002 (SMB/Admin Shares), T1569.002 (Service Execution), T1570 (Lateral Tool Transfer), T1543.003 (Windows Service).

### Why It Needs Pre-Existing Access

PSExec requires:
- Network connectivity to port 445 (SMB) on the target
- Valid credentials with admin privileges
- Access to the ADMIN$ share

You must already be inside the network with valid creds to use it, so it's Lateral Movement, not Initial Access.

### The Exception: Bad Firewall Config

Many orgs disable the Windows Firewall internally or allow inbound SMB (445) from any internal IP. When that misconfig exists plus stolen creds, an attacker can use PSExec from anywhere on the internal network — turning one compromised workstation into a launch point across departments.

In the lab, this is why you: disable the Windows Firewall, add the `LocalAccountTokenFilterPolicy` registry key (to allow local admin token creation), and use PSExec with stolen creds for a Meterpreter session. PSExec itself is a legit Microsoft admin tool — it should just be restricted to authorized admin workstations.

---

## RDP as Initial Access

RDP gives direct graphical access when an attacker has valid creds and RDP is exposed.

### MITRE Classification (depends on context)

- First entry into the network → **Valid Accounts (T1078)**
- First entry via remote services → **External Remote Services (T1133)**
- Moving between internal systems → **Remote Services: RDP (T1021.001)**
- Using stolen creds → **Use Alternative Authentication Material (T1550)**

### Why RDP Is Dangerous

- **No tools needed:** built-in `mstsc.exe` (Windows) or `xfreerdp` (Linux)
- **Full interactive access:** whole desktop, easy to exfil/persist/move laterally
- **Hard to detect:** admins and help desk use it legitimately
- **Encrypted:** TLS makes session inspection difficult

### Detection Indicators

- New RDP session from an unusual IP (Event ID 4624, Type 10)
- RDP outside business hours
- RDP to systems not normally accessed
- Brute force against RDP (Event ID 4625 failed logons)

---

## Backdooring Executables (Supply Chain, Micro Scale)

Modifying a trusted program to include malicious code. When the user runs it, the backdoor runs alongside the real functionality.

MITRE: **T1554** (Compromise Client Software Binary), **T1195.002** (Software Supply Chain Compromise).

### Why It Works

- **Trust transfer:** users trust the original app and don't expect a legit exe to be malicious
- **Evasion:** the program still works normally while the backdoor runs silently
- **Persistence:** can be installed on multiple systems

### Real-World Parallels

- **SolarWinds:** APT29 poisoned the Orion build process, hit 18,000+ orgs
- **Codecov:** attackers modified the Bash Uploader to steal CI/CD env variables
- **STARDUST CHOLLIMA (2026):** DPRK group compromised the Axios npm package to deliver crypto-stealing malware — got in using stolen credentials

---

## Detection and Defense

### Phishing with Macros

- Disable VBA macros by default (Group Policy)
- Use Mark of the Web (MOTW) to block macros in downloaded docs
- Monitor Office apps spawning cmd.exe/powershell.exe (Event ID 4688)
- Alert on Office apps making HTTP connections to weird domains
- Use application allowlisting (WDAC/AppLocker)

### Credential Abuse

- Impossible travel detection (logins from distant places in a short window)
- Brute force detection (Event ID 4625 thresholds)
- Password spraying detection (many failed logins across accounts from one source)
- RDP anomaly detection
- Dark web monitoring for exposed credentials

### PSExec / Lateral Movement

- Service creation monitoring (Event ID 7045 for PSEXESVC.exe)
- SMB share access logging (ADMIN$, C$)
- Sysmon Event ID 1 (process creation with command line)
- Sigma rules for PSExec patterns
- Alert on east-west SMB traffic between workstations

### Defense-in-Depth

No single control is enough. Layer them:
- **Prevent:** disable macros, enforce MFA, block RDP from the internet, segment networks
- **Detect:** EDR/XDR, command-line logging, Sysmon, behavioral baselines
- **Respond:** automate playbooks for credential theft, lateral movement, and C2 detection

---

## Recent Threat Intel (2025–2026)

These techniques are used at scale in the wild.

- **BREEZE COMET (UNC5669), 2026:** financially motivated, targets Brazil. Password spraying against VPN/RDP, vishing impersonating IT support, credential theft from CI/CD, RDP + SMB lateral movement, XWORM via fake tax docs.
- **UNC6671, 2026:** multi-brand vishing extortion. Voice phishing as IT helpdesk, AiTM to steal creds and MFA tokens, exfil from M365/Okta. Ransom demands $1M–$3M, final payments ~$750K.
- **Microsoft "Impersonating IT Support" campaign, 2026:** abuses Teams external collaboration to gain remote access, deploys Node.js backdoors, expands to enterprise-wide access.
- **CrowdStrike 2026 Threat Hunting Report:** 88% of vuln exploitation within 48 hrs of PoC release; vishing up 2x; SNARKY SPIDER went from account takeover to data theft in under 5 minutes; device code phishing up 15x in six months.

### The Common Pattern

1. **Social engineering** (phishing, vishing, impersonation) for a foothold or creds
2. **Credential abuse** (valid accounts, spraying, stuffing) for direct RDP/VPN/SMB access
3. **Lateral movement** (PSExec, SMB, WMI, RDP) to expand
4. **Living off the land** to evade detection

These aren't exotic — they're the same techniques from this lab, used by both nation-states and criminals.

---

## Interview Prep

### Legitimate vs Malicious Use

- **VBA Macros:** automate Office tasks → download/execute malware
- **PSExec:** remote admin/deployment → lateral movement after cred theft
- **RDP:** remote work/admin → unauthorized access with stolen creds
- **SMB Shares:** file sharing → file transfer, command execution, lateral movement
- **certutil.exe:** certificate management → file download, payload decoding
- **PowerShell:** admin/automation → post-exploitation scripting

### Common Questions (short answers)

- **Initial Access vs Lateral Movement?** Initial Access is the first entry from outside. Lateral Movement is moving between systems once inside. PSExec is Lateral (needs creds + network access first). RDP can be either.
- **Why is phishing a last resort?** Operationally expensive, high detection risk, and ethical concerns. Simpler technical routes are preferred, but phishing is best when targeting human behavior is the goal.
- **How to detect macro phishing?** VBA macro logging (Event ID 4688 with command-line auditing), Sysmon, watch for Office apps spawning child processes, EDR, and MOTW policies.
- **Why is RDP dangerous?** Built-in tools, full graphical access, encrypted, and legit admin use makes it hard to distinguish without behavioral analytics.
- **How to defend against credential attacks?** MFA everywhere (especially VPN/RDP), network segmentation, monitor for impossible travel and brute force, dark web monitoring, least-privilege access.

---

## Lab Tasks Recap

1. **Create a Macro** – VBA macro in Word downloads/executes a Meterpreter payload. Spearphishing Attachment (T1566.001). The doc is the initial access vector.
2. **Backdoor an EXE** – add a Meterpreter backdoor to a legit Windows exe. Supply Chain Compromise (T1195.002), User Execution (T1204.002).
3. **Stolen Credentials with PSExec** – PSExec with stolen creds for a Meterpreter session. Lateral Movement (T1021.002, T1569.002).
4. **RDP as Initial Access** – stolen creds to log in via RDP. True Initial Access (T1078, T1133, T1021.001).
5. **PSExec Login** – Metasploit PSExec module with stolen creds. Lateral Movement again; the registry mod and firewall disable are real-world misconfigs that enable it.
