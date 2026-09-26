Lecture: Phishing, Credential Abuse, and Initial Access in Penetration Testing
1. Phishing as Initial Access: Context in Penetration Testing
Why Phishing Exists in the Pen Tester's Toolkit
In penetration testing, Initial Access (MITRE TA0001) is the tactic that answers a single question: How does the attacker get in? Every breach, every ransomware deployment, every espionage campaign begins with some form of initial access. The MITRE ATT&CK framework catalogs over a dozen initial access techniques, but two dominate real-world intrusions: Phishing (T1566) and Valid Accounts (T1078).

Phishing is often described as a "last resort" in penetration testing-not because it is ineffective, but because it is the most disruptive and detectable method. A well-crafted phishing campaign requires sending malicious content to real employees, which introduces risk: email filters may catch it, security awareness training may cause employees to report it, and the organization's SOC may detect the resulting c2 callback. Compared to external network scanning, credential spraying against a VPN, or exploiting a public-facing application, phishing is operationally expensive and noisy.

Yet phishing remains the most effective initial access technique because it bypasses the network perimeter entirely. Firewalls do not block email. IDS/IPS systems do not inspect the intent of what a person puts in email. When a user opens a Word document and clicks "Enable Content," the malicious macro executes within the trust boundary of the user's own desktop, under the user's own privileges, with access to the user's network resources. This is why phishing is consistently the #1 initial access vector in both penetration testing engagements and real-world threat intelligence reports.
The Pen Tester's Decision Matrix
When selecting an initial access method, a penetration tester evaluates:

Factor
Phishing
Credential Spray
Exploit Public App
Trusted Relationship
Noise level
High (email + callback)
Medium (failed logins)
High (exploit signatures)
Low
Detection risk
High (SOAR, user reports)
Medium (lockout policies)
High (WAF, IDS)
Low
Scope of access
User-level, workstation
Depends on account privileges
Server-level
Varies
Speed to execute
Hours to craft campaign
Minutes to hours
Minutes if vuln exists
Hours to establish
Ethical/legal risk
Moderate (social engineering)
Low
Low
Low
Effectiveness
Very high
High
High (if vuln exists)
High


Phishing is a "last resort" not because it fails, but because it is the tool you reach for when simpler technical approaches have been exhausted OR when the engagement requires demonstrating the human risk factor.
2. The Macro: Why Office Documents Are Weaponized
How VBA Macros Enable Code Execution
Microsoft Office macros use Visual Basic for Applications (VBA), a full scripting language embedded within Office documents. VBA macros can:

Execute arbitrary commands via the Windows Command Shell (Shell function)
Create and interact with COM objects (FileSystemObject, WScript.Shell, MSXML2.XMLHTTP)
Download files from the internet
Modify Windows Registry keys
Create scheduled tasks and services
Interact with WMI for system enumeration

The key enabler is the AutoOpen (or Document_Open) macro, which executes automatically when the user opens the document. This is the mechanism that makes phishing attachments dangerous: the user opens what appears to be a legitimate document, and the macro runs silently in the background. Even when users receive a prompt to “Enable Macros” they will click it.
MITRE ATT&CK Mapping for Macro-Based Phishing
Phase
Technique
MITRE ID
Description
Reconnaissance
Phishing for Information
T1598
Gather target email addresses, organizational info
Resource Development
Develop Capabilities
T1587
Create malicious macro-enabled documents
Initial Access
Phishing: Spearphishing Attachment
T1566.001
Send macro-enabled document via email
Execution
Command and Scripting Interpreter: Visual Basic
T1059.005
VBA macro execution
Execution
Command and Scripting Interpreter: PowerShell
T1059.001
Macro spawns PowerShell for payload delivery
Execution
Command and Scripting Interpreter: Windows Command Shell
T1059.003
Macro spawns cmd.exe
Defense Evasion
Indicator Removal
T1070
Macro may delete artifacts after execution
Credential Access
OS Credential Dumping
T1003
Post-exploitation credential harvesting
Lateral Movement
Remote Services: SMB/Windows Admin Shares
T1021.002
Using stolen creds to access other systems
Lateral Movement
Use Alternative Authentication Material
T1550
Using dumped NTLM hashes or Kerberos tickets

The Anatomy of the Lab Macro
The macro in this lab demonstrates a real-world pattern used by threat actors:

HTTP Download - The macro uses MSXML2.XMLHTTP to download a payload from a remote server. This is the same technique used by Emotet, QakBot, and IcedID in real-world campaigns.
File System Interaction - The macro uses Scripting.FileSystemObject to write the payload to disk (the user's Documents folder).
Execution - The macro uses Shell to execute the downloaded batch file, which in turn downloads and executes the final payload (a Meterpreter reverse HTTPS shell).

This pattern maps directly to MITRE T1105 (Ingress Tool Transfer) - the act of downloading tools from an external source into the compromised environment.
Why reverse_https, Not reverse_tcp?
The lab asks you to use windows/x64/meterpreter/reverse_https instead of windows/x64/meterpreter/reverse_tcp. This is a deliberate choice that reflects real-world attacker tradecraft:

TLS encryption: HTTPS traffic is encrypted end-to-end. Network monitoring tools that inspect HTTP traffic cannot see the Meterpreter protocol. The HTTPS session looks like normal browsing.
Firewall bypass: Port 443 (HTTPS) is almost universally allowed outbound. Blocking it breaks legitimate business operations. Reverse_tcp on port 4444, by contrast, is trivially blocked by any egress filtering policy.
Blending with normal traffic: An HTTPS callback to your C2 server looks identical to a user browsing a website. DNS logs, proxy logs, and NetFlow data all show what appears to be a legitimate HTTPS connection.
WAF/IDS evasion: Many network security appliances perform deep packet inspection on HTTP but not on TLS-encrypted HTTPS. The Meterpreter protocol is hidden inside the encrypted tunnel.


3. Stolen Credentials: The Most Common Initial Access Vector
Phishing Is Not the Only Way In
In real-world intrusions, Valid Accounts (T1078) consistently ranks as the most common initial access technique, often surpassing phishing. Threat intelligence from Mandiant, CrowdStrike, and Microsoft all confirm that stolen credentials are the dominant initial access method for both nation-state and financially motivated threat actors.
Where Stolen Credentials Come From
Source
MITRE Mapping
Description
Dark web marketplaces
T1597 (Search Closed Sources)
Forums like Genesis Market, Russian Market, and Exploit sell "logs" - full credential dumps from infostealer malware
Data brokers
T1597.001 (Threat Intel Vendors)
Commercial services sell aggregated breach data, sometimes legally
Infostealer malware
T1555 (Credentials from Password Stores)
Malware like Raccoon Stealer, Vidar, and Lumma harvest saved browser credentials, cookies, and crypto wallets
Public breaches
T1597.001
Leaked databases from LinkedIn, Adobe, and other breaches are freely available
Credential stuffing
T1110.004 (Credential Stuffing)
Automated use of known username/password pairs across multiple services
Password spraying
T1110.003 (Password Spraying)
Trying common passwords against many accounts

How Stolen Credentials Provide Direct Access
Once an attacker obtains valid credentials, they have multiple paths for initial access - no phishing required:

RDP (T1021.001): If Remote Desktop is enabled on any internet-facing system, stolen domain or local credentials allow direct graphical login. This is Initial Access, not Lateral Movement, because the attacker is entering the network for the first time from the outside.

VPN/Remote Access (T1133): Stolen credentials used against VPN concentrators, Citrix gateways, or other remote access solutions provide direct entry to the internal network.

SMB/Open Shares (T1021.002): If port 445 is exposed (which should never happen but frequently does), stolen credentials allow direct access to file shares, including the ADMIN$ and C$ administrative shares.

Cloud Services (T1078.004): Stolen credentials for Azure AD, AWS, or other cloud platforms provide access to cloud environments, which often bridge to on-premises networks.
Real-World Evidence
The Mandiant M-Trends 2026 report confirms that Valid Accounts are the most commonly observed initial access vector in incidents investigated by Mandiant, surpassing both phishing and exploitation of public-facing applications. Threat actors purchase credentials from Initial Access Brokers (IABs) who specialize in compromising networks and selling access on dark web forums. Prices range from $50 for a standard domain user to $10,000+ for domain admin credentials to a Fortune 500 company.


4. PSExec: Lateral Movement, Not Initial Access (Usually)
The MITRE Classification
PSExec (MITRE Software ID: S0029) is classified as a Lateral Movement tool, not an Initial Access tool. The MITRE ATT&CK page for PSExec documents the following techniques:

T1021.002 (Remote Services: SMB/Windows Admin Shares): PSExec writes a binary to the ADMIN$ share on the remote system and executes it via a Windows service.
T1569.002 (System Services: Service Execution): PSExec creates a temporary Windows service to execute commands on the remote system.
T1570 (Lateral Tool Transfer): PSExec can upload files to remote systems via SMB.
T1543.003 (Create or Modify System Process: Windows Service): PSExec leverages Windows services for execution.
Why PSExec Requires Pre-Existing Access
PSExec operates by connecting to a remote system's SMB shares and creating a Windows service. This requires:

Network connectivity to port 445 (SMB) on the target system
Valid credentials with administrative privileges on the target
Administrative share access (the ADMIN$ share must be accessible)

This is why PSExec is a Lateral Movement tool: you must already be inside the network with valid credentials before you can use it. The attacker who runs PSExec has already achieved Initial Access through some other method (phishing, credential theft, etc.) and is now moving laterally within the network.
The Exception: Poorly Configured Firewalls
There is a critical exception to this classification. In many organizations, the Windows Firewall is disabled on internal workstations, or rules exist that allow inbound SMB (port 445) from any internal IP address. This is the scenario described in the lab instructions:

"Many organizations disable Windows internally or allow port 445 inbound from anywhere on their LAN. That is not needed and is generally a misunderstanding of how SMB works."

When this misconfiguration exists and stolen credentials are available, an attacker can use PSExec from anywhere on the internal network - including from a compromised workstation in one department to target servers in another. In a geographically distributed organization where all devices appear on the same logical network (like "everyone in a football stadium"), this creates a massive lateral movement surface.

In the penetration testing context, this is why the lab has you:

Disable the Windows Firewall on the target
Add the LocalAccountTokenFilterPolicy registry key to allow local admin token creation
Use PSExec with stolen credentials to gain a Meterpreter session

This demonstrates a common real-world misconfiguration that enables lateral movement at scale. PSExec is a legitimate remote system administration tool. It is provided by Microsoft and can all you to run commands and perform tasks on a few or hundreds of systems. So adding the registry key may be needed when it is used. However, PSExec should be restricted so only the administrator workstations that can use it are able to execute it on remote systems.


5. RDP as Initial Access
Remote Desktop: The Attacker's Preferred GUI
Remote Desktop Protocol (RDP) is one of the most commonly abused remote access protocols in both penetration testing and real-world attacks. When an attacker obtains valid credentials and RDP is exposed to the network (or internet), RDP provides direct, graphical access to the target system.
MITRE Classification
RDP falls under multiple MITRE techniques depending on context:

Context
Technique
MITRE ID
First entry into the network
Valid Accounts
T1078
First entry via remote services
External Remote Services
T1133
Moving between systems inside the network
Remote Services: RDP
T1021.001
Using stolen credentials
Use Alternative Authentication Material
T1550

Why RDP Is Dangerous
RDP is dangerous because:

No special tools required: The attacker uses the built-in mstsc.exe (Windows) or xfreerdp (Linux). There is nothing to download, no malware to deploy.
Full interactive access: Unlike a command-line shell, RDP provides full graphical desktop access, making it easy to exfiltrate data, install persistence, and move laterally.
Legitimate use makes detection difficult: RDP is used by administrators, help desk staff, and remote workers. An RDP login from a valid account may not trigger alerts unless behavioral analytics are in place.
Encryption: RDP uses TLS, making it difficult for network monitoring tools to inspect the session contents.
Detection Indicators
Indicator
Event Source
MITRE Mapping
New RDP session from unusual IP
Windows Security Event ID 4624 (Type 10)
T1021.001
RDP session outside business hours
Event ID 4624 + temporal analysis
T1021.001
RDP to systems not normally accessed
Network flow analysis, proxy logs
T1021.001
Brute force against RDP
Event ID 4625 (failed logons)
T1110



6. Backdooring Executables: Supply Chain Compromise at the Micro Scale
The Concept
Backdooring a legitimate executable is a form of supply chain compromise - the attacker modifies a trusted program to include malicious code. When the user runs the program, the backdoored code executes alongside the legitimate functionality.

In MITRE terms, this maps to:

T1554 (Compromise Client Software Binary): Adversaries may modify client software binaries to include malicious functionality.
T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain): Broader category of supply chain attacks.
Why This Works
The backdoor technique works because:

Trust transfer: Users trust the original application. They do not expect a signed, legitimate executable to contain malicious code.
Evasion: The original program still functions normally. The backdoor executes silently in the background while the user interacts with the legitimate application.
Persistence: The backdoored executable may be installed on multiple systems, providing multiple access points.
Real-World Parallels
This technique has been used by sophisticated threat actors:

SolarWinds (T1195.002): Russian APT29 compromised the SolarWinds Orion build process, inserting malicious code into legitimate software updates distributed to 18,000+ organizations.
Codecov (T1195.002): Attackers modified the Codecov Bash Uploader script to exfiltrate CI/CD environment variables.
STARDUST CHOLLIMA (2026): DPRK-nexus threat group compromised the Axios npm package to deliver cryptocurrency-stealing malware, as documented in CrowdStrike's 2026 Threat Hunting Report. They compromised the account using…stolen credentials.


7. Detection and Defense
Detecting Phishing with Macros
Detection Strategy
Implementation
MITRE Mapping
Disable VBA macros by default
Group Policy: Disable VBA for Office applications
T1059.005 (prevent execution)
Mark of the Web (MOTW)
Block macros in documents downloaded from the internet
T1566.001 (detection at email gateway)
Office telemetry
Monitor Event ID 4688 for WINWORD.EXE, EXCEL.EXE spawning cmd.exe or powershell.exe
T1059
Network monitoring
Alert on HTTP connections from Office applications to unusual domains
T1105
Application allowlisting
WDAC/AppLocker rules to restrict Office application behavior
T1059.005

Detecting Credential Abuse
Detection Strategy
Implementation
MITRE Mapping
Impossible travel detection
Alert on logins from geographically distant locations in short timeframes
T1078
Brute force detection
Alert on Event ID 4625 threshold exceeded
T1110
Password spraying detection
Alert on multiple failed logins across different accounts from same source
T1110.003
RDP anomaly detection
Alert on RDP logins from unusual IPs, times, or to unusual targets
T1021.001
Dark web monitoring
Monitor for organizational credentials appearing on dark web forums
T1597

Detecting PSExec and Lateral Movement
Detection Strategy
Implementation
MITRE Mapping
Service creation monitoring
Event ID 7045 (new service installed) for PSExec's PSEXESVC.exe
T1569.002
SMB share access logging
Monitor access to ADMIN$ and C$ shares
T1021.002
Sysmon Event ID 1
Process creation with command-line arguments
T1569.002
Sigma rules
Community detection rules for PSExec execution patterns
T1021.002
Network monitoring
Alert on SMB traffic between workstations (east-west)
T1021.002

The Defense-in-Depth Model
No single detection technique is sufficient. Effective defense requires layered controls:

Prevent: Disable macros by default, enforce MFA, block RDP from the internet, segment networks to limit east-west SMB traffic.
Detect: Deploy EDR/XDR, enable command-line logging, configure Sysmon, establish behavioral baselines.
Respond: Automate response playbooks for credential theft, lateral movement, and C2 callback detection.


8. Recent Threat Intelligence: These Techniques in the Wild
The following threat intelligence reports from 2025-2026 confirm that the techniques practiced in this lab are actively used by real-world threat actors.
Campaign 1: BREEZE COMET (UNC5669) - Financially Motivated Threat Actor (2026)
Source: Mandiant/Google Threat Intelligence Group (September 2026) URL: https://cloud.google.com/blog/topics/threat-intelligence/financially-motivated-threat-actor-breeze-comet-targets-brazil

BREEZE COMET is a financially motivated threat actor targeting Brazilian financial services, retail, and ecommerce. Their attack chain mirrors many of the techniques practiced in this lab:

Initial Access: Password spraying against VPN and RDP services; voice calls impersonating IT support to trick employees into installing remote monitoring tools (AnyDesk)
Credential Theft: Harvested credentials from CI/CD pipelines, cloud tokens, and API keys; used the REALBREEZE LDAP brute-forcing utility
Lateral Movement: RDP sessions using hijacked service accounts; SMB network file shares for command execution; network scanning to enumerate SMB pathways
Malware Delivery: XWORM backdoor delivered via fake tax documents (ComprovantePDF.exe) - a social engineering technique analogous to the macro-enabled documents in this lab
Persistence: Custom Rust-based COBALTSPIN tunneler for firewall bypass; LIGHTPAINT (Java-based VPN installer backdoor); KICKPLATE (Nim-based Windows Update impersonator)
Campaign 2: UNC6671 - Multi-Brand Vishing Extortion (2026)
Source: Google Threat Intelligence Group (August 2026) URL: https://cloud.google.com/blog/topics/threat-intelligence/unc6671-targets-financial-services-and-enterprise-cloud-environments

UNC6671 demonstrates the convergence of social engineering and credential theft:

Initial Access: Vishing (voice phishing) targeting enterprise employees, posing as IT helpdesk staff
Credential Interception: AiTM (Adversary-in-the-Middle) infrastructure to intercept credentials and MFA tokens
Post-Compromise: Automated scripts exfiltrate data from M365 and Okta after session hijacking
Ransom: Initial demands of $1M-$3M USD, with final payments averaging ~$750,000
Campaign 3: Microsoft Impersonating IT Support Campaign (2026)
Source: Microsoft Threat Intelligence (September 2026) URL: https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/

A human-operated intrusion campaign abusing Microsoft Teams external collaboration:

Initial Access: Threat actors impersonate IT support via Teams, gaining remote access
Persistence: Deploy Node.js-based backdoors
Lateral Movement: Turn initial remote sessions into enterprise-wide access
Campaign 4: CrowdStrike 2026 Threat Hunting Report
Source: CrowdStrike (August 2026) URL: https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-threat-hunting-report/

Key findings relevant to this lab:

88% of vulnerability exploitation occurred within 48 hours of PoC release
Vishing intrusions increased 2x in H1 2026 vs H2 2025
SNARKY SPIDER moved from account takeover to data theft in under five minutes
Monthly device code phishing attempts jumped 15x in six months
FAMOUS CHOLLIMA (DPRK) weaponized AI environments for cryptocurrency attacks
STARDUST CHOLLIMA compromised the Axios npm package (supply chain attack)
The Pattern
Across all of these campaigns, the same initial access patterns emerge:

Social engineering (phishing, vishing, impersonation) to obtain initial foothold or credentials
Credential abuse (valid accounts, password spraying, credential stuffing) for direct access via RDP, VPN, or SMB
Lateral movement (PSExec, SMB, WMI, RDP) to expand access within the network
Living off the land techniques to evade detection

These are not exotic techniques. They are the same techniques practiced in this lab, deployed at scale by both nation-state actors and financially motivated criminals.


9. Job Interview Considerations
What Interviewers Want You to Know About Initial Access
In cybersecurity interviews, particularly for SOC analyst, threat hunter, or incident responder roles, expect questions about initial access techniques. Here is what to be prepared for:
Original Use vs. Malicious Use
Tool/Technique
Legitimate Use
Malicious Use
VBA Macros
Automate repetitive Office tasks
Download and execute malware payloads
PSExec
Remote administration and software deployment
Lateral movement after credential theft
RDP
Remote work and system administration
Unauthorized access using stolen credentials
SMB Shares
File sharing and collaboration
File transfer, command execution, lateral movement
certutil.exe
Certificate management
File download, payload decoding
PowerShell
System administration and automation
Post-exploitation scripting, payload execution

Common Interview Questions
"What is the difference between Initial Access and Lateral Movement?"

Initial Access (TA0001) is the first entry into a network from the outside. Lateral Movement (TA0008) is moving between systems after already being inside. PSExec is Lateral Movement because you need credentials and network access first. RDP can be either - it's Initial Access when used from the internet with stolen credentials, and Lateral Movement when used from inside the network.

"Why is phishing considered a last resort in penetration testing?"

Because it is operationally expensive (requires crafting a campaign, evading email filters, and managing a callback), it introduces detection risk (email security tools, user awareness training, SOC alerts), and it has ethical/social engineering considerations. Simpler technical approaches (credential spraying, VPN exploitation) are preferred when available. However, phishing remains the most effective method when targeting human behavior is the objective.

"How do you detect a macro-based phishing attack?"

Enable VBA macro logging (Event ID 4688 with command-line auditing), deploy Sysmon, monitor for Office applications spawning unexpected child processes (WINWORD.EXE → cmd.exe → powershell.exe), use EDR behavioral detection, and enforce Mark of the Web (MOTW) policies to block macros in downloaded files.

"What makes RDP a dangerous initial access vector?"

RDP uses built-in tools (no malware required), provides full graphical access, is encrypted (making inspection difficult), and is legitimately used by administrators - making it hard to distinguish malicious use from legitimate use without behavioral analytics.

"How do you defend against credential-based attacks?"

Enforce MFA everywhere (especially on VPN and RDP), implement network segmentation to block east-west SMB/RDP traffic, monitor for impossible travel and brute force patterns, deploy dark web monitoring for credential exposure, and implement least-privilege access controls.


10. Lab Task Summary and MITRE Mapping
Task 1: Create a Macro (Phishing with Macros)
Objective: Create a VBA macro in Microsoft Word that downloads and executes a Meterpreter payload.

Phase
Technique
MITRE ID
Initial Access
Spearphishing Attachment
T1566.001
Execution
Command and Scripting Interpreter: Visual Basic
T1059.005
Execution
Command and Scripting Interpreter: Windows Command Shell
T1059.003
Execution
Command and Scripting Interpreter: PowerShell
T1059.001
Credential Access
Steal Web Session Cookie (via Meterpreter)
T1539
Lateral Movement
Remote Services: SMB/Windows Admin Shares
T1021.002


Initial Access Context: The macro-enabled document is the initial access vector. The user opens the document, enables macros, and the macro executes. This is the point at which the attacker transitions from outside the network to inside, with a foothold on the user's workstation.
Task 2: Backdoor an EXE
Objective: Add a Meterpreter backdoor to a legitimate Windows executable.

Phase
Technique
MITRE ID
Resource Development
Develop Capabilities
T1587.001
Initial Access
Supply Chain Compromise
T1195.002
Execution
User Execution: Malicious File
T1204.002
Defense Evasion
subvert Trust Controls
T1553


Initial Access Context: The backdoored executable is delivered to the target (via phishing email, shared drive, or social engineering). When the user runs it, both the legitimate application and the backdoor execute. This provides the attacker with initial access to the user's system.
Task 3: Stolen Credentials with PSExec
Objective: Use PSExec with stolen credentials to gain a Meterpreter session on the Windows 10 VM.

Phase
Technique
MITRE ID
Credential Access
Valid Accounts: Local Accounts
T1078.003
Lateral Movement
Remote Services: SMB/Windows Admin Shares
T1021.002
Lateral Movement
System Services: Service Execution
T1569.002


Initial Access Context: PSExec is Lateral Movement, not Initial Access. The attacker must already have valid credentials and network access to the target's SMB port. In the lab, this simulates an attacker who has already compromised credentials (through phishing, credential theft, or social engineering) and is now expanding their access within the network. The poorly configured firewall (disabled or allowing inbound SMB) enables this lateral movement.
Task 4: RDP as Initial Access
Objective: Use stolen credentials to log into the Windows 10 system via RDP.

Phase
Technique
MITRE ID
Initial Access
Valid Accounts
T1078
Initial Access
External Remote Services
T1133
Initial Access
Remote Desktop Protocol
T1021.001


Initial Access Context: This is a true Initial Access technique. The attacker uses stolen credentials to establish an RDP session from outside the network (or from a different network segment) directly into the target system. This is one of the most common initial access methods observed in real-world incidents.
Task 5: PSExec Login
Objective: Use Metasploit's PSExec module to gain access using stolen credentials.

Phase
Technique
MITRE ID
Lateral Movement
Remote Services: SMB/Windows Admin Shares
T1021.002
Lateral Movement
System Services: Service Execution
T1569.002
Lateral Movement
Lateral Tool Transfer
T1570


Initial Access Context: Like Task 3, this is Lateral Movement. The registry modification (LocalAccountTokenFilterPolicy) and firewall disable are common real-world misconfigurations that enable PSExec-based lateral movement. The lab demonstrates why proper network segmentation and firewall configuration are critical defenses.


11. References
MITRE ATT&CK Framework
T1566 - Phishing: https://attack.mitre.org/techniques/T1566/
T1566.001 - Spearphishing Attachment: https://attack.mitre.org/techniques/T1566/001/
T1078 - Valid Accounts: https://attack.mitre.org/techniques/T1078/
T1021.001 - Remote Desktop Protocol: https://attack.mitre.org/techniques/T1021/001/
T1021.002 - SMB/Windows Admin Shares: https://attack.mitre.org/techniques/T1021/002/
T1059.005 - Visual Basic: https://attack.mitre.org/techniques/T1059/005/
T1059.001 - PowerShell: https://attack.mitre.org/techniques/T1059/001/
T1059.003 - Windows Command Shell: https://attack.mitre.org/techniques/T1059/003/
T1047 - Windows Management Instrumentation: https://attack.mitre.org/techniques/T1047/
T1105 - Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/
T1550 - Use Alternative Authentication Material: https://attack.mitre.org/techniques/T1550/
T1195.002 - Supply Chain Compromise: Software Supply Chain: https://attack.mitre.org/techniques/T1195/002/
S0029 - PsExec: https://attack.mitre.org/software/S0029/
T1598 - Phishing for Information: https://attack.mitre.org/techniques/T1598/
Threat Intelligence Reports
Mandiant/Google Threat Intelligence Group - "Financially Motivated Threat Actor BREEZE COMET Targets Brazil" (September 2026): https://cloud.google.com/blog/topics/threat-intelligence/financially-motivated-threat-actor-breeze-comet-targets-brazil
Google Threat Intelligence Group - "UNC6671 Multi-Brand Vishing Extortion" (August 2026): https://cloud.google.com/blog/topics/threat-intelligence/unc6671-targets-financial-services-and-enterprise-cloud-environments
Microsoft Threat Intelligence - "Impersonating IT Support: Threat Actors Turn Remote Session into Enterprise-Wide Access" (September 2026): https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/
CrowdStrike - "2026 Threat Hunting Report" (August 2026): https://www.crowdstrike.com/en-us/blog/crowdstrike-2026-threat-hunting-report/
Mandiant - "M-Trends 2026" (March 2026): https://cloud.google.com/security/resources/m-trends
Detection and Defense Resources
LOLBAS Project - Living Off The Land Binaries, Scripts, and Libraries: https://lolbas-project.github.io/
Sigma Detection Rules - Community detection rules: https://github.com/SigmaHQ/sigma
SwiftOnSecurity Sysmon Configuration: https://github.com/SwiftOnSecurity/sysmon-config
Microsoft - Disable VBA macros in Office (Mark of the Web): https://learn.microsoft.com/en-us/deployoffice/privacy/office-preferences-for-end-users
Penetration Testing Resources
OffSec - Metasploit Unleashed: Backdooring EXE Files: https://www.offsec.com/metasploit-unleashed/backdooring-exe-files/
PortableApps - Download applications for backdooring practice: https://portableapps.com/

