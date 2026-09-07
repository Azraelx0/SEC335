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

<img width="837" height="600" alt="image" src="https://github.com/user-attachments/assets/cfbd04f3-9821-487e-abde-94b3bf01353c" />

Screenshot of the color-coded output summary

Output file saved as winpeas_output_[yourname].txt

Document the command(s) used to run WinPEAS in your Tech Journal
```.\winPEAS.ps1 | Tee-Object -FilePath winpeas_output_yourname.txt```
#### Questions to Answer:
What hash algorithm does WinPEAS use for verification? What is the file hash?

What does the RED/YELLOW/GREEN color coding indicate?
Red means that the finding is critical and has a clear privilege escalation path
Yellow means that the finding is a high-priority finding. You should look into this
Green means that the finding is most likely safe or typical

How long did the full scan take? What factors affect scan duration?

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


3. Weak Service Permissions - WeakSvc

4. Weak Registry Permissions - RegSvc

5. DLL Hijacking - DLLHijackSvc

6. Missing Service Binary - MissingBinSvc

7. Writable PATH Directory

8. Startup Folder Permissions

9. Unattend.xml with Credentials

10. Scheduled Task - VulnScheduledTask
