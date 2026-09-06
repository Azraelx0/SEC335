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
change execution policy

<img width="996" height="126" alt="image" src="https://github.com/user-attachments/assets/23a02ae1-22cf-498e-8b47-c104387893e2" />

#### Screenshot Deliverables
Screenshot of WinPEAS banner and initial execution

Screenshot of the color-coded output summary

Output file saved as winpeas_output_[yourname].txt

Document the command(s) used to run WinPEAS in your Tech Journal
```.\winPEAS.ps1```
#### Questions to Answer:
What hash algorithm does WinPEAS use for verification? What is the file hash?

What does the RED/YELLOW/GREEN color coding indicate?

How long did the full scan take? What factors affect scan duration?
