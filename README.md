# SEC335: Ethical Hacking

Writeups, scripts, and notes from an offensive security course that follows the attack lifecycle from start to finish: enumeration, privilege escalation, living off the land, staging and exfiltration, initial access, and web application exploitation. It covers both Windows and Linux targets. Each week's folder has a detailed writeup of the lab and the commands used, sometimes includes other items.

Course in progress.

Techniques are mapped to **MITRE ATT&CK** where it applies.

## Contents

| Week | Topic | Highlights |
|---|---|---|
| [Week 1](./Week1) | Course Intro & LOLBins Primer | LOLBAS / GTFOBins, `net.exe` vs `net1.exe` detection evasion |
| [Week 2](./Week2) | Windows Local Privilege Escalation | WinPEAS enumeration, interpreting output, common escalation paths and remediation |
| [Week 3](./Week3) | Living Off the Land Binaries | Executing LOLBins from real threat advisories, mapping abuse to ATT&CK (e.g. T1218) |
| [Week 4](./Week4) | Data Staging & Exfiltration | Scripted host enumeration with LOLBins (`enum.bat`), compression/staging, exfil over a custom SMTP server (`smtp_server.py`) |
| [Week 5](./Week5) | Initial Access & Execution | Macro-based phishing payload, `msfvenom` Meterpreter delivery, Metasploit handler |
| [Week 6](./Week6) | Penetration Test Campaign | Professional-style pentest report chaining it all together: spearphishing macro → Meterpreter foothold → enumeration & staging → exfil → LPE to SYSTEM via weak service binary permissions |
| [Week 7](./Week7) | Linux Privilege Escalation | Foothold over SSH, enumeration, escalation to root |
| Week 8 | Break | — |
| [Week 9](./Week9) | Living Off the Land on Linux | Host enumeration script (`enum_lin.sh`) with 25+ categorized output files |
| [Week 10](./Week10) | Linux Initial Access | Backdoored ELF delivery, tampered Debian package, SSH credential reuse, C2 over an EasyTier mesh |
| [Week 11](./Week11) | Web App Exploitation (eLECTRA) | Full assessment of a vulnerable web app, organized by difficulty phase (below) |

### Week 11: eLECTRA Web Application Assessment

A multi-phase assessment of a deliberately vulnerable utility company web app, done mostly in Burp Suite. See the [Week 11 overview](./Week11/Web-App-Exp&Discovery.md) for the full task index.

- **Recon:** application mapping, info disclosure, reflected XSS
- **Beginner:** SQLi auth bypass, IDOR, file upload → RCE
- **Intermediate:** verbose and blind SQLi (custom extraction script `blind_extract.py`), sqlmap automation, hash cracking, stored XSS, upload filter bypass
- **Advanced:** `.htaccess` hijacking, command injection, CSRF, SQLi write queries
- **Remediation:** fixes for each vector *(in progress)*

## Tools Used

`Metasploit` · `msfvenom` · `Burp Suite` · `sqlmap` · `WinPEAS` · `John the Ripper` · `Impacket` · native LOLBins (Windows & Linux) · Python · Bash · Batch

## Extras

- [Helpful Tools.md](./Helpful%20Tools.md): a running list of tools worth remembering (C2 frameworks, Layer 2 attacks, OSINT)

> All activity was performed in isolated, authorized lab environments provided for coursework.
