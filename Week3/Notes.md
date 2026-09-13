# Living Off the Land Binaries (LOLBins): Notes

## 1. What Are LOLBins and Why Attackers Use Them

LOLBins are legitimate Windows executables that ship with the OS and are signed by Microsoft. Attackers abuse them because they're already installed everywhere, carry a trusted signature, and get used by admins all the time, so malicious activity hides inside normal system noise.

The name comes from guerrilla warfare: fighters who use the terrain and local resources instead of bringing their own supplies. Same idea here, attackers use what's already on the box instead of dropping custom malware.

**Why LOLBins beat custom malware, from an attacker's perspective:**

- **AV/EDR evasion**: signed Microsoft binaries often sail through allowlists. Tools like `certutil.exe` or `rundll32.exe` rarely get flagged since they're normal admin tools (maps to MITRE ATT&CK T1218, System Binary Proxy Execution).
- **Smaller forensic footprint**: custom malware leaves files behind. LOLBin abuse can be fileless, or it writes to weird spots like NTFS Alternate Data Streams instead of the usual locations.
- **Blends in**: hundreds of legit processes run on any given Windows box. Seeing `powershell.exe`, `msbuild.exe`, or `wmic.exe` in logs looks routine unless you know the context and baseline.
- **No dev overhead**: nothing to write, compile, test, or maintain. Microsoft does that for you via Windows Update.
- **Works everywhere**: an attack chain built on `certutil.exe` and `rundll32.exe` runs the same on Windows 7 through 11.

State-sponsored groups, Volt Typhoon being a notable example, have leaned heavily on LOLBin techniques to get into and stay inside US critical infrastructure networks, per joint advisories from ACSC and NSA.

## 2. How LOLBins Slip Past Sensors: net.exe vs net1.exe

This pair is a good illustration of the evasion logic.

**The delegation pattern**: when you run `net.exe` commands (`net user`, `net group`, `net localgroup`), Windows often hands the real work off to `net1.exe`, sitting at `C:\Windows\System32\net1.exe`.

- `net.exe` is what shows up in logs and monitoring.
- `net1.exe` is what actually does the work under the hood.

A lot of security tooling watches for `net.exe` but doesn't catch `net1.exe`. So an attacker who knows this can call `net1.exe` directly and dodge detection rules that were only ever written for the parent binary, while still running with the same privileges.

This delegation pattern isn't unique to `net.exe`. Plenty of Windows binaries have helper executables, DLLs, or scripts doing the actual work behind the scenes. Understanding these chains matters for attackers and defenders alike.

**Other evasion angles:**

- **Legit-looking parent/child relationships**: `cmd.exe` spawning `certutil.exe` looks like normal command line use. Many EDRs struggle to tell certificate management apart from a malicious file download.
- **Trust in signed binaries**: Defender and other AV tools may give Microsoft-signed binaries a pass, reducing scrutiny.
- **Network anomalies get missed**: tools like `bitsadmin.exe` and `certutil.exe` use standard HTTP/HTTPS, so their traffic can blend into normal Windows Update or cert validation traffic and skip firewall rules.

## 3. Detecting LOLBin Abuse

Being a LOLBin doesn't make a binary undetectable. There are real signals to catch.

### 3.1 What tips off an admin who knows their environment

- **Unusual execution context**: `msbuild.exe` running on a workstation with no .NET dev tools is a red flag. `certutil.exe` reaching out to unfamiliar domains is worth a look.
- **Unexpected child processes**: `rundll32.exe` spawning `cmd.exe` which then kicks off PowerShell is an odd process tree.
- **Time-of-day oddities**: `wmic.exe` firing on a domain controller at 3 AM with nobody on-site is suspicious.

### 3.2 The catch: legit tools use these binaries too

- SCCM/ConfigMgr uses `msbuild.exe` to build deployment packages.
- Windows Update uses `bitsadmin.exe` for background transfers.
- Group Policy processing relies on `gpupdate.exe` and friends.
- Software installs routinely touch `msiexec.exe`, `regsvr32.exe`, and `rundll32.exe`.

This means you have to baseline normal usage first. A good detection setup doesn't alert on every `msbuild.exe` run, it alerts when the run deviates from what's normal for that environment.

### 3.3 Detection strategies that actually work

| Strategy | How it works |
|---|---|
| Process command-line logging | Windows Event ID 4688 (with command-line auditing on) captures full command lines, including flags like `certutil.exe -urlcache -f` |
| Sysmon (Event IDs 1, 3, 7, 8, 10, 11) | Covers process creation, network connections, image loads, CreateRemoteThread, process access, and file creation |
| Sigma rules | Community rules (SigmaHQ) that port across SIEM platforms |
| Application allowlisting | WDAC or AppLocker can restrict which binaries run, even legitimate ones |
| Behavioral analysis | EDR looking at process trees, network behavior, and filesystem activity instead of signatures |
| Network monitoring | Proxy logs catching odd user agents (`Microsoft-CryptoAPI/10.0`, `CertUtil URL Agent`) or connections to unusual domains |

## 4. Common Enumeration LOLBins

| Binary | Legitimate purpose | Enumeration abuse |
|---|---|---|
| `whoami.exe` | Show current user context | User identity, privileges, group membership, SID (T1033) |
| `ipconfig.exe` | Show network config | Network topology, DNS servers, domain info (T1016) |
| `systeminfo.exe` | Show system config | OS version, patches, hardware, hotfixes (T1082) |
| `net.exe` / `net1.exe` | Network administration | User/group enumeration, shares, accounts, sessions (T1069) |
| `wmic.exe` | WMI command-line interface | Process listing, installed software, OS queries, service enum (T1047) |
| `tasklist.exe` | Show running processes | ID'ing security tools and AV processes (T1057) |
| `nltest.exe` | Domain trust enumeration | Domain controllers, trust relationships (T1482) |
| `dsquery.exe` | AD queries | User/computer/group enumeration in AD (T1087.002) |
| `cmdkey.exe` | Credential management | Stored credential enumeration (T1552.001) |
| `set.exe` | Show environment variables | User profile paths, system config (T1082) |
| `arp.exe` | Show ARP cache | Network neighbors, lateral movement targets (T1018) |
| `wevtutil.exe` | Event log management | Log enumeration and clearing (T1070) |

**Most valuable for lateral movement?** `nltest.exe` or `dsquery.exe`, since they expose domain trust relationships and AD structure, which is exactly the map an attacker needs to move from a workstation toward a domain controller.

**Most suspicious to see run?** `nltest.exe /dclist:` or `dsquery` output, because domain admins rarely type these interactively on a regular workstation. They tend to show up from admin workstations or jump boxes.

**Why prefer `wmic.exe` over PowerShell?**

- `wmic.exe` predates PowerShell and runs even where PowerShell execution policy is locked down.
- PowerShell script block logging can capture and analyze commands in detail; `wmic.exe` often isn't watched as closely, especially in older environments.
- It queries WMI directly without PowerShell runtime overhead.
- Some allowlisting policies exempt it since it's considered a core Windows component.

## 5. Interview-Ready Summary

### Original use vs. malicious use

| Binary | Legitimate use | Malicious use |
|---|---|---|
| `certutil.exe` | Certificate management, encode/decode | File download, payload decode, ADS storage |
| `mshta.exe` | Run .HTA applications | Remote script execution, fileless code execution |
| `rundll32.exe` | Load DLLs for applications | Execute remote DLLs, JScript, COM objects |
| `bitsadmin.exe` | Background file transfers (Windows Update) | Stealthy file download via BITS |
| `msbuild.exe` | .NET project compilation | Inline C# execution, AppLocker bypass |
| `regsvr32.exe` | Register/unregister DLLs and OCX controls | Remote COM scriptlet execution ("Squiblydoo") |
| `wmic.exe` | WMI command-line management | Process creation, remote execution, XSL execution |
| `msiexec.exe` | Install MSI packages | Run MSI files from a remote URL |

### Likely interview questions

**What is a LOLBin?**
A legitimate Windows binary that attackers repurpose to run code, enumerate a host, or dump credentials while blending into normal activity.

**Name three LOLBins used for file download.**
`certutil.exe`, `bitsadmin.exe`, `mshta.exe`, plus `msedge.exe`, `expand.exe`, and `esentutl.exe` as backups.

**How would you detect `certutil.exe` being used to download files?**
Watch command-line logs (Event ID 4688) for `-urlcache` or `-verifyctl` flags, flag outbound connections coming from `certutil.exe`, look for the `Microsoft-CryptoAPI/10.0` or `CertUtil URL Agent` user agent strings, and lean on SigmaHQ rules.

**Can you just block all LOLBins?**
No. They're required for normal Windows operation. The answer is baselining normal use and alerting on deviation, not outright blocking.

## 6. Frequency Analysis for Spotting LOLBin Abuse

A statistical approach: build a baseline of normal execution frequency, then alert on deviations from it.

**Baseline collection** (typically 30 to 90 days), logging for each LOLBin execution:
- Binary name
- Command-line arguments
- Time of execution
- Parent process
- User account
- Source IP / workstation

**What to calculate:**
- Daily/weekly execution counts per binary
- Which users typically run it (devs vs. help desk vs. service accounts)
- What normally spawns it (Explorer.exe, svchost.exe, etc.)
- When it typically runs

**Anomalies worth flagging:**
- A sudden spike in `certutil.exe` runs from a workstation that's never used it
- `msbuild.exe` firing at 2 AM from a service account with no prior history of it
- `rundll32.exe` making its first-ever outbound connection
- A user running `nltest.exe` for the first time, especially domain trust enumeration

**Threshold examples:**
- `certutil.exe` normally runs 3x/day on a server, jumps to 50, that's an alert.
- `bitsadmin.exe` has never run on a workstation, suddenly creates a BITS job, alert.
- `wmic.exe` invoked with `/node:` targeting multiple remote hosts, alert (lateral movement signal).

**Why this approach works well for LOLBins:**
- Rare binaries (`mshta.exe`, `certutil.exe -urlcache`) have a low false-positive rate since legitimate use is already scarce in a lot of environments.
- Attack chains create noticeable bursts: a rapid `whoami` to `ipconfig` to `systeminfo` to `net user` to `nltest` sequence stands out statistically.
- Legitimate usage tends to spread across business hours, while abuse tends to cluster in tight bursts during active attack phases.

## 7. References

**MITRE ATT&CK**
- [T1218, System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
- [T1218.010, Regsvr32](https://attack.mitre.org/techniques/T1218/010/)
- [T1059, Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [T1059.001, PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1105, Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [T1033, System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)

**LOLBAS Project**
- [Main site](https://lolbas-project.github.io/)
- [Certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
- [Mshta](https://lolbas-project.github.io/lolbas/Binaries/Mshta/)
- [Rundll32](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/)
- [Bitsadmin](https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/)
- [Regsvr32](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/)
- [Msbuild](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/)

**Government advisories**
- ACSC advisory on PRC state-sponsored actors and US critical infrastructure. Note: the original URL returned a 404 at verification time; the advisory is referenced in Microsoft's Volt Typhoon documentation and available in archived form.
- NSA/CISA joint advisory, "Living off the Land: Reducing the Impact of Environment-Framing Techniques" (May 2023). Note: the original PDF link returned a 403 at verification time; the content is referenced across multiple CISA/NSA publications.

**Detection tooling**
- [SigmaHQ rules](https://github.com/SigmaHQ/sigma)
- [SwiftOnSecurity Sysmon config](https://github.com/SwiftOnSecurity/sysmon-config)
