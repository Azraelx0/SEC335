# Data Staging and Exfiltration Techniques

## What Staging and Exfiltration Are

- **Data staging** = collecting, organizing, and prepping stolen data before moving it out. Attackers compress files, bundle documents, and sometimes encrypt archives first.
- **Exfiltration** (or "exfil") = the actual transfer of that data to an attacker-controlled system.
- These are the final phase of most attacks, where the attacker actually achieves their goal.

**The attack lifecycle is a chain:** initial access → persistence → discovery → collection → staging → exfiltration. Each step depends on the one before it. You can't exfiltrate what you haven't collected, and you can't collect what you haven't found. Defenders try to break this chain.

### Key MITRE ATT&CK Techniques

- **T1074 – Data Staged:** stage data in a central spot before exfil to reduce connections to C2
- **T1048 – Exfiltration Over Alternative Protocol:** steal data over a different protocol than C2 (FTP, SMTP, DNS, SMB)
- **T1572 – Protocol Tunneling:** hide comms inside another protocol to dodge detection/filtering
- **T1071 – Application Layer Protocol:** blend in with normal app-layer traffic
- **T1041 – Exfiltration Over C2 Channel:** exfil over the existing C2 channel

### Why Attackers Stage First

- **Smaller footprint:** one bundled transfer instead of many = fewer chances to get caught
- **Compression:** smaller files move faster and use less bandwidth (matters with a narrow exfil window)
- **Encryption:** password-protected archives stay safe even if intercepted
- **Organization:** sort data by value (credentials, IP, network maps in separate archives)

Example: Volt Typhoon staged data in password-protected archives; Scattered Spider stages in a centralized database. Both cut down on transfers.

---

## Enumeration: Mapping the Host

Before exfil, attackers figure out what's on the target: processes, network connections, accounts, groups, firewall rules, and config. This tells them what's worth stealing and how they can get it out.

### LOLBins (Living Off the Land Binaries)

- Microsoft-signed executables already on every Windows box.
- Attackers prefer these over custom malware because custom tools leave artifacts (exes, DLLs, config files) that AV/EDR can catch. LOLBins look like normal admin activity.
- The **LOLBAS Project** (lolbas-project.github.io) catalogs 150+ of these mapped to MITRE.
- Context is everything: `ipconfig /all` during a help desk ticket is normal. The same command at 3 AM from a service account that's never run it is suspicious.

### Common Enumeration Commands

- `whoami /priv` – current user privileges (T1033)
- `tasklist` – running processes (T1057)
- `netstat -ano` – open network connections (T1049)
- `sc query` – running services (T1007)
- `net user` / `net localgroup` – local accounts and groups (T1087.001)
- `ipconfig /all` – network config (T1016)
- `netsh advfirewall show allprofiles` – firewall policies (T1518.001)
- `arp -a` – ARP table / network neighbors (T1018)
- `systeminfo` – OS version, patches, architecture (T1082)
- `nltest /dclist:` – domain controllers and trusts (T1482)

Others: `dsquery.exe` (AD queries), `cmdkey.exe` (stored creds), `wevtutil.exe` (event logs), `net sessions` (SMB connections), `wmic.exe` (WMI queries), `whoami /all` (SIDs/privs/groups), `certutil.exe` (certs and config).

The whole point: these tools look like normal admin work because they *are* normal admin tools being abused.

---

## Compression: Prepping Data

Goals are simple: shrink file size, bundle files, and optionally encrypt.

### Windows Native Tools

- **makecab** – creates `.cab` files (used natively for Windows Update). Also a LOLBAS binary (T1564.004).
- **PowerShell Compress-Archive** – creates `.zip` via .NET. Has a `-CompressionLevel` option and a 2GB max size.
- **tar** – on Windows 10+, supports gzip/bzip2/xz, works cross-platform, also a LOLBAS binary.

### Third-Party

- **7-Zip** – multiple formats, AES-256 password protection so contents stay encrypted even if intercepted.

### Why It Matters for Attackers

- Size reduction = faster transfer, shorter exposure
- Bundling = fewer connections
- Password protection = encrypted even if intercepted
- Weird file extensions = may dodge signature detection

Defenders should look at size differences between original and compressed files, the archive format/encryption, and how it was moved.

---

## Exfiltration Methods

### C2 Channel (T1041)

- Uses the existing command-and-control channel (Meterpreter download, Cobalt Strike, custom implants).
- **Pro:** simple, already set up. **Con:** big transfers eat bandwidth and can get flagged by traffic volume.

### Standard Protocols

- **HTTP/HTTPS:** data hidden in POST bodies, cookies, headers. Blends with browsing.
- **FTP:** direct transfer, often allowed.
- **SMB:** file share transfers, hard to block without breaking things.

### Non-Standard Protocols (harder to detect)

These protocols serve essential functions, so firewalls usually let them through.

**ICMP Tunneling**
- Data hidden in the payload of ping packets. Tools like `ptunnel` and `icmpsh`.
- Firewalls allow ICMP for diagnostics and rarely inspect the payload bytes.
- Downside: low bandwidth (small payload per packet), and some networks block ICMP entirely.
- Related real-world: Sandworm used the GOGETTER tunneler; Salt Typhoon made GRE tunnels.

**DNS Tunneling**
- Data encoded in DNS query subdomains (e.g. `SGVsbG8=.evil.com`). Can go both directions.
- DNS is essential and rarely blocked, and most tools don't inspect query content.
- Tools: **dnscat2** (encrypted C2 over DNS) and **iodine** (tunnels IPv4 over DNS, higher performance).
- Used by: APT32 (OceanLotus), APT41, OilRig, Remsec (ProjectSauron).

**SMTP Exfiltration**
- Data sent as email attachments or in the body, often through legit services (Gmail, Outlook, ProtonMail).
- Email is expected outbound traffic, and TLS blocks content inspection.
- Limits: attachment size caps (~25MB) and email filtering.
- Used by: Agent Tesla, Lazarus Group (SierraBravo-Two), Turla (Uroburos).

### Quick Comparison

| Method | Bandwidth | Stealth | Best For |
|--------|-----------|---------|----------|
| C2 Channel | High | Medium | Direct transfer during a session |
| HTTP/HTTPS | High | Medium | Blending with web traffic |
| FTP | High | Low-Med | Bulk theft |
| ICMP | Low | High | Small, slow exfil |
| DNS | Low-Med | High | Stealthy, persistent exfil |
| SMTP | Medium | Medium | Automated email theft |

---

## Real-World Threat Actors

- **APT32 (OceanLotus)** – Vietnam. Encodes stolen data in DNS subdomains via their backdoor.
- **Agent Tesla** – credential stealer. Multi-protocol (SMTP, FTP, HTTP), mostly email.
- **Lazarus Group** – North Korea. SMTP exfil via SierraBravo-Two module.
- **OilRig** – Iran. Separates DNS (for C2) from FTP (for exfil).
- **Wizard Spider (Ryuk)** – Russia. FTP exfil before encrypting, for double extortion.
- **Remsec (ProjectSauron)** – suspected Russia. DNS tunneling plus email against govs and telecoms.

---

## Detection and Defense

### Network-Level

- Inspect ICMP payloads for unusual sizes or encoded data
- Analyze DNS query volume, subdomain length, and entropy
- Watch for protocol anomalies (DNS on odd ports, ICMP with no ping responses)
- Build traffic baselines to spot deviations

### Host-Level

- Watch LOLBin usage (weird arguments or unexpected combos)
- Flag large-scale archive creation followed by network transfer
- Look for odd process parent-child relationships
- Watch for sequential file access followed by compression

### Content Inspection (the big takeaway)

**Inspect payload content, not just protocol headers.**
- DNS: decode subdomain labels to catch encoded data
- ICMP: examine payload bytes, not just headers
- Email: analyze attachments and embedded content

---

## Summary

Staging and exfil are the last steps in an attack. Attackers enumerate with LOLBins to stay hidden, compress data to shrink the footprint, and exfil through channels that blend in. Non-standard protocols (ICMP, DNS, SMTP) are hardest to catch because you can't just block DNS or ICMP without breaking the network. Detection comes down to payload inspection, behavioral baselines, and knowing what normal traffic looks like.

Core MITRE techniques: **T1074** (Data Staged), **T1048** (Exfil Over Alternative Protocol), **T1572** (Protocol Tunneling), **T1071** (Application Layer Protocol), **T1041** (Exfil Over C2).
