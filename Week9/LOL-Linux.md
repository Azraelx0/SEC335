# Living Off the Land on Linux - Host Enumeration

Output of running `./enum-script.sh`:

<img width="1946" height="337" alt="image" src="https://github.com/user-attachments/assets/33c404b2-91b6-4922-8f08-5142e841af93" />
# Living Off the Land on Linux - Host Enumeration

**Lab Environment:** Kali Linux container VM (192.168.3.205)
**User:** Standard lab user, with sudo used only where noted

All enumeration output was saved to `/tmp/enumeration/` using the naming scheme `NN_name.txt`. The script `host_enum.sh` runs every command in order. Commands that required elevation are marked in each entry.

---

## Task 1: Enumeration Commands

### 1. Current user, groups, and privileges

**Command:**

`id`

**Output file:** `01_user_id.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

The output lists the current user name, the numeric UID and GID, and every supplementary group the account belongs to. An attacker checks group membership first. Membership in the sudo group, or wheel and adm on other distributions, means privilege escalation may be simple. Membership in docker or lxd is effectively equal to root because those groups can mount the host filesystem. If the UID is 0 the attacker already has full control and no escalation is needed.

**MITRE ATT&CK:** T1033 (System Owner/User Discovery), T1087.001 (Account Discovery: Local Accounts)

---

### 2. Running processes

**Command:**

`ps aux`

**Output file:** `02_processes.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This shows every running process with the user that owns it and the full command line. An attacker reads the command lines to find passwords or tokens that were passed as arguments, to identify service accounts, and to spot high value targets like databases and web applications. The process list also reveals whether any security or backup agent is running, which tells the attacker how careful they need to be.

**MITRE ATT&CK:** T1057 (Process Discovery)

---

### 3. Open network sockets and connections

**Command:**

`ss -tulpan`

**Output file:** `03_sockets.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This lists listening and established TCP and UDP sockets along with the owning process. Ports bound only to 127.0.0.1 are reachable only after a foothold is gained, which makes them prime targets for lateral movement. Established connections show which other hosts this machine talks to, mapping out trust relationships the attacker can abuse.

**MITRE ATT&CK:** T1049 (System Network Connections Discovery)

---

### 4. Running services

**Command:**

`systemctl list-units --type=service --state=running`

**Output file:** `04_services.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This shows which services are active. The list exposes the software stack running on the host and points to candidate targets for exploitation and persistence. A service whose unit file or referenced script is writable by the attacker can be modified to run code as root.

**MITRE ATT&CK:** T1007 (System Service Discovery)

---

### 5. All local user accounts

**Command:**

`cat /etc/passwd`

**Output file:** `05_users.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This file lists every account with its UID, home directory, and login shell. Accounts with a UID of 1000 or higher are usually real human users and make good targets. A shell of /bin/bash means the account can log in, while /usr/sbin/nologin means it cannot. The home directory paths tell the attacker where to look for keys, history files, and stored credentials.

**MITRE ATT&CK:** T1087.001 (Account Discovery: Local Accounts)

---

### 6. All local groups

**Command:**

`cat /etc/group`

**Output file:** `06_groups.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This shows every group and its members. The attacker looks for powerful groups such as sudo, docker, adm, and lxd. Membership in several of these is a direct path to root. This file also reveals the overall structure of who has access to what on the system.

**MITRE ATT&CK:** T1069.001 (Permission Groups Discovery: Local Groups)

---

### 7. Users in the sudo (administrators) group

**Command:**

`getent group sudo`

**Output file:** `07_sudo_group.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This prints the exact list of accounts that belong to the sudo group. These are the administrator accounts worth targeting with password guessing, phishing, or credential theft because compromising any one of them grants root level access.

**MITRE ATT&CK:** T1069.001 (Permission Groups Discovery: Local Groups)

---

### 8. Network configuration (IP, gateway, DNS)

**Command:**

`ip addr`

**Output file:** `08_network_config.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This shows the network interfaces and their assigned IP addresses. Combined with the routing table and DNS settings, it gives the attacker a map of the internal network, the subnets in use, and the default gateway. A host with more than one interface may bridge two networks, which is valuable for pivoting deeper into the environment.

**MITRE ATT&CK:** T1016 (System Network Configuration Discovery)

---

### 9. Firewall policies

**Command:**

`sudo iptables -L -n -v`

**Output file:** `09_firewall.txt`

**Required sudo:** Yes

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This shows the firewall rules and the default policy for inbound and outbound traffic. The attacker learns what is blocked and what is allowed, which helps them find open paths for command and control traffic or data exfiltration. If there is no outbound filtering, data can leave the host freely.

**MITRE ATT&CK:** T1016 (System Network Configuration Discovery)

---

### 10. ARP table

**Command:**

`ip neigh`

**Output file:** `10_arp.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

The ARP or neighbor cache lists other hosts on the local network that this machine has recently talked to. This gives the attacker live targets for lateral movement without running a noisy network scan that could trigger detection.

**MITRE ATT&CK:** T1018 (Remote System Discovery)

---

### 11. SMB sessions

**Command:**

`sudo smbstatus`

**Output file:** `11_smb_sessions.txt`

**Required sudo:** Yes

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This shows active SMB sessions, connected users, and shared resources. It reveals file sharing relationships and which credentials are in use, which supports lateral movement. On this Kali host no SMB server is running, so an empty result is itself a finding that tells the attacker file sharing is not available here.

**MITRE ATT&CK:** T1049 (System Network Connections Discovery), T1135 (Network Share Discovery)

---

### 12. System information

**Command:**

`uname -a`

**Output file:** `12_system_info.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This prints the kernel name, version, architecture, and hostname. The kernel version is one of the most useful pieces of information for an attacker because it maps directly to known local privilege escalation vulnerabilities. The architecture tells them which compiled exploits will run on the host.

**MITRE ATT&CK:** T1082 (System Information Discovery)

---

### 13. Sudo privileges granted to the current account

**Command:**

`sudo -l`

**Output file:** `13_sudo_privileges.txt`

**Required sudo:** Yes

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This lists exactly which commands the current account may run through sudo and whether any of them are set to NOPASSWD. A NOPASSWD entry, or a command that can spawn a shell, is often an instant path to root. This is one of the first checks an attacker runs after gaining a foothold.

**MITRE ATT&CK:** T1069.001 (Permission Groups Discovery: Local Groups), T1033 (System Owner/User Discovery)

---

### 14. Logged-in users, active sessions, and login history

**Command:**

`last -a`

**Output file:** `14_sessions.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This shows a history of logins, including the user, the time, and the source address. The attacker uses this to learn normal login patterns, to blend in with regular activity, and to identify which source IP addresses administrators use. On a fresh VM this list may be short.

**MITRE ATT&CK:** T1033 (System Owner/User Discovery), T1087 (Account Discovery)

---

### 15. Shell command history left behind by local users

**Command:**

`cat ~/.bash_history`

**Output file:** `15_shell_history.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

The shell history records commands that users have typed. These often contain plaintext passwords, API tokens, database connection strings, and internal hostnames. Reading other users and root history files can hand the attacker working credentials with no cracking required. The current session is not written to the file until logout, so a fresh account may show little.

**MITRE ATT&CK:** T1552.003 (Unsecured Credentials: Bash History)

---

### 16. Environment variables of the current shell and running processes

**Command:**

`env`

**Output file:** `16_environment.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

Environment variables can hold secrets that applications need at runtime, such as API keys, database passwords, and tokens. Reading the environment of the current shell and of running processes under /proc can expose these secrets directly.

**MITRE ATT&CK:** T1082 (System Information Discovery), T1552.001 (Unsecured Credentials: Credentials In Files)

---

### 17. SUID and SGID binaries on the filesystem

**Command:**

`find / -perm -4000 -type f 2>/dev/null`

**Output file:** `17_suid_sgid.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This finds binaries that run with the privileges of their owner rather than the user who runs them. A setuid root binary that is not standard, or one listed on GTFOBins, can often be abused to gain a root shell. This is a core privilege escalation check.

**MITRE ATT&CK:** T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid)

---

### 18. File capabilities assigned to installed binaries

**Command:**

`getcap -r / 2>/dev/null`

**Output file:** `18_capabilities.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This lists binaries that carry Linux capabilities. Capabilities such as cap_setuid or cap_dac_read_search grant root level powers without the setuid bit being set, which means they are easy for defenders to miss. An attacker can abuse these to escalate privileges or read protected files.

**MITRE ATT&CK:** T1548 (Abuse Elevation Control Mechanism)

---

### 19. Scheduled tasks: cron jobs and systemd timers

**Command:**

`cat /etc/crontab`

**Output file:** `19_scheduled_tasks.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This shows scheduled jobs and the accounts they run as. A job that runs as root and calls a script the attacker can write to is a reliable method for both privilege escalation and persistence. Systemd timers serve the same purpose and should be checked as well.

**MITRE ATT&CK:** T1053.003 (Scheduled Task/Job: Cron)

---

### 20. Installed security tools and EDR agents

**Command:**

`ps aux | grep -Ei 'clamav|auditd|falcon|crowdstrike|wazuh|ossec'`

**Output file:** `20_security_tools.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This checks whether any antivirus, audit, or endpoint detection agent is running. The result shapes how stealthy the attacker must be. On this Kali host the grep returns nothing, which is itself the finding. No EDR is running, so the attacker can act with less concern about detection.

**MITRE ATT&CK:** T1518.001 (Software Discovery: Security Software Discovery)

---

### 21. Installed software package inventory

**Command:**

`dpkg -l`

**Output file:** `21_packages.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This lists every installed package and its version. The attacker scans for versions with known vulnerabilities and for useful tools already present on the host, such as compilers and interpreters that help with exploitation.

**MITRE ATT&CK:** T1518 (Software Discovery)

---

### 22. Kernel version and build information

**Command:**

`uname -r`

**Output file:** `22_kernel.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This prints the exact kernel release. The attacker matches this version against public kernel exploits to find a precise local privilege escalation that works against this host.

**MITRE ATT&CK:** T1082 (System Information Discovery)

---

### 23. Mounted filesystems and free disk space

**Command:**

`df -h`

**Output file:** `23_mounts_disk.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This shows mounted filesystems and how much space is free. The attacker learns where data is stored, whether network shares or removable media are mounted, and where there is room to stage stolen data before exfiltration.

**MITRE ATT&CK:** T1082 (System Information Discovery), T1083 (File and Directory Discovery)

---

### 24. SSH keys, authorized_keys files, and SSH configuration

**Command:**

`cat /etc/ssh/sshd_config`

**Output file:** `24_ssh.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

The SSH server configuration reveals weaknesses such as whether root login is permitted and whether password authentication is allowed. Private keys and authorized_keys files reveal trust relationships, showing which keys grant access to which hosts. Stolen private keys let the attacker move to other systems without a password.

**MITRE ATT&CK:** T1552.004 (Unsecured Credentials: Private Keys), T1021.004 (Remote Services: SSH)

---

### 25. Password hash store permissions and readability

**Command:**

`ls -l /etc/shadow`

**Output file:** `25_shadow.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This checks the permissions on the shadow file, which stores password hashes. The file should be readable only by root. If a misconfiguration makes it readable by a normal user, the attacker can copy every password hash and crack them offline at their leisure.

**MITRE ATT&CK:** T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow)

---

### 26. Authentication events and failed login attempts

**Command:**

`sudo lastb`

**Output file:** `26_auth_events.txt`

**Required sudo:** Yes

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This shows failed login attempts recorded by the system. The attacker learns which accounts are being targeted, which source addresses are attacking, and whether their own attempts are being logged. Patterns of failed logins can also hint at weak accounts under active guessing.

**MITRE ATT&CK:** T1087 (Account Discovery), T1033 (System Owner/User Discovery)

---

### 27. Running containers and container runtime socket permissions

**Command:**

`docker ps`

**Output file:** `27_containers.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This lists running containers. The permissions on the docker socket matter a great deal. If a normal user can reach the docker socket, or belongs to the docker group, they can start a container that mounts the host filesystem and gain root. On this host the daemon may not be running, which the output will show.

**MITRE ATT&CK:** T1613 (Container and Resource Discovery)

---

### 28. SELinux or AppArmor status

**Command:**

`aa-status`

**Output file:** `28_mac.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

Kali uses AppArmor rather than SELinux. This command shows whether AppArmor is loaded and which profiles are enforcing. A mandatory access control layer that is disabled or in complain mode removes a major barrier that would otherwise contain a compromised process.

**MITRE ATT&CK:** T1518.001 (Software Discovery: Security Software Discovery)

---

### 29. Exported NFS / network file shares

**Command:**

`cat /etc/exports`

**Output file:** `29_nfs.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This file defines which directories are shared over NFS and with what options. A share exported with no_root_squash and write access is a classic path to root and to data theft. On this host the file may not exist, which shows that NFS is not configured.

**MITRE ATT&CK:** T1135 (Network Share Discovery)

---

### 30. Hostname, FQDN, and configured domain membership

**Command:**

`hostname -f`

**Output file:** `30_hostname_domain.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This prints the fully qualified domain name. The name can reveal whether the host is joined to a domain and can hint at the role of the machine and the structure of the wider environment, which helps the attacker plan where to pivot next.

**MITRE ATT&CK:** T1082 (System Information Discovery), T1016 (System Network Configuration Discovery)

---

### 31. World-writable files and directories in system locations

**Command:**

`find / -perm -0002 -type f 2>/dev/null`

**Output file:** `31_world_writable.txt`

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This finds files that any user can write to. A world-writable script or config that is run by root, for example from a cron job or a service, is a direct route to escalation and persistence because the attacker can insert their own commands.

**MITRE ATT&CK:** T1083 (File and Directory Discovery)

---

### 32. Files opened by running processes, including deleted-but-still-open files

**Command:**

`sudo lsof +L1`

**Output file:** `32_open_files.txt`

**Required sudo:** Yes

**Screenshot:**

*(paste screenshot here)*

**What the Output Reveals to an attacker:**

This lists files that processes hold open but that have been deleted from disk. Programs sometimes keep logs, temporary secrets, or hidden data in deleted-but-open files to avoid leaving them on the filesystem. An attacker can recover this content straight from the open file handle.

**MITRE ATT&CK:** T1057 (Process Discovery), T1083 (File and Directory Discovery)

---

## Additional Research: 5 LOLBin Commands

### 1. getent passwd

**Command:** `getent passwd`

**What it gathers:** This enumerates user accounts from every configured name service source, not just /etc/passwd. That includes LDAP, SSSD with Active Directory, and NIS.

**Why an attacker wants it:** On a domain joined host this reveals directory users that reading /etc/passwd alone would miss. It gives the attacker the real list of accounts to target for password spraying and credential theft.

**MITRE ATT&CK:** T1087 (Account Discovery)

---

### 2. find / -mtime -2 -type f 2>/dev/null

**Command:** `find / -mtime -2 -type f 2>/dev/null`

**What it gathers:** This locates files modified in the last two days. The find binary can also run commands with its -exec flag.

**Why an attacker wants it:** Recently changed files often include fresh config, dropped credentials, and deployment artifacts worth stealing. The time filter also helps the attacker see what changed around the time of their intrusion. If find is setuid or allowed through sudo, its -exec feature becomes a root shell.

**MITRE ATT&CK:** T1083 (File and Directory Discovery), T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid)

---

### 3. strings

**Command:** `strings /path/to/file`

**What it gathers:** This prints readable text found inside binary files such as compiled programs, core dumps, and log files.

**Why an attacker wants it:** Hardcoded passwords, API keys, and connection strings are often buried inside compiled service binaries and crash dumps. The strings command pulls them out with no debugger and no special tooling required.

**MITRE ATT&CK:** T1552 (Unsecured Credentials)

---

### 4. awk

**Command:** `awk '{print}' /etc/passwd`

**What it gathers:** The awk tool reads and processes any file the caller can access. It can also spawn a shell with its system function.

**Why an attacker wants it:** It reads files quietly without using cat, and if it carries setuid rights or is allowed through sudo it can be used to run a shell and escalate privileges. Because awk is installed everywhere and is less watched than a direct shell call, it is a handy and low profile tool.

**MITRE ATT&CK:** T1059.004 (Command and Scripting Interpreter: Unix Shell), T1083 (File and Directory Discovery)

---

### 5. curl

**Command:** `curl -s http://target/resource`

**What it gathers:** This transfers data over HTTP and HTTPS. It can download files and send data to a remote server.

**Why an attacker wants it:** curl ships on nearly every Linux host, so there is no need to upload a custom downloader. The attacker uses it to pull second stage tools onto the host, to send stolen data out to their own server, and to probe internal only services once a foothold exists.

**MITRE ATT&CK:** T1105 (Ingress Tool Transfer), T1048 (Exfiltration Over Alternative Protocol)

---

## Compression

All output files in /tmp/enumeration were compressed into one archive using each of the four tools. A screenshot of each tool creating its archive is included below.

### tar with gzip

**Command:** `tar -czvf /tmp/enum_tar.tar.gz -C /tmp enumeration`

**Screenshot:**

*(paste screenshot here)*

### gzip

**Command:** `tar -cvf /tmp/enum_gzip.tar -C /tmp enumeration && gzip -v /tmp/enum_gzip.tar`

Note: gzip compresses single files, so the directory is placed into a tar archive first and then gzip compresses that single tar file.

**Screenshot:**

*(paste screenshot here)*

### zip

**Command:** `zip -r /tmp/enum.zip /tmp/enumeration`

**Screenshot:**

*(paste screenshot here)*

### 7z

**Command:** `7z a /tmp/enum.7z /tmp/enumeration`

**Screenshot:**

*(paste screenshot here)*

---

## Summary of Commands Requiring sudo

The following commands required elevation to produce full output: iptables (9), smbstatus (11), sudo -l (13), lastb (26), and lsof +L1 (32). All other commands ran as the standard lab user.
