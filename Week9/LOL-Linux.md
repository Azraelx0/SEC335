# Living Off the Land on Linux - Host Enumeration

**Lab Environment:** Kali Linux container VM (192.168.3.205)
**User:** Standard lab user, with sudo used only where noted

All enumeration output was saved to `/tmp/enumeration/` using the naming scheme `##_name.txt`. The script `enu_linm.sh` runs every command in order.

---

## Task 1: Enumeration Commands

### 1. Current user, groups, and privileges

**Command:**

`id`

**Output file:** `01_user_id.txt`

**Screenshot:**

<img width="585" height="67" alt="image" src="https://github.com/user-attachments/assets/a1a05871-b6bd-401e-8fb9-93bcddb488aa" />

**What the Output Reveals to an attacker:**

The output lists the current user name, the numeric UID and GID, and every group the account is in. An attacker would want to check which groups a user might be apart of as membership in the sudo/wheel/adm group, means privilege escalation may be simple. Membership in docker or lxd is basically root because those groups can mount the host filesystem. If the UID is 0 the attacker already has full control and no escalation is needed.

**MITRE ATT&CK:** T1033 (System Owner/User Discovery), T1087.001 (Account Discovery: Local Accounts)

---

### 2. Running processes

**Command:**

`ps aux`

**Output file:** `02_processes.txt`

**Screenshot:**

<img width="1728" height="729" alt="image" src="https://github.com/user-attachments/assets/6345f26c-2f46-4e31-a0de-037fc4953036" />

**What the Output Reveals to an attacker:**

This shows every running process with the user that owns it and the full command line. An attacker reads the command lines to find passwords or tokens that might be visible, to identify service accounts, and to potentially find targets like databases and web apps. The process list also reveals whether any security or backup agent is running.

**MITRE ATT&CK:** T1057 (Process Discovery)

---

### 3. Open network sockets and connections

**Command:**

`ss -tulpan`

**Output file:** `03_sockets.txt`

**Screenshot:**

<img width="692" height="429" alt="image" src="https://github.com/user-attachments/assets/c8c2b2c4-a57e-4d49-813e-6a219fa71928" />

**What the Output Reveals to an attacker:**

This lists listening and established TCP and UDP sockets along with the process owner. Ports on 127.0.0.1 can only be reached after a foothold is gained which makes them targets for lateral movement. Established connections show which other hosts this pc is talking to. This can map out possible trust relationships that the attacker can abuse.

**MITRE ATT&CK:** T1049 (System Network Connections Discovery)

---

### 4. Running services

**Command:**

`systemctl list-units --type=service --state=running`

**Output file:** `04_services.txt`

**Screenshot:**

<img width="826" height="463" alt="image" src="https://github.com/user-attachments/assets/11670ed3-6c45-4f8d-b0d0-949c306ea0e2" />

**What the Output Reveals to an attacker:**

This shows which services are active. The list shows the software stack that is running on the host and points to targets for exploitation and persistence. This can also reveal services that may be writable by the attacker.

**MITRE ATT&CK:** T1007 (System Service Discovery)

---

### 5. All local user accounts

**Command:**

`cat /etc/passwd`

**Output file:** `05_users.txt`

**Screenshot:**

<img width="732" height="745" alt="image" src="https://github.com/user-attachments/assets/c08efe12-6778-4790-b670-ea823c34bc96" />

**What the Output Reveals to an attacker:**

This file lists every account with its UID, home directory, and login shell. Accounts with a UID of 1000 or higher are usually real users and make good targets. A shell of /bin/bash means the account can log in, while /usr/sbin/nologin means it cannot. The home directory paths tell the attacker where to look for keys, history files, and stored credentials.

**MITRE ATT&CK:** T1087.001 (Account Discovery: Local Accounts)

---

### 6. All local groups

**Command:**

`cat /etc/group`

**Output file:** `06_groups.txt`

**Screenshot(Partial):**

<img width="417" height="292" alt="image" src="https://github.com/user-attachments/assets/ab23a143-84e6-465a-8e22-298046fdd383" />

**What the Output Reveals to an attacker:**

This shows every group and its members. The attacker looks for groups such as sudo, docker, adm, and lxd. Membership in several of these is a path to root.

**MITRE ATT&CK:** T1069.001 (Permission Groups Discovery: Local Groups)

---

### 7. Users in the sudo (administrators) group

**Command:**

`getent group sudo`

**Output file:** `07_sudo_group.txt`

**Screenshot:**

<img width="465" height="73" alt="image" src="https://github.com/user-attachments/assets/794d6e73-3363-442b-972a-87330da0851d" />

**What the Output Reveals to an attacker:**

This shows the accounts that are in the sudo group. These are the admin accounts worth targeting with password guessing, phishing, or credential theft because compromising them gains root access.

**MITRE ATT&CK:** T1069.001 (Permission Groups Discovery: Local Groups)

---

### 8. Network configuration (IP, gateway, DNS)

**Command:**

`ip addr`

**Output file:** `08_network_config.txt`

**Screenshot:**

<img width="921" height="342" alt="image" src="https://github.com/user-attachments/assets/521477d4-f106-4a2c-afd4-12ae7f3a72fb" />

**What the Output Reveals to an attacker:**

This shows the network interfaces and their assigned IP addresses. Combined with a routing table and DNS settings it basically gives the attacker a map of the network. A host with more than one interface may bridge two networks which is key for moving across the environment.

**MITRE ATT&CK:** T1016 (System Network Configuration Discovery)

---

### 9. Firewall policies

**Command:**

`sudo iptables -L -n -v`

**Output file:** `09_firewall.txt`

**Required sudo:** Yes

**Screenshot:**

<img width="911" height="96" alt="image" src="https://github.com/user-attachments/assets/5b6a1c2b-60e3-474f-8aa0-95555e663039" />

**What the Output Reveals to an attacker:**

If an account has the access to run this command it will show the firewall rules and the default policy for inbound and outbound traffic. The attacker can learn what is blocked and what is not. This helps them find paths for c2 traffic or data exfiltration.

**MITRE ATT&CK:** T1016 (System Network Configuration Discovery)

---

### 10. ARP table

**Command:**

`ip neigh`

**Output file:** `10_arp.txt`

**Screenshot:**

<img width="490" height="73" alt="image" src="https://github.com/user-attachments/assets/0ac8dfc6-1ab3-4bff-9aaf-647859c042fd" />

**What the Output Reveals to an attacker:**

The ARP cache shows other hosts on the local network that this machine has recently talked to. This gives the attacker live targets for lateral movement without running a noisy network scan that could trigger detection. In this case only the gateway is shown.

**MITRE ATT&CK:** T1018 (Remote System Discovery)

---

### 11. SMB sessions

**Command:**

`sudo smbstatus`

**Output file:** `11_smb_sessions.txt`

**Required sudo:** Yes

**Screenshot:**

<img width="467" height="39" alt="image" src="https://github.com/user-attachments/assets/0a241cd4-54e4-495c-b750-40dcc37eaaa8" />

**What the Output Reveals to an attacker:**

If installed and running this command will show active SMB sessions, connected users, and shared resources. It reveals file sharing relationships and which credentials are in use. This can lead to lateral movement.

**MITRE ATT&CK:** T1049 (System Network Connections Discovery), T1135 (Network Share Discovery)

---

### 12. System information

**Command:**

`uname -a`

**Output file:** `12_system_info.txt`

**Screenshot:**

<img width="984" height="63" alt="image" src="https://github.com/user-attachments/assets/a143224b-fa9e-41a8-b4ed-c27ee98b0345" />

**What the Output Reveals to an attacker:**

This prints the kernel name, version, architecture, and hostname. The kernel version is extremely for an attacker because it maps to known local privilege escalation vulnerabilities. The architecture tells them which exploits will run on the host.

**MITRE ATT&CK:** T1082 (System Information Discovery)

---

### 13. Sudo privileges granted to the current account

**Command:**

`sudo -l`

**Output file:** `13_sudo_privileges.txt`

**Required sudo:** Yes

**Screenshot:**

<img width="782" height="169" alt="image" src="https://github.com/user-attachments/assets/a2f9aac4-889c-4c9e-9495-fe00f15dc048" />

**What the Output Reveals to an attacker:**

This lists which commands the current account can run using sudo and whether any of them are set to NOPASSWD. A NOPASSWD entry, or a command that can spawn a shell, can be an instant way to gain root. This is one of the first checks an attacker runs after gaining a foothold.

**MITRE ATT&CK:** T1069.001 (Permission Groups Discovery: Local Groups), T1033 (System Owner/User Discovery)

---

### 14. Logged-in users, active sessions, and login history

**Command:**

`last -a`

**Output file:** `14_sessions.txt`

**Screenshot:**

<img width="686" height="220" alt="image" src="https://github.com/user-attachments/assets/b4f292a1-79bc-47f6-9f11-a0b7f4271140" />

**What the Output Reveals to an attacker:**

This shows a history of logins, including the user, the time, and the source address. The attacker uses this to learn what times the pc may be used which can allow the attacker to blend in with regular activity. This can also show which source IP addresses admins may use.

**MITRE ATT&CK:** T1033 (System Owner/User Discovery), T1087 (Account Discovery)

---

### 15. Shell command history left behind by local users

**Command:**

`cat ~/.bash_history`

**Output file:** `15_shell_history.txt`

**Screenshot(Partial):**

<img width="509" height="579" alt="image" src="https://github.com/user-attachments/assets/dfba3b76-b756-422f-b2b6-3390e880df44" />

**What the Output Reveals to an attacker:**

The shell history records commands that users have typed. These can possibly show plaintext passwords, API tokens, database connection strings, and internal hostnames. Reading other users and root history files can lead to the attacker gaining working credentials without having to actually crack anything.

**MITRE ATT&CK:** T1552.003 (Unsecured Credentials: Bash History)

---

### 16. Environment variables of the current shell and running processes

**Command:**

`env`

**Output file:** `16_environment.txt`

**Screenshot:**

<img width="2286" height="554" alt="image" src="https://github.com/user-attachments/assets/eb90c6ba-42ae-48a6-bdbb-91ee71f92422" />

**What the Output Reveals to an attacker:**

Environment variables can hold secrets that applications need, such as API keys, database passwords, and tokens. Reading the environment of the current shell and of running processes under /proc can reveal these secrets directly.

**MITRE ATT&CK:** T1082 (System Information Discovery), T1552.001 (Unsecured Credentials: Credentials In Files)

---

### 17. SUID and SGID binaries on the filesystem

**Command:**

`find / -perm -4000 -type f 2>/dev/null`

**Output file:** `17_suid_sgid.txt`

**Screenshot:**

<img width="516" height="489" alt="image" src="https://github.com/user-attachments/assets/58c244b0-0f59-4960-b586-1c16ee2d93bc" />

**What the Output Reveals to an attacker:**

This finds binaries that run with the privileges of their owner rather than the user who runs them. A setuid root binary that isn't standard may be able to be abused to gain a root shell.

**MITRE ATT&CK:** T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid)

---

### 18. File capabilities assigned to installed binaries

**Command:**

`getcap -r / 2>/dev/null`

**Output file:** `18_capabilities.txt`

**Screenshot:**

<img width="1545" height="166" alt="image" src="https://github.com/user-attachments/assets/75b445a9-94d8-47e7-91be-cace24051637" />

**What the Output Reveals to an attacker:**

This lists binaries that carry Linux capabilities. Capabilities such as cap_setuid or cap_dac_read_search grant root powers without the setuid bit being set. This means that defenders can often miss them. An attacker can abuse these to escalate privileges or read protected files.

**MITRE ATT&CK:** T1548 (Abuse Elevation Control Mechanism)

---

### 19. Scheduled tasks: cron jobs and systemd timers

**Command:**

`cat /etc/crontab`

**Output file:** `19_scheduled_tasks.txt`

**Screenshot:**

<img width="854" height="393" alt="image" src="https://github.com/user-attachments/assets/8ceba844-1a81-4118-b2c1-84a92a0c9e70" />

**What the Output Reveals to an attacker:**

This shows scheduled jobs and the accounts they run as. A job that runs as root and calls a script the attacker can write to is a popular method for both privilege escalation and persistence. Systemd timers have the same purpose and should be checked as well.

**MITRE ATT&CK:** T1053.003 (Scheduled Task/Job: Cron)

---

### 20. Installed security tools and EDR agents

**Command:**

`ps aux | grep -Ei 'clamav|auditd|falcon|crowdstrike|wazuh|ossec'`

**Output file:** `20_security_tools.txt`

**Screenshot:**

<img width="1010" height="43" alt="image" src="https://github.com/user-attachments/assets/b7fa0aea-7542-407b-a521-2f67d615d6f9" />

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
