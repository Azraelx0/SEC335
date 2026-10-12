# Linux Privilege Escalation — Phase 0: Foothold & Enumeration

## Connecting to the Remote Host

```bash
ssh -p 10019 bthomas@192.168.3.205
```

<img width="347" height="63" alt="SSH connection" src="https://github.com/user-attachments/assets/841367df-277e-4eb5-a9cb-9490c16d5b52" />

## Initial Context

First thing after landing on a host: establish who you are and what you're allowed to run as root.

```bash
id          # user, groups, uid/gid
sudo -l     # commands you may run via sudo
```

<img width="1031" height="156" alt="id and sudo -l output" src="https://github.com/user-attachments/assets/7260cf38-de8d-4e75-afa5-d5c21a7fd0f8" />

## Transferring linpeas.sh to the Target

Push linpeas from the Kali VM to the target over SSH (note `scp` uses a capital `-P` for the port):

```bash
# On Kali, from the directory containing linpeas.sh:
scp -P 10019 linpeas.sh bthomas@192.168.3.205:/tmp/
```

Confirm it transferred and is executable; add the execute bit if needed:

```bash
ls -la /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh      # only if it isn't already executable
```

Run it and tee the output to a file, then review with colors preserved:

```bash
bash /tmp/linpeas.sh &> /tmp/linpeas.out    # &> captures stdout + stderr
less -R /tmp/linpeas.out                    # -R renders ANSI colors
```

---

## Automated Enumeration (linpeas Findings)

linpeas surfaced the following. Each maps to one of the lab's exploitation vectors.

### SUID Binaries — *(V7: SUID Python)*
Found under **"Files with Interesting Permissions."** Note the anomalous `/opt/lab/bin/python3`.

<img width="692" height="32" alt="SUID binaries" src="https://github.com/user-attachments/assets/c0cf7e64-eabc-4215-b22b-32e1187cc9da" />

### Writable Directory & Files — *(V1 / V3 / V4 / V5 / V6)*
Found under the permissions section. World-writable paths root-owned content depends on.

<img width="933" height="71" alt="Writable directory" src="https://github.com/user-attachments/assets/d29556b7-7d3a-460d-bfdc-aee86c37ceb6" />

<img width="996" height="123" alt="Writable files" src="https://github.com/user-attachments/assets/15829ffd-6a88-4bb0-84da-98964793c369" />

### Cron Jobs — *(V1 / V3 / V4)*
Found under **"Check for vulnerable cron jobs under /etc/cron.d."**

<img width="475" height="52" alt="Cron jobs" src="https://github.com/user-attachments/assets/8c7db8f7-3d38-4632-b989-c5f061ec9aa8" />

### sudo Permissions — *(V2: sudo find wildcard)*
Found under **"sudo -l, /etc/sudoers, and /etc/sudoers.d."**

<img width="446" height="47" alt="sudo permissions" src="https://github.com/user-attachments/assets/ee7958d8-7d80-4260-9655-7b744f2f149f" />

### Writable PATH Entry — *(V5: PATH hijack)*
Found under **"Files (scripts) in /etc/profile.d/."** A world-writable dir prepended to root's PATH.

<img width="446" height="35" alt="Writable PATH" src="https://github.com/user-attachments/assets/28928567-d2ab-4a4f-9cb1-275419d37746" />

---

## Manual Enumeration & Confirmation

The commands below reproduce (and confirm) linpeas's findings by hand — useful both as a cross-check and for understanding *why* each item is a finding.

### User context and sudo rights
```bash
id; sudo -l
```
Shows the current user, group memberships, and what may be run as root.

<img width="1021" height="132" alt="id; sudo -l" src="https://github.com/user-attachments/assets/69c0a6aa-a5d3-47d5-9935-ba2a5c84d456" />

### SUID binaries
```bash
find / -perm -4000 -type f 2>/dev/null
```
Lists every SUID binary. Note the out-of-place `/opt/lab/bin/python3`.

<img width="493" height="452" alt="find SUID" src="https://github.com/user-attachments/assets/46bece36-cdad-453a-88ab-a6bbbd20d165" />

### Root-scheduled cron jobs
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

### Writable directories
```bash
find /opt /usr/local /etc -writable -type d 2>/dev/null
```
Directories the current user can write to.

<img width="605" height="62" alt="writable dirs" src="https://github.com/user-attachments/assets/5b393112-04c5-43c2-a158-7511643bac35" />

### Writable root-owned files
```bash
find /opt /etc -writable -type f 2>/dev/null
```
Files the current user can modify that root relies on.

<img width="505" height="57" alt="writable files" src="https://github.com/user-attachments/assets/ce7a0a1e-c695-4d04-a94d-35ad3d639d4b" />

### PATH manipulation
```bash
cat /etc/profile.d/*.sh
```
Most output is stock Ubuntu boilerplate. The critical line is the last one:

```bash
export PATH="/opt/lab/bin:$PATH"
```

This prepends the world-writable `/opt/lab/bin` to PATH for every login shell — including root's — which is the basis for the V5 PATH-hijack.

<img width="295" height="25" alt="writable PATH line" src="https://github.com/user-attachments/assets/e6e0018e-5de2-41e0-b7e9-db4f0d314d7b" />

---

## Summary of Vectors Identified

| # | Vector | Discovery signal |
|---|--------|------------------|
| V1 | Writable dir + root cron (`backup.sh`) | writable `/opt/lab/bin` + `/etc/cron.d` entry |
| V2 | sudo wildcard on `find` | `sudo -l` rule with trailing `*` |
| V3 | Writable cron script (`rotate.sh`) | world-writable script referenced by cron |
| V4 | Missing binary cron expects (`agent`) | cron references a non-existent file in writable dir |
| V5 | PATH hijack via `/opt/lab/bin` | `profile.d` prepends writable dir to PATH |
| V6 | Writable `update-motd.d` dir | world-writable MOTD directory |
| V7 | SUID `python3` | `/opt/lab/bin/python3` in SUID scan |
