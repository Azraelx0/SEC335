# Linux Privilege Escalation
Connecting to the remote host:

<img width="347" height="63" alt="image" src="https://github.com/user-attachments/assets/841367df-277e-4eb5-a9cb-9490c16d5b52" />

Output of id and sudo -l commands:

<img width="1031" height="156" alt="image" src="https://github.com/user-attachments/assets/7260cf38-de8d-4e75-afa5-d5c21a7fd0f8" />

Used scp to transfer linpeas.sh from kali vm to target ```scp -P 10019 bthomas@192.168.3.205:/tmp/```
Then used ls -la to ensure the file had execute permissions. If it does not then run ```chmod +x /tmp/linpeas.sh```
Ran it with ```bash /tmp/linpeas.sh &> /tmp/linpeas.out``` to save it to an output file. Then view it using `less -R` so we preserved the colors and can scroll through the file.

## linpeas output
Found under "Files with Interesting Permissions"
SUID Binarys: 

<img width="692" height="32" alt="image" src="https://github.com/user-attachments/assets/c0cf7e64-eabc-4215-b22b-32e1187cc9da" />

Found under category seen in screenshot
Writable Directory & File:

<img width="933" height="71" alt="image" src="https://github.com/user-attachments/assets/d29556b7-7d3a-460d-bfdc-aee86c37ceb6" />

<img width="996" height="123" alt="image" src="https://github.com/user-attachments/assets/15829ffd-6a88-4bb0-84da-98964793c369" />

Found under "Check for vulnerable cron jobs under /etc/cron.d"
Cron jobs/files

<img width="475" height="52" alt="image" src="https://github.com/user-attachments/assets/8c7db8f7-3d38-4632-b989-c5f061ec9aa8" />

Found under "sudo -l, /etc/sudoers, and /etc/sudoer.d"
sudo perms:

<img width="446" height="47" alt="image" src="https://github.com/user-attachments/assets/ee7958d8-7d80-4260-9655-7b744f2f149f" />

Found under "Files (scripts) in /etc/profile.d/"
Writable path:

<img width="446" height="35" alt="image" src="https://github.com/user-attachments/assets/28928567-d2ab-4a4f-9cb1-275419d37746" />


## Manual Enum & Confirmation 
The following commands are what would be run if doing enumeration manually or just to confirm the automatic scan done by linpeas.

id; sudo -l                                                # Shows user, group, what can be done as root

<img width="1021" height="132" alt="image" src="https://github.com/user-attachments/assets/69c0a6aa-a5d3-47d5-9935-ba2a5c84d456" />


find / -perm -4000 -type f 2>/dev/null                     # SUID binaries, note the `/opt/lab/bin/python3` binary

<img width="493" height="452" alt="image" src="https://github.com/user-attachments/assets/46bece36-cdad-453a-88ab-a6bbbd20d165" />

ls -la /etc/cron.d/ /etc/crontab                           # root-scheduled jobs

<img width="445" height="234" alt="image" src="https://github.com/user-attachments/assets/608abf94-86ff-4de0-a898-f141184b669e" />

grep -R "" /etc/cron.d/ 2>/dev/null                        # which scripts root runs, note `/opt/lab/bin/backup.sh`

<img width="1222" height="506" alt="image" src="https://github.com/user-attachments/assets/e9f09c72-9956-4d69-acf3-a317e951f6df" />

find /opt /usr/local /etc -writable -type d 2>/dev/null    # writable dirs

<img width="605" height="62" alt="image" src="https://github.com/user-attachments/assets/5b393112-04c5-43c2-a158-7511643bac35" />

find /opt /etc -writable -type f 2>/dev/null               # writable root-owned files

<img width="505" height="57" alt="image" src="https://github.com/user-attachments/assets/ce7a0a1e-c695-4d04-a94d-35ad3d639d4b" />

cat /etc/profile.d/*.sh                                    # PATH manipulation, the critical output for this lab's purpose is seen below

<img width="295" height="25" alt="image" src="https://github.com/user-attachments/assets/e6e0018e-5de2-41e0-b7e9-db4f0d314d7b" />

