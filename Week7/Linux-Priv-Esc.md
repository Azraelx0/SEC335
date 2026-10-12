# Linux Privilege Escalation
Connecting to the remote host:

<img width="347" height="63" alt="image" src="https://github.com/user-attachments/assets/841367df-277e-4eb5-a9cb-9490c16d5b52" />

Output of id and sudo -l commands:

<img width="1031" height="156" alt="image" src="https://github.com/user-attachments/assets/7260cf38-de8d-4e75-afa5-d5c21a7fd0f8" />

Used scp to transfer linpeas.sh from kali vm to target ```scp -P 10019 bthomas@192.168.3.205:/tmp/```
Then used ls -la to ensure the file had execute permissions. If it does not then run ```chmod +x /tmp/linpeas.sh```
Ran it with ```bash /tmp/linpeas.sh &> /tmp/linpeas.out``` to save it to an output file. Then view it using `less -R` so we preserved the colors and can scroll through the file.


Found under "Files with Interesting Permissions"
SUID Binarys: 

<img width="692" height="32" alt="image" src="https://github.com/user-attachments/assets/c0cf7e64-eabc-4215-b22b-32e1187cc9da" />

Found under category seen in screenshot
Writable Directory & File:
<img width="933" height="71" alt="image" src="https://github.com/user-attachments/assets/d29556b7-7d3a-460d-bfdc-aee86c37ceb6" />

<img width="996" height="123" alt="image" src="https://github.com/user-attachments/assets/15829ffd-6a88-4bb0-84da-98964793c369" />

Found under "Check for vulnerable cron jobs under /etc/cron.d"

<img width="475" height="52" alt="image" src="https://github.com/user-attachments/assets/8c7db8f7-3d38-4632-b989-c5f061ec9aa8" />

Found under "sudo -l, /etc/sudoers, and /etc/sudoer.d"
sudo perms:

<img width="446" height="47" alt="image" src="https://github.com/user-attachments/assets/ee7958d8-7d80-4260-9655-7b744f2f149f" />
