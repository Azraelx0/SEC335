# Linux Privilege Escalation
Connecting to the remote host:

<img width="347" height="63" alt="image" src="https://github.com/user-attachments/assets/841367df-277e-4eb5-a9cb-9490c16d5b52" />

Output of id and sudo -l commands:

<img width="1031" height="156" alt="image" src="https://github.com/user-attachments/assets/7260cf38-de8d-4e75-afa5-d5c21a7fd0f8" />

Used scp to transfer linpeas.sh from kali vm to target ```scp -P 10019 bthomas@192.168.3.205:/tmp/```
Then used ls -la to ensure the file had execute permissions. If it does not then run ```chmod +x /tmp/linpeas.sh```
Ran it with ```bash /tmp/linpeas.sh```
