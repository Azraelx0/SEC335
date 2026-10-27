#!/bin/bash
mkdir -p /tmp/enumeration
cd /tmp/enumeration

id > 01_user_id.txt 2>&1
ps aux > 02_processes.txt 2>&1
ss -tulpan > 03_sockets.txt 2>&1
systemctl list-units --type=service --state=running > 04_services.txt 2>&1
cat /etc/passwd > 05_users.txt 2>&1
cat /etc/group > 06_groups.txt 2>&1
getent group sudo > 07_sudo_group.txt 2>&1
ip addr > 08_network_config.txt 2>&1
sudo iptables -L -n -v > 09_firewall.txt 2>&1
ip neigh > 10_arp.txt 2>&1
sudo smbstatus > 11_smb_sessions.txt 2>&1
uname -a > 12_system_info.txt 2>&1
sudo -l > 13_sudo_privileges.txt 2>&1
last -a > 14_sessions.txt 2>&1
cat ~/.bash_history > 15_shell_history.txt 2>&1
env > 16_environment.txt 2>&1
find / -perm -4000 -type f 2>/dev/null > 17_suid_sgid.txt
getcap -r / 2>/dev/null > 18_capabilities.txt
cat /etc/crontab > 19_scheduled_tasks.txt 2>&1
ps aux | grep -Ei 'clamav|auditd|falcon|crowdstrike|wazuh|ossec' > 20_security_tools.txt 2>&1
dpkg -l > 21_packages.txt 2>&1
uname -r > 22_kernel.txt 2>&1
df -h > 23_mounts_disk.txt 2>&1
cat /etc/ssh/sshd_config > 24_ssh.txt 2>&1
ls -l /etc/shadow > 25_shadow.txt 2>&1
sudo lastb > 26_auth_events.txt 2>&1
docker ps > 27_containers.txt 2>&1
aa-status > 28_mac.txt 2>&1
cat /etc/exports > 29_nfs.txt 2>&1
hostname -f > 30_hostname_domain.txt 2>&1
find / -perm -0002 -type f 2>/dev/null > 31_world_writable.txt
sudo lsof +L1 > 32_open_files.txt 2>&1

echo "Output files in /tmp/enumeration:"
ls /tmp/enumeration
