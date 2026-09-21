@echo off
whoami /all > C:\temp\whoami.txt
tasklist /v > C:\temp\processes.txt
netstat -ano > C:\temp\netstat.txt
sc query > C:\temp\services.txt
net user > C:\temp\users.txt
net localgroup > C:\temp\groups.txt
net localgroup administrators > C:\temp\admins.txt
ipconfig /all > C:\temp\ipconfig.txt
netsh advfirewall show allprofiles > C:\temp\firewall.txt
arp -a > C:\temp\arp.txt
net use > C:\temp\smbsessions.txt 
:: net session is the cmd that we want to use here but it requires admin rights
systeminfo > C:\temp\systeminfo.txt
echo Done.