## Notes

- LOLBINS (windows) - https://lolbas-project.github.io/

- LOLBINS (Linux) - https://gtfobins.org/

net.exe- manage services, create/delete accounts, list network sessions and share
net1.exe - command executed when you execute net.exe

When you run net.exe, it calls the binary net1.exe to perform the task. Accordingly, net1.exe can be used to try to bypass sensors and rule-based tools since those are typically configured to look for "net" or "net.exe" executions.

For example, to create a new user we would use the following command:
```
net user theUsername thePassword /add
```
## Resources
Some helpful resources include the following:
```
https://github.com/frizb/MSF-Venom-Cheatsheet
https://www.ired.team/
https://hacktricks.wiki/en/index.html
```
