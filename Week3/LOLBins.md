# Living Off the Land Binaries (LOLBins) - Execution and Documentation
Learning Objectives:

- Identify Living Off the Land Binaries from real-world threat intelligence advisories
- Execute common LOLBins on a Windows system and capture their output
- Interpret LOLBin output and explain what each data field reveals to an attacker
- Map LOLBin abuse techniques to the MITRE ATT&CK framework
- Detect LOLBin abuse through Windows event logs and command-line monitoring
- Document LOLBin capabilities in a structured threat intelligence format


### Advisory Sources
https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/prc-state-sponsored-actors-compromise-and-maintain-persistent-access-us-critical-infrastructure

https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF

MITRE ATT&CK Reference:

T1218 - System Binary Proxy Execution https://attack.mitre.org/techniques/T1218/

T1059 - Command and Scripting Interpreter https://attack.mitre.org/techniques/T1059/

T1105 - Ingress Tool Transfer https://attack.mitre.org/techniques/T1105/


### Documenting an LOLBin
The format to be used in this write-up will be as follows:

Command ```whoami /all```

Screenshot 

What the output reveals to an attacker
