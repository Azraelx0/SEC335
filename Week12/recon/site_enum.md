# Site Recon & Enumeration

Target: `http://192.168.77.90/`

After briefly viewing the site in browser, find that it seems to be associated with Centurion University of Technology and Management Bhubaneswar.

The first step I took was to run a full tcp port scan on the target using `nmap -p- --min-rate 2000 -oA scans/nmap-allports 192.168.77.90` to do a broad search for open ports. Results:

<img width="633" height="296" alt="image" src="https://github.com/user-attachments/assets/3b6e9cd9-643e-478d-be92-425076ab44f8" />

Next I hone in on those open ports using this command `nmap -sC -sV -p 80,11010,11011,11012,11013,15888 -oA scans/nmap-services 192.168.77.90`. This is running a scan that looks for version and default scripts on just those. Noteworthy results:

<img width="831" height="316" alt="image" src="https://github.com/user-attachments/assets/4d40cd4c-e4b9-49d6-900c-98afa75aceb9" />

A note on those high ports is that they're just services supporting the lab environment in order to access it, so for the rest of this test I will ignore them. 
From this scan alone some critical information is unveiled. First, the service `http` already reveals that this website is going to be vulnerable to attacks that one running `https` would not be. Second, having the version `Apache httpd 2.4.67 ((Debian))` will aid in what exploits can be done against this web server. Third, this scan shows that the `httponly` flag is not set on the server. Last, several interesting directories and files are found, including: `http-robots.txt`, `/install-notes.txt`, `/studentdoc/`, `/studentpic/`, and `/studentproof`.

NOTE: ADD MORE IN THIS SECTION ON WHY I TESTED THE HIGH PORTS AT ALL


