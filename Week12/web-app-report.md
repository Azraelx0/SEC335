# Web Application Penetration Test: Centurion University Admissions Portal (Simulated Lab)

**Target:** `http://192.168.77.90/` (Online Admission System, OAS v1.2)
**Assessment type:** Authenticated and unauthenticated web application penetration test
**Methodology:** OWASP Web Security Testing Guide (WSTG), Penetration Testing Execution Standard (PTES), MITRE ATT&CK
**Author:** Caden Mercer (SEC335)

---

## 1. Scope and Authorization

Testing was limited to the single host `192.168.77.90`, conducted with the explicit authorization of the course instructor. The target is a simulated training instance of an Online Admission System (OAS v1.2) that carries Centurion University branding. It is not affiliated with, nor representative of, the live Centurion University production environment, and no system outside the authorized host was tested. Lab support services observed on other ports (a mesh-networking overlay used to reach the range) were identified, assessed as out of scope, and left untested.

## 2. Executive Summary

The assessment identified multiple critical and high severity vulnerabilities that, together, allow the complete compromise of the Online Admission System and all of its data. The most serious issues require no authentication at all.

An unauthenticated attacker on the network can execute arbitrary operating system commands on the server through a diagnostic tool, obtain an interactive shell, access the underlying database as root with no password, and recover every administrator credential, which the application stores in plaintext. This results in full control of the application. Independently, the administrator login can be bypassed with a single SQL injection payload, every applicant's personal data can be read without authentication through a direct object reference, and a low-privilege applicant can plant a script that hijacks an administrator's session.

Four distinct vulnerability classes were confirmed end to end, with additional supporting weaknesses identified during testing. The overall risk is assessed as **Critical**, because an unauthenticated attacker can achieve full remote compromise and exfiltrate all applicant and administrator data.

**Findings by severity:**

| Severity | Count |
|---|---|
| Critical | 2 |
| High | 2 |

## 3. Methodology

The engagement followed the PTES lifecycle, moving from intelligence gathering through vulnerability analysis to exploitation and post-exploitation. Individual tests were structured around the OWASP Web Security Testing Guide categories, and each confirmed vulnerability is mapped to its WSTG identifier, its CWE, and the relevant MITRE ATT&CK technique. The reconnaissance phase (host discovery, service fingerprinting, three-tier application mapping, and content discovery) is documented separately:

- **Reconnaissance and enumeration:** [recon/Site_Enum.md](./recon/Site_Enum.md)

Tooling included nmap, whatweb, wafw00f, Burp Suite, gobuster, and nikto for discovery and testing, and netcat for the post-exploitation shell. All exploitation was performed manually and reproduced end to end.

## 4. Findings Summary

| # | Finding | Severity | CVSS | WSTG | CWE | Detail |
|---|---|---|---|---|---|---|
| 1 | SQL Injection Authentication Bypass | Critical | 9.8 | ATHN-04, INPV-05 | CWE-89 | [View](./findings/ATHN-01_sqli-auth-bypass/README.md) |
| 2 | OS Command Injection (unauthenticated RCE) | Critical | 9.8 | INPV-12 | CWE-78 | [View](./findings/INPV-01_command-injection/README.md) |
| 3 | Insecure Direct Object Reference (unauthenticated PII) | High | 7.5 | ATHZ-04 | CWE-639 | [View](./findings/ATHZ-01_idor/README.md) |
| 4 | Stored Cross-Site Scripting (admin session theft) | High | 8.2 | INPV-02 | CWE-79 | [View](./findings/INPV-02_stored-xss/README.md) |

Supporting weaknesses observed during testing and referenced within the findings above include cleartext storage of credentials (CWE-256), database access as root with no password, a session cookie without the HttpOnly flag, directory listing enabled on document folders, sensitive files left in the web root, and a session identifier that is not regenerated on login.

## 5. Attack Narrative

The individual findings chain into two complete compromise paths, both reachable from an unauthenticated position.

**Path 1: Unauthenticated remote code execution to full control.** Reconnaissance recovered a deployment notes file left in the web root, which disclosed the application identity, a diagnostic tool, and the fact that the local database runs as root with no password. The diagnostic "ping" tool (`tools.php`) passes its input to a shell without sanitization, so an unauthenticated attacker can inject operating system commands (Finding 2). This was escalated to an interactive reverse shell as the `www-data` account, then used to access the MySQL database as root and recover the entire administrator credential store, which is held in plaintext. At that point the attacker has complete control of the application and all of its data.

**Path 2: Authentication bypass and session theft.** The administrator login concatenates user input directly into a SQL query, so a single injection payload bypasses authentication and grants access to the administrator console as the super-admin, with no credentials (Finding 1). Separately, applicant form fields are rendered into administrator pages without encoding, so a low-privilege applicant can store a script that executes in an administrator's session and, because the session cookie lacks the HttpOnly flag, steals the administrator's session cookie (Finding 4). In parallel, the full personal record of any applicant can be read with no authentication at all by changing a predictable identifier (Finding 3), exposing the entire applicant population.

In ATT&CK terms, the engagement moved from Exploit Public-Facing Application (T1190) to Command and Scripting Interpreter (T1059), then to credential access and the theft of web session cookies (T1539), ending in full administrative control.

## 6. Detailed Findings

Each finding below is documented in full, with the exact request or payload, the server response, the resulting effect, root cause, impact, and remediation, in its linked writeup.

### 6.1 SQL Injection Authentication Bypass (Critical)

The administrator login at `/adminlogin.php` is vulnerable to SQL injection in the `a_id` parameter. The payload `' OR 1=1-- -` bypasses the login entirely and authenticates as the super-admin with no credentials. Full writeup: [findings/ATHN-01_sqli-auth-bypass/README.md](./findings/ATHN-01_sqli-auth-bypass/README.md)

### 6.2 OS Command Injection (Critical)

The unauthenticated diagnostic tool at `/tools.php` passes the `host` parameter to a shell, allowing arbitrary command execution as `www-data`. This was escalated to an interactive shell, database compromise, and recovery of the plaintext administrator credential store. Full writeup: [findings/INPV-01_command-injection/README.md](./findings/INPV-01_command-injection/README.md)

### 6.3 Insecure Direct Object Reference (High)

The `/viewform.php` endpoint returns any applicant's full record based on a predictable `id` parameter and performs no authorization check, so an unauthenticated attacker can read and enumerate every applicant's personal data. Full writeup: [findings/ATHZ-01_idor/README.md](./findings/ATHZ-01_idor/README.md)

### 6.4 Stored Cross-Site Scripting (High)

Admission form fields are stored and rendered without output encoding, so a low-privilege applicant can store a script that executes in the administrator's session during normal review. Combined with a session cookie that lacks the HttpOnly flag, this enables administrator session theft. Full writeup: [findings/INPV-02_stored-xss/README.md](./findings/INPV-02_stored-xss/README.md)

## 7. Remediation Summary

Priorities are ordered by risk.

1. **Eliminate command execution from user input (Finding 2).** Replace the shell call in the diagnostic tool with an argument-array API that does not invoke a shell, validate the host value against a strict allow-list, and require authentication to reach the tool.
2. **Use parameterized queries everywhere (Finding 1).** Replace all string-concatenated SQL with prepared statements, and enforce authentication in application code rather than through the query.
3. **Enforce server-side authorization on record access (Finding 3).** Verify that the requesting account is permitted to view the specific record, rather than returning any record keyed on a predictable identifier.
4. **Encode all output and harden session cookies (Finding 4).** Apply context-appropriate output encoding to all user-supplied data, and set the HttpOnly flag on session cookies.
5. **Address the supporting weaknesses.** Hash stored credentials rather than storing them in plaintext, run the database under a least-privilege account with a strong password, disable directory listing, remove deployment and leftover files from the web root, and regenerate session identifiers on login.

All findings share a common root cause theme: user input is trusted and acted upon without server-side validation, while the only input controls present are client-side and therefore bypassable.

## 8. Appendix: Reconnaissance

The full reconnaissance and enumeration phase, including the host and service scans, the three-tier application map, the endpoint inventory, content discovery, and the candidate vulnerability list that drove the exploitation phase, is documented here: [recon/Site_Enum.md](./recon/Site_Enum.md)
