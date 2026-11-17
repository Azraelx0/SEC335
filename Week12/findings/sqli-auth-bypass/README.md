# SQL Injection Authentication Bypass (Admin Login)

| Field | Value |
|---|---|
| **Severity** | Critical (CVSS v3.1: 9.8) |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **WSTG** | WSTG-ATHN-04 (Bypassing Authentication Schema), WSTG-INPV-05 (SQL Injection) |
| **MITRE ATT&CK** | T1190 (Exploit Public-Facing Application) |
| **CWE** | CWE-89 (SQL Injection), CWE-287 (Improper Authentication) |
| **Affected endpoint** | `POST /adminlogin.php`, parameter `a_id` |

## Summary

The administrator login at `/adminlogin.php` builds its SQL query by concatenating user input directly into the statement, which makes the `a_id` parameter injectable. The only input validation is the client-side `filter.js` guard, and any intercepting proxy bypasses it, so an unauthenticated attacker can submit a crafted `a_id` value that satisfies the login query without knowing any credentials. A successful bypass grants full access to the administration console, which exposes applicant records, OMR and mark entry, application approval, and manager account creation.

## Reproduction

### 1. Establish a baseline

The tester first submitted invalid credentials on `/adminlogin.php` to record the application's normal behavior for a failed login. The response was an "Invalid Login" message returned with HTTP 200.

<img width="1352" height="367" alt="image" src="https://github.com/user-attachments/assets/d6588d06-6e73-4085-849d-a1c33e761b05" />

### 2. Test for injection

The failed request was sent to Burp Repeater, and the `a_id` value was changed to `test'`. The response was identical to the standard failed login, and no database error was returned. The absence of a verbose error does not rule out injection, because a login query commonly returns the same "Invalid Login" page whether it errors or simply matches no rows. Testing therefore continued behaviorally rather than relying on an error message.

### 3. Bypass authentication

The tester then set the `a_id` value to the following payload and resent the request:

```
' OR 1=1-- -
```

The response changed from the 200 "Invalid Login" page to an HTTP 302 redirect carrying the header `Location: admin.php`, which is the same response the application returns for a successful login.

<img width="1826" height="596" alt="image" src="https://github.com/user-attachments/assets/66898c6c-95de-4d90-a7c2-ea96c7d37203" />

The injected value closes the original string with a single quote, adds the always-true condition `OR 1=1`, and comments out the remainder of the statement with `-- -`. The resulting `WHERE` clause matches every row in the admin table and discards the password comparison, so the application accepts the request as a valid administrator login. No credentials were supplied.

### 4. Confirm access

To view the result in the browser, the tester right-clicked the response pane for the successful request and selected "Open response in browser." This loaded the authenticated administration dashboard.

<img width="2560" height="1390" alt="image" src="https://github.com/user-attachments/assets/4bccb734-a976-4d8d-b996-2f5cac108fb1" />

## Impact

This is a critical vulnerability. An unauthenticated attacker with network access can obtain full administrator access to the application without any credentials. From the admin console the attacker can read every applicant's personal data, alter OMR values and marks, approve or reject applications, and create new manager accounts for persistent access. Because the same input-handling weakness applies anywhere user input reaches a SQL statement, this class of flaw is expected on other endpoints as well, and those are tracked as separate findings.

## Remediation

- Use parameterized queries (prepared statements) for every database call, for example PDO or `mysqli` with bound parameters, so that user input is never concatenated into SQL.
- Validate and sanitize input on the server side. The client-side `filter.js` guard provides no protection, since any proxy bypasses it.
- Verify the submitted password in application code against a value retrieved through a parameterized lookup, rather than relying on the SQL query itself to enforce authentication.
- Run the application's database account with least privilege so that a future injection has limited reach.
- Add rate limiting and account lockout as defense in depth to slow credential and injection attacks.

## References

- OWASP WSTG-ATHN-04: Testing for Bypassing Authentication Schema
- OWASP WSTG-INPV-05: Testing for SQL Injection
- CWE-89: Improper Neutralization of Special Elements used in an SQL Command
- CWE-287: Improper Authentication
