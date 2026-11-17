# Stored Cross-Site Scripting (Applicant Field to Admin Session)

| Field | Value |
|---|---|
| **Severity** | High (CVSS v3.1: 8.2) |
| **CVSS Vector** | `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N` |
| **WSTG** | WSTG-INPV-02 (Testing for Stored Cross Site Scripting) |
| **MITRE ATT&CK** | T1059.007 (JavaScript), T1539 (Steal Web Session Cookie) |
| **CWE** | CWE-79 (Improper Neutralization of Input During Web Page Generation) |
| **Affected input** | Admission form free-text fields (for example Father's Name / `ufname`), stored and rendered on `homepageuser.php`, `admsnreport.php`, and `viewform.php` |

## Discovery

This was flagged during reconnaissance for two reasons. First, the client-side guard `filter.js` deliberately allows the `<` and `>` characters on the form fields, and a code comment in that file noted the guard was not meant to look like an XSS filter. Second, the data submitted on the admission form is rendered back into administrator views, so an applicant-controlled field is a strong candidate to execute in an administrator's browser. The tester therefore targeted `viewform.php`, a page an administrator views regularly as part of reviewing applications.

## Summary

The admission form stores free-text fields without output encoding, and those fields are later rendered directly into HTML on pages viewed by both the applicant and the administrator. A low-privilege applicant can store a script payload in a field such as Father's Name, and it executes whenever the stored value is rendered. When an administrator opens the applicant's record in `viewform.php` during normal review, the payload runs in the administrator's authenticated session. Because the session cookie has no HttpOnly flag, the script can read and exfiltrate the administrator's `PHPSESSID`, leading to session theft and full administrative takeover.

## Reproduction

### 1. Store a proof payload as a low-privilege applicant

The tester logged in with the previously created applicant account `raihn` and updated the existing application so a payload could be placed in a form field. The payload `<script>alert(1)</script>` was entered in the Father's Name field and the application was saved with "Update". On render, the payload executed, confirming the field is stored and output without encoding:

<img width="1572" height="1372" alt="image" src="https://github.com/user-attachments/assets/bb822b51-9e5d-447e-8fe5-6365d066b24e" />

### 2. Confirm the session cookie is readable

The tester repeated the process with a payload that reads the session cookie:

```
<script>alert(document.cookie)</script>
```

The alert returned the session cookie value `PHPSESSID=spoo81dqotspo7elqmqjufi1jf`, which confirms the script can read the session cookie because it lacks the HttpOnly flag:

<img width="1643" height="1353" alt="image" src="https://github.com/user-attachments/assets/5312261d-330d-4ec9-839c-c536b322490a" />

### 3. Confirm execution in the administrator session

In a real attack the payload executes when a legitimate administrator views the record during normal review, with no action required beyond opening the application. To demonstrate this, the tester logged in with administrator credentials and opened the applicant's record:

```
GET /viewform.php?id=CUTM00016
```

The page rendered under the "Welcome, admin" console and the stored payload executed in the administrator's session. Repeating the test in a separate administrator browser returned a distinct administrator `PHPSESSID`, different from the applicant's cookie, which confirms the payload reads the administrator's own session rather than a reused value. This is genuine cross-privilege session theft.

<img width="2560" height="1383" alt="image" src="https://github.com/user-attachments/assets/36de667f-4cf6-4e49-8c5e-8e65b61511c8" />

## Impact

This is a high-severity vulnerability. A low-privilege applicant can store JavaScript that executes in an administrator's session during the normal act of reviewing an application. Because the `PHPSESSID` cookie has no HttpOnly flag, the payload can read and exfiltrate the administrator's session cookie, allowing the attacker to hijack the administrator session and gain full control of the application. The same stored value also executes for any other user who views the record, so the payload persists and affects every viewer until it is removed.

A related observation during testing: when the applicant session and the administrator login occurred in the same browser, the application reused the same `PHPSESSID` rather than regenerating it on login. This session-management weakness (session identifier not regenerated on privilege change) is noted separately and is distinct from the cross-privilege session theft demonstrated above, which was confirmed with distinct cookies in separate browsers.

## Remediation

- Encode all user-supplied data on output according to the context in which it is rendered, for example HTML entity encoding for values placed in HTML body or attributes. This is the primary fix.
- Validate and sanitize input on the server side. The client-side `filter.js` guard provides no protection, since any proxy bypasses it, and it intentionally permits angle brackets.
- Set the HttpOnly flag on session cookies so that script cannot read `PHPSESSID`, which breaks the cookie-theft step of this attack.
- Consider a Content-Security-Policy that restricts inline script execution as defense in depth.

## References

- OWASP WSTG-INPV-02: Testing for Stored Cross Site Scripting
- CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
