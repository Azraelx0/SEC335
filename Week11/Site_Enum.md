# Recon & Discovery

**Target:** `http://192.168.77.80` — eLECTRA, Springfield Power & Light billing portal
**Accounts:** `m.holloway@electra.lab` (customer), anonymous, `a.deshmukh@electra.lab` (staff acc recovered from info leak)
**Tools:** Burp Suite, gobuster, Nikto, Firefox dev tools

---

The goal of this phase is to build a complete picture of the application before touching anything offensively — every endpoint, input, role boundary, and technology signal. Everything found here feeds directly into the exploit tasks that follow.

---

## Mapping the Application

I started by browsing the app with Burp Intercept off, letting Proxy history record every request automatically. I added the host to scope and filtered to in-scope to keep the history clean. I walked through the app three times — once as an anonymous visitor, once logged in as `m.holloway`, and once using the staff credentials recovered later from `install-notes.txt`.

Alongside manual browsing I ran gobuster and Nikto to catch anything the navigation didn't surface:

```bash
gobuster dir -u http://192.168.77.80 -w /usr/share/wordlists/dirb/common.txt -x php,txt,zip,sql,bak
nikto -h http://192.168.77.80
```

> **Screenshot:** Burp Proxy history showing full request coverage across all three roles

---

## Endpoint Map

Working through every nav link, form submission, and URL parameter, I built the following map. The staff endpoints were confirmed by logging in with credentials recovered from the information leak described below.

| Endpoint | Method | Who can reach | Where in the UI | Interesting input |
|---|---|---|---|---|
| `/` | GET | Anyone | Home Page | — |
| `/login` | GET/POST | Anyone | Customer Login | `email` `password` |
| `/quick/check` | GET | Anyone | Quick Check | `connection` |
| `/lookup` | GET | Anyone | Bill Lookup | `connection` |
| `/register` | GET/POST | Anyone | New Connection | `name` `email` `connectionId` `address` `password` |
| `/admin/login` | GET/POST | Anyone | Staff Login | `email` `password` |
| `/password/reset` | GET/POST | Anyone | Forgot Password | `email` |
| `/home` | GET | Customer | My Dashboard | — |
| `/home/profile` | GET | Customer | My Account | `name` `email` `address` `password` |
| `/home/profile/update` | GET | Customer | My Account (submit) | `id` `name` `email` `address` |
| `/home/upload` | GET/POST | Customer | Upload Documents | `file` |
| `/home/upload/avatar` | POST | Customer | Upload Documents | `avatar` |
| `/home/pay` | GET | Customer | My Dashboard | — |
| `/home/pdf` | POST | Customer | My Dashboard | `month` `year` |
| `/uploads/` | GET | Anyone | Upload Documents (footer) | — |
| `/logout` | POST | Customer | Account Dropdown | — |
| `/admin` | GET | Staff | Admin Dashboard | `customerId` `initial` `final` `month` `year` |
| `/admin/customers` | GET | Staff | Customers | `q` |
| `/admin/store` | POST | Staff | Admin Dashboard | — |
| `/admin/updaterate` | POST | Staff | Admin Dashboard | `rate` |
| `/admin/tools/ping` | GET | Staff | Diagnostics | `host` |
| `/admin/logout` | POST | Staff | Account Dropdown | — |

A few things worth noting from the map:

- `/lookup` and `/quick/check` are both reachable without logging in and both take a `connection` parameter — unauthenticated inputs that hit the database are always worth attention.
- `/home/profile/update` submits over **GET** with no CSRF token. This is confirmed in view-source — a state-changing action over GET means no token is possible, which feeds directly into Task 18.
- `/admin/updaterate` takes a `rate` field that sets the billing rate for all 41,300 customers. Financial impact makes this a high-value target once inside the admin panel.

> **Screenshot:** `/lookup?connection=` and `/quick/check?connection=` URL parameters visible in Burp

---

## Roles & Boundaries

| Role | Pages accessible |
|---|---|
| Anonymous | Home, Login, Register, Bill Lookup, Quick Check, Staff Login, password reset, `/uploads/` |
| Customer (`m.holloway`) | All of the above plus `/home/*` — dashboard, account, uploads, pay, pdf |
| Staff (`a.deshmukh`) | All `/admin/*` — dashboard, customers, diagnostics, updaterate |

The customer→staff boundary is enforced server-side. Sending `GET /admin` with a customer session cookie returns a 302 redirect to `/login`. The UI boundary matches the server-side enforcement here.

---

## Stack Fingerprint

Pulling signals from Burp response headers, the debug error page, cookie format, and Nikto output:

| Signal | Observed | Implies |
|---|---|---|
| `Server` | `Apache/2.4.67 (Debian)` | Apache on Debian; Nikto flags it as outdated (≥2.4.68 current) |
| `X-Powered-By` | Not sent | Stripped, but PHP confirmed by other signals |
| Session cookie | `electra_session` | Laravel `{iv,value,mac}` encrypted format — Laravel/PHP app with renamed default cookie |
| CSRF token | `csrf-token` meta + `_token` hidden field | Laravel CSRF protection active on POST forms |
| Error page | Laravel Ignition debug page | Debug mode on in production — full stack traces, source paths, and env vars leak on any error |
| Database | MariaDB (from SQL error) | MySQL-family injection syntax |
| Internal IP | `10.0.2.100` in `/images` Location header | Private IP disclosed via HTTP redirect (Nikto) |
| Security headers | None of: CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | No browser-level XSS mitigation — makes any XSS finding worse |
| Front end | Bootstrap + jQuery | — |

The combination of Laravel/PHP, Apache serving an executable `/uploads/` directory, debug mode on, and no security headers means verbose SQLi, upload→RCE, and XSS→session theft are all viable attack paths on this stack.

> **Screenshot:** Burp response headers showing `Server: Apache/2.4.67 (Debian)` and `Set-Cookie: electra_session`

---

## Cookies & Session

Checking the session cookie after login via Firefox dev tools and the `Set-Cookie` response header in Burp:

| Cookie | HttpOnly | Secure | SameSite |
|---|---|---|---|
| `electra_session` | **No** | No | None |

The session cookie is readable from JavaScript — `HttpOnly` is not set. This means any XSS that executes in the browser can read `document.cookie` and steal the session outright. `Secure` being unset also means the cookie transmits over plain HTTP. Nikto independently flagged this (`[000029]: Cookie electra_session created without the httponly flag`).

This single cookie flag is what makes the stored XSS in Task 12 turn into full account takeover rather than just a visual injection.

> **Screenshot:** Firefox dev tools Storage tab showing `electra_session` with HttpOnly: false and Secure: false

> **Screenshot:** Burp `Set-Cookie` response header confirming no flags

---

## Probe Results

After mapping the surface I did a light probe pass — throwing break characters at every input and watching for differences in the response. The goal here is to locate weaknesses, not exploit them.

### SQL Injection

**`/lookup?connection='`** immediately returned a verbose database error:

```
SQLSTATE[42000]: Syntax error: 1064 You have an error in your SQL syntax
SQL: SELECT id, customerId, month, year, units, amount, status FROM bills WHERE customerId = '''
```

This gives away the table name (`bills`), all seven column names, and confirms the input lands in a single-quoted string context. Feeds Tasks 8 and 10.

**`/login` with `email='`** triggered the Laravel Ignition debug page with a different query:

```
SQL: SELECT * FROM users WHERE email = ''' AND password = MD5(''') LIMIT 1
```

Two things in that one query: SQLi confirmed on the login form (`email` field, string context), and passwords are stored as plain **MD5 with no salt**. MD5 is a broken hashing algorithm — any password in the `users` table is trivially crackable with a wordlist. Feeds Tasks 5 and 11.

The Ignition page itself is worth noting separately — it leaks the full stack trace, source file paths (`app/Http/Controllers/Auth/LoginController.php`), all POST data, cookies, and server environment variables. Debug mode running in production is a finding on its own (CWE-209).

> **Screenshot:** Verbose SQL error on `/lookup`

> **Screenshot:** Ignition debug page on `/login` showing query, MD5 password storage, and environment panel

### Reflected XSS

Sending `<script>alert(1)</script>` as the `connection` value on `/lookup` fired an alert box in the browser. The input is reflected directly into the page without encoding or sanitisation. Same parameter as the SQLi finding — two separate vulnerabilities on a single input.

> **Screenshot:** XSS alert firing from `/lookup?connection=<script>alert(1)</script>`

### Upload Filter

Submitting `shell.php` to both uploaders:

| Uploader | Result |
|---|---|
| `/home/upload` (document) | Blocked silently by extension filter |
| `/home/upload/avatar` (photo) | `File type not allowed: .php` |

Both check the file extension. Neither was tested against alternative PHP extensions (`.phtml`, `.php5`, `.pht`) or Content-Type spoofing — that's the work of Tasks 7, 13, and 16.

> **Screenshot:** `File type not allowed: .php` error message on the avatar uploader

### Hidden Fields & IDOR Setup

View-source on `/home/profile` reveals a hidden `id` field with value `1`:

```html
<form method="GET" action="http://192.168.77.80/home/profile/update">
    <input type="hidden" name="id" value="1">
```

Value `1` is a small integer — almost certainly sequential. Flipping this to `2`, `3`, etc. in Burp is the IDOR test for Task 6. The form also confirms the GET method noted in the endpoint map.

For `/lookup`, the `connection` parameter takes a 10-digit ID that isn't sequential or guessable by incrementing — valid IDs would need to come from the admin customer directory or a SQLi dump. Not a viable IDOR path without prior enumeration.

> **Screenshot:** View-source of `/home/profile` showing hidden `id=1` and `method="GET"`

---

## Information Leaks

The two required deliverables for this task. Found via `robots.txt` and content discovery.

`robots.txt` returned the following:

```
User-agent: *
Disallow: /uploads/
Disallow: /backup/
Disallow: /install-notes.txt
```

> **Screenshot:** `robots.txt` contents in browser

This is a classic mistake — `robots.txt` is public, so listing sensitive paths in it advertises exactly what to request. All three paths were tested directly. `/backup/` returned 404 (not present). The other two are the two leaks below.

---

### Leak 1 — `install-notes.txt` *(Critical — CWE-200)*

**Path:** `http://192.168.77.80/install-notes.txt`
**Found:** listed in `robots.txt`; confirmed 200 by gobuster

```
eLECTRA v2.4.1 - DEPLOYMENT NOTES

Staff portal: /admin/login
  * Billing operations manager : a.deshmukh@electra.lab / admin123   <-- CHANGE THIS
  * Support supervisor         : v.malone@electra.lab  / trustno1    <-- CHANGE THIS

Database (local MariaDB)
  name: electra  user: electraapp  password: electra123              <-- CHANGE THIS

NOTES
  * Customer documents/photos stored in public /uploads/ (must stay web-reachable)
  * /uploads/ has "options +indexes" so staff can browse customer docs
  * Old bill-lookup API rewritten in "raw SQL" - app/Http/Controllers/LabController.php
  * Staff diagnostics tool (ping) requires "iputils-ping"
  * TODO: move this file out of web root before the audit (ticket SD-1184)
```

**What this reveals:** This file alone gives an unauthenticated attacker everything needed to fully compromise the application without running a single exploit. Staff credentials in plaintext provide immediate `/admin` access. Database credentials expose the entire backend. The note pointing to `LabController.php` names the exact file behind the `/lookup` SQL injection. The mention of `iputils-ping` confirms the attack vector for the command injection task. The `CHANGE THIS` comments and the open ticket (SD-1184) show that none of this was cleaned up before going live.

> **Screenshot:** `install-notes.txt` contents in browser

---

### Leak 2 — `/uploads/` Directory Listing *(Medium — CWE-548)*

**Path:** `http://192.168.77.80/uploads/`
**Found:** linked in the Upload Documents page footer; accessible anonymously

```
Index of /uploads
Apache/2.4.67 (Debian) Server at 192.168.77.80 Port 80
```

**What this reveals:** Directory indexing is enabled, confirmed as intentional by the `options +indexes` note in `install-notes.txt`. Any customer document uploaded to the app — meter photos, proof of payment — is browsable by anyone without authentication. More critically, any file placed in this directory is reachable at a predictable URL. That reachability is the second half of the upload→RCE chain: getting a malicious file past the filter is step one; having a URL to trigger it is step two. Both are now confirmed.

Nikto flagged `/css/` and `/images/` as also having directory listing enabled, suggesting this is a server-wide misconfiguration rather than a deliberate choice for `/uploads/` alone.

> **Screenshot:** `http://192.168.77.80/uploads/` showing Apache directory listing

---

## Content Discovery Output

gobuster:

> **Screenshot:** gobuster output showing hits including `robots.txt` (200), `install-notes.txt` (200), `web.config` (200), `/uploads/` (301), `/admin` (302)

Nikto:

> **Screenshot:** Nikto output

Notable Nikto findings not covered elsewhere: missing security headers across the board (no CSP, HSTS, X-Content-Type-Options), internal IP `10.0.2.100` disclosed via Location header on `/images`, and independent confirmation of the missing `HttpOnly` flag on `electra_session`.

---

## Leads Forward

Everything found in this phase maps to a later task:

| Finding | Task |
|---|---|
| `/lookup` `connection` — SQLi, verbose, `bills` table, 7 cols | 8, 10 |
| `/quick/check` `connection` — SQLi, likely blind | 9, 10 |
| `/login` `email` — SQLi auth bypass | 5 |
| `users` table passwords stored as MD5 | 11 |
| `/lookup` `connection` — reflected XSS | 4 |
| `/home/profile/update` `name`/`address` — stored XSS sink | 12 |
| `electra_session` no HttpOnly — session theft via XSS | 12 |
| `/home/upload` + `/home/upload/avatar` — extension filter bypass | 7, 13, 16 |
| `/uploads/` web-reachable and executable | 7, 13, 16 |
| `/home/profile/update` `id=1` — IDOR | 6 |
| `/home/profile/update` via GET, no token — CSRF | 18 |
| `/admin/tools/ping` `host` — command injection | 17 |
| `/admin/updaterate` `rate` — rate tampering, 41,300 customers | 14 |
| `install-notes.txt` staff creds — direct admin access | 14 |
