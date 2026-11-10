# Recon & Discovery

**Target:** `http://192.168.77.80` — eLECTRA, Springfield Power & Light billing portal
**Accounts:** `m.holloway@electra.lab` (customer), anonymous, `a.deshmukh@electra.lab` (staff acc recovered from info leak)
**Tools:** Burp Suite, gobuster, Nikto, Firefox dev tools

---

The goal of this phase is to build a complete picture of the application before touching anything offensively.

---

## Mapping the Application

I started by browsing the app with Burp Intercept off while letting Proxy history record every request automatically. I added the host to scope and filtered to in-scope to keep the history clean. I navigated through the app three times, once as an anonymous visitor, once logged in as `m.holloway`, and once using the staff credentials recovered later from `install-notes.txt`.

Alongside manual browsing I ran gobuster and Nikto to catch anything the navigation didn't surface:

```bash
gobuster dir -u http://192.168.77.80 -w /usr/share/wordlists/dirb/common.txt -x php,txt,zip,sql,bak
nikto -h http://192.168.77.80
```

> **Screenshot of Short Snippet of Burp History:**

<img width="915" height="416" alt="image" src="https://github.com/user-attachments/assets/5853a911-86c8-469e-be5e-511b12dc772d" />

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

- `/lookup` and `/quick/check` are both reachable without logging in and both take a `connection` parameter.
- `/home/profile/update` submits over **GET** with no CSRF token.
- `/admin/updaterate` takes a `rate` field that sets the billing rate for all customers. Financial impact makes this a high-value target once inside the admin panel.

> **Screenshot:** `/lookup?connection=` and `/quick/check?connection=` (example id used) URL parameters visible in Burp

<img width="676" height="22" alt="image" src="https://github.com/user-attachments/assets/eacaf900-edf0-4ba0-afba-d8f006195d23" />

<img width="676" height="28" alt="image" src="https://github.com/user-attachments/assets/d611caf9-3d76-4c7e-96c1-b473a0aac949" />

---

## Roles & Boundaries

| Role | Pages accessible |
|---|---|
| Anonymous | Home, Login, Register, Bill Lookup, Quick Check, Staff Login, password reset, `/uploads/` |
| Customer (`m.holloway`) | All of the above plus `/home/*` — dashboard, account, uploads, pay, pdf |
| Staff (`a.deshmukh`) | All `/admin/*` — dashboard, customers, diagnostics, updaterate |

The customer -> staff boundary is enforced server-side. Sending `GET /admin` with a customer session cookie returns a 302 redirect to `/login`.

---

## Stack Fingerprint

Pulling signals from Burp response headers, the debug error page, cookie format, and Nikto output:

| Signal | Observed | Implies |
|---|---|---|
| `Server` | `Apache/2.4.67 (Debian)` | Apache on Debian; Nikto flags it as outdated (≥2.4.68 current) |
| `X-Powered-By` | Not sent | Stripped, but PHP confirmed by other signals |
| Session cookie | `electra_session` | Laravel `{iv,value,mac}` encrypted format — Laravel/PHP app with renamed default cookie |
| CSRF token | `csrf-token` meta + `_token` hidden field | Laravel CSRF protection active on POST forms |
| Error page | Laravel Ignition debug page | Debug mode on in production |
| Database | MariaDB (from SQL error) | MySQL-family injection syntax |
| Security headers | None of: CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | No browser-level XSS mitigation — makes any XSS finding worse |
| Front end | Bootstrap + jQuery | — |

The combination of Laravel/PHP, Apache serving an executable `/uploads/` directory, debug mode on, and no security headers means verbose SQLi, upload -> RCE, and XSS -> session theft are all viable attack paths on this stack.

> **Screenshot:** Burp response headers showing `Server: Apache/2.4.67 (Debian)` and `Set-Cookie: electra_session`

<img width="252" height="27" alt="image" src="https://github.com/user-attachments/assets/cc24ed0e-de5a-48bb-942a-3f68e4477b8c" />

<img width="774" height="77" alt="image" src="https://github.com/user-attachments/assets/ddcbc23a-a680-4d7f-ad84-9a6b98b0339b" />

---

## Cookies & Session

Checking the session cookie after login via Firefox dev tools and the `Set-Cookie` response header in Burp:

| Cookie | HttpOnly | Secure | SameSite |
|---|---|---|---|
| `electra_session` | **No** | No | None |

The session cookie is readable from JavaScript as `HttpOnly` is not set. This means any XSS that executes in the browser can read `document.cookie` and steal the session. `Secure` being unset also means the cookie transmits over plain HTTP. Nikto flagged this (`[000029]: Cookie electra_session created without the httponly flag`).

> **Screenshot:** Firefox dev tools Storage tab showing `electra_session` with HttpOnly: false and Secure: false

<img width="297" height="227" alt="image" src="https://github.com/user-attachments/assets/a1fd1d7e-af64-4159-8bfe-6c88b7d79d79" />

---

## Probe Results

After mapping the surface I did a light probe pass of throwing break characters at every input and watching for differences in the response. The goal here is to simply find potential weaknesses.
### SQL Injection

**`/lookup?connection='`** immediately returned a verbose database error:

```
SQLSTATE[42000]: Syntax error: 1064 You have an error in your SQL syntax
SQL: SELECT id, customerId, month, year, units, amount, status FROM bills WHERE customerId = '''
```

This gives away the table name (`bills`), all seven column names, and confirms the input lands in a single-quoted string context.

**`/login` with `email='`** triggered the Laravel Ignition debug page with a different query:

```
SQL: SELECT * FROM users WHERE email = ''' AND password = MD5(''') LIMIT 1
```

Two things in that one query: SQLi confirmed on the login form (`email` field, string context), and passwords are stored as plain **MD5 with no salt**. MD5 is a broken hashing algorithm — any password in the `users` table is trivially crackable with a wordlist. Feeds Tasks 5 and 11.

The Ignition page itself is worth noting separately — it leaks the full stack trace, source file paths (`app/Http/Controllers/Auth/LoginController.php`), all POST data, cookies, and server environment variables. Debug mode running in production is a finding on its own (CWE-209).

> **Screenshot:** Verbose SQL error on `/lookup`

<img width="937" height="465" alt="image" src="https://github.com/user-attachments/assets/c244a7ef-7104-4770-81b5-567e6a1291ec" />

> **Screenshot:** Ignition debug page on `/login` showing query, MD5 password storage, and db details from environment panel

<img width="779" height="297" alt="image" src="https://github.com/user-attachments/assets/57c31c00-f7ba-4807-9cb3-f0d99b5d6c62" />

<img width="1298" height="484" alt="image" src="https://github.com/user-attachments/assets/d92485f6-205d-4135-ad70-c93e4b466de0" />

<img width="436" height="67" alt="image" src="https://github.com/user-attachments/assets/4fde1671-0334-4605-b9f9-6405925f5c95" />

### Reflected XSS

Sending `<script>alert(1)</script>` as the `connection` value on `/lookup` fired an alert box in the browser. The input is reflected directly into the page without encoding or sanitisation.

> **Screenshot:** XSS alert firing from `/lookup?connection=<script>alert(1)</script>`

<img width="1488" height="799" alt="image" src="https://github.com/user-attachments/assets/9813df34-5f43-4f20-9c47-2491da76c742" />

### Upload Filter

Submitting `shell.php` to both uploaders:

| Uploader | Result |
|---|---|
| `/home/upload` (document) | Blocked by extension filter |
| `/home/upload/avatar` (photo) | `File type not allowed: .php` |

Both check the file extension. Neither was tested against alternative PHP extensions (`.phtml`, `.php5`, `.pht`) or Content-Type spoofing — that's the work of Tasks 7, 13, and 16.

> **Screenshot:** Both upload options limit the file type allowed. In exploitation steps will try alternatives.
> 
<img width="753" height="230" alt="image" src="https://github.com/user-attachments/assets/47e21bf8-0318-47ab-b8f8-efbec3f5cd5c" />

<img width="744" height="253" alt="image" src="https://github.com/user-attachments/assets/7c1c1f84-79c8-439f-9acc-91f03f38da41" />

### Hidden Fields & IDOR Setup

## 6. Hidden Fields & IDOR Setup

View-source on `/home/profile` reveals a hidden `id` field with value `1`:

```html
<form method="GET" action="http://192.168.77.80/home/profile/update">
    <input type="hidden" name="id" value="1">
```

Value `1` is a small integer which almost certainly means the ID will go sequentially. To test this I sent the profile update request to Repeater and changed `id=1` to `id=4` with a non-conflicting email address. The server returned **302 -> `/home`** which was a successful update. The app ran `UPDATE users WHERE id=4` against a different account using my customer session with no check that `id=4` belonged to me.

An earlier attempt with `id=4` but the m.holloway email returned a 500 error. This means that rather than an access control rejection it was a database uniqueness constraint violation. The app tried to write and only failed because my email already existed in the table.

For `/lookup`, the `connection` parameter takes a 10-digit ID that isn't sequential or guessable by incrementing the number. A valid ID would likely need to come from the admin customer directory or a SQLi dump.

| Test | Result |
|---|---|
| `GET /home/profile/update?id=4&email=a.test@electra.lab` | 302 -> `/home`. Write succeeded on another user's record. IDOR confirmed — CWE-639. |
| `/lookup?connection=` ±1 | "No statements found" — IDs not guessable by enumeration. |

> **Screenshot:** View-source of `/home/profile` showing hidden `id=1` and `method="GET"`

<img width="660" height="38" alt="image" src="https://github.com/user-attachments/assets/a2acb4d7-ce9d-4a32-9af8-6f7558d2f4b8" />

> **Screenshot:** Burp Repeater showing `id=4` request with 302 response

<img width="1547" height="617" alt="image" src="https://github.com/user-attachments/assets/dbac50b7-a40e-4648-82ad-e2f55c2d6de3" />

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
