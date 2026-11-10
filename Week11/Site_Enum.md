# Mapping the Application

Before exploiting anything, build a complete picture of eLECTRA: every page, form, parameter, cookie, and role boundary. This map is the reference every later task reaches back into, so the goal here is to be as thorough as possible.

- **Target:** `http://192.168.77.80/` (eLECTRA website)
- **Accounts:** `m.holloway@electra.lab` (customer) · anonymous (logged out)
- **Deliverable:** the filled-in endpoint map below + notes on two information leaks

---

## Approach

Browse with Burp Intercept off and let Proxy → HTTP history record every request. Walk the whole app once per role, then read the history back to fill in the tables below. Right-click the host → *Add to scope* and filter history to in-scope. Highlighting start and end points helps reduce confusion once the requests pile up.

Role order:

1. **Anonymous** — logged out / private window
2. **Customer** — `m.holloway`
3. **Staff** — can't reach yet; recorded as a *boundary* rather than left blank

---

## 1. Endpoint map

| Endpoint | Method | Who can reach | Where in the UI | Interesting input |
|---|---|---|---|---|
| `/` | GET | Anyone | nav: Home Page | None |
| `/login` | GET (page) / POST (submit) | Anyone | nav: Login & Customer Login | `email` `password` |
| `/quick/check` | GET | Anyone | nav: Quick Check | `connection` |
| `/lookup` | GET | Anyone | nav: Bill Lookup | `connection` |
| `/register` | POST | Anyone | nav: Register & New Connection | `name` `email` `connectionId` `address` `password` `confirm password` |
| `/admin/login` | GET (page) / POST (submit) | Anyone | nav: Staff & Staff Login | `email` `password` |
| `/password/reset` | POST | Anyone | nav: Login / Staff → "Forgot Your Password?" | `email` |
| `/home` | GET | Customer | nav: My Dashboard & Home | None |
| `/home/profile` | GET | Customer | nav: My Account | `full name` `email` `billing address` `new password` |
| `/home/profile/update` | POST | Customer | My Account (submit) | `id` |
| `/home/upload` | GET/POST | Customer | nav: Upload Documents | `file`  `filename` + part `Content-Type` (upload filter) |
| `/home/upload/avatar` | POST | Customer | My Account / Upload | `avatar`  `filename` + part `Content-Type` |
| `/home/pay` | GET | Customer | nav: My Dashboard | None |
| `/home/pdf` | POST | Customer | My Dashboard | `month` `year` |
| `/uploads/` | GET | Anyone | footer link on Upload page | Directory listing enabled; stored files web-reachable/executable |
| `/logout` | POST | Customer | nav: User Account Dropdown | need `_token` |
| `/admin` | GET | Staff | nav: Admin Dashboard | `Customer Id` `initial` `final` `month` `year` |
| `/admin/customers` | GET | Staff | nav: Customers | `q` |
| `/admin/tools/ping` | GET | Staff | nav: Diagnostics | `host` |
| `/admin/updaterate` | POST | Staff | nav: Admin Dashboard | `rate` |
| `/admin/store` | POST | Staff | nav: Admin Dashboard | Same as /admin  |
| `/admin/logout` |	POST |	Staff	| nav: Admin Account Dropdown	| need `_token` |
Screenshots:

/lookup?connection=

<img width="404" height="26" alt="image" src="https://github.com/user-attachments/assets/f3090fe6-c222-448a-92dc-f81c30bf848e" />

/quick/check?connection=

<img width="347" height="25" alt="image" src="https://github.com/user-attachments/assets/cfa70e78-9c0f-4fab-ab9f-516932fa8b7f" />

---

## 2. Roles & boundaries

| Role | Nav / Pages Visible | Notes |
|---|---|---|
| Anonymous | Home, Customer Login, Register/New Connection, Bill Lookup, Quick Check, Staff Login, password reset, /uploads/ | `/lookup` and `/quick/check` reachable with no auth and both take `connection` |
| Customer (`m.holloway`) | My Dashboard, My Account, Upload Documents, pay, pdf, logout | all `/home/*` |
| Staff | Admin Dashboard (`/admin`), Customers (`/admin/customers`), Diagnostics (`/admin/tools/ping`) | require staff role; `/admin` returns **302 → /login** when unauth (gobuster) |

---

## 3. Cookies & session flags

| Cookie | HttpOnly | Secure | SameSite | Notes |
|---|---|---|---|---|
| `electra_session` | No | No | None | Laravel session cookie (renamed from default `laravel_session`). Max-Age 7200. Confirmed via dev tools + `Set-Cookie` response header. |

**What this reveals to an attacker:** `electra_session` carries the logged-in session, and with `HttpOnly` unset it is readable from JavaScript via `document.cookie` this means that any XSS becomes full session theft / account takeover. `Secure` unset also means it is sent over plain HTTP and exposed to network sniffing. Feeds the stored-XSS / session-hijacking task.

---

## 4. Stack fingerprint

| Signal | Value observed | Implies |
|---|---|---|
| `Server` header | Apache/2.4.67 (Debian) | Apache on Debian; `/uploads/` is server-executed -> `.htaccess` hijack plausible |
| `X-Powered-By` | Not sent | Stripped, but other signals confirm PHP |
| Session cookie name | `electra_session` | Laravel cookie format (`{iv,value,mac}`), renamed from default → Laravel/PHP |
| CSRF token | `csrf-token` meta + `_token` hidden field | Laravel CSRF protection on POST forms |
| Error-page style | Verbose MariaDB SQL error shown in-page | DB = MariaDB; debug/verbose errors on → leaks queries (CWE-209) |
| Database | MariaDB (from SQL error) | MySQL-family syntax for injection |
| Front end | Bootstrap + jQuery (`app.js`, `app.css`) | — |

**Summary:** Laravel/PHP app on Apache/Debian, MariaDB backend, debug errors enabled. This combo puts verbose SQLi, upload→RCE, and XSS→session theft all in play.

---

## 5. Hidden fields & parameters

| Form / page | Hidden / non-obvious field | Value seen | Why it's interesting |
|---|---|---|---|
| Logout form | `_token` | Laravel CSRF token | Confirms POST state changes are CSRF-protected |
| All pages | `csrf-token` meta | matches `_token` | CSRF task must target a state change that *lacks* a token |
| `/lookup` | `connection` reflected in page | `'` → `&#039;` | Input reflected but HTML-encoded in `value` attr (escaped there) |
| Upload (multipart) | `filename`, part `Content-Type` | client-controlled | Upload-filter bypass vectors |

---

## 6. State changes over GET

Candidate to verify during the CSRF task — the CSRF finding depends on a state change that happens over GET (no token possible).

- `/home/profile/update` — confirm whether the profile update accepts GET; if so, token-less → CSRF (Task 18).
- Logout is POST + `_token` (protected — not a candidate).

---

## 7. Information leaks *(deliverable)*

Found via `robots.txt` and gobuster content discovery, then read directly.

`robots.txt` (ironically advertises the sensitive paths):

<img width="623" height="157" alt="image" src="https://github.com/user-attachments/assets/506ee9f0-99eb-4815-9719-47e6b951a8ba" />

`install-notes.txt`:

<img width="692" height="433" alt="image" src="https://github.com/user-attachments/assets/ca2af2cc-13e4-45c1-bcf9-d62e3de92347" />

gobuster output:

```
gobuster dir -u http://192.168.77.80 -w /usr/share/wordlists/dirb/common.txt -x php,txt,zip,sql,bak
```

<img width="785" height="312" alt="image" src="https://github.com/user-attachments/assets/e66aa008-7441-443c-95a1-541b48e170d4" />

Checklist results:

- [x] `robots.txt` — Disallow: `/uploads/`, `/backup/`, `/install-notes.txt`
- [x] `install-notes.txt` — present (200)
- [x] `/uploads/` — directory listing enabled (200)
- [ ] `web.config` — present (200); IIS rewrite rules, low value
- [ ] `/backup/` — listed in robots.txt but returns 404
- [ ] `sitemap.xml`, `README`, `.git/`, `db.sql`/`web.zip` — not found

### Leak 1 — `install-notes.txt`

- **File / path:** `http://192.168.77.80/install-notes.txt`
- **How found:** named in `robots.txt` and confirmed with status 200 via gobuster
- **Contents (relevant part):**

```
eLECTRA v2.4.1 - DEPLOYMENT NOTES

Staff portal: /admin/login
  * Billing operations manager : a.deshmukh@electra.lab / admin123
  * Support supervisor         : v.malone@electra.lab  / trustno1

Database (local MariaDB)
  name: electra  user: electraapp  password: electra123

NOTES
  * Customer documents/photos stored in public /uploads/ (must stay web-reachable)
  * /uploads/ has "options +indexes" so staff can browse customer docs
  * Old bill-lookup API rewritten in "raw SQL" - app/Http/Controllers/LabController.php
  * Staff diagnostics tool (ping) requires "iputils-ping"
  * TODO: move this file out of web root before the audit (ticket SD-1184)
```

- **What this reveals to an attacker:** full pre-auth compromise. Plaintext **staff credentials** give direct `/admin` access with no exploitation needed; **DB credentials**, the **vulnerable controller** behind the `/lookup` SQLi, the intentionally-executable `/uploads/` directory, and the command-injection package for the diagnostics tool are all disclosed. Critical (CWE-200).

### Leak 2 — `/uploads/` directory listing

- **File / path:** `http://192.168.77.80/uploads/`
- **How found:** footer link on the Upload page; confirmed anonymous access
- **Contents (relevant part):**

```
Index of /uploads
Name  Last modified  Size  Description
Parent Directory       -
Apache/2.4.67 (Debian) Server at 192.168.77.80 Port 80
```

- **What this reveals to an attacker:** directory indexing is enabled, so stored customer documents (meter photos, proof-of-payment) are browsable, and any file placed here is reachable at a predictable URL — the "reachable + executable" half of the upload→RCE chain. Also confirms Apache/2.4.67 (Debian). Medium–High (CWE-200).

---

## Leads forward

| Input / endpoint | Suspected weakness | Task it feeds |
|---|---|---|
| `/lookup` `connection` | SQLi — verbose/error-based (`bills` table, 7 cols, string context) | 8, 10 |
| `/quick/check` `connection` | SQLi — likely blind | 9, 10 |
| `/login`, `/admin/login` `email` | SQLi auth bypass | 5 |
| `install-notes.txt` staff creds | direct staff login (no exploit needed) | 5 / 14 shortcut |
| `/home/upload`, `/home/upload/avatar` `filename` / `Content-Type` | upload filter bypass → RCE | 7, 13, 16 |
| `/uploads/` (executable, indexed) | reachable/executable payload location | 7, 13, 16 |
| `/home/profile/update` fields | stored XSS / write-query SQLi / IDOR (`id`) | 6, 12, 15 |
| `electra_session` (no HttpOnly) | session theft via XSS | 12 |
| `/admin/tools/ping` `host` | OS command injection (`iputils-ping`) | 17 |
| `/register` `connectionId` | account-binding / IDOR | 6 |
| `_token` present on POST | CSRF needs a token-less GET state change | 18 |

---

## Evidence

Screenshots captured: endpoint probes (`/lookup`, `/quick/check`), cookie flags panel + `Set-Cookie`, verbose SQL error on `/lookup`, `robots.txt`, `install-notes.txt`, and gobuster output.
