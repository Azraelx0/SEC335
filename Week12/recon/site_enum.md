# Site Recon & Enumeration

**Target:** `http://192.168.77.90/` — a simulated lab instance of the Centurion University of Technology and Management (Bhubaneswar) online admission portal, identified during enumeration as **OAS v1.2 (Online Admission System)**.

**Scope & Authorization:** Testing was limited to the single host `192.168.77.90`, under explicit authorization. This is a training replica and is **not** affiliated with, nor representative of, the live Centurion University production environment.

**Objective:** Build a complete picture of the application's attack surface before any exploitation, following the OWASP Web Security Testing Guide (WSTG) information-gathering methodology. Candidate vulnerabilities are tagged by WSTG category and consolidated in the *Leads Forward* table at the end. Nothing in this phase was exploited.

---

## Nmap

The tester began with a full TCP port sweep to broadly identify open ports:

```
nmap -p- --min-rate 2000 -oA scans/nmap-allports 192.168.77.90
```

<img width="633" height="296" alt="image" src="https://github.com/user-attachments/assets/3b6e9cd9-643e-478d-be92-425076ab44f8" />

The open ports were then version and script-scanned:

```
nmap -sC -sV -p 80,11010,11011,11012,11013,15888 -oA scans/nmap-services 192.168.77.90
```

<img width="831" height="316" alt="image" src="https://github.com/user-attachments/assets/4d40cd4c-e4b9-49d6-900c-98afa75aceb9" />

**Port 80 (target).** The service was identified as `Apache httpd 2.4.67 (Debian)` serving a PHP application (`PHPSESSID` cookie). Several findings surfaced from the default scripts alone:

- The application is served over **HTTP with no TLS**, so credentials and session cookies are transmitted in cleartext and are exposed to interception and man-in-the-middle attacks (candidate: CWE-319, WSTG-CRYP).
- The `PHPSESSID` session cookie is set **without the HttpOnly flag**, exposing it to theft via client-side script (candidate: CWE-1004, WSTG-SESS).
- The Apache version was recorded for later cross-reference against known issues.
- The `robots.txt` metafile disclosed four disallowed entries: `/install-notes.txt`, `/studentdoc/`, `/studentpic/`, and `/studentproof/`.

**High ports (11010–11013, 15888).** These were also open. Version and script output with Rust `rcgen`-generated self-signed certificates and the EasyTier default port 11010 both indicate that these are lab management / mesh-networking services used to reach the range, and not components of the target application. They were enumerated for completeness and then scoped out of this engagement. It is noted as **residual risk** that, because these services share a host with the web application, a compromise of any of them would also compromise the web application and its data.

## Fingerprinting the Stack (WSTG-INFO-02, WSTG-INFO-08)

To confirm the server technology and framework, the tester ran `whatweb`:

<img width="1881" height="76" alt="image" src="https://github.com/user-attachments/assets/c6eb5c58-ec19-4f4a-9e03-5e4f93a1de2a" />

A direct request was then issued with `curl` to review the raw response headers:

<img width="524" height="195" alt="image" src="https://github.com/user-attachments/assets/82a1411b-ad4f-47fa-978c-d8bbe65bcd18" />

Finally, `wafw00f` was run to check for a web application firewall. None was detected:

<img width="698" height="444" alt="image" src="https://github.com/user-attachments/assets/fd9e5841-e7c2-4cde-913b-1562122750da" />

Together these confirmed an Apache 2.4.67 / PHP stack with no WAF in front of it, meaning requests reach the application unfiltered which will become relevant later, as the application's only input guard (`filter.js`) is client-side and therefore bypassed with a proxy.

## Passive Mapping with Burp (WSTG-INFO-06, WSTG-INFO-07)

The application was mapped with Burp Suite, intercept off, proxy history recording, with `192.168.77.90` added to scope and filtered to keep the history clean. The site was walked across **all three privilege levels** including: unauthenticated visitor, registered user, and administrator. This was done because the difference between what each role can reach is where access-control flaws can surface.

### Unauthenticated Walk

The home page presents only a login form submitting to `/index.php`. From there, links lead to "Sign Up" and "Track Application." The tester first registered an account:

```
Name:          raihn
Date of Birth: 2026-11-11
Email ID:      raihn@test.com
Mobile No.:    7
```

Registration returned a generated credential pair:

```
Your User ID is CUTM00016 and Password is aiovXovn
You are successfully registered. Please check your email ID or Phone for User ID and Password.
```

Of note: the application **sends email on registration** (the "check your email" message), which becomes relevant to the mail stack discovered later. Submitting the new User ID `CUTM00016` on the Track Application page returned "No application found for that number." The application numbers are sequential (`CUTM00016`) which makes them guessable and a candidate for enumeration / IDOR against `track.php`.

With the publicly reachable endpoints mapped, the tester moved to the directories disclosed by the `robots.txt` metafile (WSTG-INFO-03). While reviewing metafiles, the tester also confirmed the absence of a sitemap and an exposed git repository; neither was present:

```
curl -s http://192.168.77.90/sitemap.xml
curl -s http://192.168.77.90/.git/HEAD
```

The highest-value entry, `/install-notes.txt`, was then examined, as deployment-notes files of this kind are frequently a significant information leak:

<img width="636" height="366" alt="image" src="https://github.com/user-attachments/assets/a7e52eeb-5f7f-429a-a612-e7317dd1bde3" />

This single file (which represents an information-disclosure or CWE-200 / CWE-540) exposed, without any exploitation:

- The application identity and version: **OAS v1.2**.
- **Staff credentials in plaintext** for the `/adminlogin.php` console — Admission manager `AD00000001` / `admin` and Assistant manager `AD00002` / `QCoxFrwx`.
- **Database credentials** — MySQL `root` with no password, schema `oas`.
- Confirmation that **directory listing was intentionally left enabled** on `studentpic/`, `studentdoc/`, and `studentproof/` so documents can be browsed without logging in.
- A previously hidden network tool at `/tools.php`.

The file was immediately extracted to the testing host, saved to the evidence store, and hashed (SHA-256) with a UTC timestamp to preserve its integrity, as the file's own TODO note indicated it was planned to be removed before the application went live.

The three document directories were then browsed directly. `/studentdoc/` contained PDFs (course syllabus, schedule, module material); `/studentpic/` contained JPG images, presumably of applicants, and `/studentproof/` contained a mix of JPGs and PDFs including identity documents and a signature image. In every case **directory listing was enabled** (CWE-548), allowing an unauthenticated visitor to browse applicants' uploaded documents which confirmed the misconfiguration advertised in the install notes.

Next, `/tools.php` was examined. This was a diagnostic page that checks whether the admission server can reach a host on the campus network. It was tested against `127.0.0.1`:

<img width="1183" height="436" alt="image" src="https://github.com/user-attachments/assets/c6df1119-18dc-4723-903d-ffd3c7673a82" />

A host-reachability/"ping" utility that passes a user-supplied `host` value to a system command is a **command-injection** candidate (CWE-78) and was flagged for the exploitation phase.

The "Back to admin console" option on `/tools.php` leads to `/admin.php`, which at first glance only states "You are not Logged In Please Login to Access this Page." Viewing the page source, however, revealed that the full administrative `<head>` and JavaScript, including back-end endpoints `readID.php` and `global_search.php` and the `srchk`/`srchk1` parameters, are **served to an unauthenticated request**. The access gate blocks the admin *data* but not the admin page's *source*, disclosing the administrative attack surface (candidate: broken access control / information disclosure, CWE-200 / CWE-284).

<img width="632" height="175" alt="image" src="https://github.com/user-attachments/assets/5fcdd43c-d1ee-421b-83c6-a4450580786b" />

Following the login prompt revealed `/adminlogin.php`. The tester submitted `test` / `test` to capture the POST request shape in Burp. The site then returned "Invalid Login! Please try again." The admin login fields (`a_id`, `a_ps`) are guarded only by the client-side `filter.js`, making them a **SQL-injection auth-bypass** candidate. This concludes the walk from an unauthenticated user.

### Registered-User Walk

Logging in as the registered user revealed a large multi-field **admission form**. Completing and submitting it produced the following request in Burp:

<img width="1036" height="469" alt="image" src="https://github.com/user-attachments/assets/fad18c14-064a-4d65-8e9a-252e03243562" />

The form posts a large parameter set to `/admsnform.php`. One parameter is highlighted: **`detid`**, a hidden field passing a blank value. This matches a recurring pattern across the application — `stid`/`stpw` on signup, `txtid` on admin login, and `detid` here — where the client supplies empty ID fields. If the server uses `detid` to select which applicant record to write to, supplying another user's ID is a **write-side IDOR / mass-assignment** candidate (CWE-639 / CWE-915). The form's free-text fields (parents' names, occupations, address, etc.) are also rendered back to the administrator who reviews the application, making them a **stored-XSS** sink (CWE-79), and the whole form performs a database `INSERT`, making it a **SQLi** surface.

Submitting the form redirects to `/documents.php` for supporting-document upload. Testing showed only image file extensions are accepted. A representative POST from this page:

<img width="824" height="334" alt="image" src="https://github.com/user-attachments/assets/f6f73e2e-f6d8-4c27-86d3-296270b7ca67" />

The page exposes seven separate file inputs (passport photo, 10th/12th mark sheets and certificates, identity proof, signature) that land in the three browsable document directories. Because the "images only" restriction is applied client-side and the destination directories are web-reachable, this is a strong **upload-filter-bypass → RCE** candidate (CWE-434). On a successful upload the page displays a verbose back-end status message, "Inserted to DB," in the top-left — a minor information leak that also serves as a useful success/failure oracle for later injection testing:

<img width="1358" height="886" alt="image" src="https://github.com/user-attachments/assets/cd8b5ed0-6365-497d-a5a2-5b870ff29e6a" />

A business-logic flaw was also observed on this page: selecting the "I accept" agreement option immediately advances to `/admsnreport.php` **without requiring document submission**, and if the agreement is not selected the report page is not shown. This indicates the mandatory document-upload step is not enforced server-side — a **workflow-circumvention** candidate (WSTG-BUSL, CWE-840): an application can reach its completed/report state with no documents uploaded. From the report page the only remaining options are to print the report or to use "Login again," which triggers `/logout.php`.

### Administrator Walk

Using the staff credentials recovered from `install-notes.txt`, the tester logged into the admission manager account. The admin console ("Administration Cell") exposes the tabs View Applications, Enter OMR, Enter Marks, Add New Manager, Diagnostics, and Logout. The most significant new endpoints are shown below.

**Administration Cell** — the application list (ID, name, DOB, email, contact, signup date) with per-row Card / approve / reject controls:

<img width="1438" height="887" alt="image" src="https://github.com/user-attachments/assets/3f1937df-3987-46fd-b528-120a221b42fe" />

**Enter OMR:**

<img width="1427" height="448" alt="image" src="https://github.com/user-attachments/assets/59161311-3302-43d6-91e6-c6efe8c27556" />

**Enter Marks:**

<img width="1386" height="458" alt="image" src="https://github.com/user-attachments/assets/947a1b84-2508-4524-b9c6-e448c649dcd2" />

**Add New Manager:**

<img width="1396" height="601" alt="image" src="https://github.com/user-attachments/assets/552308bd-69b3-4632-9a52-159c2a7b136f" />

The admin console (`admin.php`) is a single multi-function handler driven by different submit parameters: `searchtb` (search), `omarkof`/`txtomr`/`submitomr` (OMR), `markof`/`showomr`/`txtmark`/`submitmarks` (Marks), `txtname`/`txteml`/`admcreate` (Add Manager), and `disapp` (reject). The approve/reject and marks actions carry **no anti-CSRF token** and operate on an applicant ID the attacker controls — a combined **CSRF / IDOR** candidate (CWE-352 / CWE-639).

Two observations on Add New Manager: the function accepted a **duplicate** manager (identical name and email, new auto-assigned ID), indicating no uniqueness validation; and the create request ships empty `txtid`/`txtpwd` fields, raising the question of whether a chosen ID and password can be supplied to **create a privileged account with known credentials** (mass-assignment / privilege-escalation candidate, CWE-915).

Two applicant-detail endpoints were also identified — `viewform.php?id=` (full application/PII) and `adminac.php?id=` (admit card) — both keyed on a guessable applicant ID, making them **IDOR** candidates (CWE-639). Given that `admin.php` already leaks its source to unauthenticated requests, these should be tested without an admin session; if they return data, that elevates the issue to **unauthenticated PII disclosure**.

The assistant-manager account was found to expose the identical surface with no additional privileges, so both staff accounts are treated as equivalent. This concludes the passive mapping phase.

### Endpoint Map

| Endpoint | Method | Who can reach | Where in the UI | Interesting input |
|---|---|---|---|---|
| `/` | GET | Anyone | Landing / Login page | — |
| `/index.php` | GET/POST | Anyone | Login form | `u_id` `u_ps` — SQLi auth bypass |
| `/signup.php` -> `/signupconfirm.php` | GET/POST | Anyone | Sign Up | `in_name` `in_dob` `in_eml` `in_mob` `txt_captcha`; empty `stid` `stpw` |
| `/track.php` | GET | Anyone | Track Application | `appno` — IDOR / SQLi |
| `/robots.txt` | GET | Anyone | Metafile | — (disclosed the 4 entries below) |
| `/install-notes.txt` | GET | Anyone | Metafile entry | — (leaks creds, DB, paths) |
| `/studentdoc/` | GET | Anyone | Metafile entry | directory listing on |
| `/studentpic/` | GET | Anyone | Metafile entry | directory listing on; upload target |
| `/studentproof/` | GET | Anyone | Metafile entry | directory listing on; upload target |
| `/tools.php` | GET/POST | Anyone | Diagnostics (ping) | `host` — command injection |
| `/admin.php` | GET | Anyone (pre-auth) | Admin console | leaks source/JS pre-auth |
| `/adminlogin.php` | GET/POST | Anyone | Staff login | `a_id` `a_ps`; hidden `txtid` — SQLi auth bypass |
| `/admsnform.php` | GET/POST | Registered user | Admission form | large param set with hidden `detid` — IDOR/mass-assign, stored XSS, SQLi |
| `/documents.php` | GET/POST | Registered user | Document upload | 7 image fields, upload-bypass -> RCE |
| `/admsnreport.php` | GET | Registered user | Admission report | reachable without upload, workflow bypass |
| `/logout.php` | GET | Registered user | Report footer | test server-side session invalidation |
| `/admin.php` | GET/POST | Admin | Admin console | `disapp` `markof` `omarkof` (CSRF/IDOR), `txtid` `txtpwd` (mass-assign) |
| `/viewform.php` | GET | Admin | Applicant form | `id` — IDOR |
| `/adminac.php` | GET | Admin | Admit card | `id` — IDOR |
| `/global_search.php` | GET | Admin | Search bar | `term` — SQLi, XSS |
| `/readID.php` | POST | Admin | Search autocomplete | `keyword` — SQLi |

## Active Content Discovery (WSTG-INFO-04)

### Gobuster

To surface files and directories not reachable by navigation, the tester ran:

```
gobuster dir -u http://192.168.77.90/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak,old,sql,zip,conf -o scans/gobuster-root.txt
```

Beyond the already-mapped pages, this surfaced several new paths:

- **`/fileupload.php`** — a standalone upload handler (examined below).
- **`/mail/`** — a directory with listing enabled (examined below).
- **`captcha.php`** — the signup captcha generator (relevant to the `txt_captcha` parameter; candidate weak/replayable captcha).
- **`tabs.php`, `a.php`, `status.php`** — leftover developer/test artifacts. `tabs.php` is a scratch form with client-side-only validation; `a.php` and `status.php` return empty bodies / a static `1`. These do not process input, but their presence in the web root is a **deployment-hygiene / information-disclosure** finding (leftover files, CWE-489 / CWE-540).
- **`server-status`** — Apache `mod_status`, present but returning 403 (access restricted).

### fileupload.php

Requesting `/fileupload.php` directly returned a PHP notice:

```
Notice: Undefined index: user in /var/www/oas/fileupload.php on line 12
```

This disclosed two things: the application's **absolute filesystem path, `/var/www/oas/`** (CWE-209, useful for an upload-RCE target path or a SQLi `INTO OUTFILE`), and that the handler expects a **`user`** parameter. As a separate upload handler that may be reachable outside the multi-step `documents.php` flow, with a user-controlled `user` value, it is an additional **upload-RCE / IDOR** candidate.

<img width="687" height="233" alt="image" src="https://github.com/user-attachments/assets/9f0e2de3-e430-4ff3-aa85-c65f43445667" />

### /mail/

Directory listing on `/mail/` exposed the application's mail stack:

- `class.phpmailer.php`
- `class.smtp.php`
- `email.php`

All three are dated **2016-10-02**. The two class files are the **PHPMailer** library. Requesting them over HTTP returns only `1` (they execute server-side rather than serving source), but the version date places this build **before the PHPMailer security fixes of late December 2016** which lies within the vulnerable range for the critical RCE issues discussed in the grey-box review below. Because the application sends email on registration (and on manager creation), this is a high-value lead.

<img width="765" height="463" alt="image" src="https://github.com/user-attachments/assets/47b7e6f9-8c36-4386-93b0-6e409014601f" />

### Nikto

An automated misconfiguration scan was then run:

```
nikto -h http://192.168.77.90/ -o scans/nikto.txt
```

<img width="2163" height="895" alt="image" src="https://github.com/user-attachments/assets/cd45fd95-0317-45d9-9283-57c84963fe68" />

Nikto corroborated several existing findings and added a few new ones:

- **Directory indexing** confirmed on `/studentdoc/`, `/studentpic/`, `/studentproof/`, `/mail/`, `/css/`, `/images/` (CWE-548).
- **Missing security headers** — Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy all consolidated as one misconfiguration finding (CWE-693). The absence of X-Frame-Options enables **clickjacking** (CWE-1021).
- **Internal IP disclosure** — the `/images` redirect leaks the internal address `10.0.2.100` in its `Location` header (CWE-200).
- **`.gitignore` and `.dockerignore`** present in the web root which presents a minor information disclosure. However, their contents related only to lab maintenance and were scoped out.
- Apache 2.4.67 reported as slightly outdated.

Nikto also flagged `admin.php` against **CVE-2006-5412 (EasyNews)**. This was manually verified by requesting the referenced URLs and confirmed to be a **false positive** as the parameters had no effect and the standard "not logged in" page was returned. The application is OAS, not EasyNews and so the finding was discarded.

### Additional Endpoints Discovered

| Endpoint | Method | Who can reach | Notes |
|---|---|---|---|
| `/fileupload.php` | GET/POST | Anyone | `user` param; leaks path `/var/www/oas/`; upload-RCE / IDOR candidate |
| `/mail/` | GET | Anyone | directory listing; PHPMailer stack |
| `/mail/email.php` | POST | Anyone | mail send wrapper; PHPMailer RCE sink |
| `/captcha.php` | GET | Anyone | signup captcha generator; weak-captcha candidate |
| `/tabs.php` | GET | Anyone | leftover dev/test form (client-side only) |
| `/a.php`, `/status.php` | GET | Anyone | leftover stub files |
| `/server-status` | GET | restricted | Apache mod_status (403) |

## Application Identification & Grey-Box Review (WSTG-INFO-08)

The install notes identified the application as **OAS v1.2 (Online Admission System)**. A search of Exploit-DB, GitHub, and the common PHP-project repositories did not return a definitive match for this exact codebase (filenames plus Centurion branding), indicating a customized or lab-modified build so a full grey-box source review was therefore not available, and the application will be tested black/grey-box.

The bundled **PHPMailer** library, however, is a known-vulnerable component:

- **CVE-2016-10033** — remote code execution via a crafted Sender/From address, affecting PHPMailer `>= 5.0.0, < 5.2.18` (CVSS 9.8). Reference: https://nvd.nist.gov/vuln/detail/CVE-2016-10033
- **CVE-2016-10045** — a bypass of the first fix, affecting versions `< 5.2.20`. In practice, any PHPMailer build older than **5.2.20** is unsafe.

The `/mail/` files are dated 2016-10-02, which predates both patches, placing this build in the vulnerable range (candidate: CWE-1104 / bundled-component RCE). Two caveats apply before this is treated as confirmed: the classic RCE requires the `mail()` (isMail) transport, and the presence of `class.smtp.php` means the application may send over SMTP instead; and the user-controlled address field must reach the vulnerable code path. The exact version can be confirmed pre-exploit by triggering a registration email and reading the `X-Mailer` header (PHPMailer stamps its version there), or post-exploit via `dpkg -l | grep phpmailer`.

## Leads Forward

The following candidate vulnerabilities were identified during recon and carried into the exploitation phase. None were exploited during this phase.

| # | Candidate | Endpoint / Param | WSTG | CWE / CVE |
|---|---|---|---|---|
| 1 | Cleartext transmission (no TLS) | login over HTTP | CRYP | CWE-319 |
| 2 | Session cookie missing HttpOnly | `PHPSESSID` | SESS | CWE-1004 |
| 3 | Information disclosure (deployment notes) | `/install-notes.txt` | INFO-03 / CONF | CWE-200 / CWE-540 |
| 4 | Directory listing enabled | `/studentdoc/` `/studentpic/` `/studentproof/` `/mail/` | CONF | CWE-548 |
| 5 | SQLi auth bypass | `/index.php`, `/adminlogin.php` | ATHN / INPV | CWE-89 |
| 6 | SQL injection | `readID.php` `keyword`; `global_search.php` `term`; `admsnform.php`; `track.php` `appno` | INPV | CWE-89 |
| 7 | Reflected / stored XSS | autocomplete (`html:true`); `admsnform` free-text rendered in admin view | INPV / CLNT | CWE-79 |
| 8 | IDOR (read) | `track.php?appno`, `viewform.php?id`, `adminac.php?id`, `admsnreport.php` | ATHZ | CWE-639 |
| 9 | IDOR (write) / mass assignment | `detid` (admsnform); `txtid`/`txtpwd` (manager create) | ATHZ / BUSL | CWE-639 / CWE-915 |
| 10 | Broken access control | `admin.php` source leak pre-auth; unauth test of `viewform`/`adminac` | ATHZ | CWE-284 / CWE-200 |
| 11 | CSRF | admin approve / reject / marks (no token) | SESS | CWE-352 |
| 12 | Command injection | `tools.php` `host` | INPV | CWE-78 |
| 13 | Upload filter bypass → RCE | `documents.php` (7 fields); `fileupload.php` `user` | INPV | CWE-434 |
| 14 | Business logic / workflow bypass | `admsnreport.php` reachable without upload | BUSL | CWE-840 |
| 15 | Vulnerable component RCE | PHPMailer 2016 (`/mail/`) | CONF / INPV | CVE-2016-10033 / -10045 |
| 16 | Weak / replayable captcha | `captcha.php` / `txt_captcha` | BUSL | — |
| 17 | Internal IP disclosure | `/images` `Location` header (`10.0.2.100`) | INFO / CONF | CWE-200 |
| 18 | Missing security headers / clickjacking | application-wide | CONF / CLNT | CWE-693 / CWE-1021 |
| 19 | Outdated components | Apache 2.4.67; jQuery 1.8.3 / 1.10.2 / 2.1.1; jQuery-UI 1.8.2 | CONF | CWE-1104 |
| 20 | Leftover dev/test files | `tabs.php`, `a.php`, `status.php` | CONF | CWE-489 / CWE-540 |
| 21 | Verbose errors / path disclosure | `fileupload.php` (`/var/www/oas/`); "Inserted to DB" status | ERRH / INFO | CWE-209 / CWE-200 |
| 22 | Session not invalidated on logout (to verify) | `logout.php` | SESS | CWE-613 |
