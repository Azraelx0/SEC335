# Mapping the Application

Before exploiting anything, build a complete picture of eLECTRA: every page, form, parameter, cookie, and role boundary. This map is the reference every later task reaches back into, so the goal here is to be as thorough as possible.
- **Target:** `http://192.168.77.80/` (eLECTRA website)
- **Accounts:** `m.holloway@electra.lab` (customer) · anonymous (logged out)
- **Deliverable:** the filled-in endpoint map below + notes on two information leaks

---

## Approach

Browse with Burp Intercept off and let Proxy -> HTTP history record every request. Walk the whole app once per role and then read the history back to fill in the tables below. Right-click the host -> *Add to scope* and filter history to in-scope. Also highlighting start and end points can help reduce confusion once the requests start to pile up.

Role order:

1. **Anonymous** — logged out / private window
2. **Customer** — `m.holloway`
3. **Staff** — can't reach yet and will record the nav items as a *boundary* rather than blank

---

## 1. Endpoint map

| Endpoint | Method | Who can reach | Where in the UI | Interesting input |
|---|---|---|---|---|
| / | GET | Anyone | nav: Home Page | None |
| /login | GET | Anyone | nav: Login & Customer Login | `E-mail` `Password` |
| /quick/check | GET | Anyone | nav: Quick Check | `connection` |
| /lookup | GET | Anyone | nav: Bill Lookup | `connection` |
| /register | GET | Anyone | nav: Register & New Connection | `Name` `E-Mail` `Connection Id` `Address` `Password` `Confirm Password` |
| /admin/login | GET | Anyone | nav: Staff & Staff Login | `E-Mail` `Password` |
| /password/reset | GET | Anyone | nav: Login / Customer Login / Staff -> "Forgot Your Password?" | `E-Mail` |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |
|  |  |  |  |  |


Screenshots to go along:

/lookup?connection=

<img width="404" height="26" alt="image" src="https://github.com/user-attachments/assets/f3090fe6-c222-448a-92dc-f81c30bf848e" />

/quick/check?connection=

<img width="347" height="25" alt="image" src="https://github.com/user-attachments/assets/cfa70e78-9c0f-4fab-ab9f-516932fa8b7f" />

---

## 2. Roles & boundaries

What each role can see. Staff items you can't reach yet still get recorded here — the boundary is where the authorization bugs live.

| Role | Nav / pages visible | Notes |
|---|---|---|
| Anonymous |  |  |
| Customer |  |  |
| Staff *(boundary — not yet reachable)* |  |  |

---

## 3. Cookies & session flags

After logging in: dev tools → **Application → Cookies** (or read any request in Burp). Record each cookie and its flags — a missing `HttpOnly` turns any XSS into account takeover later.

| Cookie | HttpOnly | Secure | SameSite | Notes |
|---|---|---|---|---|
|  |  |  |  |  |
|  |  |  |  |  |

**What this reveals to an attacker:**
_(e.g. which cookie carries the session, and whether a client-side script could read it)_

---

## 4. Stack fingerprint

From any Burp response: `Server` / `X-Powered-By` headers, cookie names, error-page style, URL patterns. Framework knowledge tells you which bugs are even plausible.

| Signal | Value observed | Implies |
|---|---|---|
| `Server` header | Apache/2.4.67 (Debian) |  |
| `X-Powered-By` |  |  |
| Session cookie name |  |  |
| Error page style |  |  |

---

## 5. Hidden fields & parameters

View-source (**Ctrl+U**) every form, not just the visible inputs. Hidden fields carrying an `id`, `customerId`, or similar are prime targets for later IDOR / write-query tasks.

| Form / page | Hidden or non-obvious field | Value seen | Why it's interesting |
|---|---|---|---|
|  |  |  |  |
|  |  |  |  |

---

## 6. State changes over GET

Flag any action that **changes state** (updates a profile, changes a setting) but happens over **GET**. That's a double finding — no CSRF token is possible — and a free lead into the CSRF task.

- _(endpoint — what it changes — method)_
- 

---

## 7. Information leaks *(deliverable)*

Request these directly by typing the path in the browser or Burp. Don't exploit anything — just confirm it exists and read it. Two of these will pay off.

Checklist:

- [ ] `robots.txt` — read every **Disallow** entry (a free list of paths someone wanted hidden)
- [ ] `sitemap.xml`
- [ ] `install-notes.txt`
- [ ] `README` / `readme.txt`
- [ ] `.git/`
- [ ] backup files — `web.zip`, `db.sql`, etc.
- [ ] any directory that shows a listing

```bash
# examples — adjust paths as you probe
curl -s http://192.168.77.80/robots.txt
curl -s http://192.168.77.80/install-notes.txt
```

### Leak 1

- **File / path:**
- **How found:**
- **Contents (relevant part):**

```
(paste contents here)
```

- **What this reveals to an attacker:**

### Leak 2

- **File / path:**
- **How found:**
- **Contents (relevant part):**

```
(paste contents here)
```

- **What this reveals to an attacker:**

---

## Leads forward

For every input you listed above, name which later task would attack it. If a parameter has no "so what," either you've found something the guide didn't flag (good — note it) or it needs a second look.

| Input / endpoint | Suspected weakness | Task it feeds |
|---|---|---|
|  |  |  |
|  |  |  |
|  |  |  |

---

## Evidence

_Screenshots: endpoint map in Burp history, the cookie-flags panel, and each of the two leaks._
