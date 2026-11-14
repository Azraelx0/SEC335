# Task 5: SQLi Authentication Bypass

**Vulnerability:** SQL Injection (CWE-89)

**Endpoint:** `POST /login`, `POST /admin/login`

---

From recon we know that `/login` takes `email` in a single-quoted string context:

```sql
SELECT * FROM users WHERE email = '' AND password = MD5('') LIMIT 1
```

The bypass works by injecting into the `email` field to make the `WHERE` clause
always true then commenting out the password check entirely. Entering
`' OR '1'='1'-- -` rewrites the query to:

```sql
SELECT * FROM users WHERE email = '' OR '1'='1'-- -' AND password = MD5('') LIMIT 1
```

`OR '1'='1'` is always true so the query returns the first user in the table
regardless of credentials. Everything after `-- -` is commented out so the
password check never runs.

---

## Steps

Submit `' OR '1'='1'-- -` in the email field on `/login` with anything in the
password field. Note that `%27` in the URL is the encoding for a single quote:

<img width="385" height="45" alt="image" src="https://github.com/user-attachments/assets/86327e1d-ac9b-4ece-a65c-a6d52e5bcc77" />

<img width="894" height="50" alt="image" src="https://github.com/user-attachments/assets/dbf6cd88-2457-43eb-8318-1fab2d6838d2" />

Log out and repeat the same payload on `/admin/login`:

<img width="741" height="450" alt="image" src="https://github.com/user-attachments/assets/54045de2-433d-4430-af60-b1be4f308204" />

## Evidence

Customer dashboard accessed as Marcus Holloway with no password:

<img width="1370" height="611" alt="image" src="https://github.com/user-attachments/assets/20253b46-62cc-40b1-8aba-3dae5f2d298b" />

Staff billing console accessed with no password:

<img width="1233" height="765" alt="image" src="https://github.com/user-attachments/assets/d1ae856d-969f-4f60-9341-21cd63f308f7" />

## What this reveals to an attacker

Both the customer and staff portals are fully accessible without valid credentials.
The root cause is string concatenation as user input is inserted directly into the
SQL query with no parameterization, so injected syntax is interpreted as part of
the query rather than as a literal value.

## Remediation

See [remediation](../remediation.md)
