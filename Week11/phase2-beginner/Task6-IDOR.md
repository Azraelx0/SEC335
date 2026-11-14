# Task 6: IDOR: Account Tampering

**Vulnerability:** Insecure Direct Object Reference (CWE-639)

**Endpoint:** `GET /home/profile/update`

From recon we know that profile updates submit over GET with the user's `id` as a
parameter. The `id` value is a small integer sitting in a hidden form field --
directly guessable and not tied to the authenticated session on the server side.

---

## Steps

The GET request and its parameters as seen in Burp:

<img width="776" height="170" alt="image" src="https://github.com/user-attachments/assets/8d717935-700b-45dd-9a12-8634679d456a" />

The hidden `id` field visible in page source:

<img width="661" height="122" alt="image" src="https://github.com/user-attachments/assets/cbba5ea4-f5b7-49d3-b948-9315c25ea90d" />

Send the request to Repeater and change `id` to a different value. To identify a
target, run the sqlmap dump against the users table:

```bash
sqlmap -u "http://192.168.77.80/lookup?connection=1" --batch -D electra -T users --dump
```

ID 7 belongs to Robert Calloway:

<img width="1039" height="30" alt="image" src="https://github.com/user-attachments/assets/1620c5d5-ed12-4847-86bd-f3e44f59548e" />

<img width="1526" height="679" alt="image" src="https://github.com/user-attachments/assets/664f3680-d6c2-487e-8809-33d2f3e627ca" />

## Evidence

Log in as Robert using his cracked password from the dump (or via the SQLi auth
bypass). His account before tampering:

<img width="379" height="150" alt="image" src="https://github.com/user-attachments/assets/c327ecb3-e95d-4188-9537-6c059a454c5b" />

After sending the tampered request with `id=7` and updated credentials, his account
reflects the changes:

<img width="379" height="150" alt="image" src="https://github.com/user-attachments/assets/f51ba97b-a82c-4c34-93ab-79a62f6dba52" />

## What this reveals to an attacker

Any authenticated customer can overwrite any other customer's account details
including their email and password, effectively locking them out and taking over
their account. The server checks that the user is logged in but never verifies that
the `id` in the request belongs to them.

## Remediation

See [remediation](../remediation.md)
