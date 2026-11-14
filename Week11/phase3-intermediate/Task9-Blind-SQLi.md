# Task 9: Time-Based Blind SQLi

**Vulnerability:** SQL Injection, time-based blind (CWE-89)

**Endpoint:** `GET /quick/check?connection=`

The Quick Check page tells a visitor whether a connection ID is registered, and it
answers FOUND or not. Unlike the `/lookup` endpoint in Task 8, it reflects no rows
and prints no error, so there is nothing to read off the page. The response is the
same whether my injected condition is true or false, which means boolean blind has
no signal here. The one thing I can still control is how long the database takes to
answer, so here we essentially turned the query into a stopwatch. We must phrase every question so the
database sleeps when the answer is yes and replies instantly when it is no, and
read the answer off the clock.

---

## Steps

Establish the context and a baseline. A normal true condition returns FOUND with no
delay, which confirms the quote fits the single-quoted string and the row comes
back cleanly. This is done with a real id obtained during other tasks/enumeration.

```
4100237811' AND 1=1-- -
```

Next we need to build the conditional oracle. The `IF(condition, SLEEP(5), 0)=0` wrapper is the
whole technique. When the condition is true the database sleeps five seconds then
returns 0, and `0=0` keeps the row so the page still says FOUND. When it is false it
returns 0 instantly without the sleeping on the same FOUND page. This results in the same output
just different timing. A note about timings on my machine is that the true delays were 6,088 ms and false were 1,084 ms.
This slowness is most likely due to my Kali being run on a dual-booted USB.

True, delays about five seconds:

```
4100237811' AND IF(1=1,SLEEP(5),0)=0-- -
```

False, returns instantly:

```
4100237811' AND IF(1=2,SLEEP(5),0)=0-- -
```

With the oracle proven I can ask the questions I really want to know about the data. The target for this
task is an admin password hash. I select the row with `WHERE id=1` and read one
character of its password with `SUBSTRING(password,1,1)`, then ask whether that
character equals a guess. A delay means yes.

Because I already know both admin account ids from earlier tasks, I start with a
character I expect to be wrong so that I can show the negative case. This returns fast, which
tells me the first character of the hash is not `4`:

```
4100237811' AND IF((SELECT SUBSTRING(password,1,1) FROM admins WHERE id=1)='4',SLEEP(5),0)=0-- -
```

Then I "guess" the value I expect. This one hangs, confirming the first character of
id=1's hash is `0`:

```
4100237811' AND IF((SELECT SUBSTRING(password,1,1) FROM admins WHERE id=1)='0',SLEEP(5),0)=0-- -
```

Recovering all 32 characters of an MD5 hash one guess at a time by hand is quite
slow, so I wrote a script to automate it (see [blind_extract.py](./blind_extract.py)).
It does the same thing the manual requests do, but it binary-searches each
character by its ASCII value instead of guessing letter by letter, which resolves a
character in a handful of requests rather than up to sixteen. It goes through the whole
table row by row, so pointing it at `admins` recovers every staff account, and the
same code dumps `users` if I point it there.

## Evidence

Baseline true, `AND 1=1`, FOUND with no delay:

<img width="2198" height="1218" alt="baseline true condition returns FOUND instantly" src="https://github.com/user-attachments/assets/b61d5d94-adeb-49fa-8f3d-b5d8896baec1" />

True condition `IF(1=1,SLEEP(5),0)=0`, FOUND after a five second delay:

<img width="2203" height="1215" alt="true condition FOUND with five second delay" src="https://github.com/user-attachments/assets/3dbaf9c1-2acc-4759-8e1e-335e658c18fb" />

False condition `IF(1=2,SLEEP(5),0)=0`, same FOUND page but instant:

<img width="2198" height="1218" alt="false condition FOUND with no delay" src="https://github.com/user-attachments/assets/9642d093-9402-4b99-a0df-59a85e672715" />

The negative test: guessing the first hash character is `4` returns fast, so it is
not `4`:

<img width="2205" height="1226" alt="wrong hash character guess returns fast" src="https://github.com/user-attachments/assets/a69fab8c-cc9f-4abe-bcc8-6f5e5608b5dd" />

The positive test: guessing `0` returns at 6,088 ms, confirming the first character
of id=1's hash is `0`:

<img width="2201" height="1218" alt="correct hash character guess delays six seconds" src="https://github.com/user-attachments/assets/a9048038-c5c5-427b-ab3d-6b6d392ba7c2" />

The script recovering the full admin hash through the timing channel, one character
at a time:

<img width="712" height="190" alt="blind_extract.py dumping the admin hash" src="https://github.com/user-attachments/assets/5427a819-62a4-4f67-932b-f2f87322c0ac" />

The hash the script pulled for id=1 matches the a.deshmukh hash I already recovered
through some of the other tasks.

## What this reveals to an attacker

This endpoint can leak the entire credential store without reflecting any of it.
An attacker who only has this stealthy FOUND/NOT FOUND page can still
reconstruct any values in the database including admin hashes by just measuring
response times. It is slower than the verbose extraction in Task 8, but it survives the obvious fixes.
Suppressing error messages and reflecting no rows does not help, because the timing channel still leaks the data. 
Lastly, since the hash is still unsalted MD5, it's easy to crack once obtained.
account access.

## Remediation

See [remediation](../remediation.md)
