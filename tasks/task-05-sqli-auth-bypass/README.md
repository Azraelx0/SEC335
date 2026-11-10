# Task 5 — SQLi Authentication Bypass

|                 |                                  |
|-----------------|----------------------------------|
| **Endpoint**    | `/login, /admin/login` |
| **Method**      | `POST` |
| **Parameter**   | `email` |
| **Vulnerability** | CWE-89 |
| **Severity**    | Critical |
| **Type**        | Required |
| **Deliverable** | Customer dashboard + staff console after the bypass (no password) |

> Severity is yours to justify in the summary — adjust if your evidence warrants.
> Endpoint/param are pre-filled from the app map; confirm them during recon.

## Summary
<!-- 1–2 sentences: what the flaw is and what it let you do. Write this LAST. -->

## Steps to reproduce
<!-- Numbered, copy-pasteable. Paste the real request/payload in a fenced block.
     Keep it reproducible: someone should be able to follow these exactly. -->

1.
2.
3.

```http

```

## Evidence
<!-- Drop screenshots in ./images/ and embed them here. Quote the key loot inline,
     link the full dump. -->

![ ](./images/)

## What this reveals to an attacker
<!-- REQUIRED by the lab's evidence rule. Impact in plain terms: what an adversary
     gains and why it matters to the business (eLECTRA = a utility billing portal). -->

## Remediation
Summarize the fix here in a sentence or two and why it closes the hole. Patch + re-test proof live in the remediation section → [`remediation/sql-injection`](../../remediation/sql-injection/).
