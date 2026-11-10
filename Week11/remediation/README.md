# Remediation (Task 19)

The optional remediation task, extended to **every** finding rather than three.
Fixes are grouped by **root cause**: several tasks usually collapse to one defect
class with one correct pattern, and showing the pattern once (applied in each place)
is stronger than 18 isolated patches.

| Vulnerability class | CWE | Closes tasks |
|---------------------|-----|--------------|
| [SQL Injection](./sql-injection/) | CWE-89 | 05, 08, 09, 10, 15 |
| [Unrestricted File Upload](./file-upload/) | CWE-434 | 07, 13, 16 |
| [Cross-Site Scripting](./cross-site-scripting/) | CWE-79 | 04, 12 |
| [Broken Access Control / IDOR](./broken-access-control/) | CWE-639 | 06 |
| [OS Command Injection](./command-injection/) | CWE-78 | 17 |
| [Cross-Site Request Forgery](./csrf/) | CWE-352 | 18 |
| [Information Disclosure](./information-disclosure/) | CWE-200 | 03 |
| [Weak Password Hashing](./weak-password-hashing/) | CWE-916 | 11 |

## How each fix is proven
For every class folder:
- `before.*` — the vulnerable code as found in the app source.
- `after.*` — the patched code.
- `proof/` — screenshot(s) of your original exploit now **failing** against the patch.

> A fix is only proven when your own exploit fails against it. Capture the "after"
> proof at the same time you write each exploit — re-running 18 of them at the end
> is how you lose a weekend.
