# Task 13 -- Upload Filter Bypass

**Vulnerability:** Unrestricted File Upload (CWE-434)
**Endpoint:** `POST /home/upload/avatar`

The avatar uploader blocks `.php` by extension but does not validate alternative
PHP-executable extensions. Apache executes `.phtml` as PHP by default, so renaming
the shell bypasses the filter entirely.

---

## Steps

Upload a standard PHP webshell with a `.php` extension:

```php
<?php echo system($_GET['cmd']); ?>
```

Blocked:

<img width="748" height="626" alt="image" src="https://github.com/user-attachments/assets/c92b570a-066f-4e88-bc2c-dfdc74e2cfb6" />

Renaming to `.php5` gives the same result. Rename to `.phtml` and the upload succeeds:

<img width="731" height="617" alt="image" src="https://github.com/user-attachments/assets/8de096d0-335c-4460-911f-0659711c8e6a" />

The file is confirmed in `/uploads/` which is publicly browsable:

<img width="567" height="282" alt="image" src="https://github.com/user-attachments/assets/07dd030d-3562-448f-96fd-dfc4c4f53c28" />

## Evidence

Querying the `cmd` parameter confirms remote code execution:

<img width="956" height="108" alt="image" src="https://github.com/user-attachments/assets/812b2261-c9df-400b-9910-0c4e7140dd08" />

<img width="956" height="108" alt="image" src="https://github.com/user-attachments/assets/c5c77bb0-b4fe-4d86-a975-4334564eddb6" />

## What this reveals to an attacker

The filter only blocks `.php` exactly. Any PHP-executable extension the server
recognizes bypasses it. Combined with the publicly accessible `/uploads/` directory,
this gives an authenticated customer full remote code execution as `www-data`.

## Remediation

See [remediation](../remediation.md)
