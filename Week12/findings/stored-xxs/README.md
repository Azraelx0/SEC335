inject the stored payload:
the tester targets the `/viewform.php` as this is a page likely to be viewed by an admin account regularly.
first, the test logs in under their previously created account `raihn`, then updates their existing application so that an injection can but input
into one of the form fields. The injection `<script>alert(1)</script>` was placed in the "Father's Name" section of the application then the tested clicked "Update".
This resulted in the following successful injection:

<img width="1572" height="1372" alt="image" src="https://github.com/user-attachments/assets/bb822b51-9e5d-447e-8fe5-6365d066b24e" />

Now the tester performs the same steps, but this time injects `<script>alert(document.cookie)</script>` into the application.
This returns the session cookie value `PHPSESSID=spoo81dqotspo7elqmqjufi1jf` as seen below:

<img width="1643" height="1353" alt="image" src="https://github.com/user-attachments/assets/5312261d-330d-4ec9-839c-c536b322490a" />

Ordinarily, the admin would have to login to trigger this exploit. However, the tested logged in with the admin credentials to trigger it.
When the admin views `/viewform.php?id=CUTM00016` the payload is triggered.

stored xxs being triggered:

<img width="2560" height="1383" alt="image" src="https://github.com/user-attachments/assets/36de667f-4cf6-4e49-8c5e-8e65b61511c8" />

