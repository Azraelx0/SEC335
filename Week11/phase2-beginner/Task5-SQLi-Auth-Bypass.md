From recon we know that `/login` takes email in a single-quoted string context:

`SELECT * FROM users WHERE email = '' AND password = MD5('') LIMIT 1`

So we can bypass this by injecting into the email field to make the WHERE clause always true then commenting out the rest. So in the standard user login we can put `' OR '1'='1'-- -`. This sequence can be seen in the below screenshots:

<img width="385" height="45" alt="image" src="https://github.com/user-attachments/assets/86327e1d-ac9b-4ece-a65c-a6d52e5bcc77" />

<img width="385" height="45" alt="image" src="https://github.com/user-attachments/assets/998cf47a-49a3-4d73-86f5-84cba47ecef6" />


Submit: Screenshot of the customer dashboard as Marcus Holloway and the staff Billing Console after the bypass (no password used).

<img width="894" height="50" alt="image" src="https://github.com/user-attachments/assets/dbf6cd88-2457-43eb-8318-1fab2d6838d2" />

