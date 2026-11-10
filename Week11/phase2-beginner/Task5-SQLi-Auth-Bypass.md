From recon we know that `/login` takes email in a single-quoted string context:

`SELECT * FROM users WHERE email = '' AND password = MD5('') LIMIT 1`

So we can bypass this by injecting into the email field to make the WHERE clause always true then commenting out the rest. So in the standard user login we can put `' OR '1'='1'-- -`. This sequence can be seen in the below screenshots (note that %27 is the URL encoding for a single qoute):

<img width="385" height="45" alt="image" src="https://github.com/user-attachments/assets/86327e1d-ac9b-4ece-a65c-a6d52e5bcc77" />

<img width="894" height="50" alt="image" src="https://github.com/user-attachments/assets/dbf6cd88-2457-43eb-8318-1fab2d6838d2" />

We then can logout of the user account and perform the same technique on the staff login portal:

<img width="741" height="450" alt="image" src="https://github.com/user-attachments/assets/54045de2-433d-4430-af60-b1be4f308204" />

Submit: Screenshot of the customer dashboard as Marcus Holloway and the staff Billing Console after the bypass (no password used).

<img width="1370" height="611" alt="image" src="https://github.com/user-attachments/assets/20253b46-62cc-40b1-8aba-3dae5f2d298b" />


<img width="1233" height="765" alt="image" src="https://github.com/user-attachments/assets/d1ae856d-969f-4f60-9341-21cd63f308f7" />
