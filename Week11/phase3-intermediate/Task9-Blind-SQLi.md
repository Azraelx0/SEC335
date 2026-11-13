Note: to get repeater to send the command must URL encode them, use the repeater's built-in setting for this as other methods can be inconsistent.
baseline true `4100237811' AND 1=1-- -`:

<img width="2198" height="1218" alt="image" src="https://github.com/user-attachments/assets/b61d5d94-adeb-49fa-8f3d-b5d8896baec1" />

true condition `4100237811' AND IF(1=1,SLEEP(5),0)=0-- -`:

<img width="2203" height="1215" alt="image" src="https://github.com/user-attachments/assets/3dbaf9c1-2acc-4759-8e1e-335e658c18fb" />

false condition `4100237811' AND IF(1=2,SLEEP(5),0)=0-- -`:

<img width="2198" height="1218" alt="image" src="https://github.com/user-attachments/assets/9642d093-9402-4b99-a0df-59a85e672715" />


So using these values we have a baseline for comparison with future questions. We'll use this to try to find an admin's hash now.
First, we'll run `4100237811' AND IF((SELECT SUBSTRING(password,1,1) FROM admins WHERE id=1)='4',SLEEP(5),0)=0-- -`. Just a note as well, we already know both admin account ids due to other tasks, so for proof of concept I'll start with a number that should return a fast result, or in other words, let us know the first number in the admin's hash is wrong.

<img width="2205" height="1226" alt="image" src="https://github.com/user-attachments/assets/a69fab8c-cc9f-4abe-bcc8-6f5e5608b5dd" />

Now we just change the value of `4` to something else in order to test. The goal here is find a number or letter that makes the page return at roughly 6,000 ms in burp. We'll choose 0 since we already know that is the first number in this admin's hash to show this. Note that the image below shows 6,088 ms meaning that 0 is indeed the first number in the admin account belonging to id `1`.

<img width="2201" height="1218" alt="image" src="https://github.com/user-attachments/assets/a9048038-c5c5-427b-ab3d-6b6d392ba7c2" />

Obviously this is pretty tedious, so I made a script that will speed this up, see [put script to blind_]
