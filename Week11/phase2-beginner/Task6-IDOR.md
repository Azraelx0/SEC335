From our initial enumeration of the website we found that changes initiated on a users account would send a GET request with the notable parameters below:

<img width="776" height="170" alt="image" src="https://github.com/user-attachments/assets/8d717935-700b-45dd-9a12-8634679d456a" />

Critically, the `ID` value isn't hidden very well as can be seen below:

<img width="661" height="122" alt="image" src="https://github.com/user-attachments/assets/cbba5ea4-f5b7-49d3-b948-9315c25ea90d" />

Using Burp we can send this request to the repeater and attempt to gain access to another user's account. First, I will run an sqlmap dump on the target table using `sqlmap -u "http://192.168.77.80/lookup?connection=1" --batch -D electra -T users --dump` to attempt to find the customer list. After running this I randomly chose the lucky individual who owns the account with ID 7:

<img width="1039" height="30" alt="image" src="https://github.com/user-attachments/assets/1620c5d5-ed12-4847-86bd-f3e44f59548e" />


<img width="1534" height="675" alt="image" src="https://github.com/user-attachments/assets/446161e0-b006-4cc9-9bb3-a767cc3088ad" />

