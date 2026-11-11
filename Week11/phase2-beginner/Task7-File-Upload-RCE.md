As we saw in our earlier recon, the document uploader on /home/upload rejects PHP files, but its filter trusts the Content-Type header supplied in the request rather than inspecting the file’s actual contents. Since the browser sets this header automatically from the real file type, a normal upload of shell.php gets blocked every time. However, with Burp intercepting the request we can rewrite the Content-Type from application/octet-stream to image/png before it reaches the server. The server sees an apparent image and accepts the file, storing it in the publicly accessible /uploads/ directory where Apache will execute it as PHP. This gives us an RCE as www-data.

First, we create a file called `shell2.php` and put `<?php echo shell_exec($_GET["cmd"]); ?>` into it. Then navigate to the upload documents section, select the the file (Don't upload yet), and then turn intercept on in Burp. Notice the intercepted request below:

<img width="593" height="95" alt="image" src="https://github.com/user-attachments/assets/d6ea8c06-fd2d-44a7-99b6-0d9a5f909bf3" />

We then just change `application/x-php` to `image/png` and hit "forward" in Burp, then turn off intercept.

<img width="749" height="614" alt="image" src="https://github.com/user-attachments/assets/c9bc2de0-31f8-4350-9673-e190b83880c1" />

Verify our script is working with by querying the `cmd` parameter:

<img width="720" height="111" alt="image" src="https://github.com/user-attachments/assets/377a6baa-4ec9-4fc1-83b9-808301ab0d1a" />

Now we can simply use cat as we would in a normal terminal to read the .env file:

<img width="2480" height="166" alt="image" src="https://github.com/user-attachments/assets/a5a1881d-0031-4a15-bea9-d7fb7071b71f" />
