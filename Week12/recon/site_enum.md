# Site Recon & Enumeration

Target: `http://192.168.77.90/`

After briefly viewing the site in browser, find that it seems to be associated with Centurion University of Technology and Management Bhubaneswar.


## Nmap

The first step I took was to run a full tcp port scan on the target using `nmap -p- --min-rate 2000 -oA scans/nmap-allports 192.168.77.90` to do a broad search for open ports. Results:

<img width="633" height="296" alt="image" src="https://github.com/user-attachments/assets/3b6e9cd9-643e-478d-be92-425076ab44f8" />

Next I hone in on those open ports using this command `nmap -sC -sV -p 80,11010,11011,11012,11013,15888 -oA scans/nmap-services 192.168.77.90`. This is running a scan that looks for version and default scripts on just those. Noteworthy results:

<img width="831" height="316" alt="image" src="https://github.com/user-attachments/assets/4d40cd4c-e4b9-49d6-900c-98afa75aceb9" />

A note on those high ports is that they're just services supporting the lab environment in order to access it, so for the rest of this test I will ignore them. 
From this scan alone some critical information is unveiled. First, the service `http` already reveals that this website is going to be vulnerable to attacks that one running `https` would not be. Second, having the version `Apache httpd 2.4.67 ((Debian))` will aid in what exploits can be done against this web server. Third, this scan shows that the `httponly` flag is not set on the server. Last, several interesting directories and files are found, including: `http-robots.txt`, `/install-notes.txt`, `/studentdoc/`, `/studentpic/`, and `/studentproof`.

NOTE: ADD MORE IN THIS SECTION ON WHY I TESTED THE HIGH PORTS AT ALL

## Fingerprint the Stack (WSTG-INFO-02)

First, I run whatweb to see what technology and/or languages are running on this server. Results:

<img width="1881" height="76" alt="image" src="https://github.com/user-attachments/assets/c6eb5c58-ec19-4f4a-9e03-5e4f93a1de2a" />

I also run curl to see if this turns up any new information returned by the page.

<img width="524" height="195" alt="image" src="https://github.com/user-attachments/assets/82a1411b-ad4f-47fa-978c-d8bbe65bcd18" />

And wafwoof to see if the server is being protected by a waf. In this case it is not.

<img width="698" height="444" alt="image" src="https://github.com/user-attachments/assets/fd9e5841-e7c2-4cde-913b-1562122750da" />

## Passive Map with Burp (WSTG-INFO-05)
In this stage I walk the site using Burp to create a comprehensive map of the site. To do this I browse to the target `http://192.168.77.90` with my proxy, foxyproxy, on and sending http history to Burp. In addition, once I land on main home page `http://192.168.77.90` and see its GET request in Burp, it can be added to the scope and filtered so that no unrelated traffic gets in the way. This section will detail the logical walkthrough of the site with an endpoint map at the end detailing every endpoint along with other details.

### Basic Walking

First, I looked around the home page which only has a login form which is connected to `/index.php`. From there, links lead to "Sign Up" and "Track Application" which I followed. First, I created an account using:
 ```
Name: raihn
Date of Birth: 2026-11-11
Email ID: raihn@test.com
Mobile No.: 7
```

After creating the account, received the following message:
```
Your User ID is CUTM00016 and Password is aiovXovn
You are successfully registered. Please check your email ID or Phone for User ID and Password. 
```
That led me to the "Track Application" page where I input the newly acquired "User ID" of `CUTM00016` which returned "No application found for that number." 

### Digging Deeper
With the endpoints that anyone on the website can get to mapped, I am going to move onto the sub-directories found by nmap. 
I begin with `/robots.txt` which mentions four disallowed directories: `/install-notes.txt`, `/studentdoc/`, `/studentpic/`, and `/studentproof/`.
First, I browse to `/install-notes.txt/` as files like this can be extremely high value. We find the following info:

<img width="636" height="366" alt="image" src="https://github.com/user-attachments/assets/a7e52eeb-5f7f-429a-a612-e7317dd1bde3" />

I immediately extract this to my host machine, save it, and generate a hash of the file. After that is done I move onto examining the various items mentioned in "Uploads".
Also note that a new endpoint was found at `/tools.php`.

In the `/studentdoc/ ` directory found pdfs relating to course syllabus, schedule, and module teaching material. In `/studentpic/` found jpgs presumably of past/current students.
In `/studentproof/` found a mix of jpgs and pdfs containing some repeat documents as well as static images, including one of a signature. Next I navigate to `/tools.php`, here I find a page
that will check if an admission server can reach a host on campus network. I tested it out on the ip `127.0.0.1` as seen below:

<img width="1183" height="436" alt="image" src="https://github.com/user-attachments/assets/c6df1119-18dc-4723-903d-ffd3c7673a82" />

Note the vary interesting option below this tool. Clicking "Back to admin console" leads to the page `/admin.php` which is unassuming at first glance and states, "You are not Logged In Please Login to Acces this Page" along with a "Click Here to Login" option. This page becomes more interesting when views the source code by using `ctrl+u`, the code found will be noted and explored later. Page can be seen below:

<img width="632" height="175" alt="image" src="https://github.com/user-attachments/assets/5fcdd43c-d1ee-421b-83c6-a4450580786b" />

Next, I follow the prompt to login. This reveals the endpoint `/adminlogin.php` with an option to login. Here I attempt to login using the credentials `test` and `test` to trigger a POST request in Burp.
On the website we get the message "Invalid Login! Please try again."




### Endpoint Map

| Endpoint | Method | Who can reach | Where in the UI | Interesting input |
|---|---|---|---|---|
| `/` | GET | Anyone | Landing / Login page | — |
| `/index.php` | GET/POST | Anyone | Login form | `u_id` `u_ps` |
| `/signup.php` | GET/POST | Anyone | Sign Up | `stid` `stpw` `in_name` `in_dob` `in_eml` `in_mob` `txt_captcha` |
| `/track.php` | GET | Anyone | Track Application | `appno` |
| `/robots.txt` | GET | Anyone | N/A | N/A |
| `/install-notes.txt` | GET | Anyone | /robots.txt | `staff credentials` `database credentials` `Uploads` |
| `/studentdoc/` | GET | Anyone | /robots.txt | `upload vector` |
| `/studentpic/` | GET | Anyone | /robots.txt | `upload vector` |
| `/studentproof/` | GET | Anyone | /robots.txt | `upload vector` |
| `/tools.php` | GET | Anyone | /install-notes.txt | `host` |
| `/admin.php` | GET | Anyone | /tools.php | N/A |
| `/adminlogin.php` | GET/POST | Anyone | /admin.php | `a_id` `a_ps` `txtid` |
