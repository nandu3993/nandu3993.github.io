---
title: TryHackMe Lumberjack Turtle
date: 2024-10-22
tags: [tryhackme, ctf]
author: nandakishor
---
#Lumberjack Turtle

![alt text](../assets/images/lumberjack-turtle/89ef3c44b9b2c745aeee7fda1498e483.png)

##Initial recon
```
┌──(kali㉿kali)-[~/tmp]
└─$ rustscan -a 10.10.180.20 -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.180.20:22
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sCV" on ip 10.10.180.20
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-23 19:49 IST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:49
Completed NSE at 19:49, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:49
Completed NSE at 19:49, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:49
Completed NSE at 19:49, 0.00s elapsed
Initiating Ping Scan at 19:49
Scanning 10.10.180.20 [2 ports]
Completed Ping Scan at 19:49, 0.21s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:49
Completed Parallel DNS resolution of 1 host. at 19:49, 0.05s elapsed
DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 4, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 19:49
Scanning 10.10.180.20 [1 port]
Discovered open port 22/tcp on 10.10.180.20
Completed Connect Scan at 19:49, 0.27s elapsed (1 total ports)
Initiating Service scan at 19:49
Scanning 1 service on 10.10.180.20
Completed Service scan at 19:49, 0.73s elapsed (1 service on 1 host)
NSE: Script scanning 10.10.180.20.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:49
Completed NSE at 19:50, 8.17s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
Nmap scan report for 10.10.180.20
Host is up, received conn-refused (0.22s latency).
Scanned at 2024-10-23 19:49:57 IST for 10s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6a:a1:2d:13:6c:8f:3a:2d:e3:ed:84:f4:c7:bf:20:32 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCnZPtl8mVLJYrSASHm7OakFUsWHrIN9hsDpkfVuJIrX9yTG0yhqxJI1i8dbI/MrexUGrIGzYbgLpYgKGsH4Q4dxB9bj507KQaTLWXwogdrkCVtP0WuGCo2EPZKorU85EWZAhrefG1Pzj3lAx1IdaxTHIS5zTqEJSZYttPF4BHb2avjKDVfSA+4cLP7ybq0rgohJ7JLG5+1dR/ijrGpaXnfudm/9BVjiKcGMlENS6bQ+a32Fs7wxL5c7RfKoR0CjA+pROXrOj5blQM4CI4wrEdphPZ/900I4DJ+kA6Ga+NJF6donQOmmhjsEEpI6RYcz6n/4ql1bomnyyI+jayyf3t
|   256 1d:ac:5b:d6:7c:0c:7b:5b:d4:fe:e8:fc:a1:6a:df:7a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBPkLzZd9EQTP/90Y/G1/CYr+PGrh376Qm6aZTO0HZ7lCZ0dExE834/QZ1vNyQPk4jg1KmS09Mzjz1UWWtUCYLg=
|   256 13:ee:51:78:41:7e:3f:54:3b:9a:24:9b:06:e2:d5:14 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFdrmxj3Q5Et6BwEm7pC8cz5louqLoEAwNXGHi+3ee+t
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 19:50
Completed NSE at 19:50, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.84 secon
```