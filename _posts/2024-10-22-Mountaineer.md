---
title: Mountaineer
date: 2024-10-22
tags: [tryhackme, ctf]
author: nandakishor
---

## How to Efficiently Serve an LLM
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

