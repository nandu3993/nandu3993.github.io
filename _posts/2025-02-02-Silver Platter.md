---
title: TryHackMe Silver Platter
date: 2025-02-02
tags: [tryhackme, ctf]
author: nandakishor
---
#Silver Platter
Think you've got what it takes to outsmart the Hack Smarter Security team? They claim to be unbeatable, and now it's your chance to prove them wrong. Dive into their web server, find the hidden flags, and show the world your elite hacking skills. Good luck, and may the best hacker win!
But beware, this won't be a walk in the digital park. Hack Smarter Security has fortified the server against common attacks and their password policy requires passwords that have not been breached (they check it against the rockyou.txt wordlist - that's how 'cool' they are). The hacking gauntlet has been thrown, and it's time to elevate your game. Remember, only the most ingenious will rise to the top. 
![alt text](../assets/images/siilverplatter/image.png)

![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-01 195933.png>)

we can see port 80 and 8080 is open
![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-01 201238.png>)

in here we can see some clues , so ther is something called silverpeas on the 8080 port 
i scannd the directory but cant find anything intersting

![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-01 200617.png>)

![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-01 201407.png>)

we can find a login paget and in the previous page we got a username
```scr1ptkiddy```

now we need a password,
so i tried rockyou and other password list but it didnt worked so i used cewl to craft password list from the page

![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-01 202406.png>)

And 
```hydra -l scr1ptkiddy -P /usr/share/wordlists/rockyou.txt 10.10.31.248 -s 8080 http-post-form "/silverpeas/AuthenticationServlet:Login=^USER^&Password=^PASS^&DomainId=0:F=Login or password incorrect"```
used this to crack the password

![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-01 202447.png>)

![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-01 202647.png>)

![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-01 202714.png>)

in here we can see a message and the id is 5, so try parameter tampering to get some creds

![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-01 202831.png>)
![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-01 203526.png>)


the ID 6 got a username and password

 ```Username: tim

Password: cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol```

![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-02 195214.png>)


![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-02 195238.png>)

![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-02 200400.png>)

i got confused and asked chat gpt for help

![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-02 200416.png>)

so we can read log files, try to find anything related to the other user tyler in the system

![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-02 200603.png>)

```grep -Ri "tyler" /var/log/ 2>/dev/null```
![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-02 200857.png>)

so can see a password 

![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-02 200927.png>)

![alt text](<../assets/images/siilverplatter/Screenshot 2025-02-02 201134.png>)


```user flag: THM{c4ca4238a0b923820dcc509a6f75849b}
root flag: THM{098f6bcd4621d373cade4e832627b4f6}```