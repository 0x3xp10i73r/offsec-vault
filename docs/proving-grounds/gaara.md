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

Two open ports, both unremarkable on their own: a current-for-its-time OpenSSH build and a default Apache page. There's no outdated CVE-bearing service version jumping out, and no extra ports to pivot through — whatever path to a shell exists has to run through one of these two services.

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

!!! info "How the SSH brute force works"
    **Online password brute forcing** means repeatedly attempting authentication directly against a live, running service — one guess per network round trip — rather than cracking a stolen password hash offline on local hardware. It's inherently slower and noisier than offline cracking: every attempt is a real TCP connection and a real SSH authentication exchange, which a defended host would rate-limit, lock out after N failures, or flag in its auth logs. It only becomes a realistic path to a shell when two conditions line up:

    - **The username is known or easily guessed.** Here the page title and the hostname both say `Gaara`, which is exactly the kind of signal that turns a combined "guess the user *and* the password" search into a much smaller "guess the password for a known user" search.
    - **The password is weak enough to live in a common wordlist.** `rockyou.txt` is the canonical leaked-password dictionary — originally the plaintext password list from a real 2009 breach of over 32 million accounts — and it's the first thing any attacker throws at a login form or SSH service. `iloveyou2` is a textbook entry for a list like this: a memorable dictionary phrase with a lazy numeric suffix tacked on, exactly the pattern humans fall back on when forced to "add a number" to a password.

    `hydra -l gaara -P rockyou.txt ssh://<target>` fixes the username with `-l` (a single known login) and iterates the entire wordlist against it with `-P` (a password *list*; the lowercase `-p`/`-u` flags are for a single static value instead), stopping as soon as one combination authenticates successfully. Against a box with no account-lockout policy and no rate limiting, this is a cheap, fully automated attack — the real defenses are a strong/unique password, login throttling or lockout, and disabling SSH password authentication in favor of keys entirely.

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

### How SUID privilege escalation via `gdb` works

!!! note "The SUID bit, GTFOBins, and why a debugger is dangerous here"
    **The SUID (Set-owner-UID) bit** is a permission flag stored on an executable file. Normally, when a process runs, it carries the privileges of the *user who launched it*. A binary with the SUID bit set breaks that rule: the kernel instead grants the resulting process the privileges of the binary's **file owner**, for the entire lifetime of that process, regardless of who actually executed it. In `ls -l` output this shows up as an `s` in the owner's execute slot (e.g. `-rwsr-xr-x`), and in octal permissions it's the leading `4` in something like `4755` — which is exactly what `find / -perm -4000` is searching for: `4000` octal is the SUID bit on its own.

    This mechanism exists for legitimate reasons — `/usr/bin/passwd` needs to write a new hash into `/etc/shadow`, a file an unprivileged user cannot touch directly, so it runs as root just long enough to update one line and then exits. The vulnerability shows up when the SUID bit is set on a binary that was never designed to safely constrain what a caller can make it do on their behalf — particularly one that can execute arbitrary commands or code, such as a general-purpose debugger, a scripting language interpreter, a text editor, or a file-copy/archive utility.

    **GTFOBins** ([gtfobins.github.io](https://gtfobins.github.io)) is a community-curated reference of exactly this category of binary: common, often legitimately-necessary Unix utilities, each annotated with the specific invocation needed to break out of its intended use and obtain a shell, read/write arbitrary files, or escalate privileges — *when* that binary happens to be SUID, runnable via `sudo`, or has an unusual Linux capability set. Cross-referencing every hit from `find / -perm -4000` against GTFOBins is close to a reflex move on any fresh foothold, because a single match is very often an instant path to root.

    **Why `gdb` specifically works here:** GDB's entire purpose is controlling and inspecting a running process, which by design includes the ability to call arbitrary functions and even run embedded scripts — GDB ships with a built-in Python interpreter for exactly this kind of automation. Breaking down the payload:

    ```
    gdb -nx -ex 'python import os; os.setuid(0)' -ex '!/bin/sh' -ex quit
    ```

    - `-nx` skips loading any `.gdbinit` startup files, keeping execution predictable.
    - `-ex 'python import os; os.setuid(0)'` runs a line of real Python *inside GDB's own process*. Because that GDB process is running with root's effective UID (courtesy of the SUID bit), calling `os.setuid(0)` from inside it sets the process's **real** UID to 0 as well — making the privilege elevation stick for anything the process does or spawns afterward, not just a temporary effective-UID bump.
    - `-ex '!/bin/sh'` uses GDB's shell-escape syntax (`!<command>`) to spawn `/bin/sh` as a child of the now-fully-root GDB process — so the spawned shell inherits full root privileges.
    - `-ex quit` is just cleanup once the shell session ends.

    There's no memory corruption, no exploit payload, no CVE involved — the entire "exploit" is abusing a scripting feature the tool is *supposed* to have, inside a process the operating system itself handed root privileges to, purely because a file permission bit said to.

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
