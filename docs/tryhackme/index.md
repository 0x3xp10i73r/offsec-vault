---
title: TryHackMe Rooms
description: Completed TryHackMe room writeups with reproducible recon, exploitation and privilege-escalation notes.
tags:
  - TryHackMe
  - CTF
  - Walkthrough
---

# TryHackMe Rooms

This section collects writeups for **completed** TryHackMe rooms. Each page follows the same flow as the rest of the vault: a short box summary, reconnaissance, web/service enumeration, the initial foothold, and privilege escalation to root — with the *why* explained at each step alongside the exact commands.

!!! warning "Authorized lab use only"
    These procedures are for the authorized TryHackMe lab environment and any other system where you have explicit written permission to test. Target IP addresses, callback (attacker) IP addresses and session cookies shown here come from the original lab sessions — replace them with the values from your own deployed instance.

## Completed rooms

| Room | Difficulty | Core technique |
|------|------------|----------------|
| [Pickle Rick](pickle-rick.md) | Easy | Creds in source/robots.txt, web command panel, `sudo` abuse |
| [Simple CTF](simple-ctf.md) | Easy | CMS Made Simple SQLi (CVE-2019-9053), `sudo vim` GTFOBin |
| [RootMe](rootme.md) | Easy | PHP upload filter bypass (`.phtml`) RCE, SUID `python2.7` |
| [Ignite](ignite.md) | Easy | Fuel CMS 1.4.1 RCE (CVE-2018-16763), credential reuse |
| [Lazy Admin](lazy-admin.md) | Easy | SweetRice backup creds → authenticated RCE → writable `sudo` script |
| [Skynet](skynet.md) | Easy | Anonymous SMB, Cuppa CMS LFI/RFI, `tar` wildcard cron |
| [Daily Bugle](daily-bugle.md) | Hard | Joomla 3.7.0 SQLi (CVE-2017-8917), DB password reuse, `sudo yum` |
| [Debug](debug.md) | Medium | PHP insecure deserialization RCE, writable MOTD SUID |
| [Hammer](hammer.md) | Medium | Reset-code brute force, JWT `kid` key forgery, blacklist bypass RCE |
| [Watcher](watcher.md) | Medium | LFI → RCE, FTP creds, horizontal `sudo` pivots, root SSH key |
| [Corp Website](corp-website.md) | Medium | React2Shell RCE (CVE-2025-55182), `sudo python3` → root |
| [UltraTech](ultratech.md) | Medium | Express API command injection → SQLite creds, `docker` group escape |
| [Oh My WebServer](oh-my-webserver.md) | Medium | Apache path traversal RCE (CVE-2021-41773/42013), `cap_setuid` python3, OMIGOD (CVE-2021-38647) |

## Conventions used in these pages

- Commands use fenced code blocks tagged with the shell or language that produced them.
- Screenshots are migrated from the original room notes and shown in their original order.
- `nmap`, `ffuf` and other tool banners are kept close to the real output so the pages stay reproducible; very long table dumps are trimmed to the load-bearing rows.
- Flag values are shown as captured in the authorized lab, since these are public, retired TryHackMe rooms.
