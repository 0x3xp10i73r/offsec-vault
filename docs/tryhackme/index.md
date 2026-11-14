---
title: TryHackMe Rooms
description: Completed TryHackMe room writeups with reproducible recon, exploitation and privilege-escalation notes.
tags:
  - TryHackMe
  - CTF
  - Walkthrough
---

# TryHackMe Rooms

Writeups for **completed** TryHackMe rooms. Each follows the same flow as the rest of the vault: a short box summary, reconnaissance, web/service enumeration, the initial foothold, and privilege escalation to root — with the *why* explained at each step alongside the exact commands.

!!! warning "Authorized lab use only"
    These procedures are for the authorized TryHackMe lab environment and any other system where you have explicit written permission to test. Target IPs, callback IPs and session cookies shown here come from the original lab sessions — replace them with the values from your own deployed instance.

## Completed rooms

<div class="grid cards" markdown>

-   :material-flask:{ .lg .middle } __[Pickle Rick](pickle-rick.md)__

    ---

    **Easy** · Creds in source & `robots.txt`, web command panel, `sudo` abuse

-   :material-flag-checkered:{ .lg .middle } __[Simple CTF](simple-ctf.md)__

    ---

    **Easy** · CMS Made Simple SQLi (CVE-2019-9053), `sudo vim` GTFOBin

-   :material-upload:{ .lg .middle } __[RootMe](rootme.md)__

    ---

    **Easy** · PHP upload filter bypass (`.phtml`) RCE, SUID `python2.7`

-   :material-fire:{ .lg .middle } __[Ignite](ignite.md)__

    ---

    **Easy** · Fuel CMS 1.4.1 RCE (CVE-2018-16763), credential reuse

-   :material-account-cog:{ .lg .middle } __[Lazy Admin](lazy-admin.md)__

    ---

    **Easy** · SweetRice backup creds → authenticated RCE → writable `sudo` script

-   :material-robot:{ .lg .middle } __[Skynet](skynet.md)__

    ---

    **Easy** · Anonymous SMB, Cuppa CMS LFI/RFI, `tar` wildcard cron

-   :material-newspaper-variant:{ .lg .middle } __[Daily Bugle](daily-bugle.md)__

    ---

    **Hard** · Joomla 3.7.0 SQLi (CVE-2017-8917), DB password reuse, `sudo yum`

-   :material-bug:{ .lg .middle } __[Debug](debug.md)__

    ---

    **Medium** · PHP insecure deserialization RCE, writable MOTD SUID

-   :material-hammer:{ .lg .middle } __[Hammer](hammer.md)__

    ---

    **Medium** · Reset-code brute force, JWT `kid` key forgery, blacklist bypass RCE

-   :material-eye-outline:{ .lg .middle } __[Watcher](watcher.md)__

    ---

    **Medium** · LFI → RCE, FTP creds, horizontal `sudo` pivots, root SSH key

-   :material-domain:{ .lg .middle } __[Corp Website](corp-website.md)__

    ---

    **Medium** · React2Shell RCE (CVE-2025-55182), `sudo python3` → root

-   :material-chip:{ .lg .middle } __[UltraTech](ultratech.md)__

    ---

    **Medium** · Express API command injection → SQLite creds, `docker` group escape

-   :material-server:{ .lg .middle } __[Oh My WebServer](oh-my-webserver.md)__

    ---

    **Medium** · Apache path traversal RCE (CVE-2021-41773/42013), `cap_setuid` python3, OMIGOD

</div>

## Conventions used in these pages

- Commands use fenced code blocks tagged with the shell or language that produced them.
- Screenshots are migrated from the original room notes and shown in their original order.
- `nmap`, `ffuf` and other tool banners are kept close to the real output so the pages stay reproducible; very long table dumps are trimmed to the load-bearing rows.
- Flag values are shown as captured in the authorized lab, since these are public, retired TryHackMe rooms.
