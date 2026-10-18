---
title: HackTheBox Labs
description: Completed Hack The Box machine writeups with reproducible enumeration and exploitation notes.
---

# HackTheBox Labs

This section contains writeups for completed Hack The Box machines. Each page follows the same flow: metadata, reconnaissance, the initial foothold, privilege escalation, and a concise technical takeaway.

!!! warning "Authorized lab use"
    These procedures are provided for authorized Hack The Box labs and other systems where you have explicit permission to test. Replace lab IP addresses, callback addresses and hostnames with the values from your own session.

## Completed machines

<div class="grid cards" markdown>

-   :material-linux:{ .lg .middle } **Cap**

    ---

    Easy Linux/Web machine. The path is an IDOR in a packet-capture application, followed by credential reuse and a Python file capability.

    [:octicons-arrow-right-24: Open the Cap writeup](<Cap/HTB - Cap.md>)

-   :material-phone-in-talk:{ .lg .middle } **Connected**

    ---

    Linux machine featuring a web foothold through SQL injection and a FreePBX/Dahdi restart path to root.

    [:octicons-arrow-right-24: Open the Connected writeup](connected/index.md)

-   :material-cloud-outline:{ .lg .middle } **Facts**

    ---

    Linux/Web machine involving Camaleon CMS privilege escalation, exposed S3-compatible storage, SSH-key recovery and Facter sudo abuse.

    [:octicons-arrow-right-24: Open the Facts writeup](facts/index.md)

-   :material-atom:{ .lg .middle } **Reactor**

    ---

    Linux machine with a React2Shell foothold and a locally exposed Node inspector running in a privileged context.

    [:octicons-arrow-right-24: Open the Reactor writeup](reactor/index.md)

-   :material-server-network:{ .lg .middle } **WingData**

    ---

    Linux machine featuring Wing FTP Server RCE and a Python tarfile path-filter bypass to write root's authorized keys.

    [:octicons-arrow-right-24: Open the WingData writeup](wingdata/index.md)

</div>

## Conventions used in these pages

- Commands use fenced blocks with the shell or language that produced them.
- Screenshots are copied from the supplied source notes and shown in their original order.
- `images/banner.png` in each machine folder is a temporary banner generated for the page. Replace that file with the final box artwork without changing the Markdown.
- User and root flags are intentionally represented as `<USER_FLAG_REDACTED>` and `<ROOT_FLAG_REDACTED>` in the published writeups.
