---
title: "OffSec Proving Grounds"
description: "Writeups for fully-rooted OffSec Proving Grounds (PG Play) machines — recon to proof.txt, with the reasoning and exact commands at each step."
tags:
  - Proving Grounds
  - OffSec
  - Walkthrough
---

# OffSec Proving Grounds

Writeups for **fully-rooted** OffSec Proving Grounds (PG Play) machines — only boxes where `proof.txt` was obtained are published here. Each follows the same flow as the [Hack The Box](../hack-the-box-labs/index.md) and [TryHackMe](../tryhackme/index.md) sections: box info, reconnaissance, enumeration, the initial foothold, and privilege escalation to root — with the *why* explained at each step alongside the exact commands.

!!! warning "Authorised lab use only"
    These are retired OffSec practice machines. The procedures are for the authorised Proving Grounds lab environment and any system where you have explicit written permission to test. Flag values (`local.txt` / `proof.txt`) are redacted.

## Rooted machines

<div class="grid cards" markdown>

-   :material-key-variant:{ .lg .middle } __[Gaara](gaara.md)__

    ---

    **Easy** · Hydra SSH brute force, SUID `gdb` (GTFOBins) → root

-   :material-food-apple:{ .lg .middle } __[Potato](potato.md)__

    ---

    **Easy** · Anonymous FTP leak, crackable hash, `sudo` relative-path traversal

-   :material-wordpress:{ .lg .middle } __[Blogger](blogger.md)__

    ---

    **Medium** · wpDiscuz upload RCE (CVE-2020-24186), `wp-config` creds, `NOPASSWD` sudo

-   :material-database-search:{ .lg .middle } __[DC-9](dc-9.md)__

    ---

    **Intermediate** · Union SQLi, LFI, port knocking, `sudo` file-append to read `proof.txt`

-   :material-emoticon-happy-outline:{ .lg .middle } __[Funbox](funbox.md)__

    ---

    **Intermediate** · `wpscan` cracked creds, Theme Editor RCE, writable root cron script

-   :material-share-variant:{ .lg .middle } __[So Simple](so-simple.md)__

    ---

    **Intermediate** · Social Warfare RCE (CVE-2019-9978), stolen SSH key, chained `sudo`

-   :material-ticket-confirmation:{ .lg .middle } __[Tre](tre.md)__

    ---

    **Intermediate** · MantisBT exploit chain, DB-stashed password, writable boot script → SUID bash

</div>

## Conventions used in these pages

- Commands use fenced code blocks tagged with the shell or language that produced them.
- Screenshots are migrated from the original machine notes and shown in their original order.
- `nmap`, `ffuf` and tool output are kept close to the real run so the pages stay reproducible; very long dumps are trimmed to the load-bearing lines.
- `local.txt` and `proof.txt` values are redacted — these are the same retired machines everyone practises on, but there is no reason to publish the flags.
