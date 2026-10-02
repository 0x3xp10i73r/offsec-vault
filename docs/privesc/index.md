---
title: "Privilege Escalation"
description: "Complete Linux and Windows privilege escalation methodology with automated enumeration and manual exploitation paths"
tags:
  - PrivEsc
  - Linux
  - Windows
  - Post Exploitation
---

# Privilege Escalation Overview

---

## Methodology First, Tools Second

```text
1. SITUATIONAL AWARENESS Who am I? What OS/kernel? Domain-joined? What's my group membership?
2. ENUMERATE SYSTEM Patch level, services, scheduled tasks, cron, installed software,
                           network connections, mounts, DACLs/ACLs.
3. ENUMERATE IDENTITY Credentials on disk, browser data, SSH keys, config files,
                           environment variables, password manager vaults, shell history.
4. IDENTIFY ANOMALIES World-writable paths, misconfigured services, missing patches,
                           weak file permissions, privileged groups, SUID binaries.
5. EXPLOIT Try manual paths first (they're far more reliable), fall back to
                           automated exploits (kernel CVEs) only when the target matches.
6. STABILIZE & PERSIST Upgrade to a stable shell, document the exact path (for the report!).
```

!!! warning "Reliability Discipline"
    Automated checkers (`linpeas`, `winPEAS`) are for *coverage*, not for *decisions*. Every finding should be manually verified before exploitation. Kernel exploits should always be a last resort — they crash boxes, and a crashed engagement host is a failed engagement.

---

## Pages in this section

  - **[Linux Privilege Escalation](linux-privesc.md)** — SUID/SGID & capabilities, sudo/GTFOBins abuse, cron & systemd timers, wildcard injection, PATH hijacking, NFS no_root_squash, Docker/K8s escapes, and kernel CVEs.

  - **[Windows Privilege Escalation](windows-privesc.md)** — Token impersonation (Potato family), unquoted service paths, weak service/DLL permissions, AlwaysInstallElevated, DPAPI, UAC bypass, and SeDebug/SeImpersonate abuse.

---

## Things to check first

| # | Windows Check | Linux Check |
| :-- | :--- | :--- |
| 1 | `whoami /priv` → SeImpersonate / SeDebug / SeBackup | `sudo -l` → GTFOBins |
| 2 | `systeminfo` → kernel/hotfix level | `uname -a` → kernel exploits |
| 3 | Unquoted service paths | `find / -perm -4000` → SUID binaries |
| 4 | Writable service binaries / dirs | Cron jobs writable (`/etc/crontab`, `pspy`) |
| 5 | Credentials in `unattend.xml`, `web.config`, `*.txt` | Credentials in `.bash_history`, configs, `.env` |
| 6 | `AlwaysInstallElevated` registry keys | `getcap -r /` → `cap_setuid+ep` |
| 7 | Autologon registry (`DefaultPassword`) | Readable `/etc/shadow` or SSH keys |
| 8 | Stored GPP cPassword / LAPS | Writable systemd unit / PATH hijack |