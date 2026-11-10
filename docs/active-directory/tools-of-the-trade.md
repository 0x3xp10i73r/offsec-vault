---
title: "Tools of the Trade"
description: "The standard Active Directory toolkit grouped by engagement phase — unauthenticated access, credentialed enumeration, Kerberos attacks, credential dumping, lateral movement, and auditing."
tags:
  - Active Directory
  - Tooling
  - Enumeration
---

# Tools of the Trade

AD testing has a fairly stable toolkit. The same dozen or so programs show up on every internal engagement, and knowing **which tool belongs to which phase** keeps you from flailing when you land on a new network. This page is a map of that toolkit; the attack pages that follow show each tool in action.

!!! note "Linux or Windows?"
    Many of these come in pairs — a Linux/Python version and a Windows/.NET version that do the same job (`BloodHound.py` vs `SharpHound`, `GetUserSPNs.py` vs `Rubeus`). Which one you reach for depends on your attack host and on what the client's defences allow. When tooling is restricted to native binaries, see [Living Off the Land](living-off-the-land.md).

## Unauthenticated / initial access

Used before you have any credentials — to enumerate names and to capture or coerce authentication material.

| Tool | Use |
| :--- | :--- |
| `Kerbrute` | Username enumeration and password spraying via Kerberos pre-auth (stealthier, no Event 4625) |
| `Responder` | LLMNR/NBT-NS/mDNS poisoning to capture NetNTLM hashes |
| `enum4linux-ng` | SMB/RPC enumeration over null sessions, no credentials needed |
| `ldapsearch` | Raw LDAP queries (anonymous bind or authenticated) |
| `adidnsdump` | Dump the AD-integrated DNS zone |

## With credentials

Once you have any valid domain account, these map the directory and hunt for secrets.

| Tool | Use |
| :--- | :--- |
| `NetExec` / `CrackMapExec` | Swiss-army knife for SMB/WinRM/MSSQL enumeration and attack |
| `BloodHound.py` | Collect AD attack-path data from Linux (no domain join needed) |
| `SharpHound` | BloodHound data collector for Windows |
| `PowerView` / `SharpView` | Manual AD enumeration and situational awareness |
| `windapsearch` | Automated LDAP queries (users, groups, privileged/nested users) |
| `smbmap` | Share enumeration and permission checks |
| `Snaffler` | Hunt for credentials and sensitive files across shares |
| `LAPSToolkit` | Audit and attack LAPS deployments |
| `DomainPasswordSpray.ps1` | Authenticated spraying with built-in lockout safety |

## Kerberos attacks

| Tool | Use |
| :--- | :--- |
| `GetUserSPNs.py` | Kerberoasting (request service tickets) |
| `GetNPUsers.py` | AS-REP Roasting (accounts without pre-auth) |
| `Rubeus` | Full Windows Kerberos abuse — tickets, roasting, spraying |
| `ticketer.py` | Forge Golden/Silver tickets |

## Credential dumping

| Tool | Use |
| :--- | :--- |
| `Mimikatz` | Dump cleartext creds, hashes, and tickets from memory (Windows) |
| `secretsdump.py` | Remote SAM/LSA/NTDS dump over the network |
| `gpp-decrypt` | Decrypt Group Policy Preferences passwords |

## Lateral movement / execution

| Tool | Use |
| :--- | :--- |
| `psexec.py` | Semi-interactive SYSTEM shell via SMB service creation |
| `wmiexec.py` | Command execution via WMI (stealthier, no dropped binary) |
| `evil-winrm` | Interactive PowerShell shell over WinRM |
| `mssqlclient.py` | Interact with MSSQL, including `xp_cmdshell` |
| `smbserver.py` | Spin up a quick SMB server for file transfer |

## Exploit-specific

| Tool | Target |
| :--- | :--- |
| `noPac.py` | CVE-2021-42278 + CVE-2021-42287 → Domain Admin from a user |
| `PetitPotam.py` | CVE-2021-36942 → authentication coercion |
| `ntlmrelayx.py` | SMB/LDAP/HTTP NTLM relay |

## Audit / analysis

Often run for reporting value as much as for exploitation.

| Tool | Use |
| :--- | :--- |
| `BloodHound` (GUI) | Visualise attack paths from collected data |
| `AD Explorer` | Browse AD live, save snapshots, diff them over time |
| `PingCastle` | Score the domain's security posture |
| `Group3r` | Audit GPOs for misconfigurations |
| `ADRecon` | Extract a full AD dataset into an Excel report |

!!! tip "Keep a cheat sheet handy"
    Tools and flags change often. **WADComs** (an interactive table of Windows/AD offensive tooling) is worth bookmarking — it maps a given goal and access level to the exact command across the common toolset.
