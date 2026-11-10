---
title: "BloodHound"
description: "Collecting AD attack-path data with BloodHound.py and SharpHound, and finding the shortest path to Domain Admins in the BloodHound GUI."
tags:
  - Active Directory
  - BloodHound
  - SharpHound
  - Graph
  - Attack Paths
---

# BloodHound

Everything in [credentialed enumeration](credentialed-enumeration.md) can be done one object at a time — but the real power shows up once that data is put into a graph. BloodHound models AD as nodes (users, groups, computers, GPOs) and edges (group membership, ACLs, sessions, admin rights) and then finds paths through that graph that a human reading tables never would. It's the highest-value tool in this entire module, and most testers run it as early as possible.

## How it's built

Two parts, always:

1. **Collector / ingestor** — gathers the raw data. `SharpHound` (C#, runs on a Windows host) or `BloodHound.py` (Python, runs from Linux with no domain join needed).
2. **BloodHound GUI** — a Neo4j-backed app that loads the collector's JSON and runs queries (pre-built or custom Cypher) against it.

**Data collected:** users, groups, computers, group membership, GPOs, ACLs, domain trusts, local admin access, logged-on user sessions, RDP/WinRM access, and object properties.

## Collecting from Linux — BloodHound.py

No domain-joined Windows host required — a real advantage when your only foothold is a Linux attack box with valid creds.

Requires Impacket, `ldap3`, and `dnspython`.

### Collection methods (`-c`)

`Group, LocalAdmin, Session, Trusts, Default, DCOnly, DCOM, RDP, PSRemote, LoggedOn, ObjectProps, ACL, All`

```bash
sudo bloodhound-python -u 'forend' -p '<PASSWORD>' -ns <DC_IP> -d <DOMAIN> -c all
```

| Flag | Meaning |
| :--- | :--- |
| `-u` / `-p` | Credentials |
| `-ns` | Nameserver — point this at the DC |
| `-d` | Domain |
| `-c all` | Run every collection method |

```bash
ls
# 20220307163102_computers.json
# 20220307163102_domains.json
# 20220307163102_groups.json
# 20220307163102_users.json
```

### Loading into the GUI

```bash
zip -r ilfreight_bh.zip *.json
sudo neo4j start
bloodhound   # creds pre-populated, or neo4j / HTB_@cademy_stdnt!
```

Click **Upload Data** → select the zip → wait for it to finish ingesting.

## Collecting from Windows — SharpHound

```powershell
.\SharpHound.exe --help
.\SharpHound.exe -c All --zipfilename ILFREIGHT

# Prefer stealth mode (DCOnly) on evasive engagements — collects from the DC
# via LDAP only, skipping the noisier session/local-admin sweeps of every host
.\SharpHound.exe -c All --stealth
```

**Collection methods:** `Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote`

```bash
bloodhound
# Creds: neo4j : HTB_@cademy_stdnt!
# Upload Data → select zip → wait for 100% → close
```

## Running queries

Open the **Analysis** tab for the pre-built path-finding queries, or write your own in the **Raw Query** box with Cypher.

| Query | Finds |
| :--- | :--- |
| **Find Shortest Paths to Domain Admins** | The money query — every logical route (users, groups, hosts, ACLs, GPOs) to a DA |
| **Shortest Paths from Owned Principals** | Paths starting from accounts you've already compromised |
| **List all Kerberoastable Accounts** | SPN-bearing accounts — feed straight into [Kerberoasting](kerberoasting.md) |
| **Find AS-REP Roastable Users** | Accounts with Kerberos pre-auth disabled |
| **Find Computers with Unsupported Operating Systems** | Legacy Win7/Server 2008 hosts — potential MS08-067/EternalBlue targets |
| **Find Computers where Domain Users are Local Admin** | Hosts where *any* authenticated user already has local admin |

```text
BloodHound-collector (SharpHound / BloodHound.py)
  → Upload Data (GUI)
    → Analysis tab → "Find Shortest Paths to Domain Admins"
      → Mark owned principals as you compromise them
        → Re-run "Shortest Paths from Owned Principals"
```

!!! note "Legacy OS caution"
    Before attacking a host BloodHound flags as unsupported/legacy, validate it's actually "live" in the business sense — fragile EOL systems are sometimes production-critical and a crash is a bigger problem than a missed shell. Recommend segmentation or decommissioning in the report either way.

Beyond path-finding, explore the **Database Info** and **Node Info** tabs for raw object detail, and use **Settings** for dark mode and controlling how much of the graph renders at once on large domains.

## Why run it early

A single low-privileged domain user — the same one a [spray](password-spraying.md) or a [poisoning capture](llmnr-nbtns-poisoning.md) just handed you — is enough to collect the whole domain's graph. Running BloodHound at the start of credentialed access, rather than after manual enumeration is exhausted, routinely turns up an escalation chain a manual pass would have missed (nested group membership, an ACL grant nobody remembers setting, a DCOM/RDP right left over from a decommissioned admin workflow).

## Next

BloodHound will usually point at specific accounts worth targeting directly. To keep a quiet footprint while you work the graph, enumerate with native tooling only in [Living Off the Land](living-off-the-land.md). When BloodHound surfaces SPN-bearing service accounts — especially ones sitting in privileged groups — move to [Kerberoasting](kerberoasting.md).
