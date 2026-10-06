---
title: "Internal Network & Active Directory Checklist"
description: "Interactive internal network and Active Directory penetration testing checklist from foothold to domain dominance"
tags:
  - Checklists
  - Active Directory
  - Internal
  - Methodology
---

# Internal Network & Active Directory Checklist

!!! note "What this page is doing"
    Move from network position to identity graph to one validated path. Read policy before spraying or coercing, keep every directory change reversible, and record blocked actions as control evidence.

!!! tip "Keep a Parallel Detection Log"
    For purple-team engagements, log next to each item: `timestamp | ATT&CK ID | host | expected telemetry | detected?`. That single log is worth more than the screenshot dump.

---

## 1. Network Presence & Discovery

- [ ] Confirm network position (internal, DMZ, VPN, cloud VPC)
- [ ] Identify local subnet, gateway, DNS servers, and domain via DHCP/DNS config
- [ ] Ping sweep + ARP scan for live hosts (`nmap -sn`, `arp-scan`, `fping`)
- [ ] Port scan live hosts (fast sweep → targeted service scan)
- [ ] Enumerate listening UDP services (SNMP 161, DNS 53, IKE, NetBIOS)
- [ ] Identify non-AD infrastructure (NAS, printers, cameras, VoIP, OT/IoT)
- [ ] Capture broadcast traffic to find hostnames, subnets, and other segments
- [ ] Identify egress filtering (which outbound ports/protocols are allowed)

## 2. Unauthenticated Attacks

- [ ] LLMNR / NBT-NS / mDNS poisoning with Responder
- [ ] Capture and crack Net-NTLMv2 hashes (hashcat 5600)
- [ ] Check SMB signing across hosts; build a relay target list
- [ ] Relay NTLM to SMB / LDAP / ADCS / MSSQL / Exchange targets
- [ ] Test SMB null sessions and guest access on all hosts
- [ ] Test anonymous LDAP bind and RID cycling for username discovery
- [ ] Test anonymous FTP / NFS exports / SMB shares for data exposure
- [ ] Coerce authentication (PetitPotam, PrinterBug, Coercer) to capture or relay
- [ ] Check for ADIDNS wildcard injection / unauthenticated DNS updates
- [ ] Test whether unauthenticated SMB share access yields creds or scripts

## 3. Authenticated Enumeration

- [ ] Validate credentials and enumerate your effective rights
- [ ] Map domain users, groups, computers, and OUs (LDAP / NetExec)
- [ ] Read password policy and lockout policy BEFORE spraying
- [ ] Hunt passwords in `description`, `info`, `comment`, and script fields
- [ ] Enumerate SMB shares and spider them for credentials, configs, and scripts
- [ ] Look for GPP `cPassword` in SYSVOL
- [ ] Read LAPS passwords where you have rights
- [ ] Enumerate service accounts and SPN-bearing accounts
- [ ] Enumerate DNS records and internal applications (ADIDNS dump)
- [ ] Enumerate domain trusts and foreign principals with rights in this domain
- [ ] Run BloodHound collection (ACL, trusts, sessions, groups, DCOM/RDP/PSRemote)
- [ ] Analyze BloodHound for the shortest path to Domain Admins / Tier 0

## 4. Credential Attacks

- [ ] AS-REP Roast accounts without Kerberos pre-authentication
- [ ] Kerberoast service accounts with SPNs (request RC4 where possible)
- [ ] Crack captured hashes (rockyou + rules, then targeted wordlists)
- [ ] Password spray using lockout-safe windows and single-attempt-per-round
- [ ] Test for password reuse between local admin accounts (host-to-host)
- [ ] Extract local SAM/LSA secrets from any host you administer
- [ ] Dump LSASS / cached credentials on high-value hosts
- [ ] Search file shares, scripts, and config files for hardcoded credentials
- [ ] Check for unconstrained delegation hosts and coerce a DC to them
- [ ] Test constrained delegation (S4U2Self/S4U2Proxy) where applicable

## 5. ADCS & ACL Escalation

- [ ] Enumerate CAs and certificate templates (Certipy find)
- [ ] Check ESC1 (enrollee-supplied SAN) and request a DA certificate
- [ ] Check ESC2/ESC3 (Any Purpose / enrollment agent)
- [ ] Check ESC4 (writable template) and modify it into an ESC1
- [ ] Check ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)
- [ ] Check ESC7 (ManageCA / ManageCertificates rights)
- [ ] Check ESC8 (HTTP enrollment endpoint) and relay a DC to get a certificate
- [ ] Authenticate with obtained certificates via PKINIT for NT hashes
- [ ] Enumerate ACL edges: GenericAll, GenericWrite, WriteDacl, WriteOwner, AddMember
- [ ] Abuse ForceChangePassword / AddMember / AddSelf where present
- [ ] Deploy Shadow Credentials (msDS-KeyCredentialLink) on writable objects
- [ ] Perform RBCD where you can write the target's delegation attribute
- [ ] Grant yourself DCSync rights via WriteDacl on the domain object

## 6. Lateral Movement & Pivoting

- [ ] Pass-the-Hash across hosts with the same local admin password
- [ ] Pass-the-Ticket / Overpass-the-Hash with Kerberos
- [ ] Choose the least noisy remote execution method (WMIExec/WinRM over PsExec)
- [ ] Establish a pivot (Ligolo-ng / Chisel / sshuttle) into new network segments
- [ ] Add internal routes / proxy chains and verify reachability
- [ ] Enumerate known-vulnerable software & missing patches (Nessus / nmap NSE / Windows Update check)
- [ ] Test MSSQL linked servers and `xp_cmdshell` across the estate
- [ ] Identify hosts with Domain Admin sessions (BloodHound "HasSession")
- [ ] Credential-hunt on every newly compromised host (LSA, SAM, DPAPI, browser, history)
- [ ] Document each hop (source → destination → credential → technique)

## 7. Domain Dominance & Objectives

- [ ] DCSync with obtained replication rights (`secretsdump -just-dc`)
- [ ] Extract NTDS.dit via VSS or remote RPC where DCSync is not possible
- [ ] Generate a Golden Ticket (and document the blast radius)
- [ ] Test whether krbtgt rotation would invalidate all forged tickets
- [ ] Escalate to the parent/root domain via SID History injection (if child domain)
- [ ] Exploit ADCS CA takeover (ESC5/ESC7) for durable trust-level access
- [ ] Escalate to Exchange / M365 / Azure (hybrid identity, Entra Connect account)
- [ ] Access the engagement's defined crown jewels with evidence (screenshots + hashes of files)
- [ ] Test critical vulnerability condition (e.g., Domain Admin count, GPO push) only if in scope

## 8. Cleanup & Reporting

- [ ] Remove machine accounts you created (e.g., `PWNED$`)
- [ ] Remove RBCD / ACL / KeyCredential changes you introduced
- [ ] Delete scheduled tasks, services, and dropped binaries on every host
- [ ] Remove persistence (Golden Ticket evidence is fine; live backdoors are not)
- [ ] Confirm with the client if krbtgt rotation is required (and document it)
- [ ] Provide the IOC list to the blue team (IPs, domains, hashes, filenames, tools)
- [ ] Report with remediation priority: quick wins vs. structural changes
- [ ] Include the detection-gap summary (what was NOT detected, and how to detect it)
- [ ] Deliver an executive summary that is board-readable with risk quantification